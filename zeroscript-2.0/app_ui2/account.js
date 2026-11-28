/* SPDX-License-Identifier: GPL-3.0-or-later */
/* ZeroScript — account settings client.
   Every action goes through the server; the page only renders what the
   server returns and never decides a role, membership or plan locally. */
(() => {
  "use strict";

  const $ = (sel, root = document) => root.querySelector(sel);
  const $$ = (sel, root = document) => [...root.querySelectorAll(sel)];

  let csrfToken = "";
  let account = null;

  /* ── API helper ─────────────────────────────────────────────── */
  async function api(path, body) {
    const opts = {
      method: body === undefined ? "GET" : "POST",
      headers: { "Content-Type": "application/json" },
      credentials: "same-origin",
    };
    if (body !== undefined) opts.body = JSON.stringify(body);
    if (csrfToken) opts.headers["X-CSRF-Token"] = csrfToken;

    const res = await fetch(path, opts);
    let data = {};
    try {
      data = await res.json();
    } catch (err) {
      data = { ok: false, error: `Unexpected response (${res.status}).` };
    }
    if (res.status === 401) {
      window.location.href = "/2/login?next=/2/account";
      throw new Error("Session expired.");
    }
    if (!res.ok || data.ok === false) {
      const error = new Error(data.error || `Request failed (${res.status}).`);
      error.field = data.field || "";
      error.status = res.status;
      throw error;
    }
    return data;
  }

  /* ── Small helpers ─────────────────────────────────────────── */
  function banner(id, message, kind = "error") {
    const el = $(id);
    if (!el) return;
    if (!message) {
      el.hidden = true;
      el.textContent = "";
      el.className = "banner";
      return;
    }
    el.hidden = false;
    el.className = `banner ${kind === "error" ? "" : kind}`.trim();
    el.textContent = message;
  }

  function clearErrors(form) {
    $$("[data-error-for]", form).forEach((el) => (el.textContent = ""));
    $$("input", form).forEach((el) => el.classList.remove("invalid"));
  }

  function fieldError(form, field, message) {
    if (!field) return;
    const slot = $(`[data-error-for="${field}"]`, form);
    if (slot) slot.textContent = message;
    const input = form.querySelector(`[name="${field}"]`);
    if (input) input.classList.add("invalid");
  }

  function applyError(form, bannerId, err) {
    clearErrors(form);
    if (err.field) fieldError(form, err.field, err.message);
    banner(bannerId, err.message);
  }

  function busy(button, on, busyLabel) {
    if (!button) return;
    button.disabled = !!on;
    button.classList.toggle("loading", !!on);
    const label = $(".btn-label", button);
    if (label && busyLabel) label.textContent = on ? busyLabel : button.dataset.idleLabel || label.textContent;
  }

  function formatDate(value) {
    if (!value) return "—";
    const date = new Date(value);
    if (Number.isNaN(date.getTime())) return String(value);
    return date.toLocaleDateString(undefined, {
      year: "numeric", month: "short", day: "numeric",
    }) + " · " + date.toLocaleTimeString(undefined, { hour: "2-digit", minute: "2-digit" });
  }

  function formatRelative(value) {
    if (!value) return "never";
    const date = new Date(value);
    if (Number.isNaN(date.getTime())) return String(value);
    const diff = Date.now() - date.getTime();
    const minutes = Math.round(diff / 60000);
    if (minutes < 1) return "just now";
    if (minutes < 60) return `${minutes}m ago`;
    const hours = Math.round(minutes / 60);
    if (hours < 24) return `${hours}h ago`;
    return `${Math.round(hours / 24)}d ago`;
  }

  function deviceIcon(userAgent) {
    const ua = String(userAgent || "").toLowerCase();
    if (ua.includes("windows")) return "▦";
    if (ua.includes("mac os") || ua.includes("macintosh")) return "◈";
    if (ua.includes("android")) return "▯";
    if (ua.includes("iphone") || ua.includes("ipad")) return "▯";
    if (ua.includes("linux")) return "◳";
    return "▢";
  }

  /* ── Renderers ─────────────────────────────────────────────── */
  function paintAvatar(url, initial) {
    ["#acct-avatar", "#acct-avatar-preview"].forEach((selector) => {
      const box = $(selector);
      if (!box) return;
      box.innerHTML = "";
      if (url) {
        const img = document.createElement("img");
        img.src = url;
        img.alt = "Profile picture";
        box.appendChild(img);
      } else {
        const span = document.createElement("span");
        span.textContent = (initial || "Z").toUpperCase().charAt(0);
        box.appendChild(span);
      }
    });
    const first = $("#acct-initial");
    if (first) first.textContent = (initial || "Z").toUpperCase().charAt(0);
    const second = $("#acct-initial-2");
    if (second) second.textContent = (initial || "Z").toUpperCase().charAt(0);
  }

  function renderIdentity(payload) {
    const user = payload.user || {};
    const membership = payload.membership || {};
    const role = (payload.role || user.role || "user").toLowerCase();

    $("#acct-name").textContent = user.displayName || user.username || "Account";
    $("#acct-email").textContent = user.email || "";
    $("#acct-created").textContent = `Account created ${formatDate(user.createdAt)} · last sign-in ${formatRelative(user.lastLoginAt)}`;
    $("#btn-admin-panel").hidden = !["owner", "admin", "moderator"].includes(role);

    const badge = $("#acct-badge");
    badge.textContent = membership.planLabel || "AI NOOB";
    badge.className = "membership-badge " + (membership.plan === "pro" ? "pro" : membership.plan === "master" ? "master" : "");

    $("#acct-verified").hidden = !user.emailVerified;

    const used = (payload.usage && payload.usage.today) || 0;
    const limit = (payload.usage && payload.usage.limit) || 0;
    $("#acct-usage-used").textContent = used;
    $("#acct-usage-limit").textContent = limit ? `/ ${limit}` : "/ ∞";
    const ring = $("#acct-usage-ring");
    if (ring) {
      const pct = limit ? Math.min(100, Math.round((used / limit) * 100)) : 0;
      ring.style.borderColor = pct >= 100 ? "rgba(255,110,133,.7)" : `rgba(139,124,255,${0.3 + pct / 140})`;
    }

    $("#acct-role").textContent = `role: ${role.toUpperCase()}`;
    const hashInfo = payload.hashScheme || {};
    $("#acct-hash").textContent = `password hashing: ${hashInfo.scheme || "—"}`;

    paintAvatar(user.avatarUrl, user.username);
    $("#profile-username").value = user.username || "";
    $("#profile-email").value = user.email || "";
    $("#profile-display").value = user.displayName || "";
    $("#profile-bio").value = user.bio || "";
  }

  function renderPlans(payload) {
    const grid = $("#plan-grid");
    grid.innerHTML = "";
    const current = (payload.membership && payload.membership.plan) || "noob";
    const plans = payload.plans || [];

    plans.forEach((plan) => {
      const isCurrent = plan.id === current;
      const option = document.createElement("div");
      option.className = "plan-option" + (isCurrent ? " current" : "");
      option.innerHTML = `
        <div class="plan-name">
          <b>${plan.name}</b>
          <small>${plan.requestsPerDay} AI requests / day</small>
          <div class="plan-features">
            ${(plan.features || []).map((f) => `<span>${f}</span>`).join("")}
          </div>
        </div>
        <div class="plan-price">
          <b>${plan.priceCents === 0 ? "Free" : `$${plan.price}`}</b>
          <small>${plan.priceCents === 0 ? "forever" : "per month"}</small>
        </div>`;

      if (!isCurrent && plan.paid) {
        const button = document.createElement("button");
        button.className = "btn primary sm";
        button.textContent = "Upgrade";
        button.addEventListener("click", () => startCheckout(plan, button));
        option.appendChild(button);
      } else if (isCurrent) {
        const tag = document.createElement("span");
        tag.className = "device-tag";
        tag.textContent = "Current";
        option.appendChild(tag);
      }
      grid.appendChild(option);
    });

    const membership = payload.membership || {};
    $("#plan-name").textContent = membership.planLabel || "AI NOOB";
    const detail = [];
    detail.push(membership.verified ? "verified by the server" : "assigned automatically");
    if (membership.expiresAt) detail.push(`renews ${formatDate(membership.expiresAt)}`);
    $("#plan-detail").textContent = detail.join(" · ");
    const dot = $("#plan-dot");
    if (dot) {
      const plan = plans.find((p) => p.id === membership.plan);
      const color = plan ? plan.color : "#7f8ca3";
      dot.style.background = color;
      dot.style.color = color;
    }
  }

  function renderDevices(sessions) {
    const list = $("#device-list");
    list.innerHTML = "";
    if (!sessions || !sessions.length) {
      list.innerHTML = '<p class="acct-meta">No sessions recorded.</p>';
      return;
    }
    sessions.forEach((session) => {
      const revoked = !!session.revoked_at;
      const row = document.createElement("div");
      row.className = "device";
      const tag = session.persistent ? "remembered" : "session";
      row.innerHTML = `
        <span class="device-icon">${deviceIcon(session.user_agent)}</span>
        <div class="device-meta">
          <b>${(session.user_agent || "Unknown device").slice(0, 64)}</b>
          <small>${session.ip || "local"} · last active ${formatRelative(session.last_seen_at)}${session.revoke_reason ? " · " + session.revoke_reason : ""}</small>
        </div>
        <span class="device-tag ${revoked ? "stale" : ""}">${revoked ? "signed out" : tag}</span>`;
      list.appendChild(row);
    });
  }

  function renderNotifications(notifications) {
    const list = $("#notice-list");
    list.innerHTML = "";
    if (!notifications || !notifications.length) {
      list.innerHTML = '<p class="acct-meta">Nothing here yet.</p>';
      return;
    }
    notifications.forEach((note) => {
      const item = document.createElement("div");
      item.className = "notice";
      item.innerHTML = `<b>${note.title}</b><small>${note.body || ""}</small>`;
      list.appendChild(item);
    });
  }

  function renderDataStats(payload) {
    const stats = $("#data-stats");
    const chat = (payload.usage && payload.usage.chat) || {};
    const tiles = [
      { value: chat.messages || 0, label: "Chat messages" },
      { value: payload.sessions ? payload.sessions.filter((s) => !s.revoked_at).length : 0, label: "Active sessions" },
      { value: (payload.notifications || []).length, label: "Notifications" },
      { value: (payload.membership && payload.membership.planLabel) || "AI NOOB", label: "Membership" },
    ];
    stats.innerHTML = tiles
      .map((tile) => `<div class="data-stat"><b>${tile.value}</b><small>${tile.label}</small></div>`)
      .join("");
  }

  /* ── Checkout ───────────────────────────────────────────────── */
  async function startCheckout(plan, button) {
    banner("#membership-banner", "");
    busy(button, true, "Opening…");
    try {
      const result = await api("/api2/membership/checkout", { plan: plan.id });
      const checkout = result.checkout || {};
      const confirmed = window.confirm(
        `ZeroScript ${plan.name} — $${(checkout.amountCents / 100).toFixed(2)} per month.\n\n` +
        `The server created payment #${checkout.paymentId} and signed a checkout token. ` +
        `Confirm the payment to activate the plan.`
      );
      if (!confirmed) {
        banner("#membership-banner", "Checkout cancelled. No membership was changed.", "info");
        busy(button, false);
        return;
      }
      const done = await api("/api2/membership/confirm", { checkoutToken: checkout.checkoutToken });
      banner("#membership-banner", `${done.membership.planLabel} is now active.`, "ok");
      await load();
    } catch (err) {
      banner("#membership-banner", err.message);
      busy(button, false);
    }
  }

  /* ── Loaders ────────────────────────────────────────────────── */
  async function load() {
    try {
      const session = await api("/api2/auth/session");
      if (!session.authenticated) {
        window.location.href = "/2/login?next=/2/account";
        return;
      }
      csrfToken = session.csrfToken || "";
      const payload = await api("/api2/account/profile");
      account = payload;
      renderIdentity(payload);
      renderPlans(payload);
      renderDevices(payload.sessions);
      renderNotifications(payload.notifications);
      renderDataStats(payload);
    } catch (err) {
      banner("#profile-banner", err.message);
    }
  }

  async function loadSessions() {
    banner("#devices-banner", "");
    try {
      const result = await api("/api2/account/sessions");
      renderDevices(result.sessions);
    } catch (err) {
      banner("#devices-banner", err.message);
    }
  }

  /* ── Password visibility ────────────────────────────────────── */
  $$(".toggle-pw").forEach((button) => {
    button.addEventListener("click", () => {
      const input = document.getElementById(button.dataset.toggle);
      if (!input) return;
      const show = input.type === "password";
      input.type = show ? "text" : "password";
      button.setAttribute("aria-pressed", String(show));
      button.setAttribute("aria-label", show ? "Hide password" : "Show password");
      input.focus();
    });
  });

  /* ── Profile form ───────────────────────────────────────────── */
  const profileForm = $("#profile-form");
  $("#profile-save").dataset.idleLabel = "Save profile";
  profileForm.addEventListener("submit", async (event) => {
    event.preventDefault();
    banner("#profile-banner", "");
    clearErrors(profileForm);
    const button = $("#profile-save");
    busy(button, true, "Saving…");
    try {
      const result = await api("/api2/account/profile", {
        username: $("#profile-username").value.trim(),
        email: $("#profile-email").value.trim(),
        displayName: $("#profile-display").value.trim(),
        bio: $("#profile-bio").value.trim(),
      });
      banner("#profile-banner", "Profile saved.", "ok");
      renderIdentity({ ...account, user: result.user, membership: result.membership });
    } catch (err) {
      applyError(profileForm, "#profile-banner", err);
    } finally {
      busy(button, false);
    }
  });

  /* ── Avatar ─────────────────────────────────────────────────── */
  $("#avatar-file").addEventListener("change", async (event) => {
    const file = event.target.files && event.target.files[0];
    if (!file) return;
    if (file.size > 4 * 1024 * 1024) {
      banner("#profile-banner", "Images must be smaller than 4 MB.");
      event.target.value = "";
      return;
    }
    const reader = new FileReader();
    reader.onload = async () => {
      try {
        const result = await api("/api2/account/avatar", { dataUrl: reader.result });
        banner("#profile-banner", "Profile picture updated.", "ok");
        paintAvatar(result.avatarUrl, (result.user && result.user.username) || "Z");
      } catch (err) {
        banner("#profile-banner", err.message);
      }
    };
    reader.onerror = () => banner("#profile-banner", "Could not read that image.");
    reader.readAsDataURL(file);
  });

  $("#avatar-remove").addEventListener("click", async () => {
    try {
      await api("/api2/account/avatar", { dataUrl: "" });
      banner("#profile-banner", "Profile picture removed.", "ok");
      paintAvatar(null, (account && account.user && account.user.username) || "Z");
    } catch (err) {
      banner("#profile-banner", err.message);
    }
  });

  /* ── Password form ──────────────────────────────────────────── */
  const passwordForm = $("#password-form");
  $("#password-save").dataset.idleLabel = "Update password";
  passwordForm.addEventListener("submit", async (event) => {
    event.preventDefault();
    banner("#password-banner", "");
    clearErrors(passwordForm);
    const next = $("#pw-new").value;
    if (next !== $("#pw-confirm").value) {
      fieldError(passwordForm, "confirmPassword", "Passwords do not match.");
      banner("#password-banner", "Passwords do not match.");
      return;
    }
    const button = $("#password-save");
    busy(button, true, "Updating…");
    try {
      const result = await api("/api2/account/password", {
        currentPassword: $("#pw-current").value,
        password: next,
        confirmPassword: $("#pw-confirm").value,
      });
      banner(
        "#password-banner",
        `Password updated. ${result.revoked || 0} other session(s) were signed out.`,
        "ok"
      );
      passwordForm.reset();
      loadSessions();
    } catch (err) {
      applyError(passwordForm, "#password-banner", err);
    } finally {
      busy(button, false);
    }
  });

  /* ── AI conversations ────────────────────────────────────────── */
  async function loadChat() {
    banner("#chat-banner", "");
    try {
      const result = await api("/api2/chat/history?limit=40");
      const list = $("#chat-list");
      const messages = result.messages || [];
      list.innerHTML = "";
      if (!messages.length) {
        list.innerHTML = '<p class="acct-meta">No conversations saved yet. '
          + 'Use the Studio Bridge with an AI assistant and they appear here.</p>';
        return;
      }
      messages.slice().reverse().forEach((message) => {
        const item = document.createElement("div");
        item.className = "notice";
        const preview = String(message.content || "").replace(/\s+/g, " ").slice(0, 220);
        item.innerHTML = `<b>${message.role || "user"} · ${message.tool_name || message.provider || "workspace"}</b>`
          + `<small>${preview}</small>`
          + `<small style="opacity:.6;margin-top:4px">${formatDate(message.created_at)}</small>`;
        list.appendChild(item);
      });
    } catch (err) {
      banner("#chat-banner", err.message);
    }
  }

  $("#btn-refresh-chat")?.addEventListener("click", loadChat);

  /* ── Sessions ───────────────────────────────────────────────── */
  $("#btn-refresh-sessions").addEventListener("click", loadSessions);

  async function logoutAll() {
    if (!window.confirm("Sign out of every device, including this one?")) return;
    try {
      await api("/api2/auth/logout-all", {});
    } catch (err) {
      /* the cookie is cleared server side either way */
    }
    window.location.href = "/2/login";
  }

  $("#btn-logout-all").addEventListener("click", logoutAll);
  $("#btn-logout-all-2").addEventListener("click", logoutAll);

  $("#btn-logout").addEventListener("click", async () => {
    try {
      await api("/api2/auth/logout", {});
    } catch (err) {
      /* ignore */
    }
    window.location.href = "/2/login";
  });

  /* ── Data actions ───────────────────────────────────────────── */
  $("#btn-save").addEventListener("click", async () => {
    banner("#data-banner", "");
    const button = $("#btn-save");
    busy(button, true, "Saving…");
    try {
      const result = await api("/api2/data/save", {});
      banner(
        "#data-banner",
        `Saved ${result.projects} project(s), ${result.files} file(s), ${result.skills} skill(s) and ${result.plugins} plugin(s).`,
        "ok"
      );
    } catch (err) {
      banner("#data-banner", err.message);
    } finally {
      busy(button, false);
    }
  });

  $("#btn-export").addEventListener("click", async () => {
    banner("#data-banner", "");
    const button = $("#btn-export");
    busy(button, true, "Exporting…");
    try {
      const result = await api("/api2/data/backup");
      const blob = new Blob([JSON.stringify(result.backup, null, 2)], { type: "application/json" });
      const url = URL.createObjectURL(blob);
      const link = document.createElement("a");
      const stamp = new Date().toISOString().replace(/[:.]/g, "-");
      link.href = url;
      link.download = `zeroscript-backup-${stamp}.json`;
      link.click();
      setTimeout(() => URL.revokeObjectURL(url), 2000);
      banner("#data-banner", "Backup exported.", "ok");
    } catch (err) {
      banner("#data-banner", err.message);
    } finally {
      busy(button, false);
    }
  });

  /* ── Delete account ─────────────────────────────────────────── */
  const deleteForm = $("#delete-form");
  $("#delete-submit").dataset.idleLabel = "Delete my account";
  deleteForm.addEventListener("submit", async (event) => {
    event.preventDefault();
    banner("#delete-banner", "");
    clearErrors(deleteForm);
    const confirmText = $("#delete-confirm").value.trim();
    if (confirmText.toUpperCase() !== "DELETE") {
      fieldError(deleteForm, "confirm", "Type DELETE to confirm removing this account.");
      banner("#delete-banner", "Type DELETE to confirm removing this account.");
      return;
    }
    if (!window.confirm("This permanently deletes your account and its stored data. Continue?")) return;
    const button = $("#delete-submit");
    busy(button, true, "Deleting…");
    try {
      await api("/api2/account/delete", {
        confirm: confirmText,
        password: $("#delete-password").value,
      });
      window.location.href = "/2/login";
    } catch (err) {
      applyError(deleteForm, "#delete-banner", err);
      busy(button, false);
    }
  });

  /* ── Boot ───────────────────────────────────────────────────── */
  load().then(loadChat);
})();
