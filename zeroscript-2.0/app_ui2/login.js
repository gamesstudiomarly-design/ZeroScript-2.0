/* SPDX-License-Identifier: GPL-3.0-or-later */
/* ZeroScript — authentication client.
   Talks to /api2/auth/* on the local server. All validation feedback that the
   server returns is surfaced per field; the client never decides a role, a
   membership or a password policy on its own. */
(() => {
  "use strict";

  const $ = (sel, root = document) => root.querySelector(sel);
  const $$ = (sel, root = document) => [...root.querySelectorAll(sel)];

  const params = new URLSearchParams(window.location.search);
  const nextUrl = params.get("next") || "/2/";
  let csrfToken = "";

  /* ── API helper ─────────────────────────────────────────────── */
  async function api(path, body) {
    const opts = {
      method: body === undefined ? "GET" : "POST",
      headers: { "Content-Type": "application/json" },
      credentials: "same-origin",
    };
    if (body !== undefined) opts.body = JSON.stringify(body);
    if (csrfToken) opts.headers["X-CSRF-Token"] = csrfToken;

    let res;
    try {
      res = await fetch(path, opts);
    } catch (err) {
      throw new Error("Cannot reach the ZeroScript server. Is it still running?");
    }
    let data = {};
    try {
      data = await res.json();
    } catch (err) {
      data = { ok: false, error: `Unexpected response from the server (${res.status}).` };
    }
    if (!res.ok || data.ok === false) {
      const error = new Error(data.error || `Request failed (${res.status}).`);
      error.field = data.field || "";
      error.status = res.status;
      error.payload = data;
      throw error;
    }
    return data;
  }

  /* ── Screens ────────────────────────────────────────────────── */
  function showScreen(id) {
    $$(".screen").forEach((screen) => screen.classList.toggle("active", screen.id === id));
    const first = $(`#${id} input`);
    if (first) setTimeout(() => first.focus(), 60);
  }

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
    if (err.field) {
      fieldError(form, err.field, err.message);
    }
    banner(bannerId, err.message);
    const firstBad = form.querySelector("input.invalid");
    if (firstBad) firstBad.focus();
  }

  function busy(button, on) {
    if (!button) return;
    button.disabled = !!on;
    button.classList.toggle("loading", !!on);
    const label = $(".btn-label", button);
    if (label) label.textContent = on ? (button.dataset.busyLabel || "Working…") : button.dataset.idleLabel || label.textContent;
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

  /* ── Password strength meter ────────────────────────────────── */
  const strengthFill = $("#strength-fill");
  const strengthLabel = $("#strength-label");

  function scorePassword(value) {
    let score = 0;
    if (value.length >= 8) score += 1;
    if (value.length >= 12) score += 1;
    if (value.length >= 10 && /[a-z]/.test(value) && /[0-9]/.test(value)) score += 1;
    if (value.length >= 16 && /[^A-Za-z0-9]/.test(value)) score += 1;
    return score;
  }

  const STRENGTH_COLORS = ["#ff6e85", "#ff9f6e", "#e8bb62", "#7fd88f", "#51d6a1"];
  const STRENGTH_LABELS = ["Very weak", "Weak", "Fair", "Good", "Strong"];

  function renderStrength(value) {
    if (!strengthFill) return;
    const score = scorePassword(value || "");
    strengthFill.style.width = `${(score / 4) * 100}%`;
    strengthFill.style.background = STRENGTH_COLORS[score];
    strengthLabel.textContent = value
      ? STRENGTH_LABELS[score]
      : "Use 8+ characters with a number.";
  }

  $("#register-password")?.addEventListener("input", (event) => renderStrength(event.target.value));

  /* ── Avatar picker ──────────────────────────────────────────── */
  let pendingAvatar = null;
  const avatarInput = $("#register-avatar");
  const avatarPreview = $("#avatar-preview");

  function paintAvatar(dataUrl, initial) {
    if (!avatarPreview) return;
    avatarPreview.innerHTML = "";
    if (dataUrl) {
      const img = document.createElement("img");
      img.src = dataUrl;
      img.alt = "Profile picture preview";
      avatarPreview.appendChild(img);
    } else {
      const span = document.createElement("span");
      span.textContent = (initial || "Z").toUpperCase().charAt(0);
      avatarPreview.appendChild(span);
    }
  }

  function readFileAsDataUrl(file) {
    return new Promise((resolve, reject) => {
      const reader = new FileReader();
      reader.onload = () => resolve(reader.result);
      reader.onerror = () => reject(new Error("Could not read that image."));
      reader.readAsDataURL(file);
    });
  }

  avatarInput?.addEventListener("change", async () => {
    const file = avatarInput.files && avatarInput.files[0];
    if (!file) return;
    if (file.size > 4 * 1024 * 1024) {
      banner("#register-banner", "Images must be smaller than 4 MB.");
      avatarInput.value = "";
      return;
    }
    try {
      pendingAvatar = await readFileAsDataUrl(file);
      paintAvatar(pendingAvatar);
    } catch (err) {
      banner("#register-banner", err.message);
    }
  });

  $("#avatar-clear")?.addEventListener("click", () => {
    pendingAvatar = null;
    if (avatarInput) avatarInput.value = "";
    paintAvatar(null, $("#register-username")?.value);
  });

  $("#register-username")?.addEventListener("input", (event) => {
    if (!pendingAvatar) paintAvatar(null, event.target.value);
  });

  /* ── Screen navigation ──────────────────────────────────────── */
  $$("[data-goto]").forEach((button) => {
    button.addEventListener("click", () => {
      const target = button.dataset.goto;
      $$(".screen").forEach((screen) => {
        const match = screen.id === target;
        screen.classList.toggle("active", match);
        if (match) {
          const banner = $(".banner", screen);
          if (banner) banner.hidden = true;
        }
      });
      const first = $(`#${target} input`);
      if (first) setTimeout(() => first.focus(), 60);
    });
  });

  /* ── Sign in ────────────────────────────────────────────────── */
  const loginForm = $("#screen-login");
  const loginButton = $("#login-submit");
  loginButton.dataset.idleLabel = "Sign in";
  loginButton.dataset.busyLabel = "Signing in…";

  loginForm.addEventListener("submit", async (event) => {
    event.preventDefault();
    banner("#login-banner", "");
    clearErrors(loginForm);
    busy(loginButton, true);
    try {
      const result = await api("/api2/auth/login", {
        email: $("#login-email").value.trim(),
        password: $("#login-password").value,
        remember: $("#login-remember").checked,
      });
      csrfToken = result.csrfToken || "";
      try { sessionStorage.setItem("zs_csrf", csrfToken); } catch (err) { /* ignore */ }
      window.location.href = nextUrl;
    } catch (err) {
      applyError(loginForm, "#login-banner", err);
      busy(loginButton, false);
    }
  });

  /* ── Register ───────────────────────────────────────────────── */
  const registerForm = $("#screen-register");
  const registerButton = $("#register-submit");
  registerButton.dataset.idleLabel = "Create account";
  registerButton.dataset.busyLabel = "Creating…";

  registerForm.addEventListener("submit", async (event) => {
    event.preventDefault();
    banner("#register-banner", "");
    clearErrors(registerForm);

    const password = $("#register-password").value;
    const confirm = $("#register-confirm").value;
    if (password !== confirm) {
      fieldError(registerForm, "confirmPassword", "Passwords do not match.");
      banner("#register-banner", "Passwords do not match.");
      return;
    }

    busy(registerButton, true);
    try {
      const result = await api("/api2/auth/register", {
        username: $("#register-username").value.trim(),
        email: $("#register-email").value.trim(),
        password,
        confirmPassword: confirm,
        remember: $("#register-remember").checked,
      });
      csrfToken = result.csrfToken || "";

      if (pendingAvatar) {
        try {
          await api("/api2/account/avatar", { dataUrl: pendingAvatar });
        } catch (err) {
          // The account exists; the avatar can be retried from the account page.
          console.warn("Avatar upload deferred:", err.message);
        }
      }

      const verification = result.verification || {};
      if (verification.link) {
        banner(
          "#register-banner",
          `Account created. Verification link (local mail spool): ${verification.link}`,
          "ok"
        );
      } else {
        banner("#register-banner", "Account created. Check your email to verify your address.", "ok");
      }
      window.location.href = nextUrl;
    } catch (err) {
      applyError(registerForm, "#register-banner", err);
      busy(registerButton, false);
    }
  });

  /* ── Forgot password ────────────────────────────────────────── */
  const forgotForm = $("#screen-forgot");
  const forgotButton = $("#forgot-submit");
  forgotButton.dataset.idleLabel = "Send reset link";
  forgotButton.dataset.busyLabel = "Sending…";

  forgotForm.addEventListener("submit", async (event) => {
    event.preventDefault();
    banner("#forgot-banner", "");
    clearErrors(forgotForm);
    busy(forgotButton, true);
    try {
      const result = await api("/api2/auth/forgot-password", {
        email: $("#forgot-email").value.trim(),
      });
      const delivery = result.delivery || {};
      if (delivery.link) {
        banner(
          "#forgot-banner",
          `Reset link created (local mail spool): ${delivery.link}`,
          "ok"
        );
      } else {
        banner(
          "#forgot-banner",
          result.message || "If that address has an account, a reset link is on its way.",
          "ok"
        );
      }
    } catch (err) {
      applyError(forgotForm, "#forgot-banner", err);
    } finally {
      busy(forgotButton, false);
    }
  });

  /* ── Reset password ─────────────────────────────────────────── */
  const resetForm = $("#screen-reset");
  const resetButton = $("#reset-submit");
  resetButton.dataset.idleLabel = "Update password";
  resetButton.dataset.busyLabel = "Updating…";

  resetForm.addEventListener("submit", async (event) => {
    event.preventDefault();
    banner("#reset-banner", "");
    clearErrors(resetForm);
    const password = $("#reset-password").value;
    if (password !== $("#reset-confirm").value) {
      fieldError(resetForm, "confirmPassword", "Passwords do not match.");
      banner("#reset-banner", "Passwords do not match.");
      return;
    }
    busy(resetButton, true);
    try {
      await api("/api2/auth/reset-password", {
        token: params.get("reset") || "",
        password,
        confirmPassword: $("#reset-confirm").value,
      });
      banner("#reset-banner", "Password updated. You can sign in now.", "ok");
      setTimeout(() => showScreen("screen-login"), 1400);
    } catch (err) {
      applyError(resetForm, "#reset-banner", err);
      busy(resetButton, false);
    }
  });

  /* ── Verify email ───────────────────────────────────────────── */
  const verifyForm = $("#screen-verify");
  const verifyButton = $("#verify-submit");
  verifyButton.dataset.idleLabel = "Verify email address";
  verifyButton.dataset.busyLabel = "Verifying…";

  verifyForm.addEventListener("submit", async (event) => {
    event.preventDefault();
    banner("#verify-banner", "");
    busy(verifyButton, true);
    try {
      await api("/api2/auth/verify-email", { token: params.get("verify") || "" });
      banner("#verify-banner", "Email address verified.", "ok");
      setTimeout(() => showScreen("screen-login"), 1200);
    } catch (err) {
      banner("#verify-banner", err.message);
      busy(verifyButton, false);
    }
  });

  /* ── Boot ───────────────────────────────────────────────────── */
  (async function boot() {
    try {
      const session = await api("/api2/auth/session");
      if (session.authenticated) {
        window.location.href = nextUrl;
        return;
      }
      csrfToken = session.csrfToken || "";
    } catch (err) {
      /* stay on the login screen */
    }

    try {
      const info = await api("/api2/auth/plans");
      const free = (info.plans || []).find((plan) => plan.id === info.freePlan);
      if (free) {
        const chip = $("#chip-hash");
        if (chip) chip.textContent = `free tier: ${free.requestsPerDay} AI requests/day`;
      }
    } catch (err) { /* cosmetic only */ }

    if (params.get("reset")) {
      showScreen("screen-reset");
    } else if (params.get("verify")) {
      showScreen("screen-verify");
    } else if (params.get("registered")) {
      showScreen("screen-login");
      banner("#login-banner", "Account created — sign in to continue.", "ok");
    }
  })();
})();
