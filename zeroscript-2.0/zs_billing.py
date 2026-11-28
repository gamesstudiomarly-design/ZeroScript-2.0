# SPDX-License-Identifier: GPL-3.0-or-later
"""ZeroScript 2.0 - Membership plans, checkout and backend verification.

The browser is never trusted to decide a paid membership.  A client can ask
the server to open a checkout, but the server:

1. prices the plan from its own catalogue (the client cannot set an amount),
2. records a ``pending`` payment row, and
3. hands back a checkout token that is signed with a server-side secret.

Only a request carrying a valid, unexpired, correctly signed token - or a
verified provider callback, or an explicit owner/admin action recorded in the
audit trail - can move a membership to a paid tier.  Anything else leaves the
account on the free tier.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import secrets
import sqlite3
import time

import zs_db

# ---------------------------------------------------------------------------
# Plan catalogue (server owned)
# ---------------------------------------------------------------------------
PLANS = {
    "noob": {
        "id": "noob",
        "name": "AI NOOB",
        "priceCents": 0,
        "currency": "USD",
        "billingCycle": "monthly",
        "requestsPerDay": 30,
        "paid": False,
        "badge": "FREE",
        "color": "#7f8ca3",
        "features": ["Free models", "Basic tools", "Local projects"],
    },
    "pro": {
        "id": "pro",
        "name": "AI PRO",
        "priceCents": 999,
        "currency": "USD",
        "billingCycle": "monthly",
        "requestsPerDay": 500,
        "paid": True,
        "badge": "$9.99/mo",
        "color": "#8b7cff",
        "features": ["Premium models", "PRO tools", "Priority bridge"],
    },
    "master": {
        "id": "master",
        "name": "AI MASTER",
        "priceCents": 1999,
        "currency": "USD",
        "billingCycle": "monthly",
        "requestsPerDay": 2500,
        "paid": True,
        "badge": "$19.99/mo",
        "color": "#e8bb62",
        "features": ["All models", "Exclusive tools", "Early access"],
    },
}

PLAN_REQUESTS_PER_DAY = {plan_id: plan["requestsPerDay"] for plan_id, plan in PLANS.items()}
DEFAULT_PLAN = "noob"
CHECKOUT_TTL_SECONDS = 15 * 60


def public_plans() -> list:
    """Catalogue for the pricing table. Prices come from the server."""
    return [
        {
            "id": plan["id"],
            "name": plan["name"],
            "priceCents": plan["priceCents"],
            "price": f"{plan['priceCents'] / 100:.2f}",
            "currency": plan["currency"],
            "billingCycle": plan["billingCycle"],
            "requestsPerDay": plan["requestsPerDay"],
            "paid": plan["paid"],
            "badge": plan["badge"],
            "color": plan["color"],
            "features": plan["features"],
        }
        for plan in PLANS.values()
    ]


def get_plan(plan_id):
    return PLANS.get(str(plan_id or "").strip().lower())


# ---------------------------------------------------------------------------
# Server side signing secret
# ---------------------------------------------------------------------------
_secret_cache: bytes | None = None


def _server_secret() -> bytes:
    """Signing key kept on the machine; never sent to the browser."""
    global _secret_cache
    if _secret_cache is not None:
        return _secret_cache
    env_secret = os.environ.get("ZS_PAYMENT_SECRET")
    if env_secret:
        _secret_cache = env_secret.encode("utf-8")
        return _secret_cache
    zs_db.ensure_dirs()
    path = os.path.join(zs_db.DATA_DIR, "payment_secret.key")
    try:
        if os.path.isfile(path):
            with open(path, "rb") as handle:
                data = handle.read().strip()
            if data:
                _secret_cache = data
                return _secret_cache
        data = secrets.token_bytes(48)
        with open(path, "wb") as handle:
            handle.write(data)
        try:
            os.chmod(path, 0o600)
        except OSError:
            pass
        _secret_cache = data
        return _secret_cache
    except OSError:
        _secret_cache = secrets.token_bytes(48)
        return _secret_cache


def _b64e(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _b64d(text: str) -> bytes:
    padding = "=" * (-len(text) % 4)
    return base64.urlsafe_b64decode(text + padding)


def _sign(payload: bytes) -> bytes:
    return hmac.new(_server_secret(), payload, hashlib.sha256).digest()


def mint_token(payload: dict) -> str:
    body = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return f"{_b64e(body)}.{_b64e(_sign(body))}"


def read_token(token: str):
    """Return the payload of a signed token, or ``None`` when invalid."""
    if not token or "." not in token:
        return None
    body_b64, sig_b64 = token.split(".", 1)
    try:
        body = _b64d(body_b64)
        signature = _b64d(sig_b64)
    except Exception:
        return None
    if not hmac.compare_digest(signature, _sign(body)):
        return None
    try:
        payload = json.loads(body.decode("utf-8"))
    except Exception:
        return None
    return payload if isinstance(payload, dict) else None


# ---------------------------------------------------------------------------
# Checkout
# ---------------------------------------------------------------------------
def create_checkout(user_row, plan_id: str, provider: str = "local") -> dict:
    """Open a pending payment for a paid plan and return a signed checkout."""
    plan = get_plan(plan_id)
    if plan is None:
        raise ValueError("Unknown plan.")
    if not plan["paid"]:
        # The free tier is granted by the server on registration, never "purchased".
        raise ValueError("The free plan is assigned automatically and cannot be checked out.")
    nonce = secrets.token_hex(8)
    stamp = zs_db.now_iso()
    cur = zs_db.execute(
        "INSERT INTO payments (user_id, plan, amount_cents, currency, status, provider, "
        "checkout_nonce, created_at, updated_at) VALUES (?,?,?,?,?,?,?,?,?)",
        (int(user_row["id"]), plan["id"], plan["priceCents"], plan["currency"],
         "pending", provider, nonce, stamp, stamp),
    )
    payment_id = cur.lastrowid
    expires_at = zs_db.iso_in(CHECKOUT_TTL_SECONDS)
    token = mint_token({
        "pid": payment_id,
        "uid": int(user_row["id"]),
        "plan": plan["id"],
        "amount": plan["priceCents"],
        "nonce": nonce,
        "exp": int(time.time()) + CHECKOUT_TTL_SECONDS,
    })
    return {
        "paymentId": payment_id,
        "checkoutToken": token,
        "plan": plan["id"],
        "planName": plan["name"],
        "amountCents": plan["priceCents"],
        "currency": plan["currency"],
        "expiresAt": expires_at,
        "provider": provider,
    }


def confirm_checkout(user_row, checkout_token: str, provider_ref: str = "") -> dict:
    """Verify a signed checkout token and activate the paid membership.

    This is the only path through which a browser can obtain a paid plan, and
    it works because the token was signed server side.  A forged or tampered
    token, an expired token or a payment row that does not belong to the
    signed-in user is rejected.
    """
    payload = read_token(checkout_token)
    if payload is None:
        return {"ok": False, "error": "Checkout could not be verified. Please start again."}
    if int(payload.get("exp", 0)) < int(time.time()):
        return {"ok": False, "error": "That checkout expired. Please start again."}
    payment_id = int(payload.get("pid", 0))
    if payload.get("uid") != int(user_row["id"]):
        return {"ok": False, "error": "Checkout does not belong to this account."}
    plan = get_plan(payload.get("plan"))
    if plan is None or not plan["paid"]:
        return {"ok": False, "error": "Unknown plan in checkout."}
    if int(payload.get("amount", 0)) != plan["priceCents"]:
        return {"ok": False, "error": "Checkout amount does not match the plan price."}

    row = zs_db.query_one("SELECT * FROM payments WHERE id = ?", (payment_id,))
    if row is None:
        return {"ok": False, "error": "Checkout not found."}
    if row["user_id"] != int(user_row["id"]):
        return {"ok": False, "error": "Checkout does not belong to this account."}
    if row["checkout_nonce"] != payload.get("nonce"):
        return {"ok": False, "error": "Checkout has already been used."}
    if row["status"] == "paid":
        return {"ok": False, "error": "That checkout was already completed."}
    if row["status"] != "pending":
        return {"ok": False, "error": f"Checkout is {row['status']}."}
    if int(row["amount_cents"]) != plan["priceCents"]:
        return {"ok": False, "error": "Stored amount does not match the plan price."}

    stamp = zs_db.now_iso()
    zs_db.execute(
        "UPDATE payments SET status = 'paid', provider_ref = ?, verified_at = ?, "
        "verified_by = ?, updated_at = ? WHERE id = ? AND status = 'pending'",
        (str(provider_ref or f"local-{payment_id}")[:120], stamp,
         f"user:{user_row['username']}", stamp, payment_id),
    )
    expires_at = zs_db.iso_in(31 * 24 * 3600)
    membership_id = zs_auth_grant(user_row, plan["id"], price_cents=plan["priceCents"],
                                  payment_id=payment_id, source="checkout", expires_at=expires_at)
    return {
        "ok": True,
        "paymentId": payment_id,
        "membershipId": membership_id,
        "plan": plan["id"],
        "planName": plan["name"],
        "verifiedAt": stamp,
    }


def zs_auth_grant(user_row, plan_id: str, price_cents: int, payment_id,
                  source: str, expires_at=None) -> int:
    """Grant a membership, recording who verified it."""
    import zs_auth

    membership_id = zs_auth.grant_membership(
        user_row["id"], plan_id, source=source, payment_id=payment_id,
        price_cents=price_cents, status="active", expires_at=expires_at,
    )
    zs_db.execute(
        "UPDATE memberships SET verified_by = ? WHERE id = ?",
        (f"user:{user_row['username']}", membership_id),
    )
    zs_db.execute(
        "UPDATE users SET daily_request_limit = ?, updated_at = ? WHERE id = ?",
        (PLAN_REQUESTS_PER_DAY.get(plan_id, 30), zs_db.now_iso(), user_row["id"]),
    )
    return membership_id


def admin_grant_membership(actor, target_user_row, plan_id: str, source: str = "admin") -> dict:
    """Owner/admin path: grant a tier after an out-of-band payment."""
    import zs_auth

    plan = get_plan(plan_id)
    if plan is None:
        raise ValueError("Unknown plan.")
    membership_id = zs_auth.grant_membership(
        target_user_row["id"], plan["id"], source=source,
        price_cents=plan["priceCents"], status="active",
        expires_at=zs_db.iso_in(31 * 24 * 3600),
    )
    zs_db.execute(
        "UPDATE memberships SET verified_by = ?, verified_at = ? WHERE id = ?",
        (f"user:{actor['username']}", zs_db.now_iso(), membership_id),
    )
    zs_db.execute(
        "UPDATE users SET daily_request_limit = ?, updated_at = ? WHERE id = ?",
        (PLAN_REQUESTS_PER_DAY.get(plan["id"], 30), zs_db.now_iso(), target_user_row["id"]),
    )
    zs_auth.audit("membership.granted", actor, "membership", str(membership_id),
                  f"{plan['id']} for {target_user_row['username']}")
    return {"ok": True, "membershipId": membership_id, "plan": plan["id"]}


def admin_verify_payment(actor, payment_id: int) -> dict:
    """Owner/admin confirms a pending payment recorded out of band."""
    import zs_auth

    row = zs_db.query_one("SELECT * FROM payments WHERE id = ?", (int(payment_id),))
    if row is None:
        return {"ok": False, "error": "Payment not found."}
    if row["status"] == "paid":
        return {"ok": False, "error": "Payment is already verified."}
    plan = get_plan(row["plan"])
    if plan is None:
        return {"ok": False, "error": "Payment references an unknown plan."}
    target = zs_auth.find_user(row["user_id"])
    if target is None:
        return {"ok": False, "error": "The account for this payment no longer exists."}
    stamp = zs_db.now_iso()
    zs_db.execute(
        "UPDATE payments SET status = 'paid', verified_at = ?, verified_by = ?, updated_at = ? "
        "WHERE id = ? AND status = 'pending'",
        (stamp, f"user:{actor['username']}", stamp, int(payment_id)),
    )
    membership_id = zs_auth.grant_membership(
        target["id"], plan["id"], source="admin-verification",
        payment_id=int(payment_id), price_cents=plan["priceCents"],
        status="active", expires_at=zs_db.iso_in(31 * 24 * 3600),
    )
    zs_db.execute(
        "UPDATE memberships SET verified_by = ? WHERE id = ?",
        (f"user:{actor['username']}", membership_id),
    )
    zs_db.execute(
        "UPDATE users SET daily_request_limit = ?, updated_at = ? WHERE id = ?",
        (PLAN_REQUESTS_PER_DAY.get(plan["id"], 30), zs_db.now_iso(), target["id"]),
    )
    zs_auth.audit("payment.verified", actor, "payment", str(payment_id),
                  f"{plan['id']} for {target['username']}")
    return {"ok": True, "paymentId": int(payment_id), "membershipId": membership_id,
            "plan": plan["id"]}


# ---------------------------------------------------------------------------
# Provider webhook verification (real signature check, no fake success)
# ---------------------------------------------------------------------------
def verify_provider_callback(payload: dict, signature: str) -> dict:
    """Validate a provider callback using the configured webhook secret.

    Returns ``{"ok": False, "error": ...}`` when no provider secret is
    configured - it never pretends a payment succeeded.
    """
    secret = os.environ.get("ZS_PAYMENT_WEBHOOK_SECRET")
    if not secret:
        return {"ok": False, "error": "No payment provider secret is configured on this machine."}
    if not isinstance(payload, dict):
        return {"ok": False, "error": "Invalid callback payload."}
    body = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    expected = hmac.new(secret.encode("utf-8"), body, hashlib.sha256).hexdigest()
    if not signature or not hmac.compare_digest(expected, str(signature)):
        return {"ok": False, "error": "Callback signature did not verify."}
    payment_id = int(payload.get("paymentId") or 0)
    row = zs_db.query_one("SELECT * FROM payments WHERE id = ?", (payment_id,))
    if row is None:
        return {"ok": False, "error": "Callback references an unknown payment."}
    if row["status"] != "pending":
        return {"ok": False, "error": f"Payment is already {row['status']}."}
    plan = get_plan(row["plan"])
    if plan is None:
        return {"ok": False, "error": "Payment references an unknown plan."}
    target = zs_auth_find(row["user_id"])
    if target is None:
        return {"ok": False, "error": "The account for this payment no longer exists."}
    stamp = zs_db.now_iso()
    zs_db.execute(
        "UPDATE payments SET status = 'paid', provider_ref = ?, verified_at = ?, "
        "updated_at = ? WHERE id = ? AND status = 'pending'",
        (str(payload.get("reference") or "")[:120], stamp, stamp, payment_id),
    )
    import zs_auth
    membership_id = zs_auth.grant_membership(
        target["id"], plan["id"], source="provider-callback", payment_id=payment_id,
        price_cents=plan["priceCents"], status="active", expires_at=zs_db.iso_in(31 * 24 * 3600),
    )
    zs_auth.audit("payment.verified", target, "payment", str(payment_id), "provider callback")
    return {"ok": True, "paymentId": payment_id, "membershipId": membership_id}


def zs_auth_find(user_id: int):
    import zs_auth
    return zs_auth.find_user(user_id)


# ---------------------------------------------------------------------------
# Usage tracking and plan limits
# ---------------------------------------------------------------------------
def record_usage(user_id: int, feature: str, tokens: int = 0, cost_cents: float = 0.0,
                 status: str = "ok", meta: dict | None = None) -> None:
    try:
        plan_row = zs_db.query_one(
            "SELECT plan FROM memberships WHERE user_id = ? AND status = 'active' "
            "ORDER BY id DESC LIMIT 1", (int(user_id),)
        )
        plan = plan_row["plan"] if plan_row else DEFAULT_PLAN
        zs_db.execute(
            "INSERT INTO usage_records (user_id, feature, plan, requests, tokens, cost_cents, "
            "status, meta, created_at) VALUES (?,?,?,?,?,?,?,?,?)",
            (int(user_id), str(feature)[:80], plan, 1, int(tokens or 0), float(cost_cents or 0),
             status, json.dumps(meta or {}, ensure_ascii=False), zs_db.now_iso()),
        )
    except sqlite3.Error:
        pass


def usage_today(user_id: int, feature: str = "") -> int:
    day_start = zs_db.utcnow().replace(hour=0, minute=0, second=0, microsecond=0)
    stamp = day_start.replace(microsecond=0).isoformat().replace("+00:00", "Z")
    if feature:
        row = zs_db.query_one(
            "SELECT COUNT(*) AS c FROM usage_records WHERE user_id = ? AND created_at >= ? "
            "AND feature = ?",
            (int(user_id), stamp, str(feature)),
        )
    else:
        row = zs_db.query_one(
            "SELECT COUNT(*) AS c FROM usage_records WHERE user_id = ? AND created_at >= ?",
            (int(user_id), stamp),
        )
    return int(row["c"]) if row else 0


def check_usage_limit(user_row, feature: str = "ai") -> dict:
    """Enforce the daily request allowance of the current membership."""
    import zs_auth

    role = zs_auth.effective_role(user_row)
    if role in (zs_auth.ROLE_OWNER, zs_auth.ROLE_ADMIN):
        return {"allowed": True, "limit": None, "used": usage_today(user_row["id"], feature)}

    if os.environ.get("ZS_ENFORCE_USAGE_LIMITS", "1") not in ("1", "true", "yes"):
        return {"allowed": True, "limit": None, "used": usage_today(user_row["id"], feature)}

    limit = zs_auth.effective_daily_limit(user_row)
    used = usage_today(user_row["id"], feature)
    if limit and used >= limit:
        return {
            "allowed": False,
            "limit": limit,
            "used": used,
            "error": f"Daily AI request limit reached ({used}/{limit}). Upgrade your membership to continue.",
        }
    return {"allowed": True, "limit": limit, "used": used}
