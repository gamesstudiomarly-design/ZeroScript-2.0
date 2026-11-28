# SPDX-License-Identifier: GPL-3.0-or-later
"""ZeroScript 2.0 - Developer Debugging Center backend.

Aggregates bridge activity + Luau diagnostics into:
  - Live Output viewer (ring buffer of classified log lines)
  - Error tracker (deduped, with counts + first/last seen)
  - Warning detector
  - Performance profiler (per-tool timing stats from bridge activity)
  - Script diagnostics (delegates to zs_editor.diagnostics over open docs)
"""
import collections
import re
import threading
import time

_LOCK = threading.Lock()
_OUTPUT = collections.deque(maxlen=2000)
_ERRORS = {}   # key -> {message, count, first, last, samples}
_WARNINGS = {}
_STATS = {"lines": 0, "errors": 0, "warnings": 0}

_LEVEL_RE = re.compile(r"^\s*(?:\[(ERROR|WARN|WARNING|INFO|DEBUG)\])", re.IGNORECASE)


def _classify(msg):
    m = _LEVEL_RE.match(msg or "")
    if m:
        lvl = m.group(1).upper()
        return "error" if lvl == "ERROR" else ("warning" if lvl in ("WARN", "WARNING") else "info")
    low = (msg or "").lower()
    if any(k in low for k in ("error", "failed", "exception", "traceback", "nil value", "attempt to")):
        return "error"
    if any(k in low for k in ("warn", "deprecated", "caution")):
        return "warning"
    return "info"


def ingest(msg, source="bridge"):
    """Push a log line into the output buffer and classify it."""
    text = str(msg or "")
    level = _classify(text)
    with _LOCK:
        _STATS["lines"] += 1
        if level == "error":
            _STATS["errors"] += 1
            _bump(_ERRORS, text)
        elif level == "warning":
            _STATS["warnings"] += 1
            _bump(_WARNINGS, text)
        _OUTPUT.append({
            "ts": time.strftime("%H:%M:%S"),
            "source": source,
            "level": level,
            "msg": text[:2000],
        })


def _bump(bucket, text):
    key = re.sub(r"\d+", "#", text)[:200]  # normalize numbers for dedupe
    rec = bucket.get(key)
    now = time.strftime("%Y-%m-%d %H:%M:%S")
    if rec:
        rec["count"] += 1
        rec["last"] = now
        if len(rec["samples"]) < 3:
            rec["samples"].append(text[:400])
    else:
        bucket[key] = {"message": text[:400], "count": 1, "first": now, "last": now,
                       "samples": [text[:400]]}


def get_output(limit=500, level=None):
    with _LOCK:
        items = list(_OUTPUT)
    if level:
        items = [i for i in items if i["level"] == level]
    return items[-limit:]


def get_errors():
    with _LOCK:
        return sorted(_ERRORS.values(), key=lambda r: r["last"], reverse=True)


def get_warnings():
    with _LOCK:
        return sorted(_WARNINGS.values(), key=lambda r: r["last"], reverse=True)


def clear():
    with _LOCK:
        _OUTPUT.clear()
        _ERRORS.clear()
        _WARNINGS.clear()
        _STATS.update({"lines": 0, "errors": 0, "warnings": 0})
    return True


def summary():
    with _LOCK:
        return dict(_STATS)


def profile(activity_items):
    """Build a per-tool timing profile from bridge activity items."""
    agg = {}
    for it in activity_items or []:
        tool = it.get("tool") or "?"
        rec = agg.setdefault(tool, {"tool": tool, "calls": 0, "ok": 0, "errors": 0,
                                    "totalMs": 0, "maxMs": 0})
        rec["calls"] += 1
        rec["totalMs"] += int(it.get("ms") or 0)
        rec["maxMs"] = max(rec["maxMs"], int(it.get("ms") or 0))
        if it.get("ok"):
            rec["ok"] += 1
        else:
            rec["errors"] += 1
    out = []
    for rec in agg.values():
        rec["avgMs"] = int(rec["totalMs"] / rec["calls"]) if rec["calls"] else 0
        out.append(rec)
    out.sort(key=lambda r: r["totalMs"], reverse=True)
    return out