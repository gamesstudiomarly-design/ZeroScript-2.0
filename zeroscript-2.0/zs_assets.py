# SPDX-License-Identifier: GPL-3.0-or-later
"""ZeroScript 2.0 - Asset Manager backend.

Local catalog of models/images/sounds with favorites, collections, search,
preview metadata, and an unused-asset detector that scans a Luau corpus for
asset references.
"""
import hashlib
import json
import os
import re
import time

HERE = os.path.dirname(os.path.abspath(__file__))
import zs_paths  # noqa: E402 - shared install folders
ASSETS_DIR = zs_paths.install_dir("assets_catalog")
os.makedirs(ASSETS_DIR, exist_ok=True)
CATALOG_PATH = os.path.join(ASSETS_DIR, "catalog.json")

VALID_KINDS = ("model", "image", "sound", "mesh", "animation", "other")


def _load():
    if os.path.isfile(CATALOG_PATH):
        try:
            with open(CATALOG_PATH, "r", encoding="utf-8") as f:
                data = json.load(f)
                if isinstance(data, dict) and isinstance(data.get("assets"), list):
                    return data
        except Exception:
            pass
    return {"assets": [], "collections": []}


def _save(data):
    tmp = CATALOG_PATH + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
    os.replace(tmp, CATALOG_PATH)


def add_asset(payload):
    if not isinstance(payload, dict):
        return False, "invalid payload"
    name = str(payload.get("name") or "").strip()[:120]
    if not name:
        return False, "name required"
    kind = str(payload.get("kind") or "other").lower()
    if kind not in VALID_KINDS:
        kind = "other"
    aid = payload.get("id") or hashlib.sha1(
        (name + str(payload.get("source") or "") + str(time.time())).encode()
    ).hexdigest()[:12]
    rec = {
        "id": aid,
        "name": name,
        "kind": kind,
        "source": str(payload.get("source") or "")[:500],
        "assetId": str(payload.get("assetId") or "")[:40],
        "tags": [str(t)[:40] for t in (payload.get("tags") or [])][:20],
        "favorite": bool(payload.get("favorite")),
        "collections": [str(c)[:40] for c in (payload.get("collections") or [])][:20],
        "added": time.strftime("%Y-%m-%d %H:%M:%S"),
        "meta": payload.get("meta") if isinstance(payload.get("meta"), dict) else {},
    }
    data = _load()
    data["assets"] = [a for a in data["assets"] if a["id"] != aid] + [rec]
    _save(data)
    return True, rec


def list_assets(query="", kind=None, favorite=None):
    data = _load()
    q = (query or "").lower().strip()
    out = []
    for a in data["assets"]:
        if kind and a["kind"] != kind:
            continue
        if favorite is not None and bool(a["favorite"]) != bool(favorite):
            continue
        if q and q not in (a["name"] + " " + " ".join(a["tags"])).lower():
            continue
        out.append(a)
    out.sort(key=lambda a: a["name"].lower())
    return out


def toggle_favorite(asset_id):
    data = _load()
    for a in data["assets"]:
        if a["id"] == asset_id:
            a["favorite"] = not a["favorite"]
            _save(data)
            return True, a
    return False, "asset not found"


def delete_asset(asset_id):
    data = _load()
    before = len(data["assets"])
    data["assets"] = [a for a in data["assets"] if a["id"] != asset_id]
    if len(data["assets"]) == before:
        return False, "asset not found"
    _save(data)
    return True, None


def add_collection(name):
    name = str(name or "").strip()[:60]
    if not name:
        return False, "name required"
    data = _load()
    if name not in data["collections"]:
        data["collections"].append(name)
        _save(data)
    return True, data["collections"]


def find_unused(luau_corpus):
    """Return assets whose assetId/name never appears in the corpus."""
    data = _load()
    corpus = str(luau_corpus or "")
    unused = []
    for a in data["assets"]:
        needles = []
        if a.get("assetId"):
            needles.append(str(a["assetId"]))
        if a.get("name"):
            needles.append(a["name"])
        if not needles:
            continue
        if not any(n in corpus for n in needles):
            unused.append(a)
    return unused


def summary():
    data = _load()
    by_kind = {}
    for a in data["assets"]:
        by_kind[a["kind"]] = by_kind.get(a["kind"], 0) + 1
    return {
        "total": len(data["assets"]),
        "favorites": sum(1 for a in data["assets"] if a["favorite"]),
        "collections": data["collections"],
        "byKind": by_kind,
    }