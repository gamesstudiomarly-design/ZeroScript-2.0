# SPDX-License-Identifier: GPL-3.0-or-later
"""Local-only ZeroScript admin workspace storage. Not a hosted SaaS backend."""
import copy, json, os, tempfile, time, uuid
from datetime import datetime, timezone

ROOT = os.path.dirname(os.path.abspath(__file__))
DATA_PATH = os.path.join(ROOT, "admin_data.json")
COLLECTIONS = {"users", "models", "memberships", "plugins", "tools", "transactions", "announcements", "tickets", "featureFlags", "betaUsers", "admins", "updates"}

def _now(): return datetime.now(timezone.utc).isoformat(timespec="seconds")
def _seed():
    return {
      "users": [], "models": [],
      "memberships": [
        {"id":"noob","name":"AI NOOB","tier":"FREE","price":"0","requestsPerDay":30,"models":"Free models","tools":"Basic tools","enabled":True},
        {"id":"pro","name":"AI PRO","tier":"PAID","price":"9.99","requestsPerDay":500,"models":"Premium models","tools":"PRO tools","enabled":True},
        {"id":"master","name":"AI MASTER","tier":"ULTIMATE","price":"19.99","requestsPerDay":2500,"models":"All available models","tools":"Exclusive tools","enabled":True}],
      "plugins": [], "tools": [], "transactions": [], "announcements": [], "tickets": [],
      "featureFlags": [], "betaUsers": [], "admins": [], "updates": [],
      "settings":{"maintenanceMode":False,"defaultModel":"","storeCommission":15,"rateLimitPerMinute":60,"backupEnabled":True,"ownerName":"Owner","platformName":"ZeroScript"},
      "audit":[], "createdAt":_now(), "schemaVersion":1
    }

def load():
    if not os.path.exists(DATA_PATH):
        data=_seed(); save(data); return data
    try:
        with open(DATA_PATH,"r",encoding="utf-8") as f: data=json.load(f)
        if not isinstance(data,dict): raise ValueError("invalid admin data")
        base=_seed()
        for k,v in base.items(): data.setdefault(k,v)
        return data
    except Exception:
        # Preserve malformed data for manual recovery instead of overwriting it.
        raise RuntimeError("admin_data.json could not be read; preserve it and repair the JSON")

def save(data):
    os.makedirs(os.path.dirname(DATA_PATH),exist_ok=True)
    fd,tmp=tempfile.mkstemp(prefix=".admin-data-",suffix=".tmp",dir=ROOT)
    try:
        with os.fdopen(fd,"w",encoding="utf-8") as f: json.dump(data,f,ensure_ascii=False,indent=2); f.flush(); os.fsync(f.fileno())
        os.replace(tmp,DATA_PATH)
    finally:
        if os.path.exists(tmp): os.unlink(tmp)

def _audit(data, action, target="", detail=""):
    data.setdefault("audit",[]).insert(0,{"id":uuid.uuid4().hex[:12],"at":_now(),"actor":"Local Owner","action":str(action)[:100],"target":str(target)[:160],"detail":str(detail)[:300]})
    data["audit"]=data["audit"][:500]

def overview():
    d=load()
    return {"ok":True,"data":d,"metrics":{"registeredUsers":len(d["users"]),"onlineUsers":0,"aiRequests":0,"revenue":sum(float(x.get("amount") or 0) for x in d["transactions"] if x.get("status")=="paid"),"proMembers":sum(1 for x in d["users"] if str(x.get("membership","")).lower()=="pro" and x.get("status","active")=="active"),"masterMembers":sum(1 for x in d["users"] if str(x.get("membership","")).lower()=="master" and x.get("status","active")=="active"),"plugins":len(d["plugins"]),"tools":len(d["tools"]),"transactions":len(d["transactions"]),"ticketsOpen":sum(1 for x in d["tickets"] if x.get("status","open")=="open")},"localOnly":True}

def act(body):
    d=load(); action=str(body.get("action") or "")
    if action=="save_settings":
        incoming=body.get("settings") if isinstance(body.get("settings"),dict) else {}
        allowed={"maintenanceMode","defaultModel","storeCommission","rateLimitPerMinute","backupEnabled","ownerName","platformName"}
        d["settings"].update({k:v for k,v in incoming.items() if k in allowed}); _audit(d,"settings updated","platform","Local owner settings changed")
    elif action=="upsert":
        col=body.get("collection"); item=body.get("item")
        if col not in COLLECTIONS or not isinstance(item,dict): return {"ok":False,"error":"invalid collection or item"},400
        item=copy.deepcopy(item); item["id"]=str(item.get("id") or uuid.uuid4().hex[:12])
        if col=="users": item.pop("password",None); item.pop("passwordHash",None); item.pop("apiSecret",None)
        arr=d.setdefault(col,[]); idx=next((i for i,x in enumerate(arr) if str(x.get("id"))==item["id"]),None)
        if idx is None: arr.insert(0,item); verb="created"
        else: arr[idx]={**arr[idx],**item}; verb="updated"
        _audit(d,f"{col} {verb}",item["id"],item.get("name") or item.get("email") or item.get("title") or "")
    elif action=="delete":
        col=body.get("collection"); ident=str(body.get("id") or "")
        if col not in COLLECTIONS: return {"ok":False,"error":"invalid collection"},400
        old=d.setdefault(col,[]); d[col]=[x for x in old if str(x.get("id"))!=ident]
        if len(old)==len(d[col]): return {"ok":False,"error":"record not found"},404
        _audit(d,f"{col} deleted",ident,"Record removed from local admin registry")
    elif action=="toggle":
        col=body.get("collection"); ident=str(body.get("id") or ""); field=str(body.get("field") or "enabled")
        if col not in COLLECTIONS or field not in {"enabled","featured","approved","status","maintenanceMode"}: return {"ok":False,"error":"invalid toggle"},400
        row=next((x for x in d.setdefault(col,[]) if str(x.get("id"))==ident),None)
        if not row:return {"ok":False,"error":"record not found"},404
        if field=="status": row[field]=body.get("value") or ("banned" if row.get(field)!="banned" else "active")
        else: row[field]=bool(body.get("value",not row.get(field,False)))
        _audit(d,f"{col} {field} changed",ident,str(row[field]))
    elif action=="announcement":
        msg={"id":uuid.uuid4().hex[:12],"title":str(body.get("title") or "Announcement")[:160],"message":str(body.get("message") or "")[:5000],"audience":str(body.get("audience") or "all"),"scheduleAt":str(body.get("scheduleAt") or ""),"createdAt":_now(),"status":"draft"}
        d["announcements"].insert(0,msg); _audit(d,"announcement drafted",msg["id"],msg["title"])
    elif action=="backup":
        # Export a consistent snapshot as an API response; caller downloads it locally.
        _audit(d,"backup exported","admin_data.json","Owner requested local data export")
        save(d); return {"ok":True,"backup":d,"filename":"zeroscript-admin-backup.json"},200
    else: return {"ok":False,"error":"unknown admin action"},400
    save(d); return {"ok":True,**overview()},200
