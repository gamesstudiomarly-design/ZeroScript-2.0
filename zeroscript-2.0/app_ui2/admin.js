(() => {
  'use strict';
  const $ = s => document.querySelector(s), $$ = s => [...document.querySelectorAll(s)];
  const state = {data:null, metrics:{}, page:'overview', collection:'users', editing:null, accounts:[], accountCounts:{}, payments:[], sessions:[], audit:[]};
  const AUTH = {user:null, role:null, permissions:[], csrf:''};
  const PAGE = {
    overview:['Admin overview','Platform signals and local administration.'],
    users:['User management','Manage locally registered account records. No cloud identity service is connected.'],
    accounts:['Accounts & access','Real accounts created through the ZeroScript login page. Roles and memberships are enforced by the server.'],
    models:['AI model management','Configure local model catalog entries, access tiers and fallback metadata.'],
    memberships:['Membership management','Edit the AI NOOB, AI PRO and AI MASTER plan definitions.'],
    plugins:['Plugin store administration','Manage local plugin listings, review state, tiers and featured status.'],
    tools:['AI tools management','Manage tool catalog entries and local access rules.'],
    finance:['Financial center','Review a local ledger. Live checkout and provider verification are not connected.'],
    announcements:['Announcements & notifications','Compose local announcement drafts and schedule metadata.'],
    security:['Security & audit','Review admin changes and local security posture.'],
    owner:['Advanced owner controls','Configure local platform preferences and export a backup.'],
    tickets:['Support ticket center','Review locally stored support tickets; no external ticket provider is connected.'],
    updates:['Update manager','Track local release notes and update metadata. This build does not download or install updates automatically.']
  };
  const CONFIG = {
    users:{title:'Registered users',desc:'Local user registry (not connected to cloud authentication).',fields:[['name','Username','text'],['email','Email','email'],['membership','Membership','select','noob|pro|master'],['status','Account status','select','active|suspended|banned'],['requestsLimit','Daily AI limit','number'],['notes','Admin note','text']],cols:[['name','USER'],['email','EMAIL'],['membership','PLAN'],['status','STATUS'],['requestsLimit','DAILY LIMIT']]},
    models:{title:'AI models',desc:'Provider/model catalog. API secrets are deliberately not accepted in this panel.',fields:[['name','Model name','text'],['provider','Provider','text'],['modelId','Model ID','text'],['endpoint','API endpoint (optional)','url'],['access','Membership access','select','noob|pro|master|all'],['enabled','Enabled','checkbox'],['fallback','Fallback model ID','text']],cols:[['name','MODEL'],['provider','PROVIDER'],['modelId','MODEL ID'],['access','ACCESS'],['enabled','STATE']]},
    memberships:{title:'Membership plans',desc:'Edit local plan definitions and limits.',fields:[['name','Plan name','text'],['tier','Tier label','text'],['price','Price (display only)','number'],['requestsPerDay','Requests per day','number'],['models','Model access','text'],['tools','Tool access','text'],['enabled','Enabled','checkbox']],cols:[['name','PLAN'],['tier','TIER'],['price','PRICE'],['requestsPerDay','REQUESTS / DAY'],['enabled','STATE']]},
    plugins:{title:'Plugin listings',desc:'Local store metadata; uploading/running untrusted packages is not implemented.',fields:[['name','Plugin name','text'],['author','Author','text'],['description','Description','text'],['version','Version','text'],['price','Price (display only)','number'],['access','Membership access','select','free|pro|master'],['approved','Approved','checkbox'],['featured','Featured','checkbox'],['downloads','Download count (local)','number'],['revenue','Revenue (local display)','number'],['enabled','Enabled','checkbox']],cols:[['name','PLUGIN'],['author','AUTHOR'],['version','VERSION'],['access','ACCESS'],['downloads','DOWNLOADS'],['revenue','REVENUE'],['approved','REVIEW'],['enabled','STATE']]},
    tools:{title:'AI tools',desc:'Tool catalog records and access metadata.',fields:[['name','Tool name','text'],['description','Description','text'],['category','Category','text'],['price','Price (display only)','number'],['access','Membership access','select','free|pro|master'],['enabled','Enabled','checkbox']],cols:[['name','TOOL'],['category','CATEGORY'],['access','ACCESS'],['price','PRICE'],['enabled','STATE']]},
    transactions:{title:'Transaction ledger',desc:'Local ledger entries only. Payment status must be verified server-side in production.',fields:[['customer','Customer reference','text'],['provider','Payment provider','text'],['reference','Provider transaction reference','text'],['amount','Amount','number'],['currency','Currency','text'],['status','Status','select','pending|paid|refunded|failed'],['membership','Plan','select','noob|pro|master']],cols:[['customer','CUSTOMER'],['provider','PROVIDER'],['reference','REFERENCE'],['amount','AMOUNT'],['status','STATUS']]},
    tickets:{title:'Support tickets',desc:'Local support records (no email/ticket provider connected).',fields:[['title','Subject','text'],['user','User reference','text'],['priority','Priority','select','low|normal|high|urgent'],['status','Status','select','open|in-progress|resolved'],['notes','Notes','text']],cols:[['title','SUBJECT'],['user','USER'],['priority','PRIORITY'],['status','STATUS']]},
    featureFlags:{title:'Feature flags',desc:'Define local rollout flags; runtime feature enforcement is not wired to cloud users.',fields:[['name','Flag name','text'],['key','Flag key','text'],['description','Description','text'],['target','Target users / cohort','text'],['enabled','Enabled','checkbox']],cols:[['name','FLAG'],['key','KEY'],['target','TARGET'],['enabled','STATE']]},
    betaUsers:{title:'Beta testing center',desc:'Local beta participant allowlist records.',fields:[['user','User / email','text'],['cohort','Cohort','text'],['features','Early-access features','text'],['enabled','Enabled','checkbox']],cols:[['user','PARTICIPANT'],['cohort','COHORT'],['features','FEATURES'],['enabled','STATE']]},
    updates:{title:'Release records',desc:'Local release metadata only; update delivery/signing is not connected.',fields:[['version','Version','text'],['channel','Channel','select','stable|beta|nightly'],['releaseDate','Release date','text'],['notes','Release notes','text'],['status','Status','select','draft|published|deprecated']],cols:[['version','VERSION'],['channel','CHANNEL'],['releaseDate','RELEASE DATE'],['status','STATUS']]},
    admins:{title:'Admin roles',desc:'Local role labels only; multi-admin authentication is not implemented.',fields:[['name','Admin label','text'],['email','Email','email'],['role','Role','select','admin|owner|support'],['enabled','Enabled','checkbox']],cols:[['name','ADMIN'],['email','EMAIL'],['role','ROLE'],['enabled','STATE']]}
  };
  const fmt = n => Number(n||0).toLocaleString();
  const esc = v => String(v==null?'':v).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
  async function api(path,body){const opts={method:body?'POST':'GET',headers:body?{'Content-Type':'application/json'}:{},credentials:'same-origin'};if(body)opts.body=JSON.stringify(body);if(AUTH.csrf)opts.headers['X-CSRF-Token']=AUTH.csrf;const r=await fetch(path,opts);const j=await r.json();if(r.status===401){window.location.href='/2/login?next=%2Fadmin';throw Error('Sign in required.');}if(!r.ok||j.ok===false)throw Error(j.error||`Request failed (${r.status})`);return j;}
  function toast(msg){const t=$('#toast');t.textContent=msg;t.hidden=false;clearTimeout(toast.t);toast.t=setTimeout(()=>t.hidden=true,2800)}
  function status(v){const s=String(v??'—');const off=['false','disabled','banned','suspended','draft','failed','refunded'].includes(s.toLowerCase());return `<span class="status ${off?'off':''}">${esc(s)}</span>`}
  function metric(label,value,foot,glow){return `<div class="metric" style="--glow:${glow||'#8b7cff'}"><div class="label">${esc(label)}</div><div class="value">${esc(value)}</div><div class="foot">${foot||''}</div></div>`}
  async function refresh(){const j=await api('/api/admin/overview');state.data=j.data;state.metrics=j.metrics;render();}
  function render(){const d=state.data,m=state.metrics;$('#user-count').textContent=fmt(m.registeredUsers);$('#metrics').innerHTML=[metric('Registered users',fmt(m.registeredUsers),'Local account records','#8b7cff'),metric('Online users',fmt(m.onlineUsers),'Live session service not connected','#45d6e8'),metric('AI requests',fmt(m.aiRequests),'Cloud usage ingestion unavailable','#51d6a1'),metric('Recorded revenue','$'+Number(m.revenue||0).toFixed(2),'Paid ledger entries only','#e8bb62')].join('');
    $('#runtime').innerHTML=`<div class="runtime-item"><span>Local app</span><b style="color:var(--green)">ONLINE</b></div><div class="runtime-item"><span>Plugin listings</span><b>${fmt(m.plugins)}</b></div><div class="runtime-item"><span>AI tools</span><b>${fmt(m.tools)}</b></div>`;
    $('#bars').innerHTML=Array.from({length:22},(_,i)=>`<span style="height:${18+((i*31+11)%70)}%" title="Local placeholder"></span>`).join('');
    $('#recent-audit').innerHTML=(d.audit||[]).slice(0,5).map(a=>`<div class="audit-row"><span class="audit-dot"></span><div><b>${esc(a.action)} · ${esc(a.target)}</b><small>${esc(a.at)} ${a.detail?'— '+esc(a.detail):''}</small></div></div>`).join('')||'<p class="muted">No admin actions recorded yet.</p>';
    const counts=['noob','pro','master'].map(t=>({t,n:(d.users||[]).filter(u=>String(u.membership||'noob').toLowerCase()===t).length}));const max=Math.max(1,...counts.map(x=>x.n));$('#membership-chart').innerHTML=counts.map(x=>`<div class="mrow"><span>${x.t.toUpperCase()}</span><div class="mbar"><span style="width:${x.n/max*100}%"></span></div><b>${x.n}</b></div>`).join('');
    const ranked=[...d.plugins].sort((a,b)=>Number(b.revenue||0)-Number(a.revenue||0)||Number(b.downloads||0)-Number(a.downloads||0)).slice(0,5);$('#plugin-rank').innerHTML=ranked.map((x,i)=>`<div class="audit-row"><span class="audit-dot"></span><div><b>#${i+1} ${esc(x.name||'Unnamed plugin')} · ${esc(x.currency||'USD')} ${Number(x.revenue||0).toFixed(2)}</b><small>${fmt(x.downloads)} local downloads · ${x.enabled===false?'disabled':'enabled'}</small></div></div>`).join('')||'<p class="muted">No plugin listing metrics entered yet.</p>';
    $('#finance-metrics').innerHTML=[metric('Recorded revenue','$'+Number(m.revenue||0).toFixed(2),'Verified paid status in local ledger','#e8bb62'),metric('Transactions',fmt(m.transactions),'Local records','#8b7cff'),metric('Open tickets',fmt(m.ticketsOpen),'Local support records','#45d6e8'),metric('Commission',`${d.settings.storeCommission||0}%`,'Display setting only','#51d6a1')].join('');
    $('#security-metrics').innerHTML=[metric('Audit entries',fmt(d.audit.length),'Recent local actions','#8b7cff'),metric('Local admins',fmt(d.admins.length),'Role labels; no login service','#45d6e8'),metric('Secrets stored','0','Raw API secrets not collected','#51d6a1'),metric('Admin bind','LOCAL','127.0.0.1 only','#e8bb62')].join('');
    renderPage(); renderOwner(); $('#capabilities').innerHTML=[['Accounts / sessions','Live SQLite backend'],['Roles & permissions','Owner, admin, moderator, user'],['Membership checkout','Server signed & verified'],['AI provider config','Catalog metadata only'],['Plugins / tools','Listing management'],['Two-factor auth','Not implemented']].map(x=>`<div class="cap"><b>${esc(x[0])}</b><small>${esc(x[1])}</small></div>`).join('');
  }
  function renderPage(){const p=state.page;$$('.page').forEach(x=>x.classList.toggle('active',x.id===`page-${p}`||(x.id==='page-records'&&['users','models','memberships','plugins','tools','tickets','updates'].includes(p))));$$('.nav').forEach(x=>x.classList.toggle('active',x.dataset.page===p));$('#crumb').textContent=p.toUpperCase();$('#page-title').textContent=PAGE[p]?.[0]||p;$('#page-desc').textContent=PAGE[p]?.[1]||'';if(['users','models','memberships','plugins','tools','tickets','updates'].includes(p))renderRecords(p);if(p==='finance')renderFinance();if(p==='announcements')renderAnnouncements();if(p==='security')renderAudit();if(p==='accounts')renderAccounts();}
  function goto(p){state.page=p;renderPage();}
  function renderRecords(col){state.collection=col;const c=CONFIG[col];$('#table-title').textContent=c.title;$('#table-desc').textContent=c.desc;$('#table-head').innerHTML=`<tr>${c.cols.map(x=>`<th>${esc(x[1])}</th>`).join('')}<th>ACTIONS</th></tr>`;const q=($('#search').value||'').toLowerCase();const arr=(state.data[col]||[]).filter(x=>JSON.stringify(x).toLowerCase().includes(q));$('#record-count').textContent=`${arr.length} record${arr.length===1?'':'s'}`;$('#table-body').innerHTML=arr.map(x=>`<tr>${c.cols.map(([k])=>`<td>${['enabled','approved','featured'].includes(k)?status(x[k]?'enabled':'disabled'):k==='status'?status(x[k]):esc(x[k]??'—')}</td>`).join('')}<td><div class="row-actions"><button class="mini" data-edit="${esc(x.id)}">Edit</button><button class="mini" data-toggle="${esc(x.id)}" data-col="${col}">${x.enabled===false?'Enable':'Disable'}</button><button class="mini danger" data-delete="${esc(x.id)}" data-col="${col}">Delete</button></div></td></tr>`).join('')||`<tr><td colspan="${c.cols.length+1}" style="text-align:center;padding:32px;color:#718099">No records yet. Create a local record to begin.</td></tr>`;}
  function renderFinance(){const c=CONFIG.transactions;$('#finance-head').innerHTML=`<tr>${c.cols.map(x=>`<th>${esc(x[1])}</th>`).join('')}<th>ACTIONS</th></tr>`;$('#finance-body').innerHTML=(state.data.transactions||[]).map(x=>`<tr>${c.cols.map(([k])=>`<td>${k==='status'?status(x[k]):esc(k==='amount'?`${x.currency||'USD'} ${Number(x[k]||0).toFixed(2)}`:x[k]??'—')}</td>`).join('')}<td><div class="row-actions"><button class="mini" data-edit="${esc(x.id)}" data-col="transactions">Edit</button><button class="mini danger" data-delete="${esc(x.id)}" data-col="transactions">Delete</button></div></td></tr>`).join('')||'<tr><td colspan="6" style="text-align:center;padding:30px;color:#718099">No transaction records.</td></tr>';}
  function renderAnnouncements(){const cols=[['title','TITLE'],['audience','AUDIENCE'],['scheduleAt','SCHEDULE'],['status','STATUS'],['createdAt','CREATED']];$('#announcement-head').innerHTML=`<tr>${cols.map(x=>`<th>${x[1]}</th>`).join('')}<th>ACTIONS</th></tr>`;$('#announcement-body').innerHTML=(state.data.announcements||[]).map(x=>`<tr>${cols.map(([k])=>`<td>${k==='status'?status(x[k]):esc(x[k]||'—')}</td>`).join('')}<td><button class="mini danger" data-delete="${esc(x.id)}" data-col="announcements">Delete</button></td></tr>`).join('')||'<tr><td colspan="6" style="text-align:center;padding:30px;color:#718099">No drafts yet.</td></tr>';}
  function renderAudit(){const cols=[['at','TIME'],['actor','ACTOR'],['action','ACTION'],['target','TARGET'],['detail','DETAIL']];$('#audit-head').innerHTML=`<tr>${cols.map(x=>`<th>${x[1]}</th>`).join('')}</tr>`;$('#audit-body').innerHTML=(state.data.audit||[]).map(x=>`<tr>${cols.map(([k])=>`<td>${esc(x[k]||'—')}</td>`).join('')}</tr>`).join('')||'<tr><td colspan="5" style="text-align:center;padding:30px;color:#718099">No audit records yet.</td></tr>';}
  function renderOwner(){const f=$('#owner-form'),s=state.data.settings;for(const el of f.elements){if(!el.name)continue;if(el.type==='checkbox')el.checked=!!s[el.name];else el.value=s[el.name]??'';}}

  // ── Authenticated accounts (SQLite) ────────────────────────────
  async function api2(path,body){const opts={method:body===undefined?'GET':'POST',headers:{'Content-Type':'application/json'},credentials:'same-origin'};if(body!==undefined)opts.body=JSON.stringify(body);if(AUTH.csrf)opts.headers['X-CSRF-Token']=AUTH.csrf;const r=await fetch(path,opts);let j={};try{j=await r.json();}catch(e){j={ok:false,error:`Request failed (${r.status}).`};}if(r.status===401){window.location.href='/2/login?next=%2Fadmin';throw Error('Sign in required.');}if(!r.ok||j.ok===false)throw Error(j.error||`Request failed (${r.status})`);return j;}
  const can = perm => AUTH.permissions.includes(perm);
  function renderAccounts(){
    const rows=state.accounts||[];
    $('#account-count').textContent=fmt(rows.length);
    $('#account-count-label').textContent=`${rows.length} account${rows.length===1?'':'s'}`;
    const counts=state.accountCounts||{};
    $('#account-metrics').innerHTML=[
      metric('Accounts',fmt(rows.length),'Real SQLite accounts','#8b7cff'),
      metric('Active sessions',fmt((state.sessions||[]).filter(s=>!s.revoked_at).length),'Signed-in devices','#45d6e8'),
      metric('Stored sessions',fmt(counts.sessions||0),'Including signed out','#51d6a1'),
      metric('Chat messages',fmt(counts.chat_history||0),'Auto-saved conversations','#e8bb62'),
    ].join('');
    const cols=[['username','ACCOUNT'],['email','EMAIL'],['role','ROLE'],['plan','PLAN'],['status','STATUS'],['verified','EMAIL'],['sessions','SESSIONS']];
    $('#account-head').innerHTML=`<tr>${cols.map(x=>`<th>${esc(x[1])}</th>`).join('')}<th>ACTIONS</th></tr>`;
    const q=($('#account-search').value||'').toLowerCase();
    const filtered=rows.filter(r=>JSON.stringify([r.username,r.email,r.role,r.status,r.membership&&r.membership.plan]).toLowerCase().includes(q));
    $('#account-body').innerHTML=filtered.map(r=>{
      const plan=(r.membership&&r.membership.plan)||'noob';
      const planLabel=(r.membership&&r.membership.planLabel)||plan;
      const verified=r.emailVerified?'<span class="status">verified</span>':'<span class="status off">pending</span>';
      const isSelf=AUTH.user&&r.id===AUTH.user.id;
      const roleOptions=['user','moderator','admin','owner'].map(role=>`<option value="${role}" ${r.role===role?'selected':''}>${role.toUpperCase()}</option>`).join('');
      const actions=[];
      if(can('roles.grant.moderator')&&!isSelf) actions.push(`<select class="mini" data-role-for="${r.id}">${roleOptions}</select><button class="mini" data-grant="${r.id}">Set role</button>`);
      if(can('users.suspend')&&!isSelf) actions.push(`<button class="mini" data-suspend="${r.id}" data-status="${esc(r.status)}">${r.status==='active'?'Suspend':'Activate'}</button>`);
      if(can('users.delete')&&!isSelf) actions.push(`<button class="mini danger" data-del-account="${r.id}">Delete</button>`);
      return `<tr><td>${esc(r.username)}${isSelf?' <span class="tag">you</span>':''}</td><td>${esc(r.email)}</td><td>${esc(String(r.role||'user').toUpperCase())}</td><td>${esc(planLabel)}</td><td>${status(r.status)}</td><td>${verified}</td><td>${fmt(r.sessions||0)}</td><td><div class="row-actions">${actions.join('')}</div></td></tr>`;
    }).join('')||`<tr><td colspan="${cols.length+1}" style="text-align:center;padding:32px;color:#718099">No accounts yet.</td></tr>`;
    const sc=[['username','ACCOUNT'],['ip','ADDRESS'],['last_seen_at','LAST ACTIVE'],['expires_at','EXPIRES'],['actions','']];
    $('#session-head').innerHTML=`<tr>${sc.map(x=>`<th>${esc(x[1])}</th>`).join('')}</tr>`;
    $('#session-body').innerHTML=(state.sessions||[]).slice(0,60).map(s=>`<tr><td>${esc(s.username||s.user_id)}</td><td>${esc(s.ip||'local')}</td><td>${esc(s.last_seen_at||'—')}</td><td>${esc(s.expires_at||'—')}</td><td>${s.revoked_at?'<span class="status off">signed out</span>':(can('sessions.revoke')?`<button class="mini danger" data-revoke-session="${s.id}">Revoke</button>`:'<span class="status">active</span>')}</td></tr>`).join('')||`<tr><td colspan="5" style="text-align:center;padding:30px;color:#718099">No sessions.</td></tr>`;
    const pc=[['id','ID'],['plan','PLAN'],['amount','AMOUNT'],['status','STATUS'],['created_at','CREATED'],['actions','']];
    $('#payment-head').innerHTML=`<tr>${pc.map(x=>`<th>${esc(x[1])}</th>`).join('')}</tr>`;
    $('#payment-body').innerHTML=(state.payments||[]).map(p=>`<tr><td>${esc(p.id)}</td><td>${esc(String(p.plan||'').toUpperCase())}</td><td>${esc((p.currency||'USD')+' '+(Number(p.amount_cents||0)/100).toFixed(2))}</td><td>${status(p.status)}</td><td>${esc(p.created_at||'—')}</td><td>${p.status==='pending'&&can('payments.verify')?`<button class="mini" data-verify-payment="${p.id}">Verify</button>`:''}</td></tr>`).join('')||`<tr><td colspan="6" style="text-align:center;padding:30px;color:#718099">No payments recorded.</td></tr>`;
    const ac=[['created_at','TIME'],['actor_name','ACTOR'],['action','ACTION'],['target_type','TARGET'],['detail','DETAIL']];
    $('#audit-db-head').innerHTML=`<tr>${ac.map(x=>`<th>${esc(x[1])}</th>`).join('')}</tr>`;
    $('#audit-db-body').innerHTML=(state.audit||[]).map(a=>`<tr><td>${esc(a.created_at||'—')}</td><td>${esc(a.actor_name||'—')}</td><td>${esc(a.action||'—')}</td><td>${esc(a.target_type||'—')}</td><td>${esc(a.detail||'—')}</td></tr>`).join('')||`<tr><td colspan="5" style="text-align:center;padding:30px;color:#718099">No authentication events recorded yet.</td></tr>`;
  }
  async function loadAccounts(){
    const j=await api2('/api2/admin/accounts');
    state.accounts=j.users||[];state.accountCounts=j.counts||{};
    try{const p=await api2('/api2/admin/payments');state.payments=p.payments||[];}catch(e){state.payments=[];}
    try{const s=await api2('/api2/admin/sessions');state.sessions=s.sessions||[];}catch(e){state.sessions=[];}
    try{const a=await api2('/api2/admin/audit?limit=60');state.audit=a.logs||[];}catch(e){state.audit=[];}
    renderAccounts();
  }
  const modal=$('#modal'),form=$('#record-form');
  function openForm(col,item){const cfg=CONFIG[col];if(!cfg){toast('This section does not support record creation.');return}state.collection=col;state.editing=item||null;$('#modal-title').textContent=(item?'Edit ':'Create ')+cfg.title.toLowerCase().replace(/s$/,'');form.innerHTML=cfg.fields.map(([key,label,type,opts])=>{const val=item?.[key]??(type==='checkbox'?false:'');if(type==='checkbox')return `<label class="toggle-row">${esc(label)}<input name="${key}" type="checkbox" ${val?'checked':''}></label>`;if(type==='select')return `<label>${esc(label)}<select name="${key}">${opts.split('|').map(v=>`<option value="${v}" ${String(val)===v?'selected':''}>${v.toUpperCase()}</option>`).join('')}</select></label>`;return `<label>${esc(label)}<input name="${key}" type="${type}" value="${esc(val)}" ${key==='name'?'required':''} ${type==='number'?'step="any"':''}></label>`}).join('')+`<div class="wide form-actions"><button class="btn primary" type="submit">Save record</button><button class="btn ghost" type="button" id="cancel-record">Cancel</button></div>`;modal.hidden=false;$('#cancel-record').onclick=()=>modal.hidden=true;}
  async function action(body){const j=await api('/api/admin/action',body);if(j.data){state.data=j.data;state.metrics=j.metrics;render()}else await refresh();return j;}
  function download(name,data){const blob=new Blob([JSON.stringify(data,null,2)],{type:'application/json'}),url=URL.createObjectURL(blob),a=document.createElement('a');a.href=url;a.download=name;a.click();setTimeout(()=>URL.revokeObjectURL(url),1000)}
  $('#nav').addEventListener('click',e=>{const b=e.target.closest('[data-page]');if(b)goto(b.dataset.page)});
  document.body.addEventListener('click',async e=>{const g=e.target.closest('[data-goto]');if(g)goto(g.dataset.goto);const insight=e.target.closest('[data-insight]');if(insight){const d=state.data,m=state.metrics;let txt='';if(insight.dataset.insight==='health')txt=`Local runtime is running. ${(state.accounts||[]).length} authenticated account(s), ${m.plugins} plugin listings and ${m.tools} tools are registered. Accounts, sessions, roles and memberships are live in the local database.`;if(insight.dataset.insight==='plugins')txt=`${d.plugins.length} plugin listings exist. ${d.plugins.filter(x=>x.approved).length} are marked approved, ${d.plugins.filter(x=>x.featured).length} featured. Package execution/upload is not implemented.`;if(insight.dataset.insight==='cost')txt='Provider costs cannot be calculated yet: no live token telemetry or provider billing connection exists. Add verified token usage and per-model pricing before relying on a cost/profit report.';$('#assistant-output').textContent=txt;return}const edit=e.target.closest('[data-edit]');if(edit){const col=edit.dataset.col||state.collection;const item=(state.data[col]||[]).find(x=>x.id===edit.dataset.edit);if(item)openForm(col,item);return}const cmd=e.target.closest('[data-command]');if(cmd){if(cmd.dataset.command==='refresh'){await refresh();toast('Registry refreshed.')}else if(cmd.dataset.command==='backup')$('#backup').click();else if(cmd.dataset.command==='audit')goto('security');else if(cmd.dataset.command==='maintenance'){const settings={...state.data.settings,maintenanceMode:!state.data.settings.maintenanceMode};try{await action({action:'save_settings',settings});toast('Maintenance flag updated (local metadata only).')}catch(err){toast(err.message)}}return}const del=e.target.closest('[data-delete]');if(del){if(!confirm('Delete this local record? This cannot be undone.'))return;try{await action({action:'delete',collection:del.dataset.col,id:del.dataset.delete});toast('Record deleted.')}catch(err){toast(err.message)}return}const tog=e.target.closest('[data-toggle]');if(tog){const col=tog.dataset.col,id=tog.dataset.toggle,row=(state.data[col]||[]).find(x=>x.id===id);try{await action({action:'toggle',collection:col,id,field:'enabled',value:!(row?.enabled!==false)});toast('Record state updated.')}catch(err){toast(err.message)}}});
  $('#quick-add').onclick=()=>{const p=state.page,col=({users:'users',models:'models',memberships:'memberships',plugins:'plugins',tools:'tools',finance:'transactions',tickets:'tickets',updates:'updates'})[p]||'tools';openForm(col)};
  $('#add-record').onclick=()=>openForm(state.collection);$('#add-transaction').onclick=()=>openForm('transactions');$('#search').addEventListener('input',()=>renderRecords(state.collection));
  form.addEventListener('submit',async e=>{e.preventDefault();const item={...(state.editing||{})};for(const el of form.elements){if(!el.name)continue;item[el.name]=el.type==='checkbox'?el.checked:el.type==='number'?(el.value===''?'':Number(el.value)):el.value.trim()}try{await action({action:'upsert',collection:state.collection,item});modal.hidden=true;toast('Saved locally.')}catch(err){toast(err.message)}});
  $('#modal-close').onclick=()=>modal.hidden=true;modal.addEventListener('click',e=>{if(e.target===modal)modal.hidden=true});
  $('#refresh').onclick=()=>refresh().then(()=>toast('Admin data refreshed.')).catch(e=>toast(e.message));
  $('#export-records').onclick=()=>download(`${state.collection}-export.json`,state.data[state.collection]||[]);$('#export-audit').onclick=()=>download('zeroscript-admin-audit.json',state.data.audit||[]);
  $('#owner-form').addEventListener('submit',async e=>{e.preventDefault();const settings={};for(const el of e.currentTarget.elements){if(!el.name)continue;settings[el.name]=el.type==='checkbox'?el.checked:el.type==='number'?Number(el.value):el.value.trim()}try{await action({action:'save_settings',settings});toast('Owner settings saved.')}catch(err){toast(err.message)}});
  $('#backup').onclick=async()=>{try{const j=await api('/api/admin/action',{action:'backup'});download(j.filename,j.backup);await refresh();toast('Local backup exported.')}catch(err){toast(err.message)}};
  $('#announcement-form').addEventListener('submit',async e=>{e.preventDefault();const f=new FormData(e.currentTarget);try{await action({action:'announcement',title:f.get('title'),audience:f.get('audience'),message:f.get('message'),scheduleAt:f.get('scheduleAt')});e.currentTarget.reset();toast('Announcement draft saved.')}catch(err){toast(err.message)}});
  // ── Account actions (server enforced) ─────────────────────────
  document.body.addEventListener('click',async e=>{
    const grant=e.target.closest('[data-grant]');
    if(grant){
      const id=grant.dataset.grant;
      const select=document.querySelector(`[data-role-for="${id}"]`);
      const role=select?select.value:'';
      if(!role)return;
      try{await api2('/api2/admin/roles/grant',{userId:Number(id),role});toast(`Role set to ${role.toUpperCase()}.`);await loadAccounts();}catch(err){toast(err.message);}
      return;
    }
    const suspend=e.target.closest('[data-suspend]');
    if(suspend){
      const id=suspend.dataset.suspend;
      const next=suspend.dataset.status==='active'?'suspended':'active';
      try{await api2('/api2/admin/users/suspend',{userId:Number(id),status:next});toast(`Account ${next}.`);await loadAccounts();}catch(err){toast(err.message);}
      return;
    }
    const delAccount=e.target.closest('[data-del-account]');
    if(delAccount){
      if(!confirm('Delete this account and all of its stored data? This cannot be undone.'))return;
      try{await api2('/api2/admin/users/delete',{userId:Number(delAccount.dataset.delAccount)});toast('Account deleted.');await loadAccounts();}catch(err){toast(err.message);}
      return;
    }
    const revoke=e.target.closest('[data-revoke-session]');
    if(revoke){
      try{await api2('/api2/admin/sessions/revoke',{sessionId:Number(revoke.dataset.revokeSession)});toast('Session revoked.');await loadAccounts();}catch(err){toast(err.message);}
      return;
    }
    const verify=e.target.closest('[data-verify-payment]');
    if(verify){
      if(!confirm('Verify this payment on the server and activate the membership?'))return;
      try{await api2('/api2/admin/payments/verify',{paymentId:Number(verify.dataset.verifyPayment)});toast('Payment verified and membership activated.');await loadAccounts();}catch(err){toast(err.message);}
      return;
    }
  });
  $('#refresh-accounts')?.addEventListener('click',()=>loadAccounts().then(()=>toast('Accounts refreshed.')).catch(e=>toast(e.message)));
  $('#account-search')?.addEventListener('input',()=>renderAccounts());
  $('#export-audit-db')?.addEventListener('click',()=>download('zeroscript-auth-audit.json',state.audit||[]));

  (async function boot(){
    try{
      const session=await api2('/api2/auth/session');
      if(!session||!session.authenticated){window.location.href='/2/login?next=%2Fadmin';return;}
      AUTH.user=session.user;AUTH.role=session.role;AUTH.permissions=session.permissions||[];AUTH.csrf=session.csrfToken||'';
      if(!['owner','admin','moderator'].includes(String(session.role||'').toLowerCase())){
        const main=document.querySelector('.main');
        if(main)main.innerHTML='<div class="panel"><div class="panel-head"><div><h2>Access denied</h2><p>Your role does not grant access to the Ultimate Admin Panel.</p></div></div></div>';
        return;
      }
    }catch(err){
      window.location.href='/2/login?next=%2Fadmin';
      return;
    }
    try{await refresh();}catch(e){toast(e.message);const out=$('#assistant-output');if(out)out.textContent='Could not load admin data: '+e.message;}
    try{await loadAccounts();}catch(e){toast(e.message);}
  })();
})();
