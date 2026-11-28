/* ZeroScript 2.0 - Batch 5 UI injector */
(function () {
  'use strict';

  function ready(fn) {
    if (document.readyState !== 'loading') fn();
    else document.addEventListener('DOMContentLoaded', fn);
  }

  ready(function () {
    injectUndoButton();
    injectLiveAIButton();
    injectReplayButton();
    patchDebugRefresh();
  });

  function injectUndoButton() {
    const tb = document.querySelector('#view-editor .toolbar');
    if (!tb) return;
    const btn = document.createElement('button');
    btn.textContent = '\u21ba Undo AI';
    btn.title = 'Undo the last AI property change';
    btn.style.background = 'linear-gradient(135deg, #ef4444, #b91c1c)';
    btn.onclick = async () => {
      const r = await window.apiPost('/api2/undo', {});
      if (r.ok) window.flash('Undone: ' + (r.undone?.property || 'last action'));
      else alert(r.error || 'Nothing to undo');
    };
    tb.appendChild(btn);
  }

  function injectLiveAIButton() {
    const tb = document.querySelector('#view-ai .toolbar');
    if (!tb) return;
    const btn = document.createElement('button');
    btn.textContent = '\ud83d\ude80 Send to AI tab';
    btn.title = 'Copy the prompt and open the AI tab';
    btn.style.background = 'linear-gradient(135deg, #22d3ee, #0ea5e9)';
    btn.onclick = async () => {
      const action = document.getElementById('ai-action').value;
      const input = document.getElementById('ai-input').value;
      const r = await window.apiPost('/api2/ai/live/start', { action, input });
      if (!r.ok) { alert(r.error); return; }
      try {
        await navigator.clipboard.writeText(r.prompt);
        window.flash(r.mode === 'ws'
          ? 'Prompt sent to AI tab over WebSocket'
          : 'Prompt copied! Paste in AI tab, then click "Got response".');
      } catch { window.flash('Prompt ready \u2014 copy manually.'); }
      showResponseModal(r.session_id);
    };
    tb.appendChild(btn);
  }

  function showResponseModal(sid) {
    const modal = document.createElement('div');
    modal.style.cssText = 'position:fixed;inset:0;background:rgba(0,0,0,.7);z-index:99999;display:flex;align-items:center;justify-content:center;';
    modal.innerHTML =
      '<div style="background:#161925;border:1px solid #262a3a;border-radius:12px;padding:20px;width:600px;max-width:90vw;">' +
      '<h3 style="margin-top:0">Paste the AI\'s response here</h3>' +
      '<textarea id="zs-response-box" style="width:100%;height:200px;background:#0b0d14;color:#e6e8f0;border:1px solid #262a3a;border-radius:8px;padding:10px;font-family:monospace;" placeholder="Paste the AI reply or code..."></textarea>' +
      '<div style="margin-top:12px;display:flex;gap:8px;justify-content:flex-end;">' +
      '<button id="zs-response-cancel" style="background:#262a3a;">Cancel</button>' +
      '<button id="zs-response-save">Save response</button>' +
      '</div></div>';
    document.body.appendChild(modal);
    document.getElementById('zs-response-cancel').onclick = () => modal.remove();
    document.getElementById('zs-response-save').onclick = async () => {
      const response = document.getElementById('zs-response-box').value;
      const r = await window.apiPost('/api2/ai/live/response', { session_id: sid, response });
      if (r.ok) {
        modal.remove();
        window.flash('Response saved');
        document.getElementById('ai-output').textContent = response;
      } else alert(r.error);
    };
  }

  function injectReplayButton() {
    const tb = document.querySelector('#view-debug .toolbar');
    if (!tb) return;
    const btn = document.createElement('button');
    btn.textContent = '\u25b6 Replay last 10 calls';
    btn.title = 'Re-run the last 10 tool calls in Studio';
    btn.style.background = 'linear-gradient(135deg, #a78bfa, #7c3aed)';
    btn.onclick = async () => {
      if (!confirm('Re-run the last 10 tool calls? This may modify your game.')) return;
      const r = await window.apiPost('/api2/replay', { limit: 10 });
      alert(r.ok ? `Replayed ${r.count} calls (${r.ok_count} ok, ${r.fail_count} failed)` : r.error);
    };
    tb.appendChild(btn);
  }

  function patchDebugRefresh() {
    const original = window.debugRefresh;
    if (typeof original !== 'function') return;
    window.debugRefresh = async function () {
      await original.apply(this, arguments);
      document.querySelectorAll('#debug-errors > div.error, #debug-warnings > div.warning')
        .forEach(el => {
          if (el.querySelector('.zs-fix-btn')) return;
          const btn = document.createElement('button');
          btn.className = 'zs-fix-btn';
          btn.textContent = '\ud83d\udd27 Fix';
          btn.style.cssText = 'margin-left:8px;padding:2px 8px;font-size:11px;background:#22d3ee;';
          btn.onclick = async () => {
            const msg = el.textContent.replace(/\u00d7\d+/, '').replace('\ud83d\udd27 Fix', '').trim();
            const r = await window.apiPost('/api2/debug/fix', { error: msg });
            if (r.ok) {
              try { await navigator.clipboard.writeText(r.prompt); } catch {}
              if (typeof window.showView === 'function') window.showView('ai');
              const inp = document.getElementById('ai-input');
              if (inp) inp.value = r.prompt;
              window.flash('Fix prompt ready in AI tab');
            }
          };
          el.appendChild(btn);
        });
    };
  }
})();