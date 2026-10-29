// Demo-mode chrome for the members app. Served only to demo sessions.
(function () {
  function post(u, b) { return fetch(u, { method: 'POST', credentials: 'include', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(b || {}) }).then(function (r) { return r.json(); }); }
  function signOut() { post('/api/demo/signout').then(function () { location.href = '/demo-mode'; }); }
  fetch('/api/demo/state', { credentials: 'include' }).then(function (r) { return r.json(); }).then(function (st) {
    if (!st || !st.ok) return;
    var css = document.createElement('style');
    css.textContent = '#demoBar{position:sticky;top:0;z-index:70;height:36px;display:flex;align-items:center;gap:8px;padding:0 12px;background:#B4882E;color:#fff;font:600 12px/1 -apple-system,Segoe UI,Roboto,Arial,sans-serif}'
      + '#demoBar b{letter-spacing:.12em;white-space:nowrap}#demoBar .sp{flex:1}#demoBar select{max-width:150px;font:inherit;font-weight:600;border:0;border-radius:6px;padding:4px 6px;color:#0E1013;background:#fff}'
      + '#demoBar button{font:inherit;border:1px solid rgba(255,255,255,.7);background:transparent;color:#fff;border-radius:6px;padding:4px 8px;cursor:pointer;white-space:nowrap}'
      + '#demoBar .full{white-space:nowrap}@media(max-width:520px){#demoBar .full{display:none}}.nav{top:36px!important}';
    document.head.appendChild(css);
    var bar = document.createElement('div'); bar.id = 'demoBar';
    bar.innerHTML = '<b>DEMO</b><span class="full">test data only</span><span class="sp"></span>'
      + '<select id="demoAs" aria-label="Switch demo account">' + st.accounts.map(function (a) { return '<option value="' + a.n + '"' + (a.email === st.current ? ' selected' : '') + '>' + a.name + ' · ' + a.market + '</option>'; }).join('') + '</select>'
      + '<button id="demoOut">Sign out</button><button id="demoExit">Exit</button>';
    document.body.insertBefore(bar, document.body.firstChild);
    document.getElementById('demoAs').onchange = function () { post('/api/demo/signin', { n: this.value }).then(function () { location.reload(); }); };
    document.getElementById('demoOut').onclick = signOut;
    document.getElementById('demoExit').onclick = function () { post('/api/demo/exit').then(function () { location.href = '/'; }); };
    // The real "Sign out" link would end the real session; in demo it signs out of the demo account.
    document.querySelectorAll('a[href="/logout"],a[href="/auth/logout"]').forEach(function (a) { a.setAttribute('href', '#'); a.addEventListener('click', function (e) { e.preventDefault(); signOut(); }); });
    // Seller-signed form step: offer a DEMO placeholder file.
    var inp = document.getElementById('sSellerForm');
    if (inp && st.placeholder) {
      var btn = document.createElement('button'); btn.type = 'button'; btn.className = 'btn ghost sm'; btn.style.marginLeft = '8px';
      btn.textContent = 'Use DEMO placeholder form';
      btn.onclick = function () { window.SUBMIT_SELLER_FORM = { name: st.placeholder.name, url: st.placeholder.url, uploadedAt: new Date().toISOString() }; if (typeof renderSellerForm === 'function') renderSellerForm(); };
      inp.parentNode.insertBefore(btn, inp.nextSibling);
    }
  }).catch(function () {});
})();
