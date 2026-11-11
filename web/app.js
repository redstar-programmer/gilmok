// Gilmok web UI — vanilla JS, no build step.
// CSP: script-src 'self' → no inline handlers; every write request carries `X-GM: 1`.
'use strict';

// ======================================================================= helpers

const $ = (sel, root = document) => root.querySelector(sel);
let uidSeq = 0;
const uid = (p = 'id') => `${p}-${++uidSeq}`;

const PROPS = new Set(['value', 'checked', 'disabled', 'hidden', 'selected', 'indeterminate', 'readOnly', 'multiple', 'open']);

/** h('div', {class, onclick, ...}, ...children) — builds DOM without innerHTML. */
function h(tag, props, ...kids) {
  const el = document.createElement(tag);
  if (props) {
    for (const [k, v] of Object.entries(props)) {
      if (v == null || v === false) continue;
      if (k === 'class') el.className = v;
      else if (k === 'style' && typeof v === 'object') Object.assign(el.style, v);
      else if (k === 'dataset') Object.assign(el.dataset, v);
      else if (k.startsWith('on') && typeof v === 'function') el.addEventListener(k.slice(2).toLowerCase(), v);
      else if (PROPS.has(k)) el[k] = v;
      else el.setAttribute(k, v === true ? '' : String(v));
    }
  }
  append(el, kids);
  return el;
}
function append(el, kids) {
  for (const k of kids.flat(Infinity)) {
    if (k == null || k === false || k === true) continue;
    el.append(k instanceof Node ? k : document.createTextNode(String(k)));
  }
  return el;
}

const SVG_NS = 'http://www.w3.org/2000/svg';
const ICONS = {
  monitor: 'M3 5h18v11H3zM8 20h8M12 16v4',
  moon: 'M20 14.5A8 8 0 1 1 9.5 4a6.5 6.5 0 0 0 10.5 10.5z',
  sun: 'M12 8a4 4 0 1 0 0 8 4 4 0 0 0 0-8zM12 2v2M12 20v2M4.9 4.9l1.4 1.4M17.7 17.7l1.4 1.4M2 12h2M20 12h2M4.9 19.1l1.4-1.4M17.7 6.3l1.4-1.4',
  cloud: 'M7 19a5 5 0 0 1-.6-9.96A6.5 6.5 0 0 1 18.8 9.3 4.85 4.85 0 0 1 17.5 19H7z',
  plus: 'M12 5v14M5 12h14',
  x: 'M6 6l12 12M18 6L6 18',
  refresh: 'M20 11a8 8 0 1 0-2.3 5.7M20 4v7h-7',
  logout: 'M15 4h3a2 2 0 0 1 2 2v12a2 2 0 0 1-2 2h-3M10 8l-4 4 4 4M6 12h11',
  search: 'M11 18a7 7 0 1 1 0-14 7 7 0 0 1 0 14zM20 20l-4-4',
  shield: 'M12 3l8 3v6c0 4.5-3.4 8.3-8 9-4.6-.7-8-4.5-8-9V6l8-3z',
  lock: 'M6 11h12v9H6zM8.5 11V8a3.5 3.5 0 0 1 7 0v3',
  key: 'M8 21a5 5 0 1 1 0-10 5 5 0 0 1 0 10zM11.5 12.5L20 4M17 7l3 3M14.5 9.5l2 2',
  download: 'M12 4v11M7 10l5 5 5-5M5 20h14',
  upload: 'M12 20V9M7 14l5-5 5 5M5 4h14',
  user: 'M12 12a4 4 0 1 0 0-8 4 4 0 0 0 0 8zM4 21a8 8 0 0 1 16 0',
  check: 'M5 12.5l4.5 4.5L19 7.5',
  globe: 'M12 3a9 9 0 1 0 0 18 9 9 0 0 0 0-18zM3 12h18M12 3c2.4 2.5 3.6 5.5 3.6 9s-1.2 6.5-3.6 9c-2.4-2.5-3.6-5.5-3.6-9S9.6 5.5 12 3',
  code: 'M8 7l-5 5 5 5M16 7l5 5-5 5',
  clock: 'M12 3a9 9 0 1 0 0 18 9 9 0 0 0 0-18zM12 7v5l3.5 2.5',
};
function icon(name, cls = '') {
  const s = document.createElementNS(SVG_NS, 'svg');
  s.setAttribute('viewBox', '0 0 24 24');
  s.setAttribute('aria-hidden', 'true');
  s.setAttribute('class', `icon ${cls}`.trim());
  const p = document.createElementNS(SVG_NS, 'path');
  p.setAttribute('d', ICONS[name] || '');
  s.append(p);
  return s;
}

const fmtTime = (iso) => {
  if (!iso || iso.startsWith('0001-')) return '';
  const d = new Date(iso);
  if (isNaN(d)) return iso;
  return d.toLocaleString(gmLocale(), { year: 'numeric', month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit' });
};
const splitList = (s) => String(s || '').split(/[,\s]+/).map((x) => x.trim()).filter(Boolean);

// ======================================================================= API

class ApiError extends Error {
  constructor(msg, data) { super(msg); this.data = data; }
}

/** Step-up: sensitive actions answer 403 {reauth:true}; ask for the password (+code) and retry once. */
async function api(method, path, body) {
  try {
    return await apiOnce(method, path, body);
  } catch (ex) {
    if (ex instanceof ApiError && ex.data && ex.data.reauth) {
      const ok = await reauthDialog(ex.message);
      if (ok) return apiOnce(method, path, body);
    }
    throw ex;
  }
}

function reauthDialog(reason) {
  return new Promise((resolve) => {
    const pw = h('input', { type: 'password', autocomplete: 'current-password', required: true });
    const code = h('input', { type: 'text', autocomplete: 'one-time-code', maxlength: '11', placeholder: '6자리' });
    const needCode = !!(S.state && S.state.security && S.state.security.totp);
    const err = h('p', { class: 'form-error', role: 'alert', hidden: true });
    const form = h('form', { class: 'stack', novalidate: true },
      h('p', { class: 'muted' }, reason || '중요한 작업입니다 — 비밀번호를 다시 확인해 주세요.'),
      err, field(`비밀번호 (${(S.state && S.state.me && S.state.me.name) || '내 계정'})`, pw), needCode ? field('2단계 인증 코드 (또는 복구 코드)', code) : null,
      h('p', { class: 'hint' }, `확인하면 ${(S.state && S.state.settings && S.state.settings.secReauthMin) || 10}분 동안 다시 묻지 않습니다.`));
    const okBtn = h('button', { type: 'submit', class: 'btn primary' }, '확인');
    const cancel = h('button', { type: 'button', class: 'btn ghost' }, '취소');
    okBtn.setAttribute('form', form.id = uid('form'));
    let done = false;
    const d = openDialog({ title: '본인 확인', body: form, footer: [h('span', { class: 'spacer' }), cancel, okBtn], onClose: () => { if (!done) resolve(false); } });
    cancel.addEventListener('click', () => d.close());
    form.addEventListener('submit', async (e) => {
      e.preventDefault();
      err.hidden = true;
      try {
        await busy(okBtn, () => apiOnce('POST', '/api/auth/reauth', { password: pw.value, code: code.value.trim() }));
        done = true;
        d.close();
        resolve(true);
      } catch (ex) { err.textContent = ex.message; err.hidden = false; pw.select(); }
    });
    setTimeout(() => pw.focus(), 30);
  });
}

async function apiOnce(method, path, body) {
  const opt = { method, headers: {}, credentials: 'same-origin' };
  if (method !== 'GET') opt.headers['X-GM'] = '1';
  if (body !== undefined) {
    opt.headers['Content-Type'] = 'application/json';
    opt.body = JSON.stringify(body);
  }
  let res;
  try {
    res = await fetch(path, opt);
  } catch {
    throw new ApiError('서버에 연결할 수 없습니다');
  }
  noteBuild(res.headers.get('X-GM-Build'));
  const text = await res.text();
  let data = null;
  if (text) {
    try { data = JSON.parse(text); } catch { data = text; }
  }
  if (res.status === 403 && data && typeof data === 'object' && data.gate) {
    // many requests can hit the gate at once: open it only once (showGate ignores repeats)
    if (!gateOpen) api('GET', '/api/auth/state').then((st) => { if (st.me && st.me.gate) showGate(st.me); }).catch(() => {});
    throw new ApiError(data.error, data);
  }
  if (res.status === 401 && !path.startsWith('/api/auth/')) {
    showAuth();
    throw new ApiError('세션이 만료되었습니다. 다시 로그인하세요');
  }
  if (!res.ok) throw new ApiError((data && data.error) || (typeof data === 'string' && data.slice(0, 200)) || `요청 실패 (${res.status})`, data && typeof data === 'object' ? data : null);
  // anything that changes the generated files makes earlier "검증 통과" results stale
  if (method !== 'GET' && /^\/api\/(services|settings|import|apply|groups|config\/import|reset|setup)/.test(path)) S.validated = {};
  if (method !== 'GET' && /^\/api\/(apply|import|system\/update|users|groups|config\/import|reset|setup|cloudflare\/token|crowdsec\/bouncer)/.test(path)) S.checks = {};
  // a restore / reset replaces the dashboard layout: drop the cached one
  if (method !== 'GET' && /^\/api\/(config\/import|reset)$/.test(path) && typeof DASH !== 'undefined') { DASH.widgets = null; DASH.data = null; }
  return data;
}

// ======================================================================= new version after an update

let loadedBuild = null;
let buildBanner = null;
function noteBuild(b) {
  if (!b) return;
  if (!loadedBuild) { loadedBuild = b; return; }
  if (b === loadedBuild || buildBanner) return;
  const btn = h('button', { type: 'button', class: 'btn sm primary' }, '새로고침');
  btn.addEventListener('click', () => location.reload());
  buildBanner = h('div', { class: 'toast warn sticky', role: 'status' },
    h('span', null, '길목이 업데이트되었습니다 — 새 화면을 쓰려면 새로고침하세요.'), btn);
  $('#toasts').append(buildBanner);
}

// ======================================================================= toasts

function toast(msg, kind = 'ok', ms = 4500) {
  const t = h('div', { class: `toast ${kind}` }, msg);
  $('#toasts').append(t);
  setTimeout(() => t.remove(), ms);
}

// ======================================================================= dialogs (modal + drawer)
// Radix-style: aria-modal, labelled title, focus trap, Esc to close, focus restore, background inert.

const dialogStack = [];
const FOCUSABLE = 'a[href],button:not([disabled]),input:not([disabled]):not([type=hidden]),select:not([disabled]),textarea:not([disabled]),summary,[tabindex]:not([tabindex="-1"])';

function syncInert() {
  const top = dialogStack[dialogStack.length - 1];
  $('#app').inert = !!top;
  for (const d of dialogStack) d.overlay.inert = d !== top;
  document.body.classList.toggle('locked', !!top);
}

/**
 * openDialog({title, body, footer, variant: 'modal'|'drawer', size: 'wide', beforeClose, onClose})
 * returns { close, lock(bool), body, panel }
 */
function openDialog(opts) {
  const { title, body, footer, variant = 'modal', size = '', beforeClose, onClose, role = 'dialog' } = opts;
  const prevFocus = document.activeElement;
  const titleId = uid('dlg-title');
  const closeBtn = h('button', { type: 'button', class: 'icon-btn', 'aria-label': '닫기' }, icon('x'));
  const bodyEl = h('div', { class: 'dlg-body' }, body);
  const panel = h('div', {
    class: `dialog ${variant} ${size}`, role, 'aria-modal': 'true', 'aria-labelledby': titleId, tabindex: '-1',
  },
  h('header', { class: 'dlg-head' }, h('h2', { id: titleId }, title), closeBtn),
  bodyEl,
  footer ? h('footer', { class: 'dlg-foot' }, footer) : null);
  const overlay = h('div', { class: `overlay ${variant}` }, panel);

  const d = { overlay, panel, body: bodyEl, locked: false };
  let closed = false;

  d.close = (force = false) => {
    if (closed) return;
    closed = true;
    overlay.remove();
    const i = dialogStack.indexOf(d);
    if (i >= 0) dialogStack.splice(i, 1);
    syncInert();
    if (prevFocus && prevFocus.isConnected && typeof prevFocus.focus === 'function') prevFocus.focus();
    onClose && onClose(force);
  };
  d.tryClose = async () => {
    if (d.locked) return;
    if (beforeClose && !(await beforeClose())) return;
    d.close();
  };
  d.lock = (on) => {
    d.locked = on;
    closeBtn.disabled = on;
  };

  closeBtn.addEventListener('click', d.tryClose);
  overlay.addEventListener('mousedown', (e) => { if (e.target === overlay) d.tryClose(); });
  overlay.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') {
      e.stopPropagation();
      e.preventDefault();
      d.tryClose();
    } else if (e.key === 'Tab') {
      const f = [...panel.querySelectorAll(FOCUSABLE)].filter((x) => x.offsetParent !== null || x === document.activeElement);
      if (!f.length) { e.preventDefault(); panel.focus(); return; }
      const first = f[0], last = f[f.length - 1];
      if (e.shiftKey && (document.activeElement === first || document.activeElement === panel)) { e.preventDefault(); last.focus(); }
      else if (!e.shiftKey && document.activeElement === last) { e.preventDefault(); first.focus(); }
    }
  });

  document.body.append(overlay);
  dialogStack.push(d);
  syncInert();
  const auto = panel.querySelector('[autofocus]') || bodyEl.querySelector('input:not([disabled]),select,textarea');
  (auto || panel).focus();
  return d;
}

function confirmDialog({ title, message, okText = '확인', cancelText = '취소', danger = false }) {
  return new Promise((resolve) => {
    let result = false;
    const ok = h('button', { type: 'button', class: `btn ${danger ? 'danger solid' : 'primary'}` }, okText);
    const cancel = h('button', { type: 'button', class: 'btn ghost', autofocus: true }, cancelText);
    const d = openDialog({
      title, role: 'alertdialog',
      body: typeof message === 'string' ? h('p', { style: { whiteSpace: 'pre-wrap' } }, message) : message,
      footer: [cancel, ok],
      onClose: () => resolve(result),
    });
    cancel.addEventListener('click', () => d.close());
    ok.addEventListener('click', () => { result = true; d.close(); });
  });
}

// ---- small UI pieces

function spinnerRow(text) {
  return h('div', { class: 'spinner-row', role: 'status' }, h('span', { class: 'spinner', 'aria-hidden': 'true' }), text);
}
function callout(kind, ...kids) { return h('div', { class: `callout ${kind}` }, kids); }
function errorBox(msg) { return h('p', { class: 'form-error', role: 'alert' }, msg); }

function logView(lines) {
  const pre = h('pre', { class: 'log', tabindex: '0', 'aria-label': '실행 로그' });
  for (const raw of lines || []) {
    const t = raw.trimStart();
    let cls = '';
    if (t.startsWith('✓') || t.startsWith('✔')) cls = 'l-ok';
    else if (t.startsWith('✗')) cls = 'l-err';
    else if (t.startsWith('↺')) cls = 'l-warn';
    else if (t.startsWith('▶')) cls = 'l-step';
    else if (t.startsWith('$')) cls = 'l-cmd';
    pre.append(h('span', { class: cls }, raw), '\n');
  }
  if (!lines || !lines.length) pre.append(h('span', { class: 'muted' }, '(로그 없음)'));
  return pre;
}

/** Result of an operation that returns {ok, log, error}. */
function resultView(res, extra) {
  return h('div', { class: 'stack' },
    res.ok ? callout('ok', h('b', null, '✓ 성공')) : callout('danger', h('b', null, '실패'), h('span', { style: { whiteSpace: 'pre-wrap' } }, res.error || '알 수 없는 오류')),
    logView(res.log),
    extra || null);
}

function showResult(title, res, extra) {
  const close = h('button', { type: 'button', class: 'btn primary', autofocus: true }, '닫기');
  const d = openDialog({ title, body: resultView(res, extra), footer: [close], size: 'wide' });
  close.addEventListener('click', () => d.close());
  return d;
}

/** Runs an async action with a busy button. */
async function busy(btn, fn) {
  const was = btn.disabled;
  btn.disabled = true;
  btn.classList.add('busy');
  try { return await fn(); } finally {
    btn.disabled = was;
    btn.classList.remove('busy');
  }
}

// ---- form controls

function field(label, control, hint) {
  const id = control.id || (control.id = uid('f'));
  const kids = [h('label', { for: id }, label), control];
  if (hint) {
    const hid = uid('hint');
    control.setAttribute('aria-describedby', hid);
    kids.push(h('p', { class: 'hint', id: hid }, hint));
  }
  return h('div', { class: 'field' }, kids);
}

function switchCtl(label, checked, desc, attrs = {}) {
  const input = h('input', { type: 'checkbox', role: 'switch', checked: !!checked, ...attrs });
  const el = h('label', { class: 'switch' }, input, h('span', null, h('b', null, label), desc ? h('small', { class: 'hint' }, desc) : null));
  el.input = input;
  return el;
}

function segmented(name, label, options, value) {
  const legendId = uid('seg');
  const wrap = h('div', { class: 'segmented', role: 'radiogroup', 'aria-labelledby': legendId });
  for (const o of options) {
    wrap.append(h('label', { class: o.disabled ? 'disabled' : null }, h('input', { type: 'radio', name, value: o.value, checked: o.value === value, disabled: !!o.disabled }), h('span', null, o.label)));
  }
  const el = h('div', { class: 'field' }, h('span', { class: 'field-label', id: legendId }, label), wrap);
  el.get = () => (wrap.querySelector('input:checked') || {}).value;
  el.onChange = (fn) => wrap.addEventListener('change', fn);
  return el;
}

// ======================================================================= diff

function diffLines(oldText, newText) {
  const A = String(oldText || '').replace(/\r\n/g, '\n').split('\n');
  const B = String(newText || '').replace(/\r\n/g, '\n').split('\n');
  let pre = 0;
  while (pre < A.length && pre < B.length && A[pre] === B[pre]) pre++;
  let suf = 0;
  while (suf < A.length - pre && suf < B.length - pre && A[A.length - 1 - suf] === B[B.length - 1 - suf]) suf++;
  const a = A.slice(pre, A.length - suf), b = B.slice(pre, B.length - suf);
  const n = a.length, m = b.length, W = m + 1;
  const mid = [];
  if (n * m > 4e6) {
    a.forEach((s, i) => mid.push({ t: '-', a: pre + i, s }));
    b.forEach((s, j) => mid.push({ t: '+', b: pre + j, s }));
  } else {
    const L = new Uint32Array((n + 1) * W);
    for (let i = n - 1; i >= 0; i--) {
      for (let j = m - 1; j >= 0; j--) {
        L[i * W + j] = a[i] === b[j] ? L[(i + 1) * W + j + 1] + 1 : Math.max(L[(i + 1) * W + j], L[i * W + j + 1]);
      }
    }
    let i = 0, j = 0;
    while (i < n && j < m) {
      if (a[i] === b[j]) { mid.push({ t: '=', a: pre + i, b: pre + j, s: a[i] }); i++; j++; }
      else if (L[(i + 1) * W + j] >= L[i * W + j + 1]) { mid.push({ t: '-', a: pre + i, s: a[i] }); i++; }
      else { mid.push({ t: '+', b: pre + j, s: b[j] }); j++; }
    }
    for (; i < n; i++) mid.push({ t: '-', a: pre + i, s: a[i] });
    for (; j < m; j++) mid.push({ t: '+', b: pre + j, s: b[j] });
  }
  const out = [];
  for (let k = 0; k < pre; k++) out.push({ t: '=', a: k, b: k, s: A[k] });
  out.push(...mid);
  for (let k = suf; k > 0; k--) out.push({ t: '=', a: A.length - k, b: B.length - k, s: A[A.length - k] });
  return out;
}

function diffStat(ops) {
  let add = 0, del = 0;
  for (const o of ops) { if (o.t === '+') add++; else if (o.t === '-') del++; }
  return { add, del, changed: add + del > 0 };
}

function renderDiff(ops, ctx = 3) {
  // file contents: never translated (i18n.js skips translate="no")
  const box = h('div', { class: 'diff', role: 'region', 'aria-label': '변경 내용 비교', tabindex: '0', translate: 'no' });
  const keep = new Uint8Array(ops.length);
  ops.forEach((o, i) => {
    if (o.t !== '=') for (let k = Math.max(0, i - ctx); k <= Math.min(ops.length - 1, i + ctx); k++) keep[k] = 1;
  });
  let skipped = 0;
  const flush = () => {
    if (skipped) box.append(h('span', { class: 'gap' }, `⋯ ${skipped}줄 동일`));
    skipped = 0;
  };
  ops.forEach((o, i) => {
    if (!keep[i]) { skipped++; return; }
    flush();
    const cls = o.t === '+' ? 'add' : o.t === '-' ? 'del' : 'ctx';
    const sign = o.t === '=' ? ' ' : o.t;
    box.append(h('div', { class: `dl ${cls}` },
      h('span', { class: 'n' }, o.a != null ? o.a + 1 : ''),
      h('span', { class: 'n' }, o.b != null ? o.b + 1 : ''),
      h('span', { class: 's' }, sign),
      h('span', { class: 't' }, o.s || ' ')));
  });
  flush();
  return box;
}

function statBadge(st) {
  if (!st.changed) return h('span', { class: 'badge muted' }, '변경 없음');
  return h('span', { class: 'diff-stat' }, h('span', { class: 'a' }, `+${st.add}`), ' ', h('span', { class: 'd' }, `−${st.del}`));
}

// ======================================================================= app state

const S = {
  state: null, // /api/state
  tab: 'services',
  dns: null, dnsErr: '', dnsLoading: false,
  users: null, usersRedraw: null,
  checks: {},    // /api/check/{target} cache
  validated: {}, // last /api/validate result per target (this session)
  filter: { q: '', exposure: 'all' },
  view: localStorage.getItem('gm.view') === 'list' ? 'list' : 'map', // services tab: map (default) | list
};

const TABS = ['dashboard', 'services', 'caddy', 'authelia', 'cloudflare', 'crowdsec', 'logs', 'gilmok'];
const LEGACY_TABS = { dns: 'cloudflare', users: 'authelia', settings: 'gilmok', system: 'gilmok' };
const tabFromHash = () => { const t = location.hash.slice(1); return LEGACY_TABS[t] || t; };
const settings = () => (S.state && S.state.settings) || {};
const fqdn = (sub) => {
  const d = settings().domain || '<도메인>';
  sub = String(sub || '').trim();
  return !sub || sub === '@' ? d : `${sub}.${d}`;
};

// ---- components in use (each deployment differs; nothing may assume a component exists)
const COMPONENTS = [
  { key: 'caddy', flag: 'useCaddy', tab: 'caddy', name: 'Caddy', icon: 'server', role: '리버스 프록시',
    desc: '서비스(사이트)를 Caddyfile로 만들고 검증 → 무중단 적용. WAF, 대시보드 요청 통계, 인증서 확인의 바탕.',
    off: '끄면 Caddyfile을 만들거나 바꾸지 않습니다. 서비스는 DNS 레코드만 관리합니다.' },
  { key: 'authelia', flag: 'useAuthelia', tab: 'authelia', name: 'Authelia', icon: 'shield', role: '로그인 (SSO)',
    desc: '서비스마다 로그인·2단계 인증 요구(forward_auth), 접근 규칙과 사용자 관리.',
    off: '끄면 사이트에 로그인 관문을 넣지 않고 Authelia 파일도 건드리지 않습니다.' },
  { key: 'cloudflare', flag: 'useCloudflare', tab: 'cloudflare', name: 'Cloudflare', icon: 'cloud', role: 'DNS · 엣지',
    desc: 'DNS 레코드 자동 관리, 프록시(Proxied)·mTLS, 엣지 WAF 규칙, DDNS Updater.',
    off: '끄면 DNS를 바꾸지 않습니다. Proxied·mTLS·엣지 규칙 설정도 숨깁니다.' },
  { key: 'tailscale', flag: 'useTailscale', tab: null, name: 'Tailscale', icon: 'tailnet', role: '사설 접속 (VPN)',
    desc: '인터넷에 공개하지 않고 Tailscale(또는 VPN)으로만 들어오는 사이트. Caddy가 따로 받는 사설 포트(:8443)와 DNS의 Tailscale IP.',
    off: '끄면 「사설 전용」 노출과 사설 리스너·Tailscale IP 설정을 숨깁니다.' },
  { key: 'crowdsec', flag: 'useCrowdSec', tab: 'crowdsec', name: 'CrowdSec', icon: 'radar', role: '공격 IP 판정',
    desc: '접근 로그로 공격 IP를 판정. Cloudflare와 함께 쓰면 엣지에서 차단합니다.',
    off: '끄면 판정·차단 기능과 탭을 숨깁니다.' },
];
/** use('authelia') → is the component in use on this installation? */
const use = (key) => {
  const c = COMPONENTS.find((x) => x.key === key);
  return !!(c && settings()[c.flag]);
};
const usedNames = () => COMPONENTS.filter((c) => use(c.key)).map((c) => c.name);
/** private exposure ("tailscale" in the data): shown while Tailscale is used or any site still uses it */
const privOn = () => use('tailscale') || ((S.state && S.state.services) || []).some((s) => s.exposure !== 'public');
const privName = () => (use('tailscale') ? 'Tailscale 전용' : '사설 전용');

function applyComponentTabs() {
  for (const c of COMPONENTS) {
    if (!c.tab) continue;
    const t = document.getElementById(`tab-${c.tab}`);
    if (t) t.hidden = !use(c.key);
  }
  const cur = document.getElementById(`tab-${S.tab}`);
  if (cur && cur.hidden) selectTab('gilmok', false);
}

async function refreshState() {
  S.state = await api('GET', '/api/state');
  S.state.services = S.state.services || [];
  renderTopbar();
  applyComponentTabs();
}

// ======================================================================= auth screen

let authSetupMode = false;

async function showAuth(setup) {
  $('#app').hidden = true;
  for (const d of [...dialogStack]) d.close(true);
  let firstRun = false;
  try {
    const st = await api('GET', '/api/auth/state');
    if (setup === undefined) setup = st.setup;
    firstRun = !!st.firstRun;
  } catch { if (setup === undefined) setup = false; }
  authSetupMode = !!setup;
  $('#auth').hidden = false;
  $('#auth-form').hidden = false;
  if ($('#auth-gate')) $('#auth-gate').hidden = true;
  $('#auth-desc').textContent = setup
    ? '첫 실행입니다. 첫 관리자 계정의 아이디와 비밀번호(12자 이상)를 정하세요.'
    : firstRun
      ? '처음 접속입니다 — 아이디 admin, 비밀번호 admin 으로 로그인하세요. 로그인하면 바로 새 관리자 계정을 만들고, admin/admin 은 그 즉시 사용할 수 없게 됩니다.'
      : '아이디와 비밀번호를 입력하세요.';
  $('#auth-desc').classList.toggle('first-run', firstRun);
  $('#auth-name').value = setup || firstRun ? 'admin' : (localStorage.getItem('gm.user') || $('#auth-name').value || '');
  $('#auth-code-wrap').hidden = true;
  $('#auth-code').value = '';
  $('#auth-pw2-wrap').hidden = !setup;
  $('#auth-pw').autocomplete = setup ? 'new-password' : 'current-password';
  $('#auth-submit').textContent = setup ? '설정하고 시작' : '로그인';
  $('#auth-err').hidden = true;
  $('#auth-pw').value = '';
  $('#auth-pw2').value = '';
  ($('#auth-name').value ? $('#auth-pw') : $('#auth-name')).focus();
}

/** After a successful login: a gate (temporary password / 2FA) or the app. */
async function afterLogin() {
  let st = null;
  try { st = await api('GET', '/api/auth/state'); } catch { /* fall through */ }
  if (st && st.me && st.me.gate) { showGate(st.me); return; }
  await showApp();
}

function initAuthForm() {
  $('#auth-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    const pw = $('#auth-pw').value;
    const err = $('#auth-err');
    err.hidden = true;
    const showErr = (m) => { err.textContent = m; err.hidden = false; };
    if (authSetupMode) {
      if (pw.length < 12) return showErr('비밀번호는 12자 이상이어야 합니다');
      if (pw !== $('#auth-pw2').value) return showErr('비밀번호 확인이 일치하지 않습니다');
    }
    const btn = $('#auth-submit');
    try {
      const name = $('#auth-name').value.trim().toLowerCase();
      const res = await busy(btn, () => api('POST', authSetupMode ? '/api/auth/setup' : '/api/auth/login', { name, password: pw, code: $('#auth-code').value.trim() }));
      localStorage.setItem('gm.user', name);
      $('#auth-pw').value = '';
      $('#auth-pw2').value = '';
      $('#auth-code').value = '';
      if (res && res.usedRecovery) toast('복구 코드로 로그인했습니다 — 그 코드는 이제 쓸 수 없습니다. 설정 › 내 계정에서 남은 개수를 확인하세요', 'warn', 10000);
      await afterLogin();
    } catch (ex) {
      showErr(ex.message);
      if (ex.data && ex.data.needCode) {
        $('#auth-code-wrap').hidden = false;
        $('#auth-code').focus();
      } else if (!$('#auth-code-wrap').hidden && /코드/.test(ex.message)) {
        $('#auth-code').select();
      } else {
        $('#auth-pw').select();
      }
    }
  });
}

// ======================================================================= shell

async function showApp() {
  $('#auth').hidden = true;
  $('#app').hidden = false;
  try {
    await refreshState();
  } catch (e) {
    toast(e.message, 'err');
    return;
  }
  const want = tabFromHash();
  // first run (nothing imported yet) → the services tab, with the setup offer on top
  const def = S.state.services.length ? 'dashboard' : 'services';
  selectTab(TABS.includes(want) ? want : def, false);
  maybeOfferSetup();
  // entry notices: updates, disk
  const up = S.state.updates || {};
  if (up.count > 0) toast(`새 이미지 ${up.count}건 — 위쪽 「↑ 업데이트」에서 확인하세요`, 'warn', 9000);
  const disk = S.state.disk || {};
  if (disk.level === 'critical' || disk.level === 'stop') toast(`디스크 여유 ${(disk.freePct || 0).toFixed(1)}% — 로그 탭에서 정리하세요`, 'err', 12000);
}

function renderTopbar() {
  const st = S.state;
  const m = st.me || {};
  const chip = $('#me-chip');
  if (m.name) {
    chip.hidden = false;
    const readOnly = !(m.perms || []).length;
    chip.replaceChildren(...[icon('user'), h('span', null, m.display || m.name), h('small', null, m.roleName || m.role || ''),
      readOnly ? h('span', { class: 'badge warn', title: '이 계정은 보기만 할 수 있습니다 — 바꾸는 버튼은 꺼져 있습니다' }, '보기 전용') : null].filter(Boolean));
    chip.title = `${m.name} · ${m.roleName || m.role}${m.totp ? ' · 2단계 인증 켜짐' : ' · 2단계 인증 꺼짐'} — 내 계정`;
    chip.classList.toggle('warn', false);
    chip.onclick = () => gotoTab('gilmok', 'me');
  }
  const area = $('#pending-area');
  area.replaceChildren();
  const btn = $('#apply-btn');
  if (st.dirty) {
    const pend = st.pending || [];
    const n = pend.length;
    // a button so keyboard users reach it too; the list shows on hover / focus, a click opens the apply dialog
    const pill = h('button', { type: 'button', class: 'pending-pill' }, n ? `적용 대기 변경 ${n}건` : '적용 대기 변경 있음');
    pill.addEventListener('click', openApply);
    area.append(hoverTip(pill, () => h('div', { class: 'tip-body' },
      h('b', null, n ? `적용을 기다리는 변경 ${n}건` : '적용을 기다리는 변경이 있습니다'),
      n ? h('ul', { class: 'tip-list' }, pend.map((x) => h('li', null, x))) : null,
      h('p', { class: 'tip-foot' }, '눌러서 미리보기 → 적용'))));
    btn.className = 'btn primary';
    btn.textContent = '적용…';
  } else {
    const t = fmtTime(st.lastApplied);
    area.append(h('span', { class: 'synced' }, t ? `모든 변경 적용됨 · 마지막 적용 ${t}` : '모든 변경 적용됨'));
    btn.className = 'btn';
    btn.textContent = '미리보기/적용…';
  }
  btn.title = can('apply') ? '' : '보기 전용 — 「적용·외부 반영」 권한이 있어야 적용할 수 있습니다 (미리보기는 가능)';
  const disk = st.disk || {};
  if (disk.level && disk.level !== 'ok') {
    const txt = { warn: '디스크 여유 부족', critical: '디스크 여유 매우 부족', stop: '디스크 위험 — 요청 로그 중단' }[disk.level];
    const b = h('button', { type: 'button', class: `top-pill ${disk.level}`, title: `여유 ${(disk.freePct || 0).toFixed(1)}% — 로그 탭에서 정리하세요` }, `${disk.level === 'warn' ? '!' : '✗'} `, txt, ` ${(disk.freePct || 0).toFixed(0)}%`); // separate text nodes: txt is translated on its own (i18n.js)
    b.addEventListener('click', () => gotoTab('logs'));
    area.append(b);
  }
  const up = st.updates || {};
  if (up.count > 0) {
    const b = h('button', { type: 'button', class: 'top-pill update' }, `↑ 업데이트 ${up.count}건`);
    b.addEventListener('click', openUpdates);
    const avail = (up.items || []).filter((it) => it.available);
    area.append(hoverTip(b, () => h('div', { class: 'tip-body' },
      h('b', null, `새 이미지 ${avail.length || up.count}건`),
      h('ul', { class: 'tip-list' }, avail.map((it) => h('li', null,
        h('b', null, (UPD_TARGET[it.target] || [it.target])[0]), ` · ${it.container}`,
        h('div', { class: 'tip-sub mono' }, `${it.built ? '베이스 ' : ''}${it.image}${it.local ? ` · 현재 ${it.local}` : ''}${it.remote ? ` → ${it.remote}` : ''}`)))),
      h('p', { class: 'tip-foot' }, '눌러서 자세히 보기'))));
  }
}

/**
 * hoverTip(trigger, render) → wrapper. A small popover under the trigger on mouse hover and on
 * keyboard focus (Esc closes it); render() builds the content each time, so it is always current.
 */
function hoverTip(trigger, render) {
  const id = uid('tip');
  const tip = h('div', { class: 'hover-tip', role: 'tooltip', id, hidden: true });
  const wrap = h('span', { class: 'tip-wrap' }, trigger, tip);
  trigger.setAttribute('aria-describedby', id);
  let t = 0;
  const show = () => { clearTimeout(t); tip.replaceChildren(render()); tip.hidden = false; };
  const hide = () => { clearTimeout(t); t = setTimeout(() => { tip.hidden = true; }, 120); };
  wrap.addEventListener('mouseenter', show);
  wrap.addEventListener('mouseleave', hide);
  trigger.addEventListener('focus', show);
  trigger.addEventListener('blur', hide);
  trigger.addEventListener('keydown', (e) => { if (e.key === 'Escape' && !tip.hidden) { e.stopPropagation(); tip.hidden = true; } });
  return wrap;
}

const UPD_TARGET = { caddy: ['Caddy', 'caddy'], authelia: ['Authelia', 'authelia'], crowdsec: ['CrowdSec', null] };

/** Update overview: what can be updated, with a link to the in-app update step. */
async function openUpdates() {
  const body = h('div', { class: 'stack' });
  const close = h('button', { type: 'button', class: 'btn primary' }, '닫기');
  const check = h('button', { type: 'button', class: 'btn' }, icon('refresh'), '지금 확인');
  const dlg = openDialog({ title: '이미지 업데이트', body, footer: [check, h('span', { class: 'spacer' }), close], size: 'wide' });
  close.addEventListener('click', () => dlg.close());
  const draw = (u) => {
    const items = u.items || [];
    body.replaceChildren(
      h('p', { class: 'muted small' }, u.checked && !u.checked.startsWith('0001') ? `마지막 확인 ${fmtTime(u.checked)} · 레지스트리의 최신 이미지와 비교 (12시간마다 자동)` : '아직 확인하지 않았습니다'),
      items.length ? h('ul', { class: 'checks' }, items.map((it) => {
        const [label, tab] = UPD_TARGET[it.target] || [it.target, null];
        const go = tab && it.available ? h('button', { type: 'button', class: 'btn sm primary' }, '업데이트하러 가기') : null;
        if (go) go.addEventListener('click', () => { dlg.close(); gotoTab(tab, 'update'); });
        const st = it.err ? 'warn' : it.available ? 'warn' : 'ok';
        return h('li', { class: `chk ${st}` },
          h('span', { class: 'chk-mark', 'aria-hidden': 'true' }, it.err ? '?' : it.available ? '↑' : '✓'),
          h('div', { class: 'chk-text' },
            h('b', null, `${label} · ${it.container} `, it.available ? h('span', { class: 'badge warn' }, '새 버전 있음') : it.err ? h('span', { class: 'badge muted' }, '확인 불가') : h('span', { class: 'badge ok' }, '최신')),
            h('span', { class: 'chk-detail mono' }, `${it.built ? '베이스 ' : ''}${it.image}${it.local ? ` · 현재 ${it.local}` : ''}${it.remote ? ` · 최신 ${it.remote}` : ''}`),
            it.err ? h('span', { class: 'chk-detail' }, it.err) : null,
            !tab && it.available ? h('span', { class: 'chk-detail' }, 'CrowdSec은 앱 안에서 업데이트하지 않습니다 — CrowdSec compose 폴더에서 docker compose pull 후 up -d (길목 배포 스크립트를 쓴다면 다시 실행)') : null),
          go);
      })) : h('p', { class: 'muted' }, '확인할 컨테이너가 없습니다. 「지금 확인」을 눌러 보세요.'));
  };
  draw((S.state && S.state.updates) || {});
  check.addEventListener('click', () => busy(check, async () => {
    try { draw(await api('POST', '/api/updates/check')); await refreshState(); } catch (ex) { toast(ex.message, 'err'); }
  }));
}

function selectTab(name, focus = true) {
  const c = COMPONENTS.find((x) => x.tab === name);
  if (c && S.state && !use(c.key)) name = 'gilmok'; // tab of a component that is not used here
  S.tab = name;
  if (location.hash.slice(1) !== name) history.replaceState(null, '', `#${name}`);
  for (const t of document.querySelectorAll('#tabs [role=tab]')) {
    const on = t.dataset.tab === name;
    t.setAttribute('aria-selected', on ? 'true' : 'false');
    t.tabIndex = on ? 0 : -1;
    if (on && focus) t.focus();
  }
  const panel = $('#panel');
  panel.setAttribute('aria-labelledby', `tab-${name}`);
  renderPanel();
}

function renderPanel() {
  const panel = $('#panel');
  panel.replaceChildren();
  S.usersRedraw = null;
  const r = { dashboard: renderDashboard, services: renderServices, caddy: renderCaddy, authelia: renderAuthelia, cloudflare: renderCloudflare, crowdsec: renderCrowdSec, logs: renderLogs, gilmok: renderGilmok }[S.tab];
  r(panel);
}

/**
 * First visit of a new install: choose the UI language before anything else (bilingual, never
 * translated). The choice becomes the install's language (Settings.lang) for every user.
 */
function showLangChooser() {
  $('#app').hidden = true;
  $('#auth').hidden = false;
  $('#auth-form').hidden = true;
  const pick = async (v, btn) => {
    try {
      await busy(btn, () => api('POST', '/api/auth/lang', { lang: v }));
    } catch { /* already chosen elsewhere: the reload below follows the server */ }
    if (!gmI18n.sync(v)) location.reload();
  };
  const opt = (v, name, hint) => {
    const b = h('button', { type: 'button', class: 'lang-card', lang: v }, h('b', null, name), h('small', null, hint));
    b.addEventListener('click', () => pick(v, b));
    return b;
  };
  const card = h('div', { class: 'glass auth-card lang-choose', id: 'lang-choose', translate: 'no', role: 'group', 'aria-labelledby': 'lang-choose-h' },
    h('div', { class: 'brand brand-lg' }, h('span', { class: 'logo', 'aria-hidden': 'true' }), h('span', null, '길목'), ' ', h('span', { class: 'brand-en' }, 'Gilmok')),
    h('h1', { id: 'lang-choose-h' }, '언어를 선택하세요 · Choose your language'),
    h('div', { class: 'lang-cards' },
      opt('ko', '한국어', '이 설치의 모든 화면을 한국어로'),
      opt('en', 'English', 'Show every screen of this install in English')),
    h('p', { class: 'muted small' }, '나중에 설정 탭에서 바꿀 수 있습니다 · You can change it later in the Settings tab'));
  const old = $('#lang-choose');
  if (old) old.replaceWith(card); else $('#auth').append(card);
  card.querySelector('.lang-card').focus();
}

function initShell() {
  // theme (theme.js): picker in the top bar; JS-painted parts (map, charts) redraw on change
  // three icon buttons, one click each (radiogroup: arrow keys move, roving tabindex)
  const tp = document.getElementById('theme-pick');
  if (tp && window.gmTheme) {
    const opts = [['system', 'monitor', '시스템 설정 따르기'], ['dark', 'moon', '다크'], ['light', 'sun', '화이트']];
    const btns = opts.map(([v, ic, label]) => {
      const b = h('button', { type: 'button', role: 'radio', class: 'theme-btn', 'aria-label': `테마: ${label}`, title: `테마: ${label}` }, icon(ic));
      b.dataset.theme = v;
      b.addEventListener('click', () => gmTheme.set(v));
      return b;
    });
    const paint = () => {
      const cur = gmTheme.get();
      for (const b of btns) {
        const on = b.dataset.theme === cur;
        b.setAttribute('aria-checked', on ? 'true' : 'false');
        b.tabIndex = on ? 0 : -1;
      }
    };
    tp.addEventListener('keydown', (e) => {
      const i = btns.findIndex((b) => b.dataset.theme === gmTheme.get());
      const d = e.key === 'ArrowRight' || e.key === 'ArrowDown' ? 1 : e.key === 'ArrowLeft' || e.key === 'ArrowUp' ? -1 : 0;
      if (!d) return;
      e.preventDefault();
      const n = btns[(i + d + btns.length) % btns.length];
      gmTheme.set(n.dataset.theme);
      n.focus();
    });
    tp.replaceChildren(...btns);
    paint();
    document.addEventListener('gm:theme', () => {
      paint();
      if (S.state && document.getElementById('app') && !document.getElementById('app').hidden) renderPanel();
    });
  }
  const tabs = [...document.querySelectorAll('#tabs [role=tab]')];
  for (const t of tabs) {
    t.addEventListener('click', () => selectTab(t.dataset.tab, false));
    t.addEventListener('keydown', (e) => {
      const vis = tabs.filter((x) => !x.hidden);
      const i = vis.indexOf(t);
      let j = -1;
      if (e.key === 'ArrowRight') j = (i + 1) % vis.length;
      else if (e.key === 'ArrowLeft') j = (i - 1 + vis.length) % vis.length;
      else if (e.key === 'Home') j = 0;
      else if (e.key === 'End') j = vis.length - 1;
      if (j >= 0) { e.preventDefault(); selectTab(vis[j].dataset.tab); }
    });
  }
  window.addEventListener('hashchange', () => {
    const want = tabFromHash();
    if (TABS.includes(want) && want !== S.tab && !$('#app').hidden) selectTab(want, false);
  });
  $('#logout-btn').append(icon('logout'));
  $('#logout-btn').addEventListener('click', async () => {
    try { await api('POST', '/api/auth/logout'); } catch { /* ignore */ }
    S.state = null; S.dns = null; S.users = null; S.checks = {}; S.validated = {};
    showAuth(false);
  });
  $('#apply-btn').addEventListener('click', openApply);
}

// ======================================================================= services tab

async function loadDNS(force = false) {
  if (!S.state.cfConfigured || S.dnsLoading) return;
  if (S.dns && !force) return;
  S.dnsLoading = true;
  try {
    S.dns = (await api('GET', '/api/dns')) || [];
    S.dnsErr = '';
  } catch (e) {
    S.dnsErr = e.message;
  } finally {
    S.dnsLoading = false;
  }
}

function dnsStatus(s) {
  if (!S.dns) return null;
  if (!s.manageDns) return { t: 'DNS 수동', c: 'muted', title: '이 앱이 DNS를 관리하지 않습니다' };
  const rec = S.dns.find((r) => !r.missing && r.type === 'A' && r.name === fqdn(s.subdomain));
  if (!s.enabled) return rec ? { t: 'DNS 남음', c: 'muted', title: '적용 시 삭제됩니다' } : null;
  if (!rec) return { t: 'DNS 없음', c: 'warn', title: '적용하면 레코드를 만듭니다' };
  const st = settings();
  let want, wantProxied;
  if (s.exposure === 'tailscale') { want = st.tailscaleIp; wantProxied = false; }
  else { want = S.state.lastPublicIp; wantProxied = !!s.proxied; }
  const mismatch = rec.proxied !== wantProxied || (want && rec.content !== want);
  if (mismatch) return { t: 'DNS 다름', c: 'warn', title: `현재: ${rec.content}${rec.proxied ? ' (Proxied)' : ' (DNS only)'}` };
  return { t: 'DNS ✓', c: 'ok', title: `${rec.content}${rec.proxied ? ' (Proxied)' : ' (DNS only)'}` };
}

function cloudCell(s) {
  if (s.exposure !== 'public') return h('span', { class: 'dash', 'aria-label': '해당 없음' }, '—');
  return s.proxied
    ? h('span', { class: 'badge', title: 'Proxied — Cloudflare 프록시를 거쳐 들어옴' }, icon('cloud', 'fill cloud-orange'), 'Proxied')
    : h('span', { class: 'badge', title: 'DNS only — 공인 IP로 직접 들어옴' }, icon('cloud', 'fill cloud-gray'), 'DNS only');
}

function autheliaCell(s) {
  if (s.dnsOnly || !s.authelia || !s.authelia.enabled) return h('span', { class: 'dash', 'aria-label': '사용 안 함' }, '—');
  const a = s.authelia;
  return h('div', { class: 'chips' },
    h('span', { class: 'badge accent' }, icon('shield'), a.policy === 'one_factor' ? '1단계' : '2단계'),
    (a.groups || []).map((g) => h('span', { class: 'badge' }, g)));
}

/** Upstream health (probed by Gilmok every 60 s): 정상 / 응답 없음 / 확인 중. */
function healthOf(s) {
  if (!s.enabled || s.dnsOnly || !s.upstream) return null;
  const x = (S.health || {})[s.id];
  if (!x) return { st: 'wait', text: '확인 중', title: '아직 확인하지 않았습니다 (60초마다)' };
  return x.ok
    ? { st: 'ok', text: `정상 ${x.ms < 1 ? '<1' : Math.round(x.ms)}ms`, title: `${s.upstream} 연결 정상 · ${fmtTime(new Date(x.checked).toISOString())}` }
    : { st: 'down', text: '응답 없음', title: `${s.upstream}: ${x.err || '연결 실패'}` };
}

function healthBadge(s) {
  const x = healthOf(s);
  if (!x) return null;
  return h('span', { class: `badge hb ${x.st === 'ok' ? 'ok' : x.st === 'down' ? 'danger' : 'muted'}`, title: x.title },
    h('span', { 'aria-hidden': 'true' }, x.st === 'ok' ? '● ' : x.st === 'down' ? '✗ ' : '… '), x.text);
}

async function loadHealth() {
  try { S.health = (await api('GET', '/api/health')).services || {}; } catch { /* keep the last */ }
  return S.health;
}

function statusCell(s) {
  const kids = [];
  if (!s.enabled) kids.push(h('span', { class: 'badge muted' }, '중지'));
  else if (s.dnsOnly) kids.push(h('span', { class: 'badge' }, 'DNS 전용'));
  else kids.push(healthBadge(s) || h('span', { class: 'badge ok' }, '사용'));
  const d = dnsStatus(s);
  if (d) kids.push(h('span', { class: `badge ${d.c}`, title: d.title }, d.t));
  return h('div', { class: 'chips' }, kids);
}

function securityCell(s) {
  const mtls = use('cloudflare') && s.exposure === 'public' && s.proxied && s.mtls
    ? h('span', { class: 'badge ok', title: 'Cloudflare 인증된 원본 풀 (cf_only)' }, icon('lock'), 'mTLS') : null;
  const w = wafBadge(s);
  if (!mtls && !w) return h('span', { class: 'dash', 'aria-label': '없음' }, '—');
  return h('div', { class: 'chips' }, mtls, w);
}

function renderServices(panel) {
  const st = S.state;
  const search = h('input', { type: 'search', placeholder: '서브도메인·대상·메모 검색', 'aria-label': '서비스 검색', value: S.filter.q });
  const exp = h('select', { 'aria-label': '노출 방식 필터' },
    [['all', '전체'], ['public', '공개 (:443)'], privOn() ? ['tailscale', privName()] : null].filter(Boolean).map(([v, l]) => h('option', { value: v, selected: S.filter.exposure === v }, l)));
  const addBtn = h('button', { type: 'button', class: 'btn primary', disabled: !can('config'), title: can('config') ? '' : '서비스 추가에는 「구성 변경」 권한이 필요합니다' }, icon('plus'), '서비스 추가');
  const reloadDns = h('button', { type: 'button', class: 'btn', title: 'Cloudflare DNS 상태 다시 읽기', hidden: !st.cfConfigured }, icon('refresh'), 'DNS 상태');
  const hsum = h('span', { class: 'health-sum', 'aria-live': 'polite' });
  const paintSum = () => {
    const list = S.state.services.map(healthOf).filter(Boolean);
    const down = list.filter((x) => x.st === 'down').length;
    const ok = list.filter((x) => x.st === 'ok').length;
    hsum.replaceChildren();
    if (!list.length) return;
    append(hsum, [down ? h('span', { class: 'dpill crit' }, `✗ 응답 없음 ${down}`) : null, ok ? h('span', { class: 'dpill good' }, `✓ 정상 ${ok}`) : null,
      ok + down < list.length ? h('span', { class: 'muted small' }, `확인 중 ${list.length - ok - down}`) : null]);
  };
  const tableBox = h('div', { class: 'glass table-wrap' });
  const mapBox = h('div');
  const viewSeg = h('div', { class: 'segmented view-toggle', role: 'radiogroup', 'aria-label': '보기 방식' },
    [['list', '목록'], ['map', '구성도']].map(([v, l]) => h('label', null,
      h('input', { type: 'radio', name: 'svc-view', value: v, checked: S.view === v }), h('span', null, l))));

  const privLeft = st.services.filter((x) => x.exposure !== 'public').length;
  let privNote = null;
  if (!use('tailscale') && privLeft) {
    const goComp = h('button', { type: 'button', class: 'btn sm' }, '설정 › 구성요소');
    goComp.addEventListener('click', () => gotoTab('gilmok', 'components'));
    const onlyPriv = h('button', { type: 'button', class: 'btn sm' }, '사설 서비스만 보기');
    onlyPriv.addEventListener('click', () => { S.filter.exposure = 'tailscale'; S.view = 'list'; localStorage.setItem('gm.view', 'list'); renderPanel(); });
    privNote = callout('warn', h('b', null, `Tailscale을 쓰지 않는데 사설 전용 서비스 ${privLeft}개가 남아 있습니다.`),
      h('span', { class: 'small' }, `이 사이트들은 Caddy :${settings().tailscalePort || 8443}로만 받습니다. VPN 같은 다른 사설 경로로 들어온다면 구성도에서 사설 경로 칸을 눌러 「다른 VPN」을 고르세요. 아니라면 서비스마다 공개로 바꾸거나 Tailscale을 다시 켜세요.`),
      h('div', { class: 'row' }, onlyPriv, goComp));
  }
  append(panel, [privNote]);
  panel.append(
    h('div', { class: 'toolbar' },
      viewSeg, hsum,
      h('div', { class: 'search' }, icon('search'), search), exp,
      h('span', { class: 'grow' }),
      reloadDns, ...bulkButtons(), addBtn),
    tableBox, mapBox);

  const draw = () => {
    paintSum();
    const map = S.view === 'map';
    tableBox.hidden = map;
    mapBox.hidden = !map;
    search.parentElement.hidden = map;
    exp.hidden = map;
    if (map) { S.topoInfo = null; mapBox.replaceChildren(topologyPanel((s) => openServiceDrawer(s))); }
    else tableBox.replaceChildren(serviceTable());
  };
  const healthSig = () => JSON.stringify(Object.entries(S.health || {}).map(([k, v]) => [k, v && v.st]).sort());
  const healthTick = async () => {
    if (!hsum.isConnected) return;
    const before = healthSig();
    await loadHealth();
    if (!hsum.isConnected) return;
    paintSum();
    // redraw only when a service's state changed — keeps the map's scroll position and hovered path
    if (healthSig() !== before) {
      if (S.view === 'map') {
        const box = mapBox.querySelector('.topo');
        if (box && S.topoInfo) {
          const sc = mapBox.querySelector('.topo-scroll');
          const pos = sc ? [sc.scrollLeft, sc.scrollTop] : null;
          const hov = (mapBox.querySelector('.leaf:hover') || {}).dataset;
          mapBox.replaceChildren(topologyView((s) => openServiceDrawer(s), S.topoInfo, (f) => openEdgeWizard(S.topoInfo, f, () => draw())));
          const sc2 = mapBox.querySelector('.topo-scroll');
          if (sc2 && pos) [sc2.scrollLeft, sc2.scrollTop] = pos;
          const leaf = hov && hov.key ? mapBox.querySelector(`.leaf[data-key="${CSS.escape(hov.key)}"]`) : null;
          if (leaf) leaf.dispatchEvent(new Event('mouseenter'));
        }
      } else if (!tableBox.querySelector(':focus')) draw();
    }
    setTimeout(healthTick, 30000);
  };
  setTimeout(healthTick, 50);
  viewSeg.addEventListener('change', (e) => {
    S.view = e.target.value;
    localStorage.setItem('gm.view', S.view);
    draw();
  });
  search.addEventListener('input', () => { S.filter.q = search.value; draw(); });
  exp.addEventListener('change', () => { S.filter.exposure = exp.value; draw(); });
  addBtn.addEventListener('click', () => openServiceDrawer(null));
  reloadDns.addEventListener('click', () => busy(reloadDns, async () => {
    await loadDNS(true);
    if (S.dnsErr) toast(`DNS 조회 실패: ${S.dnsErr}`, 'err');
    if (S.tab === 'services') draw();
  }));
  draw();

  if (st.cfConfigured && !S.dns) {
    loadDNS().then(() => { if (S.tab === 'services' && tableBox.isConnected) draw(); });
  }
}

function serviceTable() {
  const st = S.state;
  if (!st.services.length) {
    const imp = h('button', { type: 'button', class: 'btn primary' }, icon('download'), '기존 설정 가져오기');
    imp.addEventListener('click', () => runImport(imp));
    const guideBtn = h('button', { type: 'button', class: 'btn' }, '설정 마법사');
    guideBtn.addEventListener('click', openSetupChooser);
    return h('div', { class: 'empty' },
      h('p', null, '등록된 서비스가 없습니다.'),
      h('p', { class: 'small' }, `지금 쓰는 ${importSources()}을(를) 읽어 서비스 목록을 만듭니다.`),
      h('div', { class: 'row' }, imp, guideBtn));
  }
  const q = S.filter.q.trim().toLowerCase();
  const list = st.services.filter((s) =>
    (S.filter.exposure === 'all' || s.exposure === S.filter.exposure) &&
    (!q || [s.subdomain, s.upstream, s.notes, fqdn(s.subdomain)].some((x) => String(x || '').toLowerCase().includes(q))));
  if (!list.length) return h('div', { class: 'empty' }, '검색 결과가 없습니다.');

  // multi-select (delete) — the selection survives redraws while its services exist
  const canEdit = can('config');
  const picked = (S.svcPicked = S.svcPicked || new Set());
  for (const id of [...picked]) if (!st.services.some((x) => x.id === id)) picked.delete(id);
  const selInfo = h('b', { class: 'bulk-count' });
  const delSel = h('button', { type: 'button', class: 'btn danger sm' }, '선택 삭제');
  const clearSel = h('button', { type: 'button', class: 'btn ghost sm' }, '선택 해제');
  const selBar = h('div', { class: 'bulk-bar' }, h('div', { class: 'bulk-head' }, selInfo, h('span', { class: 'grow' }), clearSel, delSel));
  const allCb = h('input', { type: 'checkbox', 'aria-label': '보이는 서비스 모두 선택', disabled: !canEdit });
  const boxes = [];
  const updSel = () => {
    const n = picked.size;
    selInfo.textContent = n ? `${n}개 선택` : '여러 개를 지우려면 왼쪽에서 고르세요';
    selBar.classList.toggle('active', n > 0);
    delSel.disabled = clearSel.disabled = !n || !canEdit;
    allCb.checked = list.length > 0 && list.every((s) => picked.has(s.id));
    allCb.indeterminate = n > 0 && !allCb.checked;
  };
  allCb.addEventListener('change', () => { for (const s of list) { if (allCb.checked) picked.add(s.id); else picked.delete(s.id); } for (const [cb, id] of boxes) { cb.checked = picked.has(id); cb.closest('tr').classList.toggle('picked', cb.checked); } updSel(); });
  clearSel.addEventListener('click', () => { picked.clear(); for (const [cb] of boxes) { cb.checked = false; cb.closest('tr').classList.remove('picked'); } updSel(); });
  delSel.addEventListener('click', async () => {
    const targets = st.services.filter((s) => picked.has(s.id));
    const ok = await confirmDialog({ title: `서비스 ${targets.length}개 삭제`, danger: true, okText: `${targets.length}개 삭제`,
      message: `${targets.map((s) => fqdn(s.subdomain)).join('\n')}\n\n적용하면 Caddy 사이트${use('cloudflare') ? '와 길목이 관리하는 DNS 레코드' : ''}가 함께 삭제됩니다.` });
    if (!ok) return;
    await busy(delSel, () => deleteServices(targets));
    picked.clear();
    await refreshState();
    renderPanel();
  });

  const tbody = h('tbody');
  let group = '';
  for (const s of list) {
    const g = s.exposure === 'public' ? '공개 서비스 · :443' : `${privName()} · :${settings().tailscalePort || 8443}`;
    if (g !== group) {
      group = g;
      const count = list.filter((x) => x.exposure === s.exposure).length;
      tbody.append(h('tr', { class: 'group-row' }, h('td', { colspan: '9' }, `${g} (${count})`)));
    }
    const open = h('button', { type: 'button', class: 'link-btn' }, h('b', null, s.subdomain === '@' ? '@ (루트)' : s.subdomain));
    open.addEventListener('click', (e) => { e.stopPropagation(); openServiceDrawer(s); });
    const cb = h('input', { type: 'checkbox', checked: picked.has(s.id), disabled: !canEdit, 'aria-label': `${fqdn(s.subdomain)} 선택` });
    cb.addEventListener('click', (e) => e.stopPropagation());
    cb.addEventListener('change', () => { if (cb.checked) picked.add(s.id); else picked.delete(s.id); cb.closest('tr').classList.toggle('picked', cb.checked); updSel(); });
    boxes.push([cb, s.id]);
    const tr = h('tr', { class: `clickable ${s.enabled ? '' : 'disabled'} ${picked.has(s.id) ? 'picked' : ''}` },
      h('td', { class: 'sel-cell' }, cb),
      h('td', null, h('div', { class: 'cell-main' }, open, s.notes ? h('span', { class: 'cell-sub', title: s.notes }, s.notes) : null)),
      !use('caddy') ? null : h('td', { class: 'mono' }, s.dnsOnly ? h('span', { class: 'dash' }, 'DNS만') : (s.upstream || h('span', { class: 'dash', title: '추가 지시어로 처리' }, '(사용자 지시어)'))),
      h('td', null, s.exposure === 'public' ? h('span', { class: 'badge public' }, '공개') : h('span', { class: 'badge ts' }, use('tailscale') ? 'Tailscale' : '사설')),
      use('cloudflare') ? h('td', null, cloudCell(s)) : null,
      use('caddy') || use('cloudflare') ? h('td', null, securityCell(s)) : null,
      use('authelia') ? h('td', null, autheliaCell(s)) : null,
      h('td', null, statusCell(s)));
    tr.addEventListener('click', () => openServiceDrawer(s));
    tbody.append(tr);
  }
  const note = S.dnsErr ? h('p', { class: 'hint', style: { padding: '8px 12px' } }, `DNS 상태를 불러오지 못했습니다: ${S.dnsErr}`) : null;
  updSel();
  return h('div', null,
    canEdit ? selBar : null,
    h('table', null,
      h('caption', { class: 'sr-only' }, '서비스 목록'),
      h('thead', null, h('tr', null, h('th', { scope: 'col', class: 'sel-cell' }, allCb), ['서브도메인', use('caddy') ? '대상' : null, '노출', use('cloudflare') ? '구름' : null, use('caddy') || use('cloudflare') ? '보안' : null, use('authelia') ? 'Authelia' : null, '상태 (연결)'].filter(Boolean).map((t) => h('th', { scope: 'col' }, t)))),
      tbody),
    note);
}

function knownGroups() {
  const set = new Set((S.state && S.state.autheliaGroups || []).map((g) => g.name));
  for (const s of (S.state && S.state.services) || []) for (const g of (s.authelia && s.authelia.groups) || []) set.add(g);
  for (const u of S.users || []) for (const g of u.groups || []) set.add(g);
  return [...set].sort();
}

function groupPicker(input) {
  const groups = knownGroups();
  if (!groups.length) return null;
  const wrap = h('div', { class: 'chips', 'aria-label': '알려진 그룹' });
  for (const g of groups) {
    const b = h('button', { type: 'button', class: 'badge chip-btn', title: `${g} 추가` }, `+ ${g}`);
    b.addEventListener('click', () => {
      const cur = splitList(input.value);
      if (!cur.includes(g)) cur.push(g);
      input.value = cur.join(', ');
      input.dispatchEvent(new Event('input', { bubbles: true }));
    });
    wrap.append(b);
  }
  return wrap;
}

function openServiceDrawer(svc, preset) {
  const isNew = !svc;
  const s = svc ? structuredClone(svc) : {
    subdomain: '', upstream: '', exposure: use('tailscale') ? 'tailscale' : 'public', proxied: false, mtls: false,
    authelia: { enabled: false, policy: 'two_factor', groups: [] },
    extra: '', notes: '', enabled: true, manageDns: true, dnsOnly: false,
    ...(preset || {}),
  };
  s.authelia = s.authelia || { enabled: false, policy: 'two_factor', groups: [] };
  const st = settings();
  let dirty = false;

  const sub = h('input', { type: 'text', value: s.subdomain, required: true, autocomplete: 'off', spellcheck: 'false', placeholder: 'immich', autofocus: isNew });
  const subField = field('서브도메인', sub, '루트 도메인은 @');
  // wrap the input with the domain suffix while keeping label/aria-describedby on the input itself
  const subGroup = h('div', { class: 'input-group' });
  sub.replaceWith(subGroup);
  subGroup.append(sub, h('span', { class: `addon ${st.domain ? '' : 'warn-text'}`, 'aria-hidden': 'true', title: st.domain ? '' : '설정 탭 › 도메인에서 먼저 정하세요' }, st.domain ? `.${st.domain}` : '.(도메인 미설정)'));

  const up = h('input', { type: 'text', value: s.upstream, autocomplete: 'off', spellcheck: 'false', placeholder: 'immich_server:2283', class: 'mono' });
  const upField = field('대상 (upstream)', up, settings().caddyMode && settings().caddyMode !== 'docker'
    ? 'Caddy가 접속할 주소 — 예: localhost:8080. 「컨테이너에서 선택」으로 게시된 포트를 고를 수 있습니다'
    : 'Caddy가 접속할 주소 — Caddy와 같은 Docker 네트워크의 컨테이너 이름:포트. 「컨테이너에서 선택」으로 고를 수 있습니다');
  if (use('caddy') && typeof openUpstreamPicker === 'function') {
    const pickUp = h('button', { type: 'button', class: 'btn', title: 'Docker 컨테이너와 포트를 골라 대상에 넣습니다' }, icon('search'), '컨테이너에서 선택');
    const upGroup = h('div', { class: 'input-group btn-addon' });
    up.replaceWith(upGroup);
    upGroup.append(up, pickUp);
    pickUp.addEventListener('click', () => openUpstreamPicker({
      current: up.value.trim(),
      onPick: (v, c) => {
        up.value = v;
        if (!sub.value.trim() && c.suggested) sub.value = c.suggested;
        dirty = true;
        up.focus();
        if (v.endsWith(':')) up.setSelectionRange(v.length, v.length);
      },
    }));
  }

  const exposure = segmented(uid('exp'), '노출 방식', [
    { value: 'public', label: '공개 (:443)' },
    { value: 'tailscale', label: `${privName()} (:${st.tailscalePort || 8443})` },
  ], s.exposure);
  if (!use('tailscale') && s.exposure === 'public') exposure.hidden = true; // only one choice: public
  const proxied = switchCtl('Proxied (Cloudflare 프록시)', s.proxied, '끄면 DNS only — 접속자가 공인 IP로 직접 들어옵니다');
  const mtls = switchCtl('mTLS (cf_only)', s.mtls, 'Cloudflare 인증된 원본 풀 인증서만 허용 — Proxied에서만 사용');
  const publicBox = h('div', { class: 'section-box' }, h('h3', null, icon('cloud', 'fill cloud-orange'), 'Cloudflare'), proxied, mtls);
  const tsNote = callout('', use('cloudflare')
    ? h('span', null, 'DNS는 ', h('code', null, st.tailscaleIp || '(설정에 Tailscale IP 없음)'), ' 로 지정되고, Caddy는 ', h('code', null, `:${st.tailscalePort || 8443}`), ' 에서 받습니다.')
    : h('span', null, 'Caddy는 ', h('code', null, `:${st.tailscalePort || 8443}`), ' 에서 받습니다 (Tailscale 등 사설 경로로만 들어오는 사이트).'));

  const authOn = switchCtl('Authelia 로그인 요구 (forward_auth)', s.authelia.enabled);
  const policy = segmented(uid('pol'), '정책', [
    { value: 'one_factor', label: '1단계 (비밀번호)' },
    { value: 'two_factor', label: '2단계 (TOTP/WebAuthn)' },
  ], s.authelia.policy || 'two_factor');
  const groups = h('input', { type: 'text', value: (s.authelia.groups || []).join(', '), placeholder: 'admins', autocomplete: 'off' });
  const groupsField = field('허용 그룹', groups, '등록된 그룹에서 고르세요. 아무것도 고르지 않으면 로그인한 모든 사용자 허용');
  groupsField.append(typeof groupChips === 'function' ? groupChips(groups) : (groupPicker(groups) || ''));
  const authDetail = h('div', { class: 'stack' }, policy, groupsField);
  const authBox = h('div', { class: 'section-box' }, h('h3', null, icon('shield'), 'Authelia'), authOn, authDetail);

  const extra = h('textarea', { class: 'code', rows: '5', spellcheck: 'false', placeholder: 'header_up X-Real-IP {remote_host}' }, s.extra || '');
  extra.value = s.extra || '';
  const extraField = field('추가 Caddy 지시어', extra, 'reverse_proxy 앞에 그대로 들어갑니다. 중괄호 { } 짝을 맞추세요.');
  const notes = h('textarea', { rows: '2' });
  notes.value = s.notes || '';
  const notesField = field('메모', notes, use('caddy') ? 'Caddyfile에 주석으로 기록됩니다' : '길목에만 저장됩니다');

  const guardSw = switchCtl('기본 차단 (봇·공격 경로)', isNew ? true : !!s.guard, '스캐너·AI 크롤러·/.env 같은 탐색 요청을 Caddy에서 바로 막습니다. 항목은 Caddy 탭 › 기본 차단에서 정합니다.');
  const waf = segmented(uid('waf'), 'Caddy WAF (Coraza + OWASP CRS)', WAF_MODES, s.waf || '');
  const wafTune = (s.wafParanoia || (s.wafExclude || []).length) ? h('p', { class: 'hint' }, `세부 설정: ${s.wafParanoia ? `민감도 ${s.wafParanoia}` : '공통 민감도'}${(s.wafExclude || []).length ? ` · 규칙 예외 ${s.wafExclude.length}개` : ''} (Caddy 탭 › 서비스별 보호)`) : null;
  const wafBox = h('div', { class: 'section-box' }, h('h3', null, icon('shield'), '보호'), guardSw, waf, wafTune,
    h('p', { class: 'hint' }, 'WAF는 요청 내용으로 공격을 막습니다. 처음엔 「탐지만」으로 두고 Caddy 탭 › WAF 이벤트에서 오탐을 확인하세요.'));

  const enabled = switchCtl('사용', s.enabled, '끄면 Caddyfile에서 빠지고, 앱이 만든 DNS 레코드는 삭제됩니다');
  const manageDns = switchCtl('DNS 자동 관리', s.manageDns, 'Cloudflare A 레코드를 생성·수정·삭제합니다');
  const dnsOnly = switchCtl('DNS 전용 (Caddy 사이트 없음)', s.dnsOnly, '예: sftpgo — DNS 레코드만 관리');
  const opts = h('div', { class: 'section-box' }, h('h3', null, '동작'), enabled);
  const noCaddy = callout('', 'Caddy를 쓰지 않는 구성이라 이 서비스는 DNS 레코드와 연결 상태만 다룹니다.');
  // rarely changed: folded away, opened when one of them is already in use
  const advOpen = !!(s.extra || '').trim() || s.dnsOnly || (use('cloudflare') && s.manageDns === false);
  const advanced = h('details', { class: 'svc-more', open: advOpen },
    h('summary', null, '고급 설정', h('span', { class: 'hint' }, ' — 추가 Caddy 지시어 · DNS 자동 관리 · DNS 전용')),
    h('div', { class: 'stack' }, extraField, manageDns, dnsOnly));

  const errEl = h('p', { class: 'form-error', role: 'alert', hidden: true });
  const form = h('form', { class: 'stack', novalidate: true },
    errEl, subField, noCaddy, upField, exposure, publicBox, tsNote, authBox, wafBox, opts, notesField, advanced);

  const sync = () => {
    const isPublic = exposure.get() === 'public';
    const only = dnsOnly.input.checked;
    publicBox.hidden = !isPublic || !use('cloudflare');
    tsNote.hidden = isPublic;
    mtls.input.disabled = !proxied.input.checked;
    if (!proxied.input.checked) mtls.input.checked = false;
    upField.hidden = only || !use('caddy');
    authBox.hidden = only || !use('authelia');
    wafBox.hidden = only || !use('caddy');
    extraField.hidden = only || !use('caddy');
    manageDns.hidden = !use('cloudflare');
    dnsOnly.hidden = !use('caddy') || !use('cloudflare');
    noCaddy.hidden = use('caddy');
    authDetail.hidden = !authOn.input.checked;
    advanced.hidden = extraField.hidden && manageDns.hidden && dnsOnly.hidden;
  };
  exposure.onChange(sync);
  form.addEventListener('change', sync);
  form.addEventListener('input', () => { dirty = true; });
  form.addEventListener('change', () => { dirty = true; });
  sync();

  const save = h('button', { type: 'submit', class: 'btn primary' }, '저장');
  const cancel = h('button', { type: 'button', class: 'btn ghost' }, '취소');
  const del = isNew ? null : h('button', { type: 'button', class: 'btn danger' }, '삭제');
  save.setAttribute('form', form.id = uid('form'));

  const d = openDialog({
    title: isNew ? '서비스 추가' : fqdn(s.subdomain),
    variant: 'drawer',
    body: form,
    footer: [del, h('span', { class: 'spacer' }), cancel, save],
    beforeClose: () => (dirty ? confirmDialog({ title: '변경 내용 버리기', message: '저장하지 않은 변경 내용이 있습니다. 닫을까요?', okText: '버리고 닫기', danger: true }) : true),
  });
  cancel.addEventListener('click', d.tryClose);

  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    errEl.hidden = true;
    sub.removeAttribute('aria-invalid');
    const body = {
      ...s,
      subdomain: sub.value.trim().toLowerCase(),
      upstream: up.value.trim(),
      exposure: exposure.get(),
      proxied: use('cloudflare') ? proxied.input.checked : s.proxied,
      mtls: use('cloudflare') ? mtls.input.checked : s.mtls,
      authelia: use('authelia') ? { enabled: authOn.input.checked, policy: policy.get(), groups: splitList(groups.value) } : s.authelia,
      waf: use('caddy') ? waf.get() || '' : s.waf,
      guard: use('caddy') ? guardSw.input.checked : !!s.guard,
      extra: extra.value.replace(/\s+$/, ''),
      notes: notes.value.trim(),
      enabled: enabled.input.checked,
      manageDns: use('cloudflare') ? manageDns.input.checked : s.manageDns,
      dnsOnly: use('caddy') && use('cloudflare') ? dnsOnly.input.checked : s.dnsOnly,
    };
    if (!body.subdomain) {
      sub.setAttribute('aria-invalid', 'true');
      errEl.textContent = '서브도메인을 입력하세요';
      errEl.hidden = false;
      sub.focus();
      return;
    }
    try {
      await busy(save, () => (isNew ? api('POST', '/api/services', body) : api('PUT', `/api/services/${encodeURIComponent(s.id)}`, body)));
      dirty = false;
      d.close();
      toast(`${fqdn(body.subdomain)} 저장됨 — 적용 버튼으로 반영하세요`);
      await refreshState();
      if (S.tab === 'services' || S.tab === 'caddy') renderPanel();
    } catch (ex) {
      errEl.textContent = ex.message;
      errEl.hidden = false;
      errEl.scrollIntoView({ block: 'nearest' });
    }
  });

  if (del) {
    del.addEventListener('click', async () => {
      const ok = await confirmDialog({
        title: '서비스 삭제',
        message: `${fqdn(s.subdomain)} 를 삭제할까요?\n적용하면 Caddy 사이트와 (앱이 관리하는) DNS 레코드가 함께 삭제됩니다.`,
        okText: '삭제', danger: true,
      });
      if (!ok) return;
      try {
        await busy(del, () => api('DELETE', `/api/services/${encodeURIComponent(s.id)}`));
        dirty = false;
        d.close();
        toast(`${fqdn(s.subdomain)} 삭제됨 — 적용 대기`);
        await refreshState();
        if (S.tab === 'services' || S.tab === 'caddy') renderPanel();
      } catch (ex) {
        toast(ex.message, 'err');
      }
    });
  }
}

async function runImport(btn) {
  const ok = await confirmDialog({
    title: '기존 설정 가져오기',
    message: `지금 쓰는 ${importSources()}을(를) 읽어서\n` + '앱의 서비스 목록과 Caddy 기본 골격을 새로 만듭니다.\n\n현재 앱에 저장된 서비스 목록은 모두 대체됩니다. (실제 파일은 바뀌지 않습니다)',
    okText: '가져오기', danger: !!(S.state.services || []).length,
  });
  if (!ok) return;
  try {
    const res = await busy(btn, () => api('POST', '/api/import'));
    S.dns = null;
    await refreshState();
    renderPanel();
    const warns = res.warnings || [];
    const close = h('button', { type: 'button', class: 'btn primary', autofocus: true }, '확인');
    const d = openDialog({
      title: '가져오기 완료',
      body: h('div', { class: 'stack' },
        callout('ok', h('b', null, `서비스 ${res.imported}개를 가져왔습니다.`), h('span', null, '적용 전에 「미리보기」로 차이를 확인하세요. 생성된 파일은 주석·구역 제목이 원본과 다를 수 있습니다.')),
        warns.length ? callout('warn', h('b', null, `확인할 점 ${warns.length}건`), h('ul', null, warns.map((w) => h('li', null, w)))) : null),
      footer: [close],
    });
    close.addEventListener('click', () => d.close());
  } catch (ex) {
    toast(`가져오기 실패: ${ex.message}`, 'err', 8000);
  }
}

// ======================================================================= apply (plan preview → apply)

const DNS_ACTIONS = {
  create: ['생성', 'ok'], update: ['수정', 'warn'], delete: ['삭제', 'danger'], ok: ['그대로', 'muted'], skip: ['건너뜀', 'warn'],
};

function dnsPlanTable(rows) {
  return h('table', null,
    h('thead', null, h('tr', null, ['레코드', '유형', '동작', '현재', '변경 후', '비고'].map((t) => h('th', { scope: 'col' }, t)))),
    h('tbody', null, rows.map((r) => {
      const [label, cls] = DNS_ACTIONS[r.action] || [r.action, ''];
      return h('tr', null,
        h('td', { class: 'mono' }, r.name),
        h('td', null, h('span', { class: 'badge' }, r.type || 'A')),
        h('td', null, h('span', { class: `badge ${cls}` }, label)),
        h('td', { class: 'mono' }, r.current || '—'),
        h('td', { class: 'mono' }, r.desired || '—'),
        h('td', { class: 'small muted' }, r.reason || ''));
    })));
}

function planSection(title, badge, content, open) {
  return h('details', { class: 'plan-sec', open: !!open },
    h('summary', null, h('span', { class: 'grow' }, title), badge),
    h('div', { class: 'sec-body' }, content));
}

async function openApply() {
  const body = h('div', { class: 'stack' }, spinnerRow('변경 사항을 계산하는 중… (Cloudflare 조회 포함, 최대 수십 초)'));
  const applyBtn = h('button', { type: 'button', class: 'btn primary', disabled: true }, '적용');
  const closeBtn = h('button', { type: 'button', class: 'btn ghost' }, '닫기');
  const d = openDialog({ title: '변경 사항 적용', body, footer: [closeBtn, applyBtn], size: 'wide' });
  closeBtn.addEventListener('click', d.tryClose);

  let plan;
  try {
    plan = await api('GET', '/api/plan');
  } catch (ex) {
    body.replaceChildren(errorBox(ex.message));
    return;
  }
  if (!d.overlay.isConnected) return;

  const caddyOps = diffLines(plan.caddyCurrent, plan.caddyNext);
  const authOps = diffLines(plan.autheliaCurrent, plan.autheliaNext);
  const cs = diffStat(caddyOps), as = diffStat(authOps);
  const dns = plan.dns || [];
  const dnsChanges = dns.filter((x) => x.action !== 'ok');
  const dnsSame = dns.filter((x) => x.action === 'ok');
  const pending = S.state.pending || [];
  const warnings = plan.warnings || [];

  // a function: the same badge appears in two places and a DOM node can only live in one
  const dnsBadge = () => (plan.dnsError
    ? h('span', { class: 'badge warn' }, '건너뜀')
    : dnsChanges.length ? h('span', { class: 'badge warn' }, `${dnsChanges.length}건 변경`) : h('span', { class: 'badge muted' }, '변경 없음'));

  const dnsContent = h('div', { class: 'stack' },
    plan.dnsError ? callout('warn', plan.dnsError) : null,
    plan.publicIp ? h('p', { class: 'small muted' }, `현재 공인 IP: ${plan.publicIp}${settings().ddnsIpv6 ? ` · IPv6: ${plan.publicIp6 || '(확인 실패)'}` : ''}${privOn() ? ` · ${use('tailscale') ? 'Tailscale' : '사설'} IP: ${settings().tailscaleIp || '(없음)'}` : ''}`) : null,
    dnsChanges.length ? h('div', { class: 'table-wrap' }, dnsPlanTable(dnsChanges)) : (!plan.dnsError ? h('p', { class: 'muted' }, 'Cloudflare DNS 변경 없음') : null),
    dnsSame.length ? h('details', null, h('summary', { class: 'small muted', style: { cursor: 'pointer' } }, `변경 없는 레코드 ${dnsSame.length}개 보기`), h('div', { class: 'table-wrap' }, dnsPlanTable(dnsSame))) : null);

  const nothing = !cs.changed && !as.changed && !dnsChanges.length;
  const authRestart = as.changed;
  const ipChanges = dns.filter((x) => x.ipChange);
  const allowIp = switchCtl('공인 IP 변경 반영', false,
    `체크하면 위 ${ipChanges.length}개 레코드의 주소를 ${plan.publicIp} 로 바꿉니다. 길목이 웹 서버와 같은 네트워크에서 실행 중일 때만 체크하세요. 체크하지 않으면 주소는 그대로 두고 나머지만 적용합니다.`);
  const ipBox = ipChanges.length ? callout('danger', h('b', null, `공개 레코드 ${ipChanges.length}개의 주소가 바뀝니다`),
    h('span', { class: 'small' }, `지금 레코드: ${[...new Set(ipChanges.map((x) => (x.current || '').replace(/ \(.*\)$/, '')))].join(', ')} → 길목이 본 공인 IP: ${plan.publicIp}`), allowIp) : null;

  body.replaceChildren();
  append(body, [
    h('div', { class: 'plan-summary' },
      h('span', { class: 'badge' }, 'Caddyfile ', statBadge(cs)),
      h('span', { class: 'badge' }, 'access_control ', statBadge(as)),
      h('span', { class: 'badge' }, 'DNS ', dnsBadge())),
    warnings.length ? callout('warn', h('b', null, '경고'), h('ul', null, warnings.map((w) => h('li', null, w)))) : null,
    pending.length ? callout('', h('b', null, `저장된 변경 ${pending.length}건`), h('ul', null, pending.map((p) => h('li', null, p)))) : null,
    use('caddy') ? planSection('Caddyfile', statBadge(cs), cs.changed ? renderDiff(caddyOps) : h('p', { class: 'muted' }, '현재 파일과 같습니다'), cs.changed) : null,
    use('authelia') ? planSection('Authelia access_control', statBadge(as), as.changed ? renderDiff(authOps) : h('p', { class: 'muted' }, '현재 블록과 같습니다'), as.changed) : null,
    use('cloudflare') ? planSection('Cloudflare DNS', dnsBadge(), dnsContent, dnsChanges.length > 0) : null,
    ipBox,
    nothing
      ? callout('ok', '실제 파일·DNS에 바뀌는 것이 없습니다. 적용하면 「적용 대기」 표시만 정리됩니다.')
      : callout('', h('span', null, '적용 순서: 검증 → 백업 → ', authRestart ? h('b', null, 'Authelia 재시작') : 'Authelia(변경 없음)', ' → Caddy 무중단 reload → DNS. 실패하면 자동으로 이전 상태로 되돌립니다.'),
        authRestart ? h('span', { class: 'small' }, 'Authelia 재시작 동안(약 5~20초) forward_auth 사이트가 잠시 502가 될 수 있습니다.') : null),
  ]);

  applyBtn.disabled = false;
  applyBtn.textContent = nothing ? '정리' : '적용';
  applyBtn.addEventListener('click', async () => {
    d.lock(true);
    applyBtn.disabled = true;
    closeBtn.disabled = true;
    body.replaceChildren(spinnerRow(authRestart ? '적용 중… Authelia 재시작을 기다리는 중 (최대 1분)' : '적용 중…'));
    let res;
    try {
      res = await api('POST', '/api/apply', { allowIpChange: !!(ipBox && allowIp.input.checked) });
    } catch (ex) {
      res = { ok: false, error: ex.message, log: [] };
    }
    d.lock(false);
    applyBtn.remove();
    closeBtn.disabled = false;
    closeBtn.className = 'btn primary';
    body.replaceChildren(resultView(res));
    closeBtn.focus();
    toast(res.ok ? '적용 완료' : '적용 실패 — 로그를 확인하세요', res.ok ? 'ok' : 'err');
    S.dns = null;
    try { await refreshState(); renderPanel(); } catch { /* ignore */ }
  }, { once: true });
  applyBtn.focus();
}

// ======================================================================= Authelia users drawer

function genPassword() {
  const abc = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789-_.!';
  const buf = new Uint32Array(20);
  crypto.getRandomValues(buf);
  return [...buf].map((x) => abc[x % abc.length]).join('');
}

function openUserDrawer(user) {
  const isNew = !user;
  const u = user ? structuredClone(user) : { username: '', displayname: '', email: '', groups: [], disabled: false };
  let dirty = false;

  const name = h('input', { type: 'text', value: u.username, autocomplete: 'off', spellcheck: 'false', disabled: !isNew, autofocus: isNew });
  const disp = h('input', { type: 'text', value: u.displayname, autocomplete: 'off', autofocus: !isNew });
  const email = h('input', { type: 'email', value: u.email, autocomplete: 'off' });
  const groups = h('input', { type: 'text', value: (u.groups || []).join(', '), autocomplete: 'off', placeholder: 'admins' });
  const groupsField = field('그룹', groups, '등록된 그룹에서 고르세요');
  groupsField.append(typeof groupChips === 'function' ? groupChips(groups) : (groupPicker(groups) || ''));
  const pw = h('input', { type: 'password', autocomplete: 'new-password', minlength: '10' });
  const show = h('button', { type: 'button', class: 'btn sm' }, '보기');
  const gen = h('button', { type: 'button', class: 'btn sm' }, icon('key'), '생성');
  show.addEventListener('click', () => {
    pw.type = pw.type === 'password' ? 'text' : 'password';
    show.textContent = pw.type === 'password' ? '보기' : '숨기기';
  });
  gen.addEventListener('click', () => {
    pw.value = genPassword();
    pw.type = 'text';
    show.textContent = '숨기기';
    dirty = true;
    pw.focus();
    pw.select();
  });
  const pwField = field(isNew ? '비밀번호' : '새 비밀번호', pw, isNew ? '10자 이상. argon2id로 해시되어 저장됩니다.' : '바꿀 때만 입력 (10자 이상)');
  pwField.append(h('div', { class: 'row' }, show, gen));
  const disabled = switchCtl('비활성화', u.disabled, '로그인을 막습니다 (계정은 유지)');

  const errEl = h('p', { class: 'form-error', role: 'alert', hidden: true });
  const form = h('form', { class: 'stack', novalidate: true },
    errEl,
    field('아이디', name, isNew ? '영문/숫자/-_. — 나중에 바꿀 수 없습니다' : null),
    field('표시 이름', disp), field('이메일', email), groupsField, pwField, disabled,
    callout('warn', '저장하면 Authelia가 재시작됩니다 (약 5~20초 동안 forward_auth 사이트 접속 불가).'));
  form.id = uid('form');
  form.addEventListener('input', () => { dirty = true; });
  form.addEventListener('change', () => { dirty = true; });

  // Authelia users take effect at once (users_database.yml + Authelia restart) — say so on the button
  const save = h('button', { type: 'submit', class: 'btn primary', form: form.id, title: '「적용」을 기다리지 않고 바로 users_database.yml에 쓰고 Authelia를 재시작합니다' }, isNew ? '추가 · 바로 반영' : '저장 · 바로 반영');
  const cancel = h('button', { type: 'button', class: 'btn ghost' }, '취소');
  const del = isNew ? null : h('button', { type: 'button', class: 'btn danger' }, '삭제');

  const d = openDialog({
    title: isNew ? '사용자 추가' : u.username,
    variant: 'drawer', body: form,
    footer: [del, h('span', { class: 'spacer' }), cancel, save],
    beforeClose: () => (dirty ? confirmDialog({ title: '변경 내용 버리기', message: '저장하지 않은 변경 내용이 있습니다. 닫을까요?', okText: '버리고 닫기', danger: true }) : true),
  });
  cancel.addEventListener('click', d.tryClose);

  const afterWrite = async (title, res) => {
    dirty = false;
    d.close();
    showResult(title, res);
    try { await loadUsers(); S.usersRedraw && S.usersRedraw(); } catch { /* ignore */ }
  };

  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    errEl.hidden = true;
    const showErr = (m, el) => { errEl.textContent = m; errEl.hidden = false; if (el) el.focus(); };
    const body = {
      username: name.value.trim(), displayname: disp.value.trim(), email: email.value.trim(),
      groups: splitList(groups.value), disabled: disabled.input.checked, password: pw.value,
    };
    if (isNew && !/^[A-Za-z0-9._-]+$/.test(body.username)) return showErr('아이디는 영문/숫자/-_. 만 사용할 수 있습니다', name);
    if ((isNew || body.password) && body.password.length < 10) return showErr('비밀번호는 10자 이상이어야 합니다', pw);
    d.lock(true);
    try {
      const res = await busy(save, () => (isNew ? api('POST', '/api/users', body) : api('PUT', `/api/users/${encodeURIComponent(u.username)}`, body)));
      d.lock(false);
      pw.value = '';
      await afterWrite(res.ok ? '사용자 저장됨' : '사용자 저장 실패', res);
    } catch (ex) {
      d.lock(false);
      showErr(ex.message);
    }
  });

  if (del) {
    del.addEventListener('click', async () => {
      const ok = await confirmDialog({ title: '사용자 삭제', message: `${u.username} 를 삭제할까요?\nAuthelia가 재시작됩니다.`, okText: '삭제', danger: true });
      if (!ok) return;
      d.lock(true);
      try {
        const res = await busy(del, () => api('DELETE', `/api/users/${encodeURIComponent(u.username)}`));
        d.lock(false);
        await afterWrite(res.ok ? '사용자 삭제됨' : '사용자 삭제 실패', res);
      } catch (ex) {
        d.lock(false);
        toast(ex.message, 'err');
      }
    });
  }
}

// ======================================================================= step layout (Caddy / Authelia / Cloudflare / 길목 tabs)
// Every component tab is the same shape: a rail of numbered steps (sticky on wide screens)
// and one card per step. Each step shows its own status so the user can go top-to-bottom.

const STEP_STATES = {
  ok: ['완료', 'ok'], warn: ['확인 필요', 'warn'], fail: ['문제 있음', 'danger'],
  todo: ['할 일', 'muted'], wait: ['확인 중…', 'muted'], opt: ['선택', 'muted'], info: ['', 'muted'],
};

/**
 * stepsLayout(panel, {title, lead, steps:[{id, title, desc, body, state, stateText} | {id, title, desc, children:[step…]}]}) → { set, select }
 * Left: the steps as a vertical tree (status per step). Right: the selected step's details.
 * A step with `children` is one rail entry whose parts are sub-tabs; set()/select()/gotoTab() still
 * address the parts by their own ids, and the group shows the worst state of its parts.
 * Hover shows the description; click / Enter / ↑↓ select.
 */
function stepsLayout(panel, { title, lead, steps }) {
  const tab = S.tab;
  S.stepSel = S.stepSel || {};
  S.subSel = S.subSel || {};
  steps = steps.filter(Boolean).map((s) => (s.children ? { ...s, children: s.children.filter(Boolean) } : s)).filter((s) => !s.children || s.children.length);
  const rail = h('ol', { class: 'step-tree', role: 'tablist', 'aria-orientation': 'vertical', 'aria-label': `${title} 단계` });
  const asideRail = h('ul', { class: 'step-tree aside-tree', role: 'tablist', 'aria-orientation': 'vertical', 'aria-label': `${title} 개별 항목` });
  const detail = h('div', { class: 'step-detail' });
  const setters = {};
  const items = [];
  const parentOf = {}; // child id → group id
  const subSelect = {}; // group id → (child id) => void
  const select = (id, focusPanel) => {
    let target = id;
    if (parentOf[id]) { target = parentOf[id]; subSelect[target](id); }
    if (!items.some((c) => c.id === target)) target = items[0].id;
    S.stepSel[tab] = target;
    for (const c of items) {
      const on = c.id === target;
      c.btn.setAttribute('aria-selected', on ? 'true' : 'false');
      c.btn.tabIndex = on ? 0 : -1;
      c.sec.hidden = !on;
      if (on && focusPanel && window.innerWidth < 960) c.sec.scrollIntoView({ behavior: 'smooth', block: 'start' });
    }
  };
  const paint = (badge, state, text) => {
    const [label, cls] = STEP_STATES[state] || STEP_STATES.info;
    const t = text || label;
    badge.className = `badge ${cls}`; badge.textContent = t; badge.hidden = !t;
    return t;
  };
  let seqNo = 0;
  steps.forEach((s) => {
    const aside = !!s.aside;
    if (!aside) seqNo++;
    const n = aside ? '' : String(seqNo);
    const numMark = aside ? '·' : n; // standalone items are not numbered in the setup flow
    const secId = `step-${tab}-${s.id}`;
    const dot = h('span', { class: 'step-dot', 'aria-hidden': 'true' }, numMark);
    const stateEl = h('span', { class: 'st-state' });
    const btn = h('button', { type: 'button', class: `st-item${aside ? ' aside' : ''}`, role: 'tab', id: `${secId}-tab`, 'aria-controls': secId, 'aria-selected': 'false' },
      dot, h('span', { class: 'st-text' }, h('b', null, s.title), stateEl));
    btn.title = s.desc || s.title;
    btn.addEventListener('click', () => select(s.id, true));
    btn.addEventListener('keydown', (e) => {
      const k = { ArrowDown: 1, ArrowRight: 1, ArrowUp: -1, ArrowLeft: -1 }[e.key];
      if (!k) return;
      e.preventDefault();
      const j = (items.findIndex((c) => c.id === s.id) + k + items.length) % items.length;
      select(items[j].id, false);
      items[j].btn.focus();
    });
    const hbadge = h('span', { class: 'badge' });
    const setOwn = (state, text) => {
      const t = paint(hbadge, state, text);
      stateEl.textContent = t;
      btn.dataset.state = state;
      dot.dataset.state = state;
      dot.textContent = state === 'ok' ? '✓' : state === 'fail' ? '!' : numMark;
      btn.title = `${s.title}${t ? ` — ${t}` : ''}${s.desc ? `\n${s.desc}` : ''}`;
    };
    let body = s.body;
    if (s.children) {
      // a group: one entry in the rail, the parts as sub-tabs inside the card
      const key = `${tab}:${s.id}`;
      const subBar = h('div', { class: 'sub-steps', role: 'tablist', 'aria-label': `${s.title} 항목` });
      const parts = [];
      const childState = {};
      const recompute = () => {
        const order = ['fail', 'warn', 'todo', 'wait'];
        const worst = order.find((st) => s.children.some((c) => childState[c.id] && childState[c.id][0] === st));
        if (worst) {
          const c = s.children.find((x) => childState[x.id][0] === worst);
          setOwn(worst, `${c.title}: ${childState[c.id][1] || STEP_STATES[worst][0]}`);
        } else {
          const anyOk = s.children.some((c) => childState[c.id] && childState[c.id][0] === 'ok');
          const first = s.children.find((c) => childState[c.id] && childState[c.id][0] === 'ok');
          setOwn(anyOk ? 'ok' : 'opt', s.stateText || (first && childState[first.id][1]) || '');
        }
      };
      const pickSub = (cid, focus) => {
        S.subSel[key] = cid;
        for (const p of parts) {
          const on = p.id === cid;
          p.tabBtn.setAttribute('aria-selected', on ? 'true' : 'false');
          p.tabBtn.tabIndex = on ? 0 : -1;
          p.panel.hidden = !on;
          if (on && focus) p.tabBtn.focus();
        }
      };
      subSelect[s.id] = (cid) => pickSub(cid, false);
      const panels = s.children.map((c) => {
        parentOf[c.id] = s.id;
        const cId = `step-${tab}-${c.id}`;
        const cdot = h('span', { class: 'sub-dot', 'aria-hidden': 'true' });
        const tabBtn = h('button', { type: 'button', role: 'tab', class: 'sub-step', id: `${cId}-tab`, 'aria-controls': cId, 'aria-selected': 'false' }, cdot, c.title);
        tabBtn.addEventListener('click', () => pickSub(c.id, false));
        tabBtn.addEventListener('keydown', (e) => {
          const k = { ArrowRight: 1, ArrowLeft: -1 }[e.key];
          if (!k) return;
          e.preventDefault();
          const j = (parts.findIndex((p) => p.id === c.id) + k + parts.length) % parts.length;
          pickSub(parts[j].id, true);
        });
        const cbadge = h('span', { class: 'badge' });
        const panelEl = h('div', { class: 'sub-panel', id: cId, role: 'tabpanel', tabindex: '-1', 'aria-labelledby': `${cId}-tab`, hidden: true },
          c.desc || cbadge ? h('div', { class: 'sub-head' }, c.desc ? h('p', { class: 'small muted grow' }, c.desc) : h('span', { class: 'grow' }), cbadge) : null,
          c.body);
        parts.push({ id: c.id, tabBtn, panel: panelEl });
        subBar.append(tabBtn);
        setters[c.id] = (state, text) => {
          childState[c.id] = [state, text];
          const t = paint(cbadge, state, text);
          cdot.dataset.state = state;
          tabBtn.title = `${c.title}${t ? ` — ${t}` : ''}${c.desc ? `\n${c.desc}` : ''}`;
          recompute();
        };
        return panelEl;
      });
      for (const c of s.children) setters[c.id](c.state || 'todo', c.stateText);
      const wantSub = S.subSel[key];
      pickSub(s.children.some((c) => c.id === wantSub) ? wantSub : s.children[0].id, false);
      body = h('div', { class: 'stack' }, subBar, ...panels);
    }
    const sec = h('section', { class: 'glass card step', id: secId, role: 'tabpanel', tabindex: '-1', 'aria-labelledby': `${secId}-tab`, hidden: true },
      h('div', { class: 'step-head' }, h('span', { class: `step-num${aside ? ' aside' : ''}`, 'aria-hidden': 'true' }, numMark),
        h('div', { class: 'grow' }, h('h2', null, s.title), s.desc ? h('p', { class: 'small muted' }, s.desc) : null), hbadge),
      h('div', { class: 'step-body' }, body));
    (aside ? asideRail : rail).append(h('li', null, btn));
    detail.append(sec);
    items.push({ id: s.id, btn, sec });
    if (!s.children) {
      setters[s.id] = setOwn;
      setOwn(s.state || 'todo', s.stateText);
    }
  });
  const railNav = h('nav', { class: 'tree-rail glass', 'aria-label': `${title} 단계` }, rail);
  if (asideRail.children.length) {
    railNav.append(h('div', { class: 'aside-sep', role: 'separator' }), asideRail);
  }
  panel.append(
    h('div', { class: 'tab-head' }, h('h1', null, title), lead ? h('p', { class: 'muted' }, lead) : null),
    h('div', { class: 'tree-layout' }, railNav, detail));
  select(S.stepSel[tab] || steps[0].id, false);
  return { set: (id, state, text) => setters[id] && setters[id](state, text), select: (id) => select(id, true) };
}

// ---- connection checks (/api/check/{target})

const CHECK_MARK = { ok: ['✓', '통과'], warn: ['!', '주의'], fail: ['✗', '실패'], skip: ['–', '건너뜀'] };

async function loadCheck(target, force = false) {
  S.checks = S.checks || {};
  if (S.checks[target] && !force) return S.checks[target];
  const res = await api('GET', `/api/check/${target}`);
  S.checks[target] = res;
  return res;
}

function checkList(res) {
  return h('ul', { class: 'check-cards', 'aria-label': '점검 결과' }, (res.checks || []).map((c) => {
    const [mark, sr] = CHECK_MARK[c.status] || ['?', c.status];
    const card = h('li', { class: `ccard ${c.status}`, tabindex: '0', title: `${sr}: ${c.label}${c.detail ? `\n${c.detail}` : ''}` },
      h('div', { class: 'cc-top' }, h('span', { class: 'chk-mark', 'aria-hidden': 'true' }, mark), h('b', null, h('span', { class: 'sr-only' }, `${sr}: `), c.label)),
      c.detail ? h('span', { class: 'cc-detail' }, c.detail) : h('span', { class: 'cc-detail muted' }, sr));
    const toggle = () => card.classList.toggle('open');
    card.addEventListener('click', toggle);
    card.addEventListener('keydown', (e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); toggle(); } });
    return card;
  }));
}

function ctrSummary(c) {
  if (!c) return null;
  return h('dl', { class: 'kv' },
    h('dt', null, '컨테이너'), h('dd', null, c.name || '—'),
    h('dt', null, '상태'), h('dd', null, !c.exists ? '없음' : c.state || '—'),
    h('dt', null, '버전'), h('dd', null, c.version || '—'),
    h('dt', null, '이미지'), h('dd', null, c.image || '—'),
    h('dt', null, '생성'), h('dd', null, fmtTime(c.created) || '—'));
}

const checkStateText = (r) => ({ ok: '연결됨', warn: '확인 필요', fail: '문제 있음' }[r.status] || '');

/** A "connection" step body: check results + a re-check button. onResult(res) updates step state. */
function connectionBlock(target, onResult) {
  const box = h('div', { class: 'stack' }, spinnerRow('연결 상태 확인 중…'));
  const btn = h('button', { type: 'button', class: 'btn' }, icon('refresh'), '다시 확인');
  const run = async (force) => {
    if (force) box.replaceChildren(spinnerRow('연결 상태 확인 중…'));
    try {
      const res = await loadCheck(target, force);
      if (!box.isConnected) return res;
      fill(box, checkList(res), res.container ? h('details', { class: 'ctr-more' }, h('summary', null, '연결 대상 정보'), ctrSummary(res.container)) : null);
      onResult && onResult(res);
      return res;
    } catch (ex) {
      box.replaceChildren(errorBox(ex.message));
      onResult && onResult({ status: 'fail' });
      return null;
    }
  };
  btn.addEventListener('click', () => busy(btn, () => run(true)));
  run(false);
  return { box, btn, run };
}

/** Docker container picker: fills `input` with a container from `docker ps -a`. */
function containerPicker(input) {
  const sel = h('select', { class: 'ctr-picker', 'aria-label': 'Docker 컨테이너 목록에서 선택' }, h('option', { value: '' }, '▾ Docker 컨테이너 목록에서 선택…'));
  let loaded = false;
  const load = async () => {
    if (loaded) return;
    loaded = true;
    sel.replaceChildren(h('option', { value: '' }, '불러오는 중…'));
    try {
      const r = await api('GET', '/api/docker/containers');
      const list = (r.containers || []).sort((a, b) => (a.state !== 'running') - (b.state !== 'running') || a.name.localeCompare(b.name));
      sel.replaceChildren(h('option', { value: '' }, `▾ Docker 컨테이너 ${list.length}개 중 선택…`),
        ...list.map((c) => h('option', { value: c.name, selected: c.name === input.value }, `${c.state === 'running' ? '●' : '○'} ${c.name} — ${c.image}${c.project ? ` (${c.project})` : ''}`)));
    } catch (ex) {
      sel.replaceChildren(h('option', { value: '' }, `목록을 읽지 못함: ${ex.message}`));
      loaded = false;
    }
  };
  sel.addEventListener('focus', load);
  sel.addEventListener('mousedown', load);
  sel.addEventListener('change', () => {
    if (!sel.value) return;
    input.value = sel.value;
    input.dispatchEvent(new Event('input', { bubbles: true }));
    input.dispatchEvent(new Event('change', { bubbles: true }));
  });
  return sel;
}

// ---- settings forms (each step saves only its own fields; the rest of Settings is preserved)

function settingsFields(defs) {
  const st = settings();
  const read = {};
  const inputs = {};
  const els = defs.map((f) => {
    if (f.type === 'switch') {
      const s = switchCtl(f.label, st[f.key], f.hint);
      read[f.key] = () => s.input.checked;
      inputs[f.key] = s.input;
      s.input.dataset.key = f.key;
      return s;
    }
    if (f.type === 'choice') {
      const name = uid('ch');
      const choiceIcon = (name) => {
        if (!name || typeof topoIcon !== 'function') return null;
        const svgEl = sv('svg', { viewBox: '0 0 24 24', width: 24, height: 24, class: 'wz-ico', 'aria-hidden': 'true' });
        svgEl.append(topoIcon(name, 12, 12, 22, TC.accentText));
        return svgEl;
      };
      const wrap = h('div', { class: 'choice-cards', role: 'radiogroup' }, f.options.map((o) => h('label', { class: `choice ${o.disabled ? 'disabled' : ''}`, title: o.disabledWhy || '' },
        h('input', { type: 'radio', name, value: o.value, checked: String(st[f.key]) === o.value, disabled: !!o.disabled }),
        h('span', { class: 'ch-body' }, h('span', { class: 'ch-head' }, choiceIcon(o.icon), h('b', null, o.label)), h('small', null, o.desc), o.disabledWhy ? h('small', { class: 'ch-why' }, o.disabledWhy) : null))));
      Object.defineProperty(wrap, 'value', { get: () => (wrap.querySelector('input:checked') || {}).value || '' });
      read[f.key] = () => wrap.value;
      inputs[f.key] = wrap;
      const lid = uid('chl');
      wrap.setAttribute('aria-labelledby', lid);
      return h('div', { class: 'field span-all choice-field' },
        h('span', { class: 'field-label', id: lid }, f.label, h('span', { class: 'choice-count' }, `${f.options.length}가지 중 하나 선택`)),
        wrap, f.hint ? h('p', { class: 'hint' }, f.hint) : null);
    }
    if (f.type === 'select') {
      const el = h('select', null, f.options.map(([v, l]) => h('option', { value: v, selected: String(st[f.key]) === v }, l)));
      read[f.key] = () => (f.num ? parseInt(el.value, 10) : el.value);
      inputs[f.key] = el;
      return field(f.label, el, f.hint);
    }
    if (f.type === 'custom') { // { el, read(), label?, hint? } — any control with its own value
      read[f.key] = f.read;
      inputs[f.key] = f.el;
      return h('div', { class: `field ${f.span === false ? '' : 'span-all'}` }, f.label ? h('span', { class: 'field-label' }, f.label) : null, f.el, f.hint ? h('p', { class: 'hint' }, f.hint) : null);
    }
    if (f.type === 'code') {
      const el = h('textarea', { class: 'code', rows: String(f.rows || 20), spellcheck: 'false', placeholder: f.placeholder || '' });
      el.value = st[f.key] || '';
      read[f.key] = () => el.value;
      inputs[f.key] = el;
      return field(f.label, el, f.hint);
    }
    const el = h('input', {
      type: f.type === 'number' ? 'number' : 'text', value: st[f.key] ?? '', autocomplete: 'off', spellcheck: 'false',
      class: f.mono ? 'mono' : null, placeholder: f.placeholder, ...(f.attrs || {}),
    });
    read[f.key] = () => (f.type === 'number' ? parseInt(el.value, 10) || 0 : el.value.trim());
    inputs[f.key] = el;
    const fl = field(f.label, el, f.hint);
    if (f.picker === 'container') fl.append(containerPicker(el));
    return fl;
  });
  els.forEach((el, i) => { if (defs[i].wide && el.classList) el.classList.add('span-all'); });
  return { els, inputs, read: () => Object.fromEntries(Object.entries(read).map(([k, fn]) => [k, fn()])) };
}

async function saveSettingsPatch(patch) {
  const res = await api('PUT', '/api/settings', { ...settings(), ...patch });
  await refreshState();
  toast(res.pending ? '저장됨 — 생성 결과가 바뀌어 「적용 대기」에 추가했습니다' : '저장됨');
  return res;
}

/** settingsForm(defs, {grid, actions, extra, validate(patch)→msg, onSaved(patch)}) */
function settingsForm(defs, opts = {}) {
  const f = settingsFields(defs);
  const errEl = h('p', { class: 'form-error', role: 'alert', hidden: true });
  const save = h('button', { type: 'submit', class: 'btn primary' }, '저장');
  const form = h('form', { class: 'stack', novalidate: true },
    errEl,
    opts.grid === false ? f.els : h('div', { class: 'grid-2' }, f.els),
    opts.extra || null,
    h('div', { class: 'row' }, opts.actions || null, h('span', { class: 'grow' }), save));
  const mark = () => { save.textContent = '저장 *'; };
  form.addEventListener('input', mark);
  form.addEventListener('change', mark);
  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    errEl.hidden = true;
    const patch = f.read();
    const msg = opts.validate ? await opts.validate(patch, f.inputs) : '';
    if (msg) { errEl.textContent = msg; errEl.hidden = false; return; }
    if (msg === false) return; // validate cancelled (e.g. confirm dialog)
    try {
      await busy(save, () => saveSettingsPatch(patch));
      save.textContent = '저장';
      opts.onSaved && opts.onSaved(patch);
    } catch (ex) {
      errEl.textContent = ex.message;
      errEl.hidden = false;
    }
  });
  form.inputs = f.inputs;
  return form;
}

// ---- validate / preview (Caddy, Authelia)

/** validateBlock(target, onState) — "생성 결과 미리보기" + "검증만 실행" with inline result. */
function validateBlock(target, onState) {
  const label = target === 'caddy' ? 'Caddyfile' : 'access_control';
  const out = h('div', { class: 'stack' });
  const prevBtn = h('button', { type: 'button', class: 'btn' }, `생성될 ${label} 미리보기`);
  const valBtn = h('button', { type: 'button', class: 'btn primary' }, '검증만 실행');
  const show = (res) => {
    out.replaceChildren(res.ok
      ? callout('ok', h('b', null, '✓ 검증 통과'), h('span', { class: 'small' }, `${fmtTime(res.at)} · 아직 파일에 쓰지 않았습니다. 「적용」을 누르면 반영됩니다.`))
      : callout('danger', h('b', null, '검증 실패'), h('span', { style: { whiteSpace: 'pre-wrap' } }, res.error || '')));
    if (res.log && res.log.length) out.append(logView(res.log));
  };
  prevBtn.addEventListener('click', () => busy(prevBtn, () => openPreview(target)));
  valBtn.addEventListener('click', () => busy(valBtn, async () => {
    let res;
    try { res = await api('POST', '/api/validate', { target }); } catch (ex) { res = { ok: false, error: ex.message }; }
    res.at = new Date().toISOString();
    S.validated[target] = res;
    show(res);
    onState && onState(res.ok ? 'ok' : 'fail', res.ok ? '검증 통과' : '검증 실패');
  }));
  if (S.validated[target]) show(S.validated[target]);
  return { body: h('div', { class: 'stack' }, h('div', { class: 'row' }, prevBtn, valBtn), out) };
}

async function openPreview(target) {
  const plan = await api('GET', '/api/plan?dns=0');
  const [cur, next, title] = target === 'caddy'
    ? [plan.caddyCurrent, plan.caddyNext, 'Caddyfile']
    : [plan.autheliaCurrent, plan.autheliaNext, 'Authelia access_control'];
  const ops = diffLines(cur, next);
  const st = diffStat(ops);
  const full = h('details', null, h('summary', { class: 'small muted', style: { cursor: 'pointer' } }, '생성 결과 전체 보기'),
    h('pre', { class: 'log', tabindex: '0' }, next || ''));
  const close = h('button', { type: 'button', class: 'btn primary', autofocus: true }, '닫기');
  const d = openDialog({
    title: `${title} — 현재 파일과 비교`, size: 'wide', footer: [close],
    body: h('div', { class: 'stack' },
      h('div', { class: 'plan-summary' }, statBadge(st)),
      (plan.warnings || []).length ? callout('warn', h('ul', null, plan.warnings.map((w) => h('li', null, w)))) : null,
      st.changed ? renderDiff(ops) : callout('ok', '현재 파일과 같습니다.'),
      full),
  });
  close.addEventListener('click', () => d.close());
}

// ---- update (docker compose) step

/** /run/desktop/mnt/host/d/Docker/x (Docker Desktop daemon form) → D:\Docker\x */
function hostPathView(p) {
  if (!p) return '';
  const m = /^\/run\/desktop\/mnt\/host\/(\w)(\/.*)?$/.exec(p);
  return m ? `${m[1].toUpperCase()}:${(m[2] || '/').replace(/\//g, '\\')}` : p;
}

function manualUpdateHelp(target) {
  const st = settings();
  const c = (S.checks[target] || {}).compose || {};
  const dir = hostPathView(c.hostDir) || (target === 'caddy' ? '<Caddy compose 폴더>' : '<Authelia compose 폴더>');
  const svc = c.service || (target === 'caddy' ? st.caddyService : st.autheliaService) || target;
  const proj = c.project ? ` -p ${c.project}` : '';
  const lines = ['# 호스트(PowerShell)에서 직접 실행', `cd "${dir}"`];
  if (target === 'caddy' && use('cloudflare')) lines.push('$env:CLOUDFLARE_API_TOKEN = "<Cloudflare 토큰>"   # Caddy compose가 토큰을 환경변수로 받는 경우');
  lines.push(`docker compose${proj} pull --ignore-buildable ${svc}`);
  lines.push(`docker compose${proj} build --pull ${svc}`);
  lines.push(`docker compose${proj} up -d --no-deps ${svc}`);
  return h('div', { class: 'stack' },
    h('p', { class: 'small muted' }, '앱 안에서 업데이트가 안 될 때 호스트에서 직접 실행하세요.'),
    h('pre', { class: 'code-block' }, lines.join('\n')));
}

/** Image update step. compose project/folder are auto-detected from the container's labels
 *  (see compose.go); the folder setting is only a fallback when detection fails. */
function updateBlock(target, onState) {
  const name = target === 'caddy' ? 'Caddy' : 'Authelia';
  const dirKey = target === 'caddy' ? 'caddyStackDir' : 'autheliaStackDir';
  const upd = h('button', { type: 'button', class: 'btn', disabled: true }, icon('upload'), '업데이트');
  const recheck = h('button', { type: 'button', class: 'btn' }, icon('refresh'), '새 버전 확인');
  const force = h('button', { type: 'button', class: 'btn sm' }, '그래도 다시 받기·빌드');
  const info = h('div', { class: 'stack' }, spinnerRow('compose 정보 확인 중…'));
  const help = h('div');
  let last = null; // last compose check result
  // update state is read from S.state every time (it changes after an update / re-check)
  const items = () => ((S.state.updates || {}).items || []).filter((it) => it.target === target);
  const draw = (res) => {
    if (res !== undefined) last = res;
    const c = last && last.compose;
    const chk = ((last && last.checks) || []).find((x) => x.id === 'compose');
    const ready = !!chk && chk.status === 'ok';
    const ver = last && last.container && last.container.version;
    const its = items();
    const avail = its.filter((x) => x.available);
    const errs = its.filter((x) => x.err);
    const known = its.length > 0 && !errs.length;
    const checked = (S.state.updates || {}).checked;
    let note = null;
    if (avail.length) {
      note = callout('warn', h('b', null, '↑ 새 이미지가 있습니다'), h('span', { class: 'small mono' }, avail.map((x) => `${x.built ? '베이스 ' : ''}${x.image} ${x.local || ''} → ${x.remote || ''}`).join(' · ')));
    } else if (known) {
      note = callout('ok', h('b', null, '✓ 최신 버전입니다'), h('span', { class: 'small' }, `확인 ${fmtTime(checked)} · ${its.map((x) => `${x.built ? '베이스 ' : ''}${x.image}`).join(', ')}`));
    } else if (errs.length) {
      note = callout('', h('b', null, '새 버전 여부를 확인하지 못했습니다'), h('span', { class: 'small' }, errs.map((x) => x.err).join(' · ')));
    }
    // button: only a real action when there is something new (or the check could not tell)
    if (!ready) {
      upd.disabled = true;
      upd.className = 'btn';
      upd.lastChild.textContent = '업데이트';
    } else if (avail.length) {
      upd.disabled = false;
      upd.className = 'btn primary';
      upd.lastChild.textContent = '최신 버전으로 업데이트';
    } else if (known) {
      upd.disabled = true;
      upd.className = 'btn';
      upd.lastChild.textContent = '이미 최신 버전';
    } else {
      upd.disabled = false;
      upd.className = 'btn';
      upd.lastChild.textContent = '업데이트 (새 버전 여부 모름)';
    }
    force.hidden = !ready || !!avail.length || !known;
    info.replaceChildren();
    append(info, [note,
      c ? h('dl', { class: 'kv' },
        h('dt', null, '현재 버전'), h('dd', null, ver || '—'),
        h('dt', null, 'compose 프로젝트'), h('dd', null, `${c.project || '—'} / ${c.service || '—'}`),
        h('dt', null, '폴더 (호스트)'), h('dd', null, hostPathView(c.hostDir) || '—'),
        h('dt', null, '감지 방식'), h('dd', null, c.manual ? '설정에서 직접 지정' : '컨테이너 라벨에서 자동 감지'),
        h('dt', null, '앱 안에서 업데이트'), h('dd', null, ready ? '가능 (compose 파일 확인됨)' : '불가')) : null,
      chk && !ready ? callout('warn', h('b', null, '앱 안에서 업데이트할 수 없습니다'), h('span', null, chk.detail)) : null]);
    help.replaceChildren(manualUpdateHelp(target));
    onState && onState(avail.length ? 'warn' : known ? 'ok' : ready ? 'info' : 'opt',
      avail.length ? '새 버전 있음' : known ? (ver ? `${ver} · 최신` : '최신') : ready ? '확인 필요' : '수동');
  };
  loadCheck(target).then(draw).catch(() => draw(null));
  recheck.addEventListener('click', () => busy(recheck, async () => {
    try {
      await api('POST', '/api/updates/check');
      await refreshState();
      draw();
      toast(items().some((x) => x.available) ? '새 버전이 있습니다' : '최신 버전입니다');
    } catch (ex) { toast(ex.message, 'err'); }
  }));
  const form = settingsForm([
    { key: dirKey, label: 'compose 폴더 직접 지정 (자동 감지가 안 될 때만)', mono: true, placeholder: '비워 두면 자동 감지',
      hint: '길목 컨테이너 안에서 읽을 수 있고, Docker 데몬도 해석할 수 있는 경로 (Docker Desktop: /run/desktop/mnt/host/d/Docker/…)' },
  ], { onSaved: async () => { draw(await loadCheck(target, true)); } });

  upd.addEventListener('click', async () => {
    const ok = await confirmDialog({
      title: `${name} 업데이트`,
      message: target === 'caddy'
        ? '최신 이미지를 받아 다시 빌드하고, 바뀐 것이 있으면 컨테이너를 재생성합니다.\n재생성되는 몇 초 동안 모든 사이트 접속이 끊깁니다.'
        : '최신 이미지를 받고, 바뀐 것이 있으면 컨테이너를 재생성합니다.\n시작될 때까지 forward_auth 사이트가 502가 됩니다.',
      okText: '업데이트',
    });
    if (!ok) return;
    await runUpdate(upd);
  });
  force.addEventListener('click', async () => {
    const ok = await confirmDialog({
      title: `${name} 다시 받기·빌드`,
      message: '새 버전이 없다고 확인됐지만 이미지를 다시 받고 빌드합니다.\n바뀐 것이 없으면 컨테이너는 그대로 둡니다 (「이미 최신」).',
      okText: '다시 받기',
    });
    if (ok) await runUpdate(force);
  });
  async function runUpdate(btn) {
    let res;
    try { res = await busy(btn, () => api('POST', '/api/system/update', { target })); } catch (ex) { res = { ok: false, error: ex.message, log: [] }; }
    // the answer already carries the re-checked state: refresh it before showing anything
    try { await refreshState(); } catch { /* ignore */ }
    showResult(res.ok ? `${name} 업데이트 완료` : `${name} 업데이트 실패`, res, res.ok ? null : manualUpdateHelp(target));
    try { draw(await loadCheck(target, true)); } catch { draw(); }
  }
  return h('div', { class: 'stack' },
    h('p', { class: 'small muted' }, '이미지 업데이트는 서비스 설정과 분리되어 있습니다. 기본 골격·서비스는 그대로 두고 컨테이너만 최신 버전으로 바꿉니다.'),
    info,
    h('div', { class: 'row' }, upd, recheck, h('span', { class: 'grow' }), force),
    h('details', null, h('summary', { class: 'small muted', style: { cursor: 'pointer' } }, '고급: 폴더 직접 지정 · 수동 명령'), h('div', { class: 'stack', style: { marginTop: '12px' } }, form, help)));
}

function gotoTab(name, stepId) {
  if (stepId) { S.stepSel = S.stepSel || {}; S.stepSel[name] = stepId; }
  selectTab(name, false);
  if (stepId) {
    const el = document.getElementById(`step-${name}-${stepId}`);
    if (el) { el.scrollIntoView({ block: 'start' }); el.focus({ preventScroll: true }); }
  } else window.scrollTo({ top: 0 });
}

// ======================================================================= Caddy tab

/** How the internet reaches Caddy :443 — from the topology device chain, generic if unknown. */
function edgeText(st) {
  const hops = (st.topoHops || []).filter((x) => typeof HOP_KINDS === 'undefined' || HOP_KINDS[x.kind]);
  if (!hops.length) return '외부(공유기 포트포워딩·방화벽 등)에서 들어오는 HTTPS';
  const nm = (x) => (x.name || '').trim() || (typeof HOP_KINDS !== 'undefined' ? HOP_KINDS[x.kind].name : x.kind);
  const last = hops[hops.length - 1];
  return `${hops.map(nm).join(' → ')}${last.kind === 'tunnel' ? '(아웃바운드)' : last.extPort ? ` TCP ${last.fwdPort || last.extPort}` : ''}`;
}

/** How private (Tailscale / VPN) clients reach Caddy's private port. */
function privText(st) {
  const p = st.tailscalePort || 8443;
  const kind = use('tailscale') || st.topoPrivKind === 'vpn' ? st.topoPrivKind : '';
  switch (kind) {
    case 'ts_serve': return `${(st.topoPrivName || '').trim() || 'tailscale serve'} → 127.0.0.1:${p}`;
    case 'ts_direct': return `Tailscale IP${st.tailscaleIp ? ` ${st.tailscaleIp}` : ''}:${p}로 직접`;
    case 'vpn': return `${(st.topoPrivName || '').trim() || 'VPN'} → :${p}`;
    default: return use('tailscale') ? `사설 경로(예: tailscale serve) → :${p}` : `들어올 경로 없음 (Tailscale 사용 안 함) — VPN 등 → :${p}`;
  }
}

function privHint(st) {
  return use('tailscale') && (st.topoPrivKind === 'ts_serve' || !st.topoPrivKind)
    ? 'tailscale serve를 쓴다면: tailscale serve --tcp 443 tcp://127.0.0.1:이 포트'
    : '사설 경로가 Caddy에 넘겨주는 포트';
}

function renderCaddy(panel) {
  const st = settings();
  const sites = S.state.services.filter((s) => s.enabled && !s.dnsOnly);
  const nPublic = sites.filter((s) => s.exposure === 'public').length;
  let L;

  const conn = connectionBlock('caddy', (r) => L.set('conn', r.status || 'fail', checkStateText(r)));
  const modeHelp = h('div');
  const connForm = settingsForm([
    { key: 'caddyMode', type: 'choice', label: 'Caddy 위치', hint: '「PC에 설치」 두 가지는 길목이 어디서 실행되느냐의 차이입니다 — 길목이 Docker 안이면 Windows 프로그램을 직접 실행할 수 없어서 Caddy의 관리 창구(HTTP :2019)로 연결합니다.',
      options: [
        { value: 'docker', icon: 'box', label: 'Docker 컨테이너', desc: 'Caddy가 Docker에서 실행 (지금 구성). 길목이 docker exec로 검증·적용' },
        { value: 'api', icon: 'host', label: 'PC에 설치 · 길목은 Docker', desc: 'Windows 등에 직접 설치한 Caddy. 길목이 Caddy 관리 API(:2019)에 HTTP로 접속해 검증·적용' },
        { value: 'native', icon: 'server', label: 'PC에 설치 · 길목도 같은 PC', desc: '길목을 Docker 없이 같은 PC에서 실행(gilmok.exe). caddy validate / reload 명령을 직접 실행',
          disabled: !!(S.state.security && S.state.security.selfName) && settings().caddyMode !== 'native',
          disabledWhy: S.state.security && S.state.security.selfName ? `길목이 지금 Docker(${S.state.security.selfName}) 안에서 실행 중이라 고를 수 없습니다` : '' },
      ] },
    { key: 'caddyContainer', label: 'Caddy 컨테이너', mono: true, hint: 'docker ps 에 보이는 이름', picker: 'container' },
    { key: 'caddyAdmin', label: 'Caddy 관리 API 주소', mono: true, placeholder: 'http://host.docker.internal:2019', hint: '길목에서 접속할 수 있는 주소' },
    { key: 'caddyBin', label: 'caddy 실행 파일', mono: true, placeholder: 'C:\\Caddy\\caddy.exe', hint: 'PATH에 있으면 caddy' },
    { key: 'caddyfilePath', label: 'Caddyfile 경로 — 길목이 보는 위치', mono: true, hint: '길목이 읽고 쓰는 파일 (예: /stacks/caddy/Caddyfile)' },
    { key: 'caddyfileInCtr', label: 'Caddyfile 경로 — Caddy 컨테이너 안', mono: true, hint: 'caddy reload 가 읽는 파일 (보통 /etc/caddy/Caddyfile)' },
  ], { actions: [conn.btn], extra: modeHelp, onSaved: () => conn.run(true) });
  {
    const inp = connForm.inputs;
    const show = () => {
      const m = inp.caddyMode.value;
      const vis = { caddyContainer: m === 'docker', caddyfileInCtr: m === 'docker', caddyAdmin: m === 'api', caddyBin: m === 'native' };
      for (const [k, v] of Object.entries(vis)) inp[k].closest('.field').hidden = !v;
      fill(modeHelp, m === 'api' ? callout('', h('b', null, '관리 API 연결 (Windows native Caddy 등)'),
        h('ol', { class: 'flow' },
          h('li', null, 'Caddyfile 전역 옵션(기본 골격)에 ', h('code', null, 'admin 0.0.0.0:2019 { origins host.docker.internal:2019 }'), ' 를 넣고 Caddy를 다시 시작'),
          h('li', null, 'Windows 방화벽에서 TCP 2019는 Docker(WSL) 대역만 허용 — 관리 API는 Caddy 전체를 바꿀 수 있습니다'),
          h('li', null, 'Caddyfile이 있는 폴더를 길목 컨테이너에 마운트하고, 위의 「길목이 보는 위치」에 그 경로를 적기')),
        h('span', { class: 'small' }, '검증은 /adapt, 적용은 /load(실패하면 Caddy가 이전 설정 유지). 대시보드 요청 통계와 이미지 업데이트는 Docker 모드에서만 됩니다.'))
        : m === 'native' ? callout('', h('b', null, '같은 PC의 caddy 실행 파일'), h('span', null, '길목을 Docker가 아니라 같은 PC에서 직접 실행할 때 씁니다(gilmok.exe). caddy validate / caddy reload 를 직접 호출합니다.'))
          : null);
    };
    inp.caddyMode.addEventListener('change', show);
    show();
  }

  const listenForm = settingsForm([
    privOn() ? { key: 'tailscalePort', type: 'number', label: `${use('tailscale') ? 'Tailscale(사설)' : '사설'} 사이트 포트`, hint: privHint(st), attrs: { min: '1', max: '65535' } } : null,
  ].filter(Boolean), {
    grid: privOn() ? undefined : false,
    extra: h('div', { class: 'listen-map' },
      h('div', { class: 'section-box' }, h('h3', null, h('span', { class: 'badge public' }, '공개'), ':443'),
        h('p', { class: 'small muted' }, `${edgeText(st)} → Caddy :443. 공개 서비스 ${nPublic}개`)),
      privOn() ? h('div', { class: 'section-box' }, h('h3', null, h('span', { class: 'badge ts' }, use('tailscale') ? 'Tailscale' : '사설'), `:${st.tailscalePort || 8443}`),
        h('p', { class: 'small muted' }, `${privText(st)}. ${privName()} 서비스 ${sites.length - nPublic}개`)) : null,
      h('p', { class: 'hint span-all' }, `들어오는 길(공유기·터널${use('tailscale') ? '·tailscale serve' : privOn() ? '·VPN' : ''} 등)은 서비스 탭 › 구성도에서 공유기·Tailscale 칸을 눌러 고칠 수 있습니다.`)),
  });

  const baseImport = h('button', { type: 'button', class: 'btn' }, icon('download'), '현재 Caddyfile에서 가져오기…');
  baseImport.addEventListener('click', () => runImport(baseImport));
  const baseForm = settingsForm([
    { key: 'caddyBase', type: 'code', label: '전역 옵션 + 스니펫', hintGeneric: true, rows: 22, hint: `{ } 전역 블록과 스니펫(예: ${[use('cloudflare') ? '(cf_only)' : null, use('authelia') ? '(authelia)' : null].filter(Boolean).join(', ') || '(공통 헤더)'}). 서비스 사이트 블록은 이 아래에 자동으로 붙습니다.` },
  ], {
    grid: false, actions: [baseImport],
    validate: (p) => (p.caddyBase.split('{').length !== p.caddyBase.split('}').length ? '중괄호 { } 개수가 맞지 않습니다' : ''),
    onSaved: (p) => L.set('base', p.caddyBase.trim() ? 'ok' : 'todo', p.caddyBase.trim() ? '설정됨' : '비어 있음'),
  });

  const val = validateBlock('caddy', (s, t) => L.set('validate', s, t));

  L = stepsLayout(panel, {
    title: 'Caddy',
    lead: '리버스 프록시. 연결 → 사이트 → 전역 설정 → 보호 → 검증 순서입니다. 사이트는 「리버스 프록시」(또는 서비스 탭)에서 추가·수정·삭제하고, 엑셀로 한 번에 올릴 수도 있습니다.',
    steps: [
      { id: 'conn', title: 'Caddy 연결', desc: 'Docker 컨테이너 / 관리 API / 로컬 실행 파일 중 하나로 연결하고, Caddyfile에 접근할 수 있는지 확인합니다.', state: 'wait',
        body: h('div', { class: 'stack' }, typeof stackCard === 'function' ? stackCard('caddy', () => conn.run(true)) : null, conn.box, h('hr', { class: 'sep' }), connForm) },
      proxySitesStep(),
      { id: 'global', title: '전역 설정', desc: '모든 사이트에 공통인 부분 — 들어오는 포트와 Caddyfile 기본 골격(전역 옵션·스니펫).', children: [
        { id: 'base', title: '기본 골격', desc: '전역 옵션과 스니펫. Caddy 이미지 업데이트·서비스 변경과 독립적으로 관리합니다.', state: st.caddyBase ? 'ok' : 'todo', stateText: st.caddyBase ? '설정됨' : '비어 있음',
          body: baseForm },
        { id: 'listen', title: '포트', desc: privOn() ? `공개 사이트(:443)와 ${privName()} 사이트가 들어오는 포트입니다.` : '공개 사이트가 들어오는 포트(:443)입니다.', state: 'ok', stateText: privOn() ? `:443 / :${st.tailscalePort || 8443}` : ':443',
          body: listenForm },
      ] },
      { id: 'protect', title: '보호 (기본 차단 · WAF)', desc: 'Caddy에서 공격 요청을 막습니다. 공통 규칙을 정하고, 사이트마다 켜고 끕니다.', children: [
        { ...guardStep(), title: '기본 차단' },
        { ...wafEngineStep(), title: 'WAF 엔진' },
        { ...wafServicesStep(), title: '사이트별 적용' },
      ] },
      { id: 'validate', title: '생성 결과 검증', desc: `기본 골격 + 서비스 ${sites.length}개로 만든 Caddyfile을 Caddy 컨테이너 안에서 검증합니다. 파일은 바꾸지 않습니다.`,
        state: S.validated.caddy ? (S.validated.caddy.ok ? 'ok' : 'fail') : 'todo', stateText: S.validated.caddy ? (S.validated.caddy.ok ? '검증 통과' : '검증 실패') : '',
        body: val.body },
      { id: 'wafmon', title: '차단 기록 · 시험', aside: true, desc: '막힌 요청을 확인해 오탐을 예외로 돌리고, 실제로 막히는지 시험합니다.', children: [
        { ...wafEventsStep(), title: '차단 기록' },
        { ...wafTestStep(), title: '시험 요청' },
      ] },
      { id: 'update', title: '이미지 업데이트', aside: true, desc: 'docker compose로 최신 이미지를 받아 다시 만듭니다.', state: 'opt',
        body: updateBlock('caddy', (s, t) => L.set('update', s, t)) },
    ],
  });
}

// ======================================================================= Authelia tab

/** The Authelia portal itself (upstream is the Authelia container / service): never put it behind forward_auth. */
function isAutheliaPortal(svc) {
  const host = String(svc.upstream || '').split(':')[0].toLowerCase();
  const ctr = String(settings().autheliaContainer || '').toLowerCase();
  return !!host && (host === ctr || host === 'authelia');
}

/** Pick, from every registered service, which ones require an Authelia login. */
function openAutheliaPicker() {
  const all = [...S.state.services].sort((a, b) => a.subdomain.localeCompare(b.subdomain));
  const on0 = new Set(all.filter((x) => x.authelia && x.authelia.enabled && !x.dnsOnly).map((x) => x.id));
  const q = h('input', { type: 'search', placeholder: '서비스 검색', 'aria-label': '서비스 검색', autocomplete: 'off' });
  const pol = h('select', { 'aria-label': '새로 켜는 서비스의 정책' }, [['two_factor', '2단계 (비밀번호 + OTP 등) — 권장'], ['one_factor', '1단계 (비밀번호만)']].map(([v, l]) => h('option', { value: v }, l)));
  const grp = groupSelect([], { label: '새로 켜는 서비스의 허용 그룹' });
  const count = h('span', { class: 'badge accent' });
  const list = h('div', { class: 'pick-list', role: 'group', 'aria-label': '서비스' });
  const boxes = [];
  const groupsOf = (label, items) => {
    if (!items.length) return null;
    return h('div', { class: 'pick-group' }, h('div', { class: 'pick-head small muted' }, `${label} ${items.length}`),
      items.map((svc) => {
        const portal = isAutheliaPortal(svc);
        const why = svc.dnsOnly ? 'DNS 전용 — Caddy 사이트가 없어 로그인을 걸 수 없음'
          : portal ? 'Authelia 로그인 화면 자신 — 여기에 로그인을 걸면 로그인할 수 없게 됩니다'
            : !svc.enabled ? '꺼진 서비스 — 켜면 적용됨' : '';
        const cb = h('input', { type: 'checkbox', value: svc.id, checked: on0.has(svc.id), disabled: !!svc.dnsOnly || (portal && !on0.has(svc.id)) });
        boxes.push({ cb, svc });
        const cur = svc.authelia && svc.authelia.enabled && !svc.dnsOnly
          ? `${svc.authelia.policy === 'one_factor' ? '1단계' : '2단계'}${(svc.authelia.groups || []).length ? ` · ${svc.authelia.groups.join(', ')}` : ''}` : '';
        return h('label', { class: `pick-item ${cb.disabled ? 'disabled' : ''}`, 'data-name': `${svc.subdomain} ${fqdn(svc.subdomain)}` },
          cb,
          h('span', { class: 'grow' }, h('b', null, svc.subdomain), h('small', { class: 'mono' }, fqdn(svc.subdomain)), why ? h('small', { class: 'pick-why' }, why) : null),
          cur ? h('span', { class: 'badge muted' }, cur) : null,
          typeof expoBadge === 'function' ? expoBadge(svc) : null);
      }));
  };
  const pub = all.filter((x) => x.exposure === 'public');
  const priv = all.filter((x) => x.exposure !== 'public');
  append(list, [groupsOf('공개', pub), groupsOf(privOn() ? privName() : '사설', priv)]);
  const upd = () => {
    const n = boxes.filter((b) => b.cb.checked).length;
    count.textContent = `${n}개 선택`;
    const added = boxes.filter((b) => b.cb.checked && !on0.has(b.svc.id)).length;
    defBox.hidden = added === 0;
  };
  const defBox = h('div', { class: 'section-box stack tight' },
    h('b', { class: 'small' }, '새로 켜는 서비스에 줄 기본값'),
    h('div', { class: 'grid-2' }, field('정책', pol), field('허용 그룹', grp)),
    h('p', { class: 'hint' }, '이미 켜져 있던 서비스의 정책·그룹은 그대로 둡니다. 나중에 표에서 서비스마다 바꿀 수 있습니다.'));
  const selAll = h('button', { type: 'button', class: 'btn sm' }, '보이는 것 모두 선택');
  const selNone = h('button', { type: 'button', class: 'btn sm' }, '모두 해제');
  selAll.addEventListener('click', () => { for (const b of boxes) if (!b.cb.disabled && !b.cb.closest('.pick-item').hidden) b.cb.checked = true; upd(); });
  selNone.addEventListener('click', () => { for (const b of boxes) if (!b.cb.disabled) b.cb.checked = false; upd(); });
  q.addEventListener('input', () => {
    const t = q.value.trim().toLowerCase();
    for (const el of list.querySelectorAll('.pick-item')) el.hidden = !!t && !el.dataset.name.toLowerCase().includes(t);
  });
  list.addEventListener('change', upd);
  const err = h('p', { class: 'form-error', role: 'alert', hidden: true });
  const body = h('div', { class: 'stack' },
    h('p', { class: 'small' }, '체크한 서비스는 접속할 때 Authelia 로그인을 거칩니다 (Caddy forward_auth + access_control 규칙). 저장하면 「적용 대기」가 되고, 「적용」하면 Authelia가 재시작됩니다.'),
    h('div', { class: 'toolbar' }, h('div', { class: 'search' }, icon('search'), q), h('span', { class: 'grow' }), count, selAll, selNone),
    list, defBox, err);
  upd();
  const save = h('button', { type: 'button', class: 'btn primary' }, '저장');
  const cancel = h('button', { type: 'button', class: 'btn ghost' }, '취소');
  const d = openDialog({ title: 'Authelia 적용할 서비스 선택', body, footer: [h('span', { class: 'spacer' }), cancel, save], size: 'wide' });
  cancel.addEventListener('click', () => d.close());
  save.addEventListener('click', () => busy(save, async () => {
    err.hidden = true;
    const changes = boxes.filter((b) => !b.cb.disabled && b.cb.checked !== on0.has(b.svc.id));
    if (!changes.length) { d.close(); return; }
    const groups = splitList(grp.value);
    let done = 0;
    try {
      for (const { cb, svc } of changes) {
        const a0 = svc.authelia || {};
        const next = cb.checked
          ? { ...a0, enabled: true, policy: pol.value, groups }
          : { ...a0, enabled: false };
        await api('PUT', `/api/services/${encodeURIComponent(svc.id)}`, { ...svc, authelia: next });
        done++;
      }
      await refreshState();
      const on = changes.filter((c) => c.cb.checked).length;
      toast(`Authelia ${on ? `켬 ${on}개` : ''}${on && changes.length - on ? ' · ' : ''}${changes.length - on ? `끔 ${changes.length - on}개` : ''} — 적용 대기`);
      d.close();
      renderPanel();
    } catch (ex) {
      err.textContent = `${done}개 저장 후 실패: ${ex.message}`;
      err.hidden = false;
      try { await refreshState(); } catch { /* ignore */ }
    }
  }));
}

function renderAuthelia(panel) {
  const st = settings();
  const guarded = S.state.services.filter((s) => s.enabled && !s.dnsOnly && s.authelia && s.authelia.enabled);
  let L;

  const conn = connectionBlock('authelia', (r) => L.set('conn', r.status || 'fail', checkStateText(r)));
  const connForm = settingsForm([
    { key: 'autheliaContainer', label: 'Authelia 컨테이너', mono: true, hint: 'docker ps 에 보이는 이름', picker: 'container' },
    { key: 'autheliaConfig', label: 'configuration.yml — 길목 컨테이너 안', mono: true },
    { key: 'autheliaUsers', label: 'users_database.yml — 길목 컨테이너 안', mono: true },
    { key: 'autheliaCtrDir', label: 'config 폴더 — Authelia 컨테이너 안', mono: true, hint: '검증용 후보 파일을 이 폴더 기준으로 읽습니다 (보통 /config)' },
  ], { actions: [conn.btn], onSaved: () => conn.run(true) });

  // per-service rules, editable here (saved into the service — same data as the 서비스 tab)
  const sites = S.state.services.filter((s) => s.enabled && !s.dnsOnly);
  const onlyOn = switchCtl('Authelia를 쓰는 서비스만 보기', guarded.length > 0);
  const tbody = h('tbody');
  const saveAuth = async (svc, patch, row) => {
    row.classList.add('saving');
    try {
      const next = { ...svc.authelia, ...patch };
      await saveServicePatch(svc, { authelia: next });
      svc.authelia = next;
      toast(`${fqdn(svc.subdomain)}: ${next.enabled ? `${next.policy === 'one_factor' ? '1단계' : '2단계'}${(next.groups || []).length ? ` · ${next.groups.join(', ')}` : ''}` : 'Authelia 끔'} — 적용 대기`);
      L.set('policy', 'ok', `${settings().defaultPolicy || 'deny'} · 규칙 ${S.state.services.filter((x) => x.enabled && !x.dnsOnly && x.authelia && x.authelia.enabled).length}`);
      return true;
    } catch (ex) {
      toast(ex.message, 'err');
      return false;
    } finally { row.classList.remove('saving'); }
  };
  const picked = new Set(); // service ids selected for bulk edit
  let visible = [];
  const allCb = h('input', { type: 'checkbox', 'aria-label': '보이는 서비스 모두 선택' });
  const drawRules = () => {
    tbody.replaceChildren();
    const list = sites.filter((x) => !onlyOn.input.checked || (x.authelia && x.authelia.enabled));
    visible = list.map((x) => x.id);
    for (const id of [...picked]) if (!visible.includes(id)) picked.delete(id);
    updBulk();
    if (!list.length) {
      tbody.append(h('tr', null, h('td', { colspan: '6', class: 'muted' }, onlyOn.input.checked ? '아직 Authelia 로그인을 요구하는 서비스가 없습니다. 위 스위치를 끄면 모든 서비스가 보이고, 여기서 바로 켤 수 있습니다.' : 'Caddy 사이트가 있는 서비스가 없습니다.')));
      return;
    }
    for (const svc of list) {
      const a0 = svc.authelia || { enabled: false, policy: 'two_factor', groups: [] };
      const row = h('tr');
      const on = h('input', { type: 'checkbox', role: 'switch', checked: !!a0.enabled, 'aria-label': `${fqdn(svc.subdomain)} Authelia 로그인 요구` });
      const pol = h('select', { 'aria-label': `${fqdn(svc.subdomain)} 정책` },
        [['two_factor', '2단계 (비밀번호 + OTP 등)'], ['one_factor', '1단계 (비밀번호만)']].map(([v, l]) => h('option', { value: v, selected: (a0.policy || 'two_factor') === v }, l)));
      const grp = groupSelect(a0.groups || [], { label: `${fqdn(svc.subdomain)} 허용 그룹` });
      if (isAutheliaPortal(svc) && !a0.enabled) {
        on.disabled = true;
        on.title = 'Authelia 로그인 화면 자신이라 로그인을 걸 수 없습니다';
      }
      const sync = () => { pol.disabled = grp.disabled = !on.checked; row.classList.toggle('disabled', !on.checked); };
      sync();
      on.addEventListener('change', async () => {
        sync();
        if (!(await saveAuth(svc, { enabled: on.checked, policy: pol.value, groups: splitList(grp.value) }, row))) { on.checked = !on.checked; sync(); }
      });
      pol.addEventListener('change', () => saveAuth(svc, { policy: pol.value }, row));
      grp.addEventListener('change', () => saveAuth(svc, { groups: splitList(grp.value) }, row));
      const selCb = h('input', { type: 'checkbox', checked: picked.has(svc.id), 'aria-label': `${fqdn(svc.subdomain)} 일괄 변경에 포함` });
      selCb.addEventListener('change', () => { if (selCb.checked) picked.add(svc.id); else picked.delete(svc.id); row.classList.toggle('picked', selCb.checked); updBulk(); });
      row.classList.toggle('picked', selCb.checked);
      row.append(
        h('td', { class: 'sel-cell' }, selCb),
        h('td', null, h('b', null, svc.subdomain), h('div', { class: 'cell-sub mono' }, fqdn(svc.subdomain))),
        h('td', null, typeof expoBadge === 'function' ? expoBadge(svc) : null),
        h('td', null, h('label', { class: 'switch mini' }, on)),
        h('td', null, pol),
        h('td', { class: 'grp-cell' }, grp));
      tbody.append(row);
    }
  };
  // ---- bulk edit: policy / allowed groups / login requirement for the selected services
  const bulkCount = h('b', { class: 'bulk-count' });
  const bulkOn = h('select', { 'aria-label': '로그인 요구 일괄 변경' }, [['', '로그인 요구: 그대로'], ['on', '로그인 요구: 켜기'], ['off', '로그인 요구: 끄기']].map(([v, l]) => h('option', { value: v }, l)));
  const bulkPol = h('select', { 'aria-label': '정책 일괄 변경' }, [['', '정책: 그대로'], ['two_factor', '정책: 2단계'], ['one_factor', '정책: 1단계']].map(([v, l]) => h('option', { value: v }, l)));
  const bulkMode = h('select', { 'aria-label': '허용 그룹 일괄 변경 방식' }, [['', '허용 그룹: 그대로'], ['set', '허용 그룹: 이것으로 바꾸기'], ['add', '허용 그룹: 추가'], ['remove', '허용 그룹: 빼기'], ['clear', '허용 그룹: 비우기 (로그인한 모든 사용자)']].map(([v, l]) => h('option', { value: v }, l)));
  const bulkGrp = groupSelect([], { label: '일괄 변경할 그룹', empty: '그룹 고르기' });
  const bulkBtn = h('button', { type: 'button', class: 'btn primary sm' }, '선택한 서비스에 저장');
  const bulkClear = h('button', { type: 'button', class: 'btn ghost sm' }, '선택 해제');
  const bulkBar = h('div', { class: 'bulk-bar' },
    h('div', { class: 'bulk-head' }, bulkCount, h('span', { class: 'grow' }), bulkClear, bulkBtn),
    h('div', { class: 'bulk-ctrls' }, bulkOn, bulkPol, bulkMode, bulkGrp));
  function updBulk() {
    const n = picked.size;
    bulkCount.textContent = n ? `${n}개 선택` : '일괄 변경: 표 왼쪽에서 서비스를 고르세요';
    bulkBar.classList.toggle('active', n > 0);
    for (const el of [bulkOn, bulkPol, bulkMode, bulkGrp, bulkBtn, bulkClear]) el.disabled = !n;
    bulkGrp.hidden = !bulkMode.value || bulkMode.value === 'clear';
    allCb.checked = visible.length > 0 && visible.every((id) => picked.has(id));
    allCb.indeterminate = n > 0 && !allCb.checked;
  }
  bulkMode.addEventListener('change', updBulk);
  allCb.addEventListener('change', () => {
    for (const id of visible) { if (allCb.checked) picked.add(id); else picked.delete(id); }
    drawRules();
  });
  bulkClear.addEventListener('click', () => { picked.clear(); drawRules(); });
  bulkBtn.addEventListener('click', () => busy(bulkBtn, async () => {
    const mode = bulkMode.value;
    const g = splitList(bulkGrp.value);
    if (!bulkOn.value && !bulkPol.value && !mode) { toast('바꿀 항목(로그인 요구·정책·허용 그룹)을 하나 이상 고르세요', 'warn'); return; }
    if ((mode === 'set' || mode === 'add' || mode === 'remove') && !g.length) { toast('그룹을 고르세요', 'warn'); bulkGrp.focus(); return; }
    const targets = sites.filter((x) => picked.has(x.id));
    let changed = 0;
    const skipped = [];
    try {
      for (const svc of targets) {
        const a0 = svc.authelia || { enabled: false, policy: 'two_factor', groups: [] };
        const a = { ...a0, groups: [...(a0.groups || [])] };
        if (bulkOn.value === 'on') {
          if (isAutheliaPortal(svc)) { skipped.push(`${svc.subdomain} (Authelia 로그인 화면)`); continue; }
          a.enabled = true;
        } else if (bulkOn.value === 'off') a.enabled = false;
        if (bulkPol.value) a.policy = bulkPol.value;
        if (mode === 'set') a.groups = g;
        else if (mode === 'add') a.groups = [...new Set([...a.groups, ...g])];
        else if (mode === 'remove') a.groups = a.groups.filter((x) => !g.includes(x));
        else if (mode === 'clear') a.groups = [];
        if (JSON.stringify(a) === JSON.stringify({ ...a0, groups: a0.groups || [] })) continue;
        await api('PUT', `/api/services/${encodeURIComponent(svc.id)}`, { ...svc, authelia: a });
        svc.authelia = a;
        changed++;
      }
    } catch (ex) {
      toast(`${changed}개 저장 후 실패: ${ex.message}`, 'err');
    }
    await refreshState();
    if (changed) toast(`${changed}개 서비스 변경 — 적용 대기${skipped.length ? ` · 건너뜀: ${skipped.join(', ')}` : ''}`);
    else toast(skipped.length ? `바뀐 것 없음 · 건너뜀: ${skipped.join(', ')}` : '이미 그 값이라 바뀐 것이 없습니다', 'warn');
    picked.clear();
    renderPanel();
  }));
  onlyOn.input.addEventListener('change', drawRules);
  drawRules();
  const pickBtn = h('button', { type: 'button', class: 'btn primary sm' }, icon('plus'), '적용할 서비스 선택…');
  pickBtn.addEventListener('click', () => openAutheliaPicker());
  const rules = h('div', { class: 'table-wrap glass-inner' }, h('table', { class: 'compact policy-table' },
    h('caption', { class: 'sr-only' }, '서비스별 Authelia 접근 규칙'),
    h('thead', null, h('tr', null, h('th', { scope: 'col', class: 'sel-cell' }, allCb), ['서비스', '노출', '로그인 요구', '정책', '허용 그룹'].map((t) => h('th', { scope: 'col' }, t)))), tbody));

  // generated access_control preview
  const preview = h('details', { class: 'preset' }, h('summary', null, '생성될 access_control 보기'));
  preview.addEventListener('toggle', async () => {
    if (!preview.open) return;
    preview.querySelector('pre') && preview.querySelector('pre').remove();
    const pre = h('pre', { class: 'code' }, '불러오는 중…');
    preview.append(pre);
    try {
      const plan = await api('GET', '/api/plan?dns=0');
      pre.textContent = plan.autheliaNext || '(Authelia를 쓰지 않는 구성)';
    } catch (ex) { pre.textContent = ex.message; }
  });

  const policyForm = settingsForm([
    { key: 'defaultPolicy', type: 'select', label: '기본 정책 (default_policy)', hint: '아래 규칙에 걸리지 않은 요청의 처리. deny 권장',
      options: [['deny', 'deny — 규칙 없으면 거부'], ['one_factor', 'one_factor'], ['two_factor', 'two_factor']] },
  ], {
    extra: h('div', { class: 'stack' },
      h('div', { class: 'row wrap' }, h('h3', { class: 'grow' }, '서비스별 규칙'), onlyOn, pickBtn),
      h('p', { class: 'hint' }, '바꾸면 바로 저장되고 「적용 대기」가 됩니다 (서비스 탭의 같은 서비스 설정과 같은 값). 「적용」하면 Authelia가 재시작됩니다. 허용 그룹을 정하면 그 그룹 외 사용자는 거부하는 규칙이 함께 생성됩니다.'),
      bulkBar, rules, preview,
      h('p', { class: 'hint' }, 'configuration.yml에서 access_control: 블록만 다시 씁니다. 주석·{{ secret }} 템플릿·OIDC·notifier는 그대로 둡니다.')),
  });

  const val = validateBlock('authelia', (s, t) => L.set('validate', s, t));
  const users = usersBlock((n) => L.set('users', n ? 'ok' : 'warn', n ? `${n}명` : '사용자 없음'));

  L = stepsLayout(panel, {
    title: 'Authelia',
    lead: '로그인·2단계 인증. 연결 → 접근 정책 → 검증 순서로 확인하세요. 사용자·그룹은 아래 개별 항목에서 언제든 관리합니다. 설정이 바뀌면 적용 때 Authelia가 재시작되고, 실패하면 자동으로 되돌립니다.',
    steps: [
      { id: 'conn', title: '컨테이너 연결', desc: '설정 파일 읽기·쓰기와 컨테이너가 같은 파일을 보는지 확인합니다.', state: 'wait',
        body: h('div', { class: 'stack' }, typeof stackCard === 'function' ? stackCard('authelia', () => conn.run(true)) : null, conn.box, h('hr', { class: 'sep' }), connForm) },
      { id: 'policy', title: '접근 정책', desc: '기본 정책과 서비스마다 로그인 요구·정책(1단계/2단계)·허용 그룹을 여기서 바로 정합니다.', state: 'ok', stateText: `${st.defaultPolicy || 'deny'} · 규칙 ${guarded.length}`,
        body: policyForm },
      { id: 'validate', title: '생성 결과 검증', desc: 'access_control을 바꾼 configuration.yml을 Authelia 컨테이너 안에서 검증합니다. 재시작하지 않습니다.',
        state: S.validated.authelia ? (S.validated.authelia.ok ? 'ok' : 'fail') : 'todo', stateText: S.validated.authelia ? (S.validated.authelia.ok ? '검증 통과' : '검증 실패') : '',
        body: val.body },
      { id: 'people', title: '사용자 · 그룹', aside: true, desc: '로그인할 사람과 그룹. 그룹은 서비스의 「허용 그룹」에서 골라 씁니다.', children: [
        { id: 'users', title: '사용자', desc: 'users_database.yml — 저장하면 바로 Authelia가 재시작됩니다 (적용 버튼과 별개).', state: 'wait',
          body: users },
        { id: 'groups', title: '그룹',
          state: 'info', stateText: `${(S.state.autheliaGroups || []).length}개`,
          body: groupsPanel(() => { renderPanel(); }, (n, undef) => L.set('groups', undef ? 'warn' : 'info', undef ? `목록에 없는 그룹 ${undef}개` : `${n}개`)).el },
      ] },
      { id: 'update', title: '이미지 업데이트', aside: true, desc: 'docker compose로 최신 이미지를 받아 다시 만듭니다.', state: 'opt',
        body: updateBlock('authelia', (s, t) => L.set('update', s, t)) },
    ],
  });
}

// ---- users (inside the Authelia tab)

async function loadUsers() {
  S.users = (await api('GET', '/api/users')) || [];
}

function usersBlock(onCount) {
  const add = h('button', { type: 'button', class: 'btn primary', disabled: !can('authelia_users'), title: can('authelia_users') ? '' : '사용자 추가에는 「Authelia 사용자」 권한이 필요합니다' }, icon('plus'), '사용자 추가');
  const reload = h('button', { type: 'button', class: 'btn' }, icon('refresh'), '새로고침');
  const box = h('div', { class: 'table-wrap' }, spinnerRow('users_database.yml 읽는 중…'));
  const draw = () => {
    onCount && onCount(S.users.length);
    if (!S.users.length) { box.replaceChildren(h('div', { class: 'empty' }, '사용자가 없습니다.')); return; }
    box.replaceChildren(h('table', null,
      h('caption', { class: 'sr-only' }, 'Authelia 사용자'),
      h('thead', null, h('tr', null, ['아이디', '표시 이름', '이메일', '그룹', '상태'].map((t) => h('th', { scope: 'col' }, t)))),
      h('tbody', null, S.users.map((u) => {
        const open = h('button', { type: 'button', class: 'link-btn' }, h('b', null, u.username));
        open.addEventListener('click', (e) => { e.stopPropagation(); openUserDrawer(u); });
        const tr = h('tr', { class: `clickable ${u.disabled ? 'disabled' : ''}` },
          h('td', null, open),
          h('td', null, u.displayname || h('span', { class: 'dash' }, '—')),
          h('td', { class: 'mono' }, u.email || h('span', { class: 'dash' }, '—')),
          h('td', null, (u.groups || []).length ? h('div', { class: 'chips' }, u.groups.map((g) => h('span', { class: 'badge accent' }, g))) : h('span', { class: 'dash' }, '—')),
          h('td', null, u.disabled ? h('span', { class: 'badge muted' }, '비활성') : h('span', { class: 'badge ok' }, '활성')));
        tr.addEventListener('click', () => openUserDrawer(u));
        return tr;
      }))));
  };
  const load = async () => {
    try {
      await loadUsers();
      if (box.isConnected) draw();
    } catch (ex) {
      box.replaceChildren(h('div', { class: 'empty' }, errorBox(ex.message)));
      onCount && onCount(0);
    }
  };
  S.usersRedraw = () => { if (box.isConnected) draw(); };
  add.addEventListener('click', () => openUserDrawer(null));
  reload.addEventListener('click', () => busy(reload, load));
  if (S.users) queueMicrotask(draw); else load();
  return h('div', { class: 'stack' }, h('div', { class: 'row' }, h('span', { class: 'grow' }), reload, add), box);
}

// ======================================================================= Cloudflare tab

function renderCloudflare(panel) {
  const st = S.state;
  let L;
  const conn = connectionBlock('cloudflare', (r) => L.set('token', r.status || 'fail', r.status === 'ok' ? '연결됨' : checkStateText(r)));
  const tokenCard = cfTokenCard(async () => { if (S.checks) delete S.checks.cloudflare; S.dns = null; await refreshState(); renderPanel(); });


  const ddnsForm = settingsForm([
    { key: 'ddnsEnabled', type: 'switch', label: 'DDNS Updater 사용', hint: '공인 IP가 바뀌면 공개 서비스의 레코드 주소를 고칩니다. 길목이 웹 서버와 같은 네트워크(같은 공유기)에서 실행될 때만 켜세요 — 다른 곳(테스트 PC 등)에서 켜면 그곳의 IP로 바꿔 버립니다. 다른 DDNS 도구(예: favonia/cloudflare-ddns 컨테이너)가 같은 레코드를 고치고 있다면 둘 중 하나만 켜세요.' },
    { key: 'ddnsIntervalMin', type: 'number', label: '확인 주기 (분)', attrs: { min: '1', max: '1440' } },
    { key: 'ddnsIpv6', type: 'switch', label: 'IPv6 (AAAA 레코드)도 관리', hint: '공개 서비스마다 AAAA 레코드를 만들고 IPv6 주소가 바뀌면 고칩니다. 레코드 생성·삭제는 「적용」 때 합니다. 끄면 길목이 만든 AAAA만 지웁니다.' },
  ], { onSaved: (p) => { L.set('ddns', ddnsState(p).state, ddnsState(p).text); refreshState().then(() => fill(ddnsBox, ddnsStatusView())); } });
  const ddnsBox = h('div', { class: 'stack' }, ddnsStatusView());
  const ddnsWarn = callout('warn', h('b', null, 'IPv6를 켜기 전에 확인하세요'),
    h('ul', null,
      h('li', null, '길목이 IPv6 주소를 알아내려면 길목이 도는 곳(컨테이너 또는 PC)에 IPv6 인터넷 연결이 있어야 합니다. Docker는 기본으로 IPv6가 꺼져 있어 확인에 실패할 수 있습니다 — 아래 「지금 확인」으로 먼저 보세요.'),
      h('li', null, 'IPv6에는 NAT·포트포워딩이 없습니다. 공유기의 IPv4 허용 목록(국가·Cloudflare 대역 등)이 IPv6에는 적용되지 않을 수 있으니, 공유기의 IPv6 방화벽에서 443만 이 서버로 허용됐는지 확인하세요. 특히 DNS only 서비스는 IPv6로 직접 노출됩니다.'),
      h('li', null, '들어오는 IPv6 연결이 Caddy까지 실제로 닿는지(Docker의 IPv6 포트 게시 등)도 확인해야 합니다. 닿지 않으면 IPv6로 접속하는 사람에게 사이트가 열리지 않습니다.')));
  const showWarn = () => { ddnsWarn.hidden = !settings().ddnsIpv6; };
  showWarn();
  ddnsForm.addEventListener('change', (e) => { if (e.target && e.target.dataset && e.target.dataset.key === 'ddnsIpv6') ddnsWarn.hidden = !e.target.checked; });

  const records = h('div', { class: 'stack' });
  if (st.cfConfigured) dnsTable(records); else records.append(h('p', { class: 'muted' }, '토큰을 설정하면 레코드 목록이 보입니다.'));

  const s = settings();
  L = stepsLayout(panel, {
    title: 'Cloudflare',
    lead: `DNS 자동화와 엣지 보안. 레코드는 적용할 때 서비스 설정에 맞춰 생성·수정·삭제됩니다 (앱이 만든 레코드만). 도메인${privOn() ? (use('tailscale') ? '·Tailscale IP' : '·사설 IP') : ''}는 설정 탭 › 도메인에서 정합니다.`,
    steps: [
      { id: 'token', title: 'API 토큰 · 존', desc: st.cfConfigured ? '토큰이 이 도메인을 관리할 수 있는지 확인합니다.' : '먼저 Cloudflare에서 토큰을 만들어 넣으세요.', state: 'wait',
        body: h('div', { class: 'stack' }, conn.box, h('div', { class: 'row' }, conn.btn), tokenCard) },
      { id: 'records', title: 'DNS 레코드', aside: true, desc: '존의 모든 레코드와 서비스 설정의 차이. 서비스와 관계없는 레코드는 여기서 직접 추가·수정·삭제합니다.', state: st.cfConfigured ? 'info' : 'opt', stateText: `앱 관리 ${(st.managedDns || []).length}개`,
        body: records },
      { id: 'ddns', title: 'DDNS Updater', aside: true, desc: '공인 IP(IPv4·IPv6) 변경 감시 (선택).', state: ddnsState(s).state, stateText: ddnsState(s).text,
        body: h('div', { class: 'stack' }, ddnsForm, ddnsWarn, ddnsBox) },
      { id: 'edge', title: '엣지 보안', aside: true, desc: 'Cloudflare 엣지에서 막는 규칙과 그 기록 — Proxied 사이트에만 적용됩니다.', children: [
        { ...cfWafStep(() => L), title: 'WAF 규칙' },
        { ...cfEventsStep(), title: '차단 기록' },
      ] },
    ],
  });
}

/** Cloudflare API token: status + how to make one + input (value never comes back from the server). */
function cfTokenCard(onChanged) {
  const st = S.state;
  const src = st.cfTokenSource || '';
  const fromCtr = src === 'container-file' || src === 'container-env';
  const dom = settings().domain || '';
  const box = h('div', { class: 'stack' });

  const how = h('details', { class: 'howto', open: !st.cfConfigured },
    h('summary', null, h('b', null, 'Cloudflare에서 토큰 만드는 방법 (2분)')),
    h('ol', { class: 'howto-list' },
      h('li', null, h('a', { href: 'https://dash.cloudflare.com/profile/api-tokens', target: '_blank', rel: 'noopener noreferrer' }, 'Cloudflare 대시보드 › 내 프로필 › API 토큰'), '을 엽니다 (새 창).'),
      h('li', null, '「토큰 생성」 → 템플릿 「', h('b', null, '영역 DNS 편집'), '」(Edit zone DNS)의 「템플릿 사용」을 누릅니다.'),
      h('li', null, '권한에 두 줄이 있어야 합니다:',
        h('ul', null,
          h('li', null, h('code', null, '영역 · DNS · 편집'), ' (Zone · DNS · Edit) — 템플릿에 이미 있음'),
          h('li', null, h('code', null, '영역 · 영역 · 읽기'), ' (Zone · Zone · Read) — 「+ 더 추가」로 넣기'))),
      h('li', null, '영역 리소스: 「포함 › 특정 영역 › ', h('b', null, dom || '내 도메인'), '」.'),
      h('li', null, '「요약 계속」 → 「토큰 생성」 → 나온 토큰을 복사해 아래에 붙여넣습니다. Cloudflare는 토큰을 한 번만 보여 줍니다.')),
    use('crowdsec') || (st.settings || {}).cfAsnRule
      ? h('p', { class: 'hint' }, 'Cloudflare WAF 규칙·CrowdSec 차단 목록까지 쓰려면 권한을 더 넣으세요: ', h('code', null, '영역 · 영역 WAF · 편집'), ', ', h('code', null, '계정 · 계정 필터 목록 · 편집'), ' (계정 리소스: 내 계정).')
      : h('p', { class: 'hint' }, '나중에 WAF 규칙·CrowdSec까지 쓰면 ', h('code', null, '영역 WAF 편집'), '·', h('code', null, '계정 필터 목록 편집'), ' 권한이 더 필요합니다 (Cloudflare에서 같은 토큰을 편집해 추가).'),
    h('p', { class: 'hint' }, '「Global API Key」는 쓰지 마세요 — 계정 전체 권한이라 위험하고, 길목도 받지 않습니다.'));

  if (fromCtr) {
    box.append(callout('info',
      h('b', null, `토큰 출처: ${src === 'container-file' ? '컨테이너 secret 파일 (GM_CF_TOKEN_FILE)' : '컨테이너 환경변수 (GM_CF_TOKEN)'}`),
      h('span', { class: 'small' }, '배포 설정에서 넣은 토큰이 우선합니다. 바꾸려면 그 파일(예: secrets/cf_token)이나 환경변수를 고친 뒤 길목 컨테이너를 다시 시작하세요. 위 점검에서 권한 문제가 보이면 Cloudflare에서 같은 토큰을 편집해 권한만 추가하면 됩니다 (값은 그대로).')),
      how);
    return box;
  }

  const input = h('input', { type: 'password', autocomplete: 'off', spellcheck: 'false', class: 'mono', placeholder: st.cfConfigured ? '새 토큰으로 바꿀 때만 붙여넣기' : 'Cloudflare에서 복사한 토큰 붙여넣기' });
  input.id = uid('cft');
  const err = h('p', { class: 'form-error', role: 'alert', hidden: true });
  const save = h('button', { type: 'submit', class: 'btn primary' }, st.cfConfigured ? '확인 후 교체' : '확인 후 저장');
  const form = h('form', { class: 'stack', novalidate: true },
    h('div', { class: 'field' }, h('label', { for: input.id }, 'API 토큰'), input,
      h('p', { class: 'hint' }, `저장 전에 Cloudflare에 물어 「토큰이 유효한지 · ${dom || '도메인'} 존을 볼 수 있는지 · DNS를 읽을 수 있는지」 확인합니다. 하나라도 실패하면 저장하지 않습니다. 저장된 토큰은 길목 데이터 폴더(secrets/cf_token)에만 있고 화면·로그에 다시 나오지 않습니다.`)),
    err, h('div', { class: 'row' }, save));
  form.addEventListener('submit', (e) => {
    e.preventDefault();
    err.hidden = true;
    const v = input.value.trim();
    if (!v) { err.textContent = '토큰을 붙여넣으세요.'; err.hidden = false; input.focus(); return; }
    if (!dom) { err.textContent = '먼저 「도메인」 단계에서 도메인을 저장하세요 — 토큰이 그 존을 볼 수 있는지 확인합니다.'; err.hidden = false; return; }
    busy(save, async () => {
      try {
        await api('POST', '/api/cloudflare/token', { token: v });
        input.value = '';
        toast(`토큰 확인 완료 — ${dom} 존에 접근할 수 있습니다`);
        await onChanged();
      } catch (ex) {
        err.textContent = ex.message; err.hidden = false;
      }
    });
  });

  let del = null;
  if (st.cfConfigured) {
    del = h('button', { type: 'button', class: 'btn ghost' }, '저장된 토큰 삭제');
    del.addEventListener('click', async () => {
      const ok = await confirmDialog({ title: 'Cloudflare 토큰 삭제', message: '토큰을 지우면 DNS 동기화·DDNS Updater·WAF 규칙·CrowdSec 차단 전송이 멈춥니다. Cloudflare에 있는 레코드·규칙은 그대로 남습니다. 삭제할까요?' });
      if (!ok) return;
      busy(del, async () => {
        try { await api('DELETE', '/api/cloudflare/token'); toast('토큰을 삭제했습니다', 'warn'); await onChanged(); } catch (ex) { toast(ex.message, 'err'); }
      });
    });
  }
  box.append(
    st.cfConfigured
      ? callout('ok', h('b', null, '토큰 출처: 이 화면에서 입력'), h('span', { class: 'small' }, '바꾸려면 새 토큰을 붙여넣고 「확인 후 교체」를 누르세요.'), h('div', { class: 'row' }, del))
      : callout('warn', h('b', null, 'Cloudflare API 토큰이 없습니다.'),
        h('span', { class: 'small' }, '토큰이 없으면 DNS 레코드 동기화·DDNS Updater·WAF 규칙을 건너뜁니다. 아래 방법대로 만들어 붙여넣으세요.')),
    how, form);
  return box;
}

function ddnsState(s) {
  if (!s.ddnsEnabled) return { state: 'opt', text: '사용 안 함' };
  const d = (S.state && S.state.ddns) || {};
  if (d.result === 'fail') return { state: 'fail', text: '실패 — 재시도 중' };
  return { state: 'ok', text: `${s.ddnsIntervalMin}분마다${s.ddnsIpv6 ? ' · IPv4+IPv6' : ''}` };
}

/** Last DDNS Updater run + 「지금 확인」. */
function ddnsStatusView() {
  const st = S.state;
  const s = settings();
  const d = st.ddns || {};
  const run = h('button', { type: 'button', class: 'btn' }, icon('refresh'), '지금 확인');
  run.disabled = !s.ddnsEnabled || !st.cfConfigured;
  run.title = !s.ddnsEnabled ? 'DDNS Updater를 켜고 저장하면 쓸 수 있습니다' : !st.cfConfigured ? 'Cloudflare 토큰이 필요합니다' : '공인 IP를 확인하고 다른 레코드를 바로 고칩니다';
  run.addEventListener('click', () => busy(run, async () => {
    try {
      const r = await api('POST', '/api/ddns/run');
      await refreshState();
      toast(r.msg || '확인했습니다', r.result === 'fail' ? 'err' : 'ok');
    } catch (ex) { toast(ex.message, 'err'); }
    fill(view.parentNode || view, ddnsStatusView());
  }));
  const kinds = { ok: ['정상', 'ok'], updated: ['레코드 수정함', 'ok'], fail: ['실패', 'danger'] };
  const [rt, rc] = kinds[d.result] || ['아직 확인 안 함', 'muted'];
  const t = (iso) => (iso && !iso.startsWith('0001-') ? fmtTime(iso) : '—');
  const ipRow = (label, ip, err, on) => !on ? null : [h('dt', null, label), h('dd', null,
    ip ? h('span', { class: 'mono' }, ip) : null, err ? h('div', { class: 'small', style: 'color: var(--warn)' }, err) : (!ip ? '—' : null))];
  const list = (title, items, cls) => items && items.length ? h('div', { class: 'small' }, h('b', null, title),
    h('ul', { class: `ddns-list ${cls}` }, items.map((x) => h('li', { class: 'mono' }, x)))) : null;
  const view = h('div', { class: 'ddns-status' },
    h('div', { class: 'row' }, h('span', { class: `badge ${rc}` }, rt), h('span', { class: 'small muted grow' }, d.msg || (s.ddnsEnabled ? '첫 확인을 기다리는 중입니다' : 'DDNS Updater가 꺼져 있습니다')), run),
    h('dl', { class: 'kv' },
      h('dt', null, '마지막 확인'), h('dd', null, t(d.checked)),
      h('dt', null, '마지막 비교'), h('dd', null, t(d.synced), h('span', { class: 'small muted' }, ' (주소가 그대로여도 1시간마다 Cloudflare와 비교)')),
      h('dt', null, '마지막 수정'), h('dd', null, t(d.changed)),
      ipRow('IPv4', d.ip4 || st.lastPublicIp, d.ip4Err, true),
      ipRow('IPv6', d.ip6 || st.lastPublicIp6, d.ip6Err, !!s.ddnsIpv6)),
    list('수정한 레코드', d.updated, 'ok'),
    list('실패한 레코드 (다음 확인 때 다시 시도)', d.failed, 'fail'),
    h('p', { class: 'hint' }, 'DDNS Updater는 이미 있는 레코드의 주소만 고칩니다. 레코드 생성·삭제와 Proxied/DNS only 전환은 「적용」에서 합니다. 주소 변경·실패·복구는 로그 › 시스템에 남습니다.'));
  return view;
}

const DNS_STATUS = {
  ok: ['✓ 서비스와 같음', 'ok'], diff: ['다름', 'warn'], missing: ['없음', 'warn'], orphan: ['삭제 예정', 'danger'], unknown: ['확인 불가', 'muted'],
};

function dnsTable(wrap) {
  const st = S.state;
  const q = h('input', { type: 'search', placeholder: '이름·내용 검색', 'aria-label': 'DNS 검색' });
  const kind = h('select', { 'aria-label': '보기', style: { width: 'auto' } },
    [['main', 'A·AAAA·CNAME'], ['all', '모든 유형'], ['issue', '서비스와 다른 것만'], ['manual', '수동 레코드만']].map(([v, l]) => h('option', { value: v }, l)));
  const reload = h('button', { type: 'button', class: 'btn' }, icon('refresh'), '새로고침');
  const add = h('button', { type: 'button', class: 'btn primary' }, icon('plus'), '레코드 추가');
  add.addEventListener('click', () => openDNSEditor(null, refresh));
  const summary = h('div', { class: 'stack tight' });
  const box = h('div', { class: 'table-wrap' });
  wrap.append(
    summary,
    h('div', { class: 'toolbar' }, h('div', { class: 'search' }, icon('search'), q), kind, h('span', { class: 'grow' }),
      h('span', { class: 'small muted' }, `공인 IP(마지막 확인): ${st.lastPublicIp || '—'}`), reload, add),
    box);

  const refresh = async () => { await loadDNS(true); if (S.dnsErr) toast(S.dnsErr, 'err'); draw(); };
  const takeOver = async (r) => {
    const svc = S.state.services.find((x) => x.id === r.serviceId);
    if (!svc) return;
    const ok = await confirmDialog({
      title: `${r.name} — 길목이 관리`,
      message: `서비스 「${svc.subdomain}」의 「DNS 자동 관리」를 켭니다.\n적용하면 이 레코드를 서비스 설정에 맞춥니다 (${svc.exposure === 'public' ? `공인 IP · ${svc.proxied ? 'Proxied' : 'DNS only'}` : '사설 IP'}). 서비스를 지우거나 끄면 레코드도 지웁니다.\n지금 값: ${r.content}${r.proxied ? ' (Proxied)' : ''}`,
      okText: '길목이 관리',
    });
    if (!ok) return;
    try {
      await saveServicePatch(svc, { manageDns: true });
      toast(`${r.name} 을 길목이 관리합니다 — 적용 대기`);
      await refresh();
    } catch (ex) { toast(ex.message, 'err'); }
  };
  const del = async (r) => {
    const ok = await confirmDialog({
      title: 'DNS 레코드 삭제',
      message: `${r.type} ${r.name} → ${r.content}\n\nCloudflare에서 바로 지웁니다 (적용 단계 없음, 되돌리기 없음). 이 이름으로 쓰던 접속이 끊길 수 있습니다.`,
      okText: '삭제', danger: true,
    });
    if (!ok) return;
    try {
      await api('DELETE', `/api/dns/records/${encodeURIComponent(r.id)}`);
      toast(`${r.type} ${r.name} 삭제됨`, 'warn');
      await refresh();
    } catch (ex) { toast(ex.message, 'err'); }
  };

  const draw = () => {
    if (S.dnsErr && !S.dns) { box.replaceChildren(h('div', { class: 'empty' }, errorBox(S.dnsErr))); return; }
    if (!S.dns) { box.replaceChildren(spinnerRow('Cloudflare에서 레코드를 읽는 중…')); return; }
    // summary of differences with the services
    const cnt = (x) => S.dns.filter((r) => r.status === x).length;
    const nIP = S.dns.filter((r) => r.status === 'diff' && r.ipChange).length;
    const nDiff = cnt('diff') - nIP; const nMiss = cnt('missing'); const nOrph = cnt('orphan'); const nUnk = cnt('unknown');
    const openPlan = h('button', { type: 'button', class: 'btn sm' }, '적용 화면에서 보기');
    openPlan.addEventListener('click', () => openApply());
    summary.replaceChildren();
    if (nDiff + nMiss + nOrph) {
      summary.append(callout('warn', h('b', null, `서비스 설정과 다른 레코드: 다름 ${nDiff} · 없음 ${nMiss} · 삭제 예정 ${nOrph}`),
        h('span', { class: 'small' }, '「적용」하면 서비스 설정에 맞춰 고치고·만들고·지웁니다. 아래 「상태」 열에 무엇이 바뀌는지 적혀 있습니다.'), h('div', null, openPlan)));
    }
    if (nIP) {
      const ips = [...new Set(S.dns.filter((r) => r.status === 'diff' && r.ipChange).map((r) => r.content))].join(', ');
      summary.append(callout('', h('b', null, `주소 다름 ${nIP}개 — 적용해도 기본으로는 바꾸지 않습니다`),
        h('span', { class: 'small' }, `레코드는 ${ips}, 길목이 마지막으로 본 공인 IP는 ${st.lastPublicIp || '—'} 입니다. 길목이 웹 서버와 다른 네트워크(예: 테스트 PC)에서 돌고 있다면 레코드 쪽이 맞는 값이니 그대로 두세요. 공인 IP가 정말 바뀐 것이라면 적용할 때 「공인 IP 변경 반영」을 체크하거나 DDNS Updater를 쓰세요.`)));
    }
    if (!(nDiff + nMiss + nOrph + nIP) && S.dns.some((r) => r.status === 'ok')) {
      summary.append(callout('ok', h('b', null, '✓ 길목이 관리하는 레코드가 모두 서비스 설정과 같습니다')));
    }
    if (nUnk) summary.append(callout('', h('span', { class: 'small' }, `확인 불가 ${nUnk}개 — 공인 IP를 아직 모르거나(DDNS Updater·적용 때 확인) 사설 IP가 비어 있습니다.`)));

    const term = q.value.trim().toLowerCase();
    const v = kind.value;
    const rows = S.dns.filter((r) => {
      if (v === 'main' && !['A', 'AAAA', 'CNAME'].includes(r.type)) return false;
      if (v === 'issue' && !['diff', 'missing', 'orphan'].includes(r.status)) return false;
      if (v === 'manual' && !(r.editable && !r.managed)) return false;
      return !term || `${r.name} ${r.content || ''} ${r.comment || ''} ${r.service || ''}`.toLowerCase().includes(term);
    });
    if (!rows.length) { box.replaceChildren(h('div', { class: 'empty' }, v === 'issue' ? '서비스와 다른 레코드가 없습니다.' : '레코드가 없습니다.')); return; }
    box.replaceChildren(h('table', { class: 'dns-table' },
      h('caption', { class: 'sr-only' }, 'Cloudflare DNS 레코드'),
      h('thead', null, h('tr', null, ['이름', '유형', '내용', '프록시', '서비스', '상태', '관리'].map((t) => h('th', { scope: 'col' }, t)))),
      h('tbody', null, rows.map((r) => {
        const content = r.missing ? h('span', { class: 'muted' }, '(아직 없음)')
          : r.content === st.settings.tailscaleIp
            ? h('span', null, h('span', { class: 'mono' }, r.content), ' ', h('span', { class: 'badge ts' }, privOn() && use('tailscale') ? 'Tailscale' : '사설'))
            : h('span', { class: 'mono' }, r.type === 'MX' ? `${r.priority ?? ''} ${r.content}` : r.content);
        const [stT, stC] = r.ipChange ? ['주소 다름 (보류)', 'muted'] : DNS_STATUS[r.status] || ['', ''];
        const status = r.status
          ? h('div', null, h('span', { class: `badge ${stC}` }, stT),
            (r.status === 'diff' && !r.ipChange) || r.status === 'missing' ? h('div', { class: 'cell-sub' }, `적용하면 → ${r.desired}`) : null,
            r.ipChange ? h('div', { class: 'cell-sub', title: r.reason }, `길목이 본 IP: ${(r.desired || '').replace(/ \(.*\)$/, '')}`) : null,
            r.reason && r.status !== 'missing' && !r.ipChange ? h('div', { class: 'cell-sub' }, r.reason) : null)
          : h('span', { class: 'dash' }, '—');
        let mgmt;
        if (r.managed || r.svcManage) mgmt = h('span', { class: 'badge ok', title: '서비스 설정대로 길목이 만들고 고치고, 서비스를 지우거나 끄면 지웁니다' }, '앱 관리');
        else if (r.serviceId && !r.missing) {
          const b = h('button', { type: 'button', class: 'btn sm', title: '이 서비스의 「DNS 자동 관리」를 켜서 길목이 맞춥니다' }, '길목이 관리');
          b.addEventListener('click', () => takeOver(r));
          mgmt = h('div', null, h('span', { class: 'badge muted', title: '서비스는 있지만 「DNS 자동 관리」가 꺼져 있습니다' }, '수동'), ' ', b);
        } else mgmt = h('span', { class: 'badge muted', title: '서비스와 관계없는 레코드 — 길목이 적용 때 건드리지 않습니다' }, '수동');
        let acts = null;
        if (r.editable && !r.missing) {
          const e = h('button', { type: 'button', class: 'btn sm', 'aria-label': `${r.type} ${r.name} 편집` }, '편집');
          e.addEventListener('click', () => openDNSEditor(r, refresh));
          const d = h('button', { type: 'button', class: 'btn sm ghost', 'aria-label': `${r.type} ${r.name} 삭제` }, '삭제');
          d.addEventListener('click', () => del(r));
          acts = h('div', { class: 'row nowrap dns-acts' }, e, d);
        }
        return h('tr', { class: r.missing ? 'missing' : '' },
          h('td', { class: 'mono' }, r.name, r.comment ? h('div', { class: 'cell-sub' }, r.comment) : null),
          h('td', null, h('span', { class: 'badge' }, r.type)),
          h('td', null, content),
          h('td', null, r.missing || !['A', 'AAAA', 'CNAME'].includes(r.type) ? h('span', { class: 'dash' }, '—') : r.proxied
            ? h('span', { class: 'badge' }, icon('cloud', 'fill cloud-orange'), 'Proxied')
            : h('span', { class: 'badge' }, icon('cloud', 'fill cloud-gray'), 'DNS only')),
          h('td', null, r.service ? h('span', { class: 'badge accent' }, r.service) : h('span', { class: 'dash' }, '—')),
          h('td', null, status),
          h('td', { class: 'dns-mgmt-cell' }, h('div', { class: 'row nowrap dns-mgmt' }, mgmt, acts)));
      }))));
  };
  q.addEventListener('input', draw);
  kind.addEventListener('change', draw);
  reload.addEventListener('click', () => busy(reload, refresh));
  draw();
  if (!S.dns) loadDNS().then(() => { if (box.isConnected) draw(); });
}

/** Add / edit a record that no service manages. r = null → new. */
function openDNSEditor(r, onDone) {
  const dom = settings().domain || '';
  const isNew = !r;
  const short = (n) => (n === dom ? '@' : n && n.endsWith(`.${dom}`) ? n.slice(0, -dom.length - 1) : n || '');
  const type = h('select', null, ['A', 'AAAA', 'CNAME', 'TXT', 'MX'].map((t) => h('option', { value: t, selected: (r ? r.type : 'A') === t }, t)));
  const name = h('input', { type: 'text', value: r ? short(r.name) : '', placeholder: 'www 또는 @ (도메인 자체)', autocomplete: 'off', spellcheck: 'false', class: 'mono' });
  const content = h('input', { type: 'text', value: r ? r.content : '', autocomplete: 'off', spellcheck: 'false', class: 'mono' });
  const prio = h('input', { type: 'number', min: '0', max: '65535', value: r && r.priority != null ? String(r.priority) : '10' });
  const ttl = h('select', null, [['1', '자동'], ['300', '5분'], ['3600', '1시간'], ['86400', '1일']].map(([v, l]) => h('option', { value: v, selected: String(r ? r.ttl || 1 : 1) === v }, l)));
  const proxied = switchCtl('Proxied (Cloudflare 프록시)', r ? r.proxied : false, '켜면 Cloudflare를 거쳐 들어오고 실제 IP가 숨겨집니다. 끄면 DNS only.');
  const comment = h('input', { type: 'text', value: r ? r.comment || '' : '', maxlength: '100', autocomplete: 'off', placeholder: '예: 원격 데스크톱용' });
  const nameHint = h('span', { class: 'mono small muted' });
  const contentField = field('내용', content);
  const prioField = field('우선순위 (MX)', prio, '숫자가 작을수록 먼저');
  const err = h('p', { class: 'form-error', role: 'alert', hidden: true });
  const PH = { A: '203.0.113.10', AAAA: '2001:db8::10', CNAME: 'target.example.com', TXT: 'v=spf1 include:_spf.example.com ~all', MX: 'mail.example.com' };
  const LBL = { A: '내용 — IPv4 주소', AAAA: '내용 — IPv6 주소', CNAME: '내용 — 가리킬 도메인', TXT: '내용 — 텍스트', MX: '내용 — 메일 서버' };
  const sync = () => {
    const t = type.value;
    content.placeholder = PH[t];
    contentField.querySelector('label').textContent = LBL[t];
    prioField.hidden = t !== 'MX';
    proxied.hidden = !['A', 'AAAA', 'CNAME'].includes(t);
    ttl.disabled = proxied.input.checked && !proxied.hidden;
    const n = name.value.trim().toLowerCase();
    nameHint.textContent = `→ ${!n || n === '@' ? dom : n.endsWith(dom) ? n : `${n}.${dom}`}`;
  };
  const form = h('form', { class: 'stack', novalidate: true }, err,
    h('div', { class: 'grid-2' }, field('유형', type), h('div', { class: 'field' }, h('label', null, '이름'), name, nameHint)),
    contentField, prioField, proxied,
    h('div', { class: 'grid-2' }, field('TTL', ttl, 'Proxied면 항상 자동'), field('메모', comment, 'Cloudflare 레코드 메모로 저장됩니다')),
    h('p', { class: 'hint' }, '저장하면 Cloudflare에 바로 반영됩니다 (적용 단계 없음). 서비스가 관리하는 이름은 여기서 만들 수 없습니다 — 서비스 탭에서 바꾸세요.'));
  form.addEventListener('input', sync);
  form.addEventListener('change', sync);
  sync();
  const save = h('button', { type: 'submit', class: 'btn primary', title: '「적용」을 기다리지 않고 Cloudflare에 바로 반영합니다' }, isNew ? '추가 · Cloudflare에 바로 반영' : '저장 · Cloudflare에 바로 반영');
  const cancel = h('button', { type: 'button', class: 'btn ghost' }, '취소');
  save.setAttribute('form', form.id = uid('form'));
  const d = openDialog({ title: isNew ? 'DNS 레코드 추가' : `${r.type} ${r.name} 편집`, body: form, footer: [h('span', { class: 'spacer' }), cancel, save] });
  cancel.addEventListener('click', () => d.close());
  form.addEventListener('submit', (e) => {
    e.preventDefault();
    err.hidden = true;
    const body = { type: type.value, name: name.value.trim() || '@', content: content.value.trim(), proxied: !proxied.hidden && proxied.input.checked,
      ttl: parseInt(ttl.value, 10) || 1, priority: parseInt(prio.value, 10) || 0, comment: comment.value.trim() };
    if (!body.content) { err.textContent = '내용을 입력하세요'; err.hidden = false; content.focus(); return; }
    busy(save, async () => {
      try {
        if (isNew) await api('POST', '/api/dns/records', body);
        else await api('PUT', `/api/dns/records/${encodeURIComponent(r.id)}`, body);
        toast(`${body.type} ${body.name === '@' ? dom : body.name} ${isNew ? '추가' : '수정'}됨`);
        d.close();
        onDone && onDone();
      } catch (ex) { err.textContent = ex.message; err.hidden = false; }
    });
  });
}

// ======================================================================= 길목 tab

const FAULTS = [
  ['authelia-start', 'Authelia 시작 실패', '다음 적용에서 검증 통과 후 깨진 configuration.yml을 씁니다 → Authelia 재시작 실패 → 원래 파일로 복구·재시작되어야 합니다.'],
  ['caddy-reload', 'Caddy reload 실패', '다음 적용에서 깨진 Caddyfile을 씁니다 → reload 실패 → Caddyfile 복구 (같은 적용에서 바뀐 다른 구성요소도 함께 되돌아가야 합니다).'],
  ['users-start', '사용자 저장 후 Authelia 시작 실패', '다음 사용자 저장에서 깨진 users_database.yml을 씁니다 → 원래 파일로 복구되어야 합니다.'],
];

/** 길목 › 구성요소: which parts of the edge this installation uses (saved with step-up auth). */
/** "Caddyfile·access_control·DNS" — only the sources of the components in use. */
function importSources() {
  return ['Caddyfile', use('authelia') ? 'Authelia access_control' : null, use('cloudflare') ? 'Cloudflare DNS' : null].filter(Boolean).join('·');
}

function componentsStep() {
  const set = settings();
  const icoSvg = (name) => {
    const el = sv('svg', { viewBox: '0 0 26 26', width: 26, height: 26, class: 'wz-ico', 'aria-hidden': 'true' });
    el.append(topoIcon(name, 13, 13, 24, TC.accentText));
    return el;
  };
  const boxes = {};
  const grid = h('div', { class: 'comp-cards' }, COMPONENTS.map((c) => {
    const cb = h('input', { type: 'checkbox', checked: !!set[c.flag] });
    boxes[c.key] = cb;
    const note = h('small', { class: 'comp-off' });
    const card = h('label', { class: 'comp-card' }, cb,
      h('span', { class: 'cc-head' }, icoSvg(c.icon), h('span', null, h('b', null, c.name), h('small', null, c.role))),
      h('small', { class: 'cc-desc' }, c.desc), note);
    const sync = () => {
      card.classList.toggle('on', cb.checked);
      note.textContent = cb.checked ? '' : c.off;
    };
    cb.addEventListener('change', sync);
    sync();
    return card;
  }));
  const warn = h('div');
  const syncWarn = () => {
    warn.replaceChildren();
    if (boxes.crowdsec.checked && !boxes.cloudflare.checked) warn.append(callout('warn', 'CrowdSec만 켜면 공격 IP를 판정만 하고 차단은 하지 않습니다. 차단은 Cloudflare 엣지에서 하기 때문입니다.'));
    if (boxes.crowdsec.checked && !boxes.caddy.checked) warn.append(callout('warn', 'CrowdSec은 Caddy 접근 로그를 읽습니다 — Caddy 없이는 판정할 기록이 없습니다.'));
    if (!Object.values(boxes).some((b) => b.checked)) warn.append(callout('', '아무것도 고르지 않으면 길목은 대시보드·로그·보안 기능만 씁니다.'));
    // switching off something sites depend on removes protection on the next apply
    const live = S.state.services.filter((x) => x.enabled && !x.dnsOnly);
    const mtlsN = live.filter((x) => x.exposure === 'public' && x.proxied && x.mtls).length;
    const authN = live.filter((x) => x.authelia && x.authelia.enabled).length;
    if (set.useCloudflare && !boxes.cloudflare.checked && mtlsN) warn.append(callout('danger', h('b', null, `mTLS 서비스 ${mtlsN}개의 cf_only가 빠집니다.`), h('span', null, '적용하면 그 사이트들은 Cloudflare를 거치지 않은 접속도 받습니다(원본 서버 노출). DNS만 직접 관리하려는 것이라면 Cloudflare를 켜 둔 채 토큰을 비우세요.')));
    if (set.useAuthelia && !boxes.authelia.checked && authN) warn.append(callout('danger', h('b', null, `Authelia 로그인 관문 ${authN}개가 사라집니다.`), h('span', null, '적용하면 그 사이트들은 로그인 없이 열립니다.')));
    const privN = live.filter((x) => x.exposure !== 'public').length;
    if (set.useTailscale && !boxes.tailscale.checked && privN) warn.append(callout('warn', `사설 전용 서비스 ${privN}개는 그대로 남습니다 (Caddy :${set.tailscalePort || 8443}). 공개로 바꾸거나 지우려면 서비스 탭에서 고치세요.`));
    if (set.useCaddy && !boxes.caddy.checked && live.length) warn.append(callout('warn', `Caddy를 끄면 길목은 Caddyfile을 더 이상 만들지 않습니다 (지금 Caddy는 마지막 설정 그대로 계속 동작).`));
  };
  grid.addEventListener('change', syncWarn);
  syncWarn();
  const save = h('button', { type: 'button', class: 'btn primary' }, '저장');
  save.addEventListener('click', () => busy(save, async () => {
    if (warn.querySelector('.callout.danger')) {
      const ok = await confirmDialog({ title: '보호 기능이 빠집니다', danger: true, okText: '그래도 저장',
        message: [...warn.querySelectorAll('.callout.danger b')].map((b) => b.textContent).join('\n') + '\n\n저장 후 「적용」해야 실제로 반영됩니다.' });
      if (!ok) return;
    }
    try {
      await saveSettingsPatch(Object.fromEntries(COMPONENTS.map((c) => [c.flag, boxes[c.key].checked])));
      applyComponentTabs();
      renderPanel();
    } catch (ex) { toast(ex.message, 'err'); }
  }));
  const used = usedNames();
  return {
    id: 'components', title: '구성요소', desc: '이 설치가 실제로 쓰는 것만 고르세요. 고르지 않은 구성요소의 탭·설정·적용 단계는 숨기고 건드리지 않습니다.',
    state: used.length ? 'ok' : 'todo', stateText: used.length ? used.join(' · ') : '고르기',
    body: h('div', { class: 'stack' }, grid, warn,
      h('div', { class: 'row' }, h('p', { class: 'hint grow' }, '바꾸면 생성되는 Caddyfile이 달라질 수 있어 「적용」이 필요합니다. 보안에 영향을 주므로 비밀번호를 다시 확인합니다.'), save)),
  };
}

function renderGilmok(panel) {
  const st = S.state;
  let L;

  // 3) apply status
  const pend = st.pending || [];
  const applyBig = h('button', { type: 'button', class: `btn ${st.dirty ? 'primary' : ''}` }, '미리보기·적용…');
  applyBig.addEventListener('click', openApply);
  const applyBody = h('div', { class: 'stack' },
    st.dirty
      ? callout('warn', h('b', null, `저장됐지만 아직 적용하지 않은 변경 ${pend.length}건`), pend.length ? h('ul', null, pend.map((p) => h('li', null, p))) : null)
      : callout('ok', `모든 변경이 적용되어 있습니다${fmtTime(st.lastApplied) ? ` · 마지막 적용 ${fmtTime(st.lastApplied)}` : ''}`),
        h('ol', { class: 'flow' }, [`검증 (실제 ${['Caddy', 'Authelia'].filter((n) => use(n.toLowerCase())).join('·') || '구성요소'}로)`, '백업 (/data/backups)', use('authelia') ? 'Authelia 쓰기 → 재시작 → 시작 로그 확인' : null, use('caddy') ? 'Caddy 쓰기 → 무중단 reload' : null, use('cloudflare') ? 'Cloudflare DNS 동기화' : null].filter(Boolean).map((t) => h('li', null, t))),
    h('p', { class: 'hint' }, use('caddy') && use('authelia') ? '어느 단계든 실패하면 Caddy·Authelia를 모두 이전 파일로 되돌립니다.'
      : `어느 단계든 실패하면 ${['Caddy', 'Authelia'].find((n) => use(n.toLowerCase())) || '바꾼 파일'}을(를) 이전 파일로 되돌립니다.`),
    h('div', { class: 'row' }, applyBig));

  // 4) backups
  const backups = h('div', null, spinnerRow('불러오는 중…'));
  api('GET', '/api/backups').then((list) => {
    list = list || [];
    backups.replaceChildren(list.length
      ? h('ul', { class: 'backup-list' }, list.map((n) => {
        const m = /^(\d{4})(\d{2})(\d{2})-(\d{2})(\d{2})(\d{2})-(.+)$/.exec(n);
        return h('li', null, h('span', null, m ? `${m[1]}-${m[2]}-${m[3]} ${m[4]}:${m[5]}:${m[6]}` : n),
          h('span', { class: 'badge' }, m ? (m[7] === 'apply' ? '적용' : m[7] === 'users' ? '사용자' : m[7]) : ''));
      }))
      : h('p', { class: 'muted' }, '백업이 없습니다.'));
    L.set('backups', 'info', `${list.length}개`);
  }).catch((ex) => backups.replaceChildren(errorBox(ex.message)));

  // 6) fault injection (GM_DEV_FAULTS=1 only)
  let faultBody = null;
  if (st.faultInjection) {
    const faults = FAULTS.filter(([v]) => (v === 'caddy-reload' ? use('caddy') : use('authelia')));
    const seg = segmented(uid('fault'), '다음 작업에 주입할 장애', faults.map(([v, l]) => ({ value: v, label: l })), st.fault || (faults[0] || FAULTS[0])[0]);
    const desc = h('p', { class: 'small muted' });
    const syncDesc = () => { desc.textContent = (FAULTS.find((f) => f[0] === seg.get()) || [])[2] || ''; };
    seg.onChange(syncDesc);
    syncDesc();
    const arm = h('button', { type: 'button', class: 'btn danger' }, '장애 예약');
    const disarm = h('button', { type: 'button', class: 'btn ghost' }, '해제');
    const now = h('p', { class: 'small' });
    const showNow = () => {
      now.replaceChildren(S.state.fault ? h('span', { class: 'badge warn' }, `예약됨: ${S.state.fault} — 다음 1회만 발동`) : h('span', { class: 'badge muted' }, '예약 없음'));
      L && L.set('fault', S.state.fault ? 'warn' : 'opt', S.state.fault ? '예약됨' : '테스트용');
    };
    const setFault = async (kind, btn) => {
      try {
        await busy(btn, () => api('POST', '/api/dev/fault', { kind }));
        await refreshState();
        showNow();
        toast(kind ? `장애 예약: ${kind}` : '장애 예약 해제', kind ? 'warn' : 'ok');
      } catch (ex) { toast(ex.message, 'err'); }
    };
    arm.addEventListener('click', () => setFault(seg.get(), arm));
    disarm.addEventListener('click', () => setFault('', disarm));
    faultBody = h('div', { class: 'stack' },
      callout('warn', h('b', null, '테스트 스택 전용 (GM_DEV_FAULTS=1).'), '운영 컨테이너에는 이 환경변수를 넣지 마세요.'),
      seg, desc, h('div', { class: 'row' }, now, h('span', { class: 'grow' }), disarm, arm));
    queueMicrotask(showNow);
  }

  const domForm = settingsForm([
    { key: 'domain', label: '도메인', mono: true, placeholder: 'example.com', attrs: { required: true },
      hint: '모든 서비스 주소의 기준입니다 — 서비스 「photo」 → photo.example.com. 가지고 있는 도메인을 넣으세요 (Cloudflare를 쓰면 그 존과 같아야 합니다).' },
    privOn() ? { key: 'tailscaleIp', label: use('tailscale') ? 'Tailscale IP' : '사설 서비스 IP', mono: true, placeholder: use('tailscale') ? '100.x.y.z' : '',
      hint: use('tailscale') ? `${privName()} 서비스의 DNS(A 레코드) 값 — 이 서버의 Tailscale 주소 (100.x)` : `${privName()} 서비스의 DNS(A 레코드) 값 — 사설 경로(VPN 등)에서 이 서버에 닿는 주소`, attrs: { inputmode: 'decimal' } } : null,
  ].filter(Boolean), {
    validate: async (p, inputs) => {
      p.domain = String(p.domain || '').trim().toLowerCase().replace(/^https?:\/\//, '').replace(/\/.*$/, '').replace(/\.$/, '');
      if (!/^([a-z0-9-]+\.)+[a-z]{2,}$/.test(p.domain)) { inputs.domain.focus(); return '도메인 형식이 아닙니다 (예: example.com)'; }
      if (use('tailscale') && p.tailscaleIp && !/^100\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(p.tailscaleIp)) {
        const ok = await confirmDialog({ title: 'Tailscale IP 확인', message: `${p.tailscaleIp} 는 Tailscale(100.x) 주소가 아닙니다. 그대로 저장할까요?` });
        return ok ? '' : false;
      }
      return '';
    },
    onSaved: () => { S.dns = null; if (S.checks) delete S.checks.cloudflare; renderPanel(); },
  });
  if (use('tailscale') && domForm.inputs.tailscaleIp && typeof tsFinder === 'function') domForm.inputs.tailscaleIp.closest('.field').append(tsFinder(domForm.inputs.tailscaleIp));
  const steps = [
    componentsStep(),
    { id: 'domain', title: privOn() ? (use('tailscale') ? '도메인 · Tailscale IP' : '도메인 · 사설 IP') : '도메인', desc: privOn() ? `모든 서비스 주소의 기준과 ${privName()} 서비스가 가리킬 IP.` : '모든 서비스 주소의 기준이 되는 도메인입니다.',
      state: st.settings.domain && (st.settings.tailscaleIp || !privOn()) ? 'ok' : st.settings.domain ? 'warn' : 'todo', stateText: st.settings.domain ? (privOn() && !st.settings.tailscaleIp ? `${use('tailscale') ? 'Tailscale' : '사설'} IP 없음` : st.settings.domain) : '정하지 않음',
      body: h('div', { class: 'stack' },
        st.settings.domain ? null : callout('warn', h('b', null, '도메인을 먼저 정하세요'), h('span', { class: 'small' }, '정하기 전에는 서비스 주소를 만들 수 없고 「적용」도 막혀 있습니다. 기존 Caddyfile을 가져오면 사이트 주소에서 자동으로 알아냅니다.')),
        domForm) },
    use('caddy') && { id: 'import', title: '기존 설정 가져오기', desc: `지금 쓰는 ${importSources()}을(를) 읽어` + ' 서비스 목록과 Caddy 기본 골격을 만듭니다. 실제 파일은 바뀌지 않습니다.',
      state: st.services.length ? 'ok' : 'todo', stateText: st.services.length ? `서비스 ${st.services.length}개` : '',
      body: (() => { const b = h('button', { type: 'button', class: 'btn' }, icon('download'), '기존 설정 가져오기…'); b.addEventListener('click', () => runImport(b)); return h('div', { class: 'row' }, b, h('span', { class: 'hint' }, '앱에 저장된 서비스 목록은 대체됩니다')); })() },
    { id: 'ops', title: '적용 · 백업', aside: true, desc: '저장된 변경을 실제 파일·컨테이너·DNS에 반영하고, 그 직전 상태를 백업합니다.', children: [
      { id: 'apply', title: '적용', desc: '저장된 변경을 실제 파일·컨테이너·DNS에 반영합니다.', state: st.dirty ? 'warn' : 'ok', stateText: st.dirty ? `대기 ${pend.length}건` : '최신',
        body: applyBody },
      { id: 'backups', title: '파일 백업', desc: '적용·사용자 변경 직전에 자동으로 저장됩니다 (/data/backups, 최근 30개).', state: 'info', body: backups },
      configBackupStep(),
      resetStep(),
      faultBody && { id: 'fault', title: '롤백 테스트', desc: '검증은 통과시킨 뒤 실제로 깨진 파일을 써서, 실패 감지와 자동 복구가 동작하는지 확인합니다.', state: 'opt', stateText: '테스트용', body: faultBody },
    ] },
    { id: 'people', title: '계정', aside: true, desc: '내 계정과, 권한이 있으면 다른 사람의 계정·역할.', children: [
      myAccountStep(),
      can('accounts') && accountsStep(() => L),
    ] },
    { ...securityStep(), aside: true },
  ].filter(Boolean);
  steps.push({ id: 'lang', title: '화면 언어', aside: true, desc: '이 설치의 모든 사용자에게 보이는 화면 언어입니다. 바꾸면 화면을 다시 불러옵니다.',
    state: 'info', stateText: (window.gmI18n && gmI18n.langs[settings().lang]) || settings().lang || '',
    body: settingsForm([{ key: 'lang', type: 'select', label: '화면 언어', options: [['ko', '한국어'], ['en', 'English']],
      hint: '로그인 화면과 모든 계정에 적용됩니다. 서버가 만드는 파일(Caddyfile 주석 등)은 한국어 그대로입니다.' }],
    { grid: false, onSaved: (p) => { if (window.gmI18n && p.lang) gmI18n.sync(p.lang); } }) });
  steps.push({ id: 'about', title: '정보', aside: true, state: 'info', stateText: st.version ? `v${st.version}` : '',
    body: h('dl', { class: 'kv' },
      h('dt', null, '버전'), h('dd', null, st.version || '—'),
      h('dt', null, '마지막 적용'), h('dd', null, fmtTime(st.lastApplied) || '—'),
      h('dt', null, '공인 IP'), h('dd', null, st.lastPublicIp || '—'),
      use('cloudflare') ? [h('dt', null, 'Cloudflare'), h('dd', null, st.cfConfigured ? '토큰 설정됨' : '토큰 없음')] : null,
      h('dt', null, '구성요소'), h('dd', null, usedNames().join(' · ') || '—')) });

  const wizBtn = h('button', { type: 'button', class: 'btn sm', disabled: !(can('config') && can('system')) }, '설정 마법사 열기');
  wizBtn.addEventListener('click', openSetupChooser);
  L = stepsLayout(panel, {
    title: '설정',
    lead: [`길목 자체의 설정입니다. ${usedNames().length ? `이 설치는 ${usedNames().join(' · ')}을(를) 씁니다 — 각 탭에서 구성요소를, 서비스 탭에서 사이트를 관리합니다. ` : ''}처음부터 차례로 하려면 `, wizBtn],
    steps,
  });
}

// ======================================================================= boot

async function boot() {
  if (window.gmI18n) await gmI18n.ready; // translations first (non-Korean UI)
  initAuthForm();
  initShell();
  let st;
  try {
    st = await api('GET', '/api/auth/state');
  } catch (e) {
    document.body.append(h('div', { class: 'auth' }, h('div', { class: 'glass auth-card' }, errorBox(e.message))));
    return;
  }
  // the install's language: not chosen yet → ask first; otherwise follow it (reloads if this
  // browser still shows another one)
  if (window.gmI18n) {
    if (!st.lang) { showLangChooser(); return; }
    if (gmI18n.sync(st.lang)) return;
  }
  $('#auth-ver').textContent = st.version ? `v${st.version}` : '';
  if (st.loggedIn) await showApp();
  else showAuth(st.setup);
}

document.addEventListener('DOMContentLoaded', boot);
