// Gilmok web UI — security: Caddy WAF (Coraza) + basic blocking, Cloudflare edge rules, CrowdSec tab.
// Loaded after app.js; uses its helpers (h, api, stepsLayout, settingsForm, …).
'use strict';

const WAF_MODES = [
  { value: '', label: '끔' },
  { value: 'detect', label: '탐지만 (기록)' },
  { value: 'block', label: '차단 (403)' },
];
const wafLabel = (m) => ({ detect: '탐지', block: '차단' }[m] || '');

function wafBadge(s) {
  if (!use('caddy') || s.dnsOnly || (!s.waf && !s.guard)) return null;
  const parts = [];
  if (s.waf) parts.push(`WAF ${wafLabel(s.waf)}`);
  if (s.guard) parts.push('기본 차단');
  const tip = [s.waf ? `Caddy WAF (Coraza + OWASP CRS): ${s.waf === 'block' ? '차단' : '탐지만'}${s.wafParanoia ? ` · 민감도 ${s.wafParanoia}` : ''}${(s.wafExclude || []).length ? ` · 예외 ${s.wafExclude.length}개` : ''}` : null,
    s.guard ? '기본 차단: 스캐너·AI 크롤러·공격 경로 등 (Caddy 탭 › 기본 차단)' : null].filter(Boolean).join('\n');
  return h('span', { class: `badge ${s.waf === 'block' ? 'danger' : s.waf ? 'warn' : 'accent'}`, title: tip }, icon('shield'), parts.join(' · '));
}

async function saveServicePatch(s, patch) {
  await api('PUT', `/api/services/${encodeURIComponent(s.id)}`, { ...s, ...patch });
  await refreshState();
}

let WAF_META = null;
async function wafMeta(force) {
  if (!WAF_META || force) WAF_META = await api('GET', '/api/waf/meta');
  return WAF_META;
}

// ---- small controls

/** Checkbox grid: items [{value,label,desc}] → element with .value (checked values). */
function checkGroup(items, checked) {
  const on = new Set(checked || []);
  const wrap = h('div', { class: 'check-grid', role: 'group' }, items.map((it) => h('label', { class: 'check-item' },
    h('input', { type: 'checkbox', value: it.value, checked: on.has(it.value) }),
    h('span', null, h('b', null, it.label), it.desc ? h('small', null, it.desc) : null))));
  Object.defineProperty(wrap, 'value', { get: () => [...wrap.querySelectorAll('input:checked')].map((i) => i.value) });
  return wrap;
}

/** Which Proxied services a Cloudflare rule applies to: [] = whole zone. */
function scopePicker(selected) {
  const svcs = S.state.services.filter((s) => s.enabled && s.exposure === 'public' && s.proxied);
  const name = uid('scope');
  const allR = h('input', { type: 'radio', name, value: 'all', checked: !(selected || []).length });
  const someR = h('input', { type: 'radio', name, value: 'some', checked: !!(selected || []).length });
  const list = checkGroup(svcs.map((s) => ({ value: s.id, label: s.subdomain, desc: s.mtls ? 'mTLS' : '' })), selected);
  const sync = () => { list.hidden = !someR.checked; };
  const wrap = h('div', { class: 'stack tight' },
    h('div', { class: 'row wrap' },
      h('label', { class: 'radio-inline' }, allR, ' 존 전체 (모든 Proxied 사이트)'),
      h('label', { class: 'radio-inline' }, someR, ' 선택한 서비스만')),
    svcs.length ? list : h('p', { class: 'small muted' }, 'Proxied 서비스가 없습니다.'));
  wrap.addEventListener('change', sync);
  sync();
  Object.defineProperty(wrap, 'value', { get: () => (someR.checked ? list.value : []) });
  return wrap;
}

/** Editable list of CRS rule exclusions [{id, note}]. */
function exclusionEditor(list) {
  const rows = h('div', { class: 'excl-rows' });
  const addRow = (x = { id: '', note: '' }, focus) => {
    const id = h('input', { type: 'text', class: 'mono', value: x.id, placeholder: '942100', inputmode: 'numeric', 'aria-label': '규칙 번호', autocomplete: 'off' });
    const note = h('input', { type: 'text', value: x.note || '', placeholder: '메모 — 왜 뺐는지 (예: 업로드 API 오탐)', 'aria-label': '메모', autocomplete: 'off' });
    const del = h('button', { type: 'button', class: 'btn sm ghost', 'aria-label': `${x.id || '새'} 규칙 예외 삭제` }, '✕');
    const row = h('div', { class: 'excl-row' }, id, note, del);
    del.addEventListener('click', () => { row.remove(); rows.dispatchEvent(new Event('change', { bubbles: true })); });
    row.read = () => ({ id: id.value.trim(), note: note.value.trim() });
    rows.append(row);
    if (focus) id.focus();
  };
  (list || []).forEach((x) => addRow(x));
  const add = h('button', { type: 'button', class: 'btn sm' }, '+ 예외 추가');
  add.addEventListener('click', () => addRow(undefined, true));
  const wrap = h('div', { class: 'stack tight' }, rows, h('div', null, add));
  Object.defineProperty(wrap, 'value', { get: () => [...rows.children].map((r) => r.read()).filter((x) => x.id) });
  return wrap;
}

/** Horizontal bar list [{label, count, sub}] — one hue, value always printed. */
function barList(items, { max } = {}) {
  const top = max || Math.max(1, ...items.map((x) => x.count));
  return h('ul', { class: 'bar-list' }, items.map((x) => h('li', null,
    h('span', { class: 'bl-label', title: x.title || x.label }, x.label, x.sub ? h('small', null, x.sub) : null),
    h('span', { class: 'bl-track', 'aria-hidden': 'true' }, h('span', { class: 'bl-fill', style: { width: `${Math.max(2, (x.count / top) * 100)}%` } })),
    h('span', { class: 'bl-val' }, x.count.toLocaleString()))));
}

function expoBadge(s) {
  if (s.exposure !== 'public') return h('span', { class: 'badge ts' }, use('tailscale') ? 'Tailscale' : '사설');
  if (!use('cloudflare')) return h('span', { class: 'badge public' }, '공개');
  return s.proxied
    ? h('span', { class: 'badge', title: 'Proxied — Cloudflare 경유' }, icon('cloud', 'fill cloud-orange'), s.mtls ? 'Proxied · mTLS' : 'Proxied')
    : h('span', { class: 'badge', title: 'DNS only — 공인 IP로 직접' }, icon('cloud', 'fill cloud-gray'), 'DNS only');
}

const svcByHost = (host) => S.state.services.find((s) => fqdn(s.subdomain) === host);

// ======================================================================= Caddy tab: WAF engine

const PL_OPTS = [['1', '1 — 기본 (오탐 적음, 권장)'], ['2', '2 — 엄격'], ['3', '3 — 매우 엄격'], ['4', '4 — 최고 (오탐 많음)']];

function wafEngineStep() {
  const st = settings();
  const sites = S.state.services.filter((s) => s.enabled && !s.dnsOnly);
  const used = sites.filter((s) => s.waf);
  const moduleBox = h('div', null, spinnerRow('Caddy 이미지에 Coraza 모듈이 있는지 확인 중…'));
  loadCheck('caddy').then((r) => {
    const c = (r.checks || []).find((x) => x.id === 'waf');
    if (!moduleBox.isConnected) return;
    if (!c) { moduleBox.replaceChildren(callout('warn', 'Caddy가 실행 중이 아니라 Coraza 모듈 여부를 확인하지 못했습니다.')); return; }
    moduleBox.replaceChildren(c.status === 'ok'
      ? callout('ok', h('b', null, '✓ Coraza WAF 모듈 있음'), h('span', { class: 'small' }, c.detail))
      : callout(c.status === 'fail' ? 'danger' : 'warn', h('b', null, 'Caddy 이미지에 Coraza가 없습니다'),
        h('span', null, 'Caddy compose 폴더의 Dockerfile을 ', h('code', null, 'deploy/caddy/Dockerfile'), ' 내용으로 바꾸고 「이미지 업데이트」를 실행하세요. (「기본 차단」은 Coraza 없이도 동작합니다)')));
  }).catch(() => moduleBox.replaceChildren());

  const body = h('div', { class: 'stack' }, moduleBox, spinnerRow('WAF 설정 불러오는 중…'));
  wafMeta().then((m) => {
    const groups = checkGroup(m.groups.map((g) => ({ value: g.id, label: `${g.id} ${g.name}`, desc: g.desc })),
      m.groups.map((g) => g.id).filter((id) => !(st.wafGroupsOff || []).includes(id)));
    const excl = exclusionEditor(st.wafExclude);
    const form = settingsForm([
      { key: 'wafParanoia', type: 'select', num: true, label: '차단 민감도 (paranoia level)', options: PL_OPTS,
        hint: '높을수록 더 많은 규칙이 켜져 더 많이 잡지만, 정상 요청도 막을 수 있습니다.' },
      { key: 'wafDetectPl', type: 'select', num: true, label: '기록만 하는 민감도', options: [['0', '차단 민감도와 같음'], ['2', '2'], ['3', '3'], ['4', '4']],
        hint: '차단 민감도보다 높게 두면, 그 위 단계 규칙은 막지 않고 「WAF 이벤트」에만 남깁니다. 민감도를 올리기 전에 오탐을 미리 보는 용도.' },
      { key: 'wafInbound', type: 'number', label: '요청 차단 점수', attrs: { min: '1', max: '1000' },
        hint: '걸린 규칙의 점수(심각 5 · 오류 4 · 경고 3 · 알림 2)를 더해 이 값 이상이면 막습니다. 기본 5 — 낮출수록 엄격, 오탐이 많으면 일시적으로 올리기도 합니다.' },
      { key: 'wafOutbound', type: 'number', label: '응답 차단 점수', attrs: { min: '1', max: '1000' }, hint: '응답 검사용 (기본 4). 응답 본문 검사는 꺼져 있어 영향이 적습니다.' },
      { key: 'wafBodyAccess', type: 'switch', label: '요청 본문 검사', hint: '로그인 폼·API 본문까지 검사합니다. 끄면 업로드(사진 등)가 빠르고 크기 제한이 없습니다.' },
      { key: 'wafBodyLimitMb', type: 'number', label: '검사할 본문 크기 (MB)', attrs: { min: '0', max: '1024' }, hint: '0 = 기본 12.5MB. 넘는 부분은 검사하지 않고 통과시킵니다.' },
      { key: 'wafMethods', wide: true, label: '허용 HTTP 메서드', mono: true, placeholder: 'GET HEAD POST OPTIONS PUT PATCH DELETE',
        hint: '목록 밖 메서드는 911 규칙이 막습니다. OWASP 기본값(GET HEAD POST OPTIONS)은 PUT·DELETE를 쓰는 앱을 막으므로 넓혀 두었습니다. WebDAV는 PROPFIND MKCOL COPY MOVE LOCK UNLOCK 추가.' },
      { key: 'wafGroupsOff', type: 'custom', el: groups, read: () => m.groups.map((g) => g.id).filter((id) => !groups.value.includes(id)),
        label: '검사 항목 (OWASP CRS 규칙 그룹)', hint: '체크한 그룹만 검사합니다. 앱 특성상 계속 오탐이 나는 그룹(예: Java 앱이 아닌데 944)은 꺼도 됩니다.' },
      { key: 'wafExclude', type: 'custom', el: excl, read: () => excl.value, label: '모든 사이트 공통 규칙 예외',
        hint: '특정 규칙 번호를 끕니다 (예: 942100, 범위 942100-942199). 한 서비스에서만 오탐이면 「서비스별 보호」에서 그 서비스에만 넣으세요. 「WAF 이벤트」에서 버튼으로도 추가됩니다.' },
      { key: 'wafDirectives', wide: true, type: 'code', rows: 3, label: '고급: 추가 SecLang 지시어', placeholder: 'SecRuleUpdateTargetById 942100 "!ARGS:password"',
        hint: '규칙 그룹·예외 뒤에 그대로 붙습니다. 잘못 쓰면 「생성 결과 검증」에서 걸립니다.' },
    ], { onSaved: () => { WAF_META = null; } });
    fill(body, moduleBox,
      callout('', h('b', null, '권장 순서'), h('ol', { class: 'flow' },
        h('li', null, '「서비스별 보호」에서 사이트를 「탐지만」으로 두고 며칠 사용'),
        h('li', null, '「WAF 이벤트」에서 정상 요청이 걸린 규칙을 그 서비스(또는 공통) 예외로 추가'),
        h('li', null, '「차단」으로 바꾸고 적용 → 「WAF 시험」으로 실제로 막히는지 확인'))),
      form);
  }).catch((ex) => fill(body, moduleBox, errorBox(ex.message)));

  return {
    id: 'waf', title: 'WAF 엔진 (Coraza + OWASP CRS)',
    desc: `요청 내용(SQL 인젝션, XSS, 경로 탐색, 명령 실행 등)을 보고 막습니다. 접속자 IP와 무관하게 동작하므로 ${[use('cloudflare') ? 'Proxied·DNS only' : '공개', privOn() ? (use('tailscale') ? 'Tailscale' : '사설') : null].filter(Boolean).join('·')} 사이트 모두에 쓸 수 있습니다.`,
    state: used.length ? 'ok' : 'opt', stateText: used.length ? `${used.length}개 사이트 · 민감도 ${st.wafParanoia || 1}` : '사용 안 함',
    body,
  };
}

// ======================================================================= Caddy tab: per-service protection

function openServiceWafDialog(s) {
  const pl = h('select', { 'aria-label': '민감도' }, [['0', `공통 설정 따름 (${settings().wafParanoia || 1})`], ...PL_OPTS].map(([v, l]) => h('option', { value: v, selected: String(s.wafParanoia || 0) === v }, l)));
  const excl = exclusionEditor(s.wafExclude);
  const err = h('p', { class: 'form-error', role: 'alert', hidden: true });
  const form = h('form', { class: 'stack', novalidate: true }, err,
    field('이 서비스의 차단 민감도', pl, '공통보다 높이거나(중요한 관리 화면) 낮출(오탐이 많은 앱) 때 씁니다.'),
    h('div', { class: 'field' }, h('span', { class: 'field-label' }, '이 서비스에만 적용할 규칙 예외'), excl,
      h('p', { class: 'hint' }, '다른 사이트는 그대로 검사합니다. 민감도나 예외가 있으면 이 서비스는 전용 WAF 스니펫을 씁니다.')));
  const save = h('button', { type: 'submit', class: 'btn primary' }, '저장');
  const cancel = h('button', { type: 'button', class: 'btn ghost' }, '취소');
  save.setAttribute('form', form.id = uid('form'));
  const d = openDialog({ title: `${fqdn(s.subdomain)} — WAF 세부 설정`, body: form, footer: [h('span', { class: 'spacer' }), cancel, save] });
  cancel.addEventListener('click', () => d.close());
  form.addEventListener('submit', (e) => {
    e.preventDefault();
    busy(save, async () => {
      try {
        await saveServicePatch(s, { wafParanoia: parseInt(pl.value, 10) || 0, wafExclude: excl.value });
        toast(`${fqdn(s.subdomain)} WAF 세부 설정 저장 — 적용 대기`);
        d.close();
        renderPanel();
      } catch (ex) { err.textContent = ex.message; err.hidden = false; }
    });
  });
}

function wafServicesStep() {
  const sites = S.state.services.filter((s) => s.enabled && !s.dnsOnly);
  const rows = h('tbody');
  for (const s of sites) {
    const sel = h('select', { 'aria-label': `${fqdn(s.subdomain)} WAF 모드` }, WAF_MODES.map((o) => h('option', { value: o.value, selected: (s.waf || '') === o.value }, o.label)));
    sel.addEventListener('change', async () => {
      sel.disabled = true;
      try {
        await saveServicePatch(s, { waf: sel.value });
        toast(`${fqdn(s.subdomain)} WAF: ${WAF_MODES.find((o) => o.value === sel.value).label} — 적용 대기`);
      } catch (ex) { toast(ex.message, 'err'); } finally { sel.disabled = false; }
    });
    const guard = h('input', { type: 'checkbox', role: 'switch', checked: !!s.guard, 'aria-label': `${fqdn(s.subdomain)} 기본 차단` });
    guard.addEventListener('change', async () => {
      guard.disabled = true;
      try {
        await saveServicePatch(s, { guard: guard.checked });
        toast(`${fqdn(s.subdomain)} 기본 차단 ${guard.checked ? '켬' : '끔'} — 적용 대기`);
      } catch (ex) { toast(ex.message, 'err'); guard.checked = !guard.checked; } finally { guard.disabled = false; }
    });
    const tune = h('button', { type: 'button', class: 'btn sm' }, '세부…');
    tune.addEventListener('click', () => openServiceWafDialog(s));
    const ex = (s.wafExclude || []).length;
    rows.append(h('tr', null,
      h('td', null, h('b', null, s.subdomain), s.authelia && s.authelia.enabled && use('authelia') ? h('div', { class: 'cell-sub' }, 'Authelia — WAF는 로그인 뒤 요청에 동작') : null),
      h('td', null, expoBadge(s)),
      h('td', null, h('label', { class: 'switch mini' }, guard)),
      h('td', null, sel),
      h('td', { class: 'small' }, s.wafParanoia ? `민감도 ${s.wafParanoia}` : h('span', { class: 'muted' }, '공통'), ex ? h('div', { class: 'cell-sub' }, `예외 ${ex}개`) : null),
      h('td', null, tune)));
  }
  const allOn = h('button', { type: 'button', class: 'btn sm' }, '기본 차단 모두 켜기');
  allOn.addEventListener('click', () => busy(allOn, async () => {
    const todo = sites.filter((s) => !s.guard);
    if (!todo.length) { toast('이미 모두 켜져 있습니다'); return; }
    const ok = await confirmDialog({ title: '기본 차단 모두 켜기', message: `${todo.length}개 사이트에 기본 차단(스캐너·공격 경로 등)을 켭니다. 적용해야 Caddy에 반영됩니다.`, okText: '켜기' });
    if (!ok) return;
    try {
      for (const s of todo) await api('PUT', `/api/services/${encodeURIComponent(s.id)}`, { ...s, guard: true });
      await refreshState();
      toast(`${todo.length}개 사이트 기본 차단 켬 — 적용 대기`);
      renderPanel();
    } catch (ex) { toast(ex.message, 'err'); }
  }));
  const guarded = sites.filter((s) => s.guard).length;
  const wafd = sites.filter((s) => s.waf).length;
  return {
    id: 'wafsvc', title: '서비스별 보호', desc: '사이트마다 기본 차단 · WAF 모드 · 민감도 · 규칙 예외를 정합니다. 바꾸면 「적용 대기」가 됩니다.',
    state: guarded || wafd ? 'ok' : 'todo', stateText: `기본 차단 ${guarded} · WAF ${wafd} / ${sites.length}`,
    body: h('div', { class: 'stack' },
      sites.length ? h('div', { class: 'table-wrap glass-inner' }, h('table', { class: 'compact' },
        h('thead', null, h('tr', null, ['서비스', '노출', '기본 차단', 'WAF', '민감도·예외', ''].map((t) => h('th', { scope: 'col' }, t)))), rows))
        : h('p', { class: 'muted' }, 'Caddy 사이트가 있는 서비스가 없습니다.'),
      h('div', { class: 'row' }, allOn, h('span', { class: 'hint' }, 'Caddy에서는 인증(Authelia)이 WAF보다 먼저 실행됩니다. 로그인하지 않은 요청은 Authelia가 먼저 막습니다.'))),
  };
}

// ======================================================================= Caddy tab: basic blocking

function guardStep() {
  const st = settings();
  const n = S.state.services.filter((s) => s.enabled && !s.dnsOnly && s.guard).length;
  const body = h('div', { class: 'stack' }, spinnerRow('목록 불러오는 중…'));
  wafMeta().then((m) => {
    const listOf = (title, arr) => h('details', { class: 'preset' }, h('summary', null, `${title} ${arr.length}개 보기`), h('div', { class: 'chips' }, arr.map((x) => h('code', null, x))));
    const form = settingsForm([
      { key: 'guardBots', type: 'switch', label: '스캐너·공격 도구', hint: `User-Agent로 판단 — ${m.botUAs.slice(0, 6).join(', ')} …` },
      { key: 'guardAi', type: 'switch', label: 'AI 크롤러', hint: `${m.aiUAs.slice(0, 5).join(', ')} … — 검색엔진(Googlebot, Bingbot)은 포함하지 않습니다.` },
      { key: 'guardPaths', type: 'switch', label: '공격 경로', hint: `${m.paths.slice(0, 6).join(', ')} … 같은 탐색 경로` },
      { key: 'guardEmptyUa', type: 'switch', label: 'User-Agent 없는 요청', hint: '자동화 도구가 흔히 비워 둡니다. 일부 API 클라이언트·모니터링이 막힐 수 있으니 확인 후 켜세요.' },
      { key: 'guardPhp', type: 'switch', label: 'PHP 요청 (*.php)', hint: 'PHP 앱(Nextcloud, WordPress 등)이 없을 때만. 있다면 그 서비스는 기본 차단을 끄세요.' },
      { key: 'guardUa', type: 'code', rows: 3, label: '추가로 막을 User-Agent', placeholder: 'badbot\nsome-scraper', hint: '한 줄에 하나, 부분 일치·대소문자 무시.' },
      { key: 'guardPathList', type: 'code', rows: 3, label: '추가로 막을 경로', placeholder: '/old-admin\n/backup.zip', hint: '한 줄에 하나, / 로 시작, 경로 어디든 포함되면 차단.' },
    ], { onSaved: () => { WAF_META = null; } });
    fill(body,
      h('p', { class: 'small' }, '앱과 관계없이 공격인 요청을 Caddy 앞단에서 바로 403으로 돌려보냅니다. Coraza 없이도 동작하고, 접속자 IP를 쓰지 않아 모든 사이트에 쓸 수 있습니다. 어떤 사이트에 켤지는 「서비스별 보호」에서 정합니다.'),
      form,
      h('div', { class: 'grid-2' }, listOf('스캐너·공격 도구', m.botUAs), listOf('AI 크롤러', m.aiUAs), listOf('공격 경로', m.paths)),
      m.guardSnippet ? h('details', { class: 'preset' }, h('summary', null, '생성되는 Caddy 스니펫 보기'), h('pre', { class: 'code' }, m.guardSnippet)) : null,
      use('cloudflare') ? h('p', { class: 'hint' }, '추가 User-Agent·경로 목록은 Cloudflare 탭 › WAF 규칙 › 위협 차단에서도 같이 씁니다 (엣지에서 미리 막기).') : null);
  }).catch((ex) => fill(body, errorBox(ex.message)));
  return {
    id: 'guard', title: '기본 차단 (봇·공격 경로)', desc: '스캐너, AI 크롤러, /.env 같은 탐색 경로를 앱까지 보내지 않고 막습니다.',
    state: n ? 'ok' : 'todo', stateText: n ? `${n}개 사이트` : '사용 안 함', body,
  };
}

// ======================================================================= Caddy tab: WAF events

async function addExclusion(ruleId, msg, host) {
  const svc = host ? svcByHost(host) : null;
  const name = uid('exsc');
  const rSvc = h('input', { type: 'radio', name, value: 'svc', checked: !!svc, disabled: !svc });
  const rAll = h('input', { type: 'radio', name, value: 'all', checked: !svc });
  const note = h('input', { type: 'text', value: msg ? msg.slice(0, 80) : '', 'aria-label': '메모' });
  const body = h('div', { class: 'stack' },
    h('p', null, h('b', { class: 'mono' }, ruleId), ' ', msg || ''),
    h('div', { class: 'stack tight' },
      h('label', { class: 'radio-inline' }, rSvc, svc ? ` 이 서비스만 (${fqdn(svc.subdomain)}) — 권장` : ' 이 서비스만 (어느 서비스인지 알 수 없음)'),
      h('label', { class: 'radio-inline' }, rAll, ' 모든 사이트 공통')),
    field('메모', note, '나중에 왜 뺐는지 알 수 있게'),
    h('p', { class: 'hint' }, '저장하면 「적용 대기」가 됩니다. 적용해야 Caddy에 반영됩니다.'));
  const ok = h('button', { type: 'button', class: 'btn primary' }, '예외 추가');
  const cancel = h('button', { type: 'button', class: 'btn ghost' }, '취소');
  const d = openDialog({ title: `규칙 ${ruleId} 예외`, body, footer: [h('span', { class: 'spacer' }), cancel, ok] });
  cancel.addEventListener('click', () => d.close());
  ok.addEventListener('click', () => busy(ok, async () => {
    const x = { id: ruleId, note: note.value.trim() };
    try {
      if (rSvc.checked && svc) {
        const cur = svc.wafExclude || [];
        if (cur.some((e) => e.id === ruleId)) { toast('이미 이 서비스의 예외입니다'); d.close(); return; }
        await saveServicePatch(svc, { wafExclude: [...cur, x] });
      } else {
        const cur = settings().wafExclude || [];
        if (cur.some((e) => e.id === ruleId)) { toast('이미 공통 예외입니다'); d.close(); return; }
        await saveSettingsPatch({ wafExclude: [...cur, x] });
      }
      toast(`규칙 ${ruleId} 예외 추가 — 적용 대기`);
      d.close();
    } catch (ex) { toast(ex.message, 'err'); }
  }));
}

function wafEventsStep() {
  const since = h('select', { 'aria-label': '기간', style: { width: 'auto' } }, [['1h', '최근 1시간'], ['24h', '최근 24시간'], ['168h', '최근 7일']].map(([v, l]) => h('option', { value: v, selected: v === '24h' }, l)));
  const kind = h('select', { 'aria-label': '종류', style: { width: 'auto' } }, [['', '전체'], ['waf', 'WAF (CRS)'], ['guard', '기본 차단']].map(([v, l]) => h('option', { value: v }, l)));
  const hostSel = h('select', { 'aria-label': '서비스', style: { width: 'auto' } }, h('option', { value: '' }, '모든 서비스'));
  const load = h('button', { type: 'button', class: 'btn' }, icon('refresh'), '불러오기');
  const out = h('div', { class: 'stack' }, h('p', { class: 'muted' }, '「불러오기」를 누르면 Caddy 로그에서 WAF·기본 차단 기록을 읽습니다.'));
  let data = null;
  const AGG = new Set(['949110', '959100', '980170', '980130']);
  const draw = () => {
    if (!data) return;
    const k = kind.value;
    const hs = hostSel.value;
    const evs = (data.events || []).filter((e) => (!k || e.kind === k) && (!hs || e.host === hs));
    const rules = (data.rules || []).filter((r) => (!k || (k === 'guard') === (r.group === 'guard')) && (!hs || (r.hosts || {})[hs]));
    if (!data.events.length) { out.replaceChildren(callout('ok', '이 기간에 WAF·기본 차단에 걸린 요청이 없습니다.')); return; }
    const hostItems = Object.entries(data.hosts || {}).sort((a, b) => b[1] - a[1]).map(([h0, c]) => ({ label: svcByHost(h0) ? svcByHost(h0).subdomain : h0, title: h0, count: c }));
    out.replaceChildren(
      h('div', { class: 'row wrap' },
        h('span', { class: 'badge danger' }, `차단 ${data.denied}`),
        h('span', { class: 'badge accent' }, `기본 차단 ${data.guard}`),
        h('span', { class: 'badge warn' }, `기록 ${data.events.length >= 500 ? '500+' : data.events.length}건`),
        h('span', { class: 'hint' }, '949110·959100은 「점수 합계 초과」 판정입니다 — 원인이 된 개별 규칙을 예외로 넣으세요.')),
      h('div', { class: 'grid-2' },
        h('div', { class: 'section-box' }, h('h3', null, '항목별'), barList((data.groups || []).map((g) => ({ label: g.key === 'guard' ? g.label : `${g.key} ${g.label}`, count: g.count })))),
        h('div', { class: 'section-box' }, h('h3', null, '서비스별'), hostItems.length ? barList(hostItems) : h('p', { class: 'small muted' }, '서비스를 알 수 없음 (접근 로그가 꺼진 사이트)'))),
      h('div', { class: 'table-wrap glass-inner' }, h('table', { class: 'compact' },
        h('thead', null, h('tr', null, ['규칙', '내용', '서비스', '횟수', '차단', ''].map((t) => h('th', { scope: 'col' }, t)))),
        h('tbody', null, rules.slice(0, 40).map((x) => {
          const hosts = Object.keys(x.hosts || {});
          const b = h('button', { type: 'button', class: 'btn sm' }, '예외…');
          b.addEventListener('click', () => addExclusion(x.ruleId, x.msg, hosts.length === 1 ? hosts[0] : hs || ''));
          const isGuard = x.group === 'guard';
          return h('tr', null,
            h('td', { class: 'mono' }, isGuard ? h('span', { class: 'badge accent' }, '기본 차단') : x.ruleId),
            h('td', null, x.msg),
            h('td', { class: 'small' }, hosts.map((hh) => (svcByHost(hh) ? svcByHost(hh).subdomain : hh)).join(', ') || '—'),
            h('td', null, String(x.count)),
            h('td', null, x.denied ? h('span', { class: 'badge danger' }, String(x.denied)) : '—'),
            h('td', null, isGuard || AGG.has(x.ruleId) ? null : b));
        })))),
      h('details', null, h('summary', null, `최근 기록 ${evs.length}건`),
        h('div', { class: 'table-wrap' }, h('table', { class: 'compact' },
          h('thead', null, h('tr', null, ['시각', '결과', '서비스', '규칙', 'URI'].map((t) => h('th', { scope: 'col' }, t)))),
          h('tbody', null, evs.slice(0, 150).map((e) => h('tr', null,
            h('td', null, fmtTime(e.time)),
            h('td', null, e.action === 'denied' ? h('span', { class: 'badge danger' }, '차단') : h('span', { class: 'badge warn' }, '탐지')),
            h('td', { class: 'small' }, e.host ? (svcByHost(e.host) ? svcByHost(e.host).subdomain : e.host) : '—'),
            h('td', { class: 'mono' }, e.kind === 'guard' ? (WAF_META && WAF_META.categories[e.ruleId]) || e.ruleId : e.ruleId),
            h('td', { class: 'mono ellipsis', title: e.uri }, e.uri))))))));
  };
  const run = () => busy(load, async () => {
    out.replaceChildren(spinnerRow('Caddy 로그 읽는 중…'));
    try {
      await wafMeta();
      data = await api('GET', `/api/waf/events?since=${since.value}`);
      const hosts = Object.keys(data.hosts || {}).sort();
      hostSel.replaceChildren(h('option', { value: '' }, '모든 서비스'), ...hosts.map((x) => h('option', { value: x }, svcByHost(x) ? svcByHost(x).subdomain : x)));
      draw();
    } catch (ex) { out.replaceChildren(errorBox(ex.message)); }
  });
  load.addEventListener('click', run);
  kind.addEventListener('change', draw);
  hostSel.addEventListener('change', draw);
  return {
    id: 'wafevents', title: 'WAF 이벤트', desc: 'WAF·기본 차단에 걸린 요청을 항목·서비스·규칙별로 모읍니다. 오탐은 「예외…」로 그 서비스나 공통 예외에 넣으세요.', state: 'opt', stateText: '',
    body: h('div', { class: 'stack' }, h('div', { class: 'row wrap' }, since, kind, hostSel, load), out),
  };
}

// ======================================================================= Caddy tab: WAF test

function wafTestStep() {
  const sites = S.state.services.filter((s) => s.enabled && !s.dnsOnly);
  const sel = h('select', { 'aria-label': '시험할 서비스', style: { width: 'auto' } }, sites.map((s) => h('option', { value: s.id }, `${s.subdomain}${s.waf ? ` · WAF ${wafLabel(s.waf)}` : ''}${s.guard ? ' · 기본 차단' : ''}`)));
  const run = h('button', { type: 'button', class: 'btn primary' }, '시험 요청 보내기');
  const out = h('div', { class: 'stack' });
  const V = { ok: ['✓ 맞음', 'ok'], fail: ['✗ 확인 필요', 'danger'], info: ['참고', 'muted'] };
  const EXP = { block: '차단', pass: '통과', log: '통과 + 기록' };
  run.addEventListener('click', () => busy(run, async () => {
    out.replaceChildren(spinnerRow('시험 요청 8개를 보내는 중…'));
    try {
      const r = await api('POST', '/api/waf/test', { id: sel.value });
      const bad = r.results.filter((x) => x.verdict === 'fail').length;
      out.replaceChildren(
        bad ? callout('danger', h('b', null, `${bad}개 항목이 예상과 다릅니다`), h('span', { class: 'small' }, '아래 설명을 확인하세요. 설정을 바꿨다면 먼저 「적용」해야 Caddy에 반영됩니다.'))
          : callout('ok', h('b', null, `✓ ${r.host} — 설정대로 동작합니다`)),
        h('div', { class: 'table-wrap glass-inner' }, h('table', { class: 'compact' },
          h('thead', null, h('tr', null, ['항목', '보낸 요청', '예상', '결과', '판정'].map((t) => h('th', { scope: 'col' }, t)))),
          h('tbody', null, r.results.map((x) => {
            const [vt, vc] = V[x.verdict] || [x.verdict, ''];
            return h('tr', null,
              h('td', null, h('b', null, x.name)),
              h('td', { class: 'mono small ellipsis', title: x.request }, x.request),
              h('td', null, EXP[x.expect] || x.expect),
              h('td', null, x.status ? `HTTP ${x.status}` : '—', x.by ? h('div', { class: 'cell-sub' }, { guard: '기본 차단', waf: 'WAF', auth: 'Authelia' }[x.by]) : null),
              h('td', null, h('span', { class: `badge ${vc}` }, vt), x.note ? h('div', { class: 'cell-sub' }, x.note) : null));
          })))));
    } catch (ex) { out.replaceChildren(errorBox(ex.message)); }
  }));
  return {
    id: 'waftest', title: 'WAF 시험', desc: '길목이 Caddy로 공격 모양의 시험 요청을 직접 보내 실제로 막히는지 확인합니다.', state: 'opt', stateText: '',
    body: h('div', { class: 'stack' },
      h('p', { class: 'small' }, 'SQL 인젝션, XSS, 경로 탐색, 명령 실행, 스캐너·AI 크롤러 User-Agent, /.env 요청을 한 번씩 보냅니다. 막히지 않는 설정이면 요청이 앱까지 가지만 실제 공격 코드는 아닙니다. mTLS 사이트는 Cloudflare 인증서가 있어야 해서 시험할 수 없습니다.'),
      sites.length ? h('div', { class: 'row' }, sel, run) : h('p', { class: 'muted' }, '시험할 사이트가 없습니다.'),
      out),
  };
}

// ======================================================================= Cloudflare tab: edge rules

const CF_ACTION = { managed_challenge: '관리형 챌린지', block: '차단', js_challenge: 'JS 챌린지', challenge: '대화형 챌린지', skip: '건너뛰기 (허용)', log: '기록' };
const PLAN_ACT = { create: ['만듦', 'ok'], update: ['수정', 'warn'], disable: ['끔', 'warn'], delete: ['지움', 'danger'], ok: ['변경 없음', 'muted'], skip: ['사용 안 함', 'muted'], error: ['설정 오류', 'danger'] };
const CF_KEYS = { allow: '신뢰 IP 허용', crowdsec: 'CrowdSec', threat: '위협 차단', asn: '국가·통신사', custom: '사용자 규칙', rate: '속도 제한' };
const ACT_OPTS = [['block', '차단'], ['managed_challenge', '관리형 챌린지 (권장: 사람은 통과)'], ['js_challenge', 'JS 챌린지'], ['challenge', '대화형 챌린지']];

// Missing Cloudflare token permissions → what breaks and exactly how to add them.
const CF_PERMS = {
  waf: { scope: '영역', res: '영역 WAF', level: '편집', en: 'Zone · Zone WAF · Edit', what: 'WAF 규칙 (신뢰 IP, 위협 차단, 국가·통신사, 사용자 규칙, 속도 제한)' },
  analytics: { scope: '영역', res: '분석', level: '읽기', en: 'Zone · Analytics · Read', what: '엣지 이벤트 (Cloudflare가 막은 요청 보기)' },
  lists: { scope: '계정', res: '계정 필터 목록', level: '편집', en: 'Account · Account Filter Lists · Edit', what: 'CrowdSec 차단 IP 목록' },
};

function cfPermHelp(perms, onRecheck, { title } = {}) {
  const ps = [...new Set(perms)].filter((p) => CF_PERMS[p]);
  const recheck = h('button', { type: 'button', class: 'btn primary sm' }, icon('refresh'), '권한 추가 후 다시 확인');
  recheck.addEventListener('click', () => busy(recheck, async () => { await onRecheck(); }));
  const tokenStep = h('button', { type: 'button', class: 'btn sm' }, 'API 토큰 · 존 단계');
  tokenStep.addEventListener('click', () => gotoTab('cloudflare', 'token'));
  const acct = ps.includes('lists');
  // missing permissions are a to-do for the user, not a failure: warning level
  return callout('warn',
    h('b', null, title || `Cloudflare 토큰에 권한이 ${ps.length}개 모자랍니다 — 이 기능은 권한을 추가할 때까지 쓸 수 없습니다`),
    h('div', { class: 'perm-list' }, ps.map((p) => h('div', { class: 'perm-row' },
      h('span', { class: 'perm-chip' }, h('span', null, CF_PERMS[p].scope), '›', h('span', null, CF_PERMS[p].res), '›', h('b', null, CF_PERMS[p].level)),
      h('span', { class: 'small' }, CF_PERMS[p].what, h('span', { class: 'muted' }, ` · ${CF_PERMS[p].en}`))))),
    h('details', { class: 'howto', open: true },
      h('summary', null, h('b', null, '권한 추가 방법 (토큰 값은 그대로, 길목에 다시 넣을 필요 없음)')),
      h('ol', { class: 'howto-list' },
        h('li', null, h('a', { href: 'https://dash.cloudflare.com/profile/api-tokens', target: '_blank', rel: 'noopener noreferrer' }, 'Cloudflare 대시보드 › 내 프로필 › API 토큰'), '을 엽니다 (새 창).'),
        h('li', null, '목록에서 길목에 넣은 토큰을 찾아 오른쪽 「⋯」 › ', h('b', null, '편집'), '을 누릅니다. 어떤 토큰인지 모르겠으면 「최근 사용」 시각이 방금인 토큰입니다. (새로 만들 필요는 없습니다)'),
        h('li', null, '「권한」 아래 ', h('b', null, '「+ 더 추가」'), '를 눌러, 위에 빨갛게 표시된 권한마다 세 칸을 차례로 고릅니다: ',
          h('ul', null, ps.map((p) => h('li', null, h('code', null, CF_PERMS[p].scope), ' → ', h('code', null, CF_PERMS[p].res), ' → ', h('code', null, CF_PERMS[p].level))))),
        h('li', null, '「영역 리소스」가 ', h('b', null, `「포함 › 특정 영역 › ${settings().domain || '내 도메인'}」`), '인지 확인합니다 (영역 권한은 이 범위에만 적용).',
          acct ? h('span', null, ' 계정 권한을 넣었다면 「계정 리소스」도 ', h('b', null, '「포함 › 내 계정」'), '으로 정합니다.') : null),
        h('li', null, '아래로 내려 「요약 계속」 → ', h('b', null, '「토큰 업데이트」'), '를 누릅니다. 반영은 즉시입니다.'),
        h('li', null, '돌아와서 아래 「권한 추가 후 다시 확인」을 누릅니다.'))),
    h('p', { class: 'hint' }, '토큰을 컨테이너 설정(GM_CF_TOKEN_FILE)으로 넣었어도 방법은 같습니다 — Cloudflare에서 같은 토큰의 권한만 늘리면 됩니다.'),
    h('div', { class: 'row' }, recheck, tokenStep));
}

/** One form made of several cards; a single 저장 saves every card's fields. */
function cardsForm(cards, onSaved) {
  const all = [];
  const err = h('p', { class: 'form-error', role: 'alert', hidden: true });
  const SAVE = '규칙 설정 저장';
  const save = h('button', { type: 'submit', class: 'btn primary', title: '설정만 저장합니다 — Cloudflare에는 아래 「Cloudflare에 규칙 적용」을 눌러야 반영됩니다' }, SAVE);
  const form = h('form', { class: 'stack', novalidate: true }, err,
    h('div', { class: 'rule-cards' }, cards.map((c) => {
      const f = settingsFields(c.defs);
      all.push(f);
      const head = c.toggle ? settingsFields([c.toggle]) : null;
      if (head) all.push(head);
      const card = h('section', { class: 'rule-card section-box', 'data-key': c.toggle ? c.toggle.key : '' },
        h('header', { class: 'rc-head' }, h('div', { class: 'grow' }, h('h3', null, c.icon ? icon(c.icon) : null, c.title), c.desc ? h('p', { class: 'small muted' }, c.desc) : null), c.badge || null),
        head ? head.els : null,
        h('div', { class: 'rc-body grid-2' }, f.els),
        c.extra || null);
      if (head) {
        const input = head.inputs[c.toggle.key];
        const sync = () => { card.classList.toggle('off', !input.checked); };
        input.addEventListener('change', sync);
        sync();
      }
      return card;
    })),
    h('div', { class: 'row sticky-actions' }, h('span', { class: 'grow hint' }, '저장만으로는 Cloudflare가 바뀌지 않습니다 — 저장한 뒤 아래 「Cloudflare에 규칙 적용」을 누르세요. (상단 「적용」은 DNS만 다룹니다)'), save));
  form.addEventListener('input', () => { save.textContent = `${SAVE} *`; });
  form.addEventListener('change', () => { save.textContent = `${SAVE} *`; });
  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    err.hidden = true;
    const patch = Object.assign({}, ...all.map((f) => f.read()));
    try {
      await busy(save, () => saveSettingsPatch(patch));
      save.textContent = SAVE;
      WAF_META = null;
      onSaved && onSaved();
    } catch (ex) { err.textContent = ex.message; err.hidden = false; }
  });
  return form;
}

function cfWafStep(getL) {
  const st = S.state;
  const s = settings();
  const view = h('div', { class: 'stack' });
  const preview = { threat: h('div'), asn: h('div') };
  const showPreview = async () => {
    try {
      const m = await wafMeta(true);
      fill(preview.threat, m.threatErr ? h('p', { class: 'hint warn-text' }, m.threatErr)
        : h('details', { class: 'preset' }, h('summary', null, `규칙 식 미리보기 (${m.threatLen.toLocaleString()} / ${m.exprMax.toLocaleString()}자)`), h('pre', { class: 'code wrap' }, m.threatExpr)));
      fill(preview.asn, m.geoErr ? h('p', { class: 'hint warn-text' }, m.geoErr)
        : h('details', { class: 'preset' }, h('summary', null, '규칙 식 미리보기'), h('pre', { class: 'code wrap' }, m.geoExpr)));
    } catch { /* preview only */ }
  };
  const csGo = h('button', { type: 'button', class: 'btn sm' }, 'CrowdSec 탭');
  csGo.addEventListener('click', () => gotoTab('crowdsec', 'sync'));
  const scope = (key) => { const el = scopePicker(s[key]); return { key, type: 'custom', el, read: () => el.value, label: '적용 대상' }; };
  const cards = [
    { title: '신뢰 IP 허용', icon: 'check', desc: '목록의 IP는 아래 규칙을 모두 건너뜁니다 (사무실·집 고정 IP 등). 규칙 맨 앞에 둡니다.',
      toggle: { key: 'cfAllowRule', type: 'switch', label: '사용' },
      defs: [{ key: 'cfAllowIps', type: 'code', rows: 3, label: 'IP / 대역', placeholder: '203.0.113.10\n198.51.100.0/24', hint: '한 줄에 하나. 이 IP에서 오는 요청은 국가 제한·위협 차단·사용자 규칙에 걸리지 않습니다.' }] },
    { title: 'CrowdSec 차단 목록', icon: 'shield', desc: 'CrowdSec이 판정한 공격 IP를 엣지에서 차단합니다. 켜고 끄기는 CrowdSec 탭에서 합니다.',
      defs: [], badge: h('span', { class: `badge ${use('crowdsec') && s.crowdsecEnabled && s.crowdsecSync ? 'ok' : 'muted'}` }, use('crowdsec') && s.crowdsecEnabled && s.crowdsecSync ? '사용' : '사용 안 함'),
      extra: h('div', { class: 'row' }, csGo) },
    { title: '위협 차단', icon: 'shield', desc: '차단 IP · 스캐너 · AI 크롤러 · 공격 경로를 규칙 하나로 묶어 막습니다 (Free 플랜 규칙 수 절약).',
      toggle: { key: 'cfThreatRule', type: 'switch', label: '사용' },
      defs: [
        { key: 'cfThreatAction', type: 'select', label: '처리', options: ACT_OPTS },
        scope('cfThreatHosts'),
        { key: 'cfThreatBots', type: 'switch', label: '스캐너·공격 도구 (User-Agent)' },
        { key: 'cfThreatAi', type: 'switch', label: 'AI 크롤러' },
        { key: 'cfThreatPaths', type: 'switch', label: '공격 경로 (/.env, /.git/ …)' },
        { key: 'cfThreatEmptyUa', type: 'switch', label: 'User-Agent 없는 요청' },
        { key: 'cfThreatPhp', type: 'switch', label: 'PHP 요청 (*.php)' },
        { key: 'cfDenyIps', type: 'code', rows: 3, label: '차단 IP / 대역', placeholder: '203.0.113.66\n192.0.2.0/24', hint: '한 줄에 하나. 「엣지 이벤트」에서 버튼으로도 추가됩니다.' },
      ], extra: h('div', { class: 'stack tight' }, h('p', { class: 'hint' }, '목록 내용과 추가 User-Agent·경로는 Caddy 탭 › 기본 차단과 같이 씁니다.'), preview.threat) },
    { title: '국가·통신사 제한', icon: 'globe', desc: '접속자의 국가·통신사(ASN)로 거릅니다. 실제 접속자 IP로 판단하는 엣지에서만 가능한 기능입니다.',
      toggle: { key: 'cfAsnRule', type: 'switch', label: '사용' },
      defs: [
        { key: 'cfGeoMode', type: 'select', label: '방식', options: [['allow', '허용 목록 — 목록 밖에서 오면 처리'], ['block', '차단 목록 — 목록에서 오면 처리']] },
        { key: 'cfAsnAction', type: 'select', label: '처리', options: ACT_OPTS },
        { key: 'cfGeoCountries', label: '국가 코드', mono: true, placeholder: 'KR', hint: 'ISO 2글자, 공백으로 구분 (예: KR JP). 비우면 통신사만 봅니다.' },
        { key: 'cfAsnList', label: '통신사 ASN', mono: true, hint: '공백으로 구분. 예: 4766 KT · 9318 SK브로드밴드 · 3786 LG U+ · 17858 LG U+(파워콤) · 9644 SK텔레콤. 허용 목록에서 국가와 같이 쓰면 「둘 중 하나라도 맞으면 허용」입니다.' },
        { key: 'cfGeoBots', type: 'switch', label: '검색엔진 등 확인된 봇은 통과', hint: 'Cloudflare가 확인한 봇(Googlebot 등)은 국가 제한을 받지 않습니다.' },
        scope('cfGeoHosts'),
      ], extra: preview.asn },
    { title: '사용자 규칙', icon: 'code', desc: 'Cloudflare 규칙 식을 직접 씁니다 (고급).',
      toggle: { key: 'cfCustomRule', type: 'switch', label: '사용' },
      defs: [
        { key: 'cfCustomName', label: '이름', placeholder: '관리 경로 보호' },
        { key: 'cfCustomAction', type: 'select', label: '처리', options: ACT_OPTS },
        { key: 'cfCustomExpr', type: 'code', rows: 3, label: '조건식', placeholder: '(http.host eq "admin.example.com" and not ip.src.country in {"KR"})',
          hint: '예: http.request.uri.path contains "/admin" · ip.src.country eq "CN" · http.request.method eq "POST". 문법이 틀리면 적용할 때 Cloudflare가 거부합니다.' },
      ] },
    { title: '요청 속도 제한', icon: 'clock', desc: '같은 IP가 짧은 시간에 너무 많이 요청하면 막습니다 (로그인 무차별 대입 방지). 사용자 지정 규칙과 별도 한도입니다.',
      toggle: { key: 'cfRateRule', type: 'switch', label: '사용' },
      defs: [
        { key: 'cfRatePaths', type: 'code', rows: 3, label: '대상 경로', placeholder: '/login\n/api/auth', hint: '한 줄에 하나, 경로에 포함되면 대상. 비우면 모든 요청.' },
        { key: 'cfRateRequests', type: 'number', label: '허용 요청 수', attrs: { min: '1' }, hint: '아래 기간 동안 IP 하나가 보낼 수 있는 요청 수' },
        { key: 'cfRatePeriod', type: 'select', num: true, label: '기간', options: [['10', '10초 (Free 플랜은 이것만)'], ['60', '1분'], ['120', '2분'], ['300', '5분'], ['600', '10분'], ['3600', '1시간']] },
        { key: 'cfRateTimeout', type: 'select', num: true, label: '차단 시간', options: [['10', '10초 (Free 플랜은 이것만)'], ['60', '1분'], ['600', '10분'], ['3600', '1시간'], ['86400', '1일']] },
        { key: 'cfRateAction', type: 'select', label: '처리', options: [['block', '차단'], ['managed_challenge', '관리형 챌린지']] },
      ] },
  ];
  const form = cardsForm(cards, async () => {
    showPreview();
    await draw();
    // saving is only half of it: lead the eye to the plan and the apply button
    if (!applyBtn.disabled) {
      applyBtn.scrollIntoView({ behavior: 'smooth', block: 'center' });
      applyBtn.classList.add('pulse');
      setTimeout(() => applyBtn.classList.remove('pulse'), 2400);
      toast('규칙 설정을 저장했습니다 — 「Cloudflare에 규칙 적용」을 눌러야 엣지에 반영됩니다', 'warn', 7000);
    }
  });
  const top = h('div', { class: 'stack' });
  const lockForm = (on, why) => {
    form.inert = on;
    form.classList.toggle('locked', on);
    form.title = on ? why || '' : '';
  };
  const lockCard = (key, on) => {
    const c = form.querySelector(`.rule-card[data-key="${key}"]`);
    if (!c) return;
    c.inert = on;
    c.classList.toggle('locked', on);
  };
  lockForm(true, 'Cloudflare 규칙을 읽는 중');

  const applyBtn = h('button', { type: 'button', class: 'btn primary' }, 'Cloudflare에 규칙 적용…');
  const reload = h('button', { type: 'button', class: 'btn' }, icon('refresh'), '다시 읽기');
  const meter = (label, used, after, limit) => {
    const pct = limit ? Math.min(100, (after / limit) * 100) : 0;
    const over = limit && after > limit;
    return h('div', { class: `meter ${over ? 'over' : ''}` },
      h('div', { class: 'row' }, h('b', null, label), h('span', { class: 'grow' }), h('span', { class: 'small' }, limit ? `지금 ${used} → 적용 후 ${after} / 한도 ${limit}` : `지금 ${used} → 적용 후 ${after}`)),
      limit ? h('div', { class: 'meter-track', role: 'meter', 'aria-valuemin': '0', 'aria-valuemax': String(limit), 'aria-valuenow': String(after), 'aria-label': label },
        h('span', { class: 'meter-fill', style: { width: `${pct}%` } })) : null);
  };
  const ruleTable = (rules, caption) => h('div', { class: 'table-wrap glass-inner' }, h('table', { class: 'compact' },
    h('caption', { class: 'sr-only' }, caption),
    h('thead', null, h('tr', null, ['#', '규칙', '동작', '상태', '조건'].map((t) => h('th', { scope: 'col' }, t)))),
    h('tbody', null, rules.length ? rules.map((r, i) => h('tr', { class: r.enabled ? '' : 'disabled' },
      h('td', null, String(i + 1)),
      h('td', null, h('b', null, r.description || '(이름 없음)'), r.managed ? h('span', { class: 'badge accent', style: { marginLeft: '6px' } }, `길목 · ${CF_KEYS[r.managed] || r.managed}`) : null),
      h('td', null, CF_ACTION[r.action] || r.action, r.ratelimit ? h('div', { class: 'cell-sub' }, `${r.ratelimit.requests_per_period}회 / ${r.ratelimit.period}초`) : null),
      h('td', null, r.enabled ? h('span', { class: 'badge ok' }, '켜짐') : h('span', { class: 'badge muted' }, '꺼짐')),
      h('td', { class: 'mono ellipsis', title: r.expression }, r.expression)))
      : h('tr', null, h('td', { colspan: '5', class: 'muted' }, '규칙이 없습니다.')))));

  const draw = async () => {
    top.replaceChildren();
    if (!S.state.cfConfigured) {
      const go = h('button', { type: 'button', class: 'btn sm' }, 'API 토큰 · 존 단계로');
      go.addEventListener('click', () => gotoTab('cloudflare', 'token'));
      top.append(callout('warn', h('b', null, 'Cloudflare 토큰이 없어 WAF 규칙을 설정할 수 없습니다'), h('span', { class: 'small' }, '먼저 토큰을 넣으세요. WAF 규칙에는 「영역 · 영역 WAF · 편집」 권한이 필요합니다.'), h('div', null, go)));
      lockForm(true, '토큰 없음');
      view.replaceChildren();
      applyBtn.disabled = true;
      reload.disabled = true;
      return;
    }
    view.replaceChildren(spinnerRow('Cloudflare WAF 규칙 읽는 중…'));
    let v;
    try { v = await api('GET', '/api/cfwaf'); } catch (ex) { view.replaceChildren(); top.append(errorBox(ex.message)); lockForm(true); return; }
    if (!view.isConnected) return;
    const perms = v.perms || [];
    if (v.error) {
      applyBtn.disabled = true;
      view.replaceChildren();
      lockForm(true, '토큰 권한이 모자라 설정할 수 없습니다');
      top.append(perms.length
        ? cfPermHelp(perms, draw, { title: 'WAF 규칙을 쓸 수 없습니다 — Cloudflare 토큰에 권한이 없습니다' })
        : callout('danger', h('b', null, 'Cloudflare WAF 규칙을 읽지 못했습니다'), h('span', null, v.error)));
      getL().set('waf', perms.length ? 'warn' : 'fail', perms.length ? '권한 필요' : '읽기 실패');
      return;
    }
    lockForm(false);
    // partial: rate limiting / IP list permissions
    const ratePerm = v.rateError && perms.includes('waf');
    lockCard('cfRateRule', !!ratePerm);
    if (perms.length) top.append(cfPermHelp(perms, draw, { title: `일부 기능을 쓸 수 없습니다 — ${perms.map((p) => (CF_PERMS[p] || {}).what).filter(Boolean).join(', ')}` }));
    const kids = [];
    const planName = { free: 'Free', pro: 'Pro', business: 'Business', enterprise: 'Enterprise' }[v.plan] || v.plan || '알 수 없음';
    kids.push(h('div', { class: 'grid-2' },
      meter(`사용자 지정 규칙 (${planName} 플랜)`, v.used, v.after, v.limit),
      meter('속도 제한 규칙', v.rateUsed, v.rateAfter, v.rateLimit)));
    if (v.overLimit) kids.push(callout('danger', h('b', null, '규칙 수 한도 초과'), h('span', null, v.overLimit)));
    for (const r of v.adoptable || []) {
      const b = h('button', { type: 'button', class: 'btn sm primary' }, '길목이 관리하도록 가져오기');
      b.addEventListener('click', () => busy(b, async () => {
        try {
          await api('POST', '/api/cfwaf/adopt', { id: r.id });
          await refreshState();
          toast(`「${r.description || r.id}」 규칙을 가져왔습니다 — 국가·통신사 제한 카드에 반영됨`);
          renderPanel();
        } catch (ex) { toast(ex.message, 'err'); }
      }));
      kids.push(callout('warn', h('b', null, `직접 만든 통신사(ASN) 규칙 발견: 「${r.description || r.id}」`),
        h('span', { class: 'mono small' }, r.expression),
        h('span', { class: 'small' }, '가져오면 그 규칙을 이 화면에서 관리합니다 (새로 만들지 않고 같은 규칙을 수정, 끄면 지우지 않고 비활성화).'), h('div', null, b)));
    }
    if (v.listError && !perms.includes('lists')) kids.push(callout('danger', h('b', null, 'IP 목록 접근 실패'), h('span', null, v.listError)));
    if (v.rateError && !ratePerm) kids.push(callout('warn', h('b', null, '속도 제한 규칙을 읽지 못했습니다'), h('span', { class: 'small' }, v.rateError)));
    const changes = (v.items || []).filter((p) => p.action !== 'ok' && p.action !== 'skip');
    const errs = (v.items || []).filter((p) => p.action === 'error');
    kids.push(h('h3', null, '적용 계획'), h('ul', { class: 'checks' }, (v.items || []).map((p) => {
      const [t, c] = PLAN_ACT[p.action] || [p.action, 'muted'];
      const d = p.desired || p.current;
      const cls = p.action === 'ok' ? 'ok' : p.action === 'skip' ? 'skip' : p.action === 'error' ? 'fail' : 'warn';
      return h('li', { class: `chk ${cls}` },
        h('span', { class: 'chk-mark', 'aria-hidden': 'true' }, p.action === 'ok' ? '✓' : p.action === 'skip' ? '–' : p.action === 'error' ? '!' : '•'),
        h('div', { class: 'chk-text' }, h('b', null, p.name, ' ', h('span', { class: `badge ${c}` }, t)),
          d && p.action !== 'skip' ? h('span', { class: 'chk-detail mono' }, `${CF_ACTION[d.action] || d.action} · ${d.expression.length > 220 ? `${d.expression.slice(0, 220)}…` : d.expression}`) : null,
          p.reason ? h('span', { class: 'chk-detail' }, p.reason) : null));
    })));
    kids.push(h('details', null, h('summary', null, `Cloudflare에 있는 사용자 지정 규칙 ${v.rules.length}개`), ruleTable(v.rules, '사용자 지정 규칙')));
    if (v.rateRules.length) kids.push(h('details', null, h('summary', null, `속도 제한 규칙 ${v.rateRules.length}개`), ruleTable(v.rateRules, '속도 제한 규칙')));
    applyBtn.disabled = !changes.length || !!errs.length || !!v.overLimit;
    applyBtn.title = errs.length ? '설정 오류를 먼저 고치세요' : v.overLimit ? '규칙 수 한도를 넘습니다' : '';
    view.replaceChildren(...kids);
    const managed = [...v.rules, ...v.rateRules].filter((r) => r.managed && r.enabled).length;
    getL().set('waf', errs.length || v.overLimit ? 'fail' : changes.length ? 'warn' : managed ? 'ok' : 'opt',
      errs.length ? '설정 오류' : v.overLimit ? '한도 초과' : changes.length ? `변경 ${changes.length}건` : managed ? `길목 규칙 ${managed}개` : '사용 안 함');
  };
  reload.addEventListener('click', () => busy(reload, draw));
  applyBtn.addEventListener('click', async () => {
    const ok = await confirmDialog({ title: 'Cloudflare WAF 규칙 적용', message: '계획대로 규칙을 만들거나 고치거나 지웁니다.\n길목이 관리하지 않는 규칙은 건드리지 않습니다. 반영은 몇 초 안에 됩니다.', okText: '적용' });
    if (!ok) return;
    await busy(applyBtn, async () => {
      let res;
      try { res = await api('POST', '/api/cfwaf/apply'); } catch (ex) { res = { ok: false, error: ex.message }; }
      showResult('Cloudflare WAF 규칙', res);
      draw();
    });
  });
  setTimeout(() => { draw(); showPreview(); }, 0);
  return {
    id: 'waf', title: 'WAF 규칙', desc: 'Cloudflare 엣지의 규칙. 실제 접속자 IP·국가·통신사로 판단하고 서버에 닿기 전에 막습니다 — Proxied 사이트에만 적용됩니다.',
    state: st.cfConfigured ? 'wait' : 'opt', stateText: st.cfConfigured ? '' : '토큰 없음',
    body: h('div', { class: 'stack' }, top, form, h('hr', { class: 'sep' }), view, h('div', { class: 'row' }, reload, h('span', { class: 'grow' }), applyBtn)),
  };
}

// ======================================================================= Cloudflare tab: edge events

const CF_EV_ACT = { block: ['차단', 'danger'], managed_challenge: ['관리형 챌린지', 'warn'], challenge: ['챌린지', 'warn'], jschallenge: ['JS 챌린지', 'warn'], js_challenge: ['JS 챌린지', 'warn'],
  challenge_solved: ['챌린지 통과', 'ok'], managed_challenge_interactive_solved: ['챌린지 통과', 'ok'], managed_challenge_non_interactive_solved: ['챌린지 통과', 'ok'], skip: ['건너뜀', 'muted'], log: ['기록', 'muted'], allow: ['허용', 'ok'] };

function cfEventsStep() {
  const since = h('select', { 'aria-label': '기간', style: { width: 'auto' } }, [['1h', '최근 1시간'], ['6h', '최근 6시간'], ['24h', '최근 24시간']].map(([v, l]) => h('option', { value: v, selected: v === '24h' }, l)));
  const load = h('button', { type: 'button', class: 'btn' }, icon('refresh'), '불러오기');
  const out = h('div', { class: 'stack' }, h('p', { class: 'muted' }, '「불러오기」를 누르면 Cloudflare가 막거나 챌린지한 요청을 읽습니다. 토큰에 「영역 · 분석 · 읽기」 권한이 필요합니다.'));
  const denyIP = async (ip) => {
    const cur = settings().cfDenyIps || '';
    if (cur.split('\n').map((x) => x.trim()).includes(ip)) { toast('이미 차단 목록에 있습니다'); return; }
    const ok = await confirmDialog({ title: `${ip} 차단`, message: `위협 차단 규칙의 「차단 IP」에 ${ip} 를 넣고 저장합니다.\n「Cloudflare에 적용」을 눌러야 엣지에 반영됩니다.${settings().cfThreatRule ? '' : '\n(위협 차단 규칙이 꺼져 있어 함께 켭니다)'}`, okText: '추가' });
    if (!ok) return;
    try {
      await saveSettingsPatch({ cfDenyIps: (cur.trim() ? `${cur.trim()}\n` : '') + ip, cfThreatRule: true });
      renderPanel();
    } catch (ex) { toast(ex.message, 'err'); }
  };
  const run = () => busy(load, async () => {
    out.replaceChildren(spinnerRow('Cloudflare 보안 이벤트 읽는 중…'));
    let r;
    try { r = await api('GET', `/api/cfwaf/events?since=${since.value}`); } catch (ex) {
      const perms = (ex.data && ex.data.perms) || [];
      out.replaceChildren(perms.length ? cfPermHelp(perms, run, { title: '엣지 이벤트를 볼 수 없습니다 — Cloudflare 토큰에 권한이 없습니다' }) : errorBox(ex.message));
      return;
    }
    if (!r.total) { out.replaceChildren(callout('ok', '이 기간에 Cloudflare가 막거나 챌린지한 요청이 없습니다.')); return; }
    const box = (title, items, fmt) => h('div', { class: 'section-box' }, h('h3', null, title), items.length ? barList(items.map(fmt)) : h('p', { class: 'small muted' }, '없음'));
    out.replaceChildren(
      h('div', { class: 'row wrap' },
        ...r.byAction.map((a) => { const [t, c] = CF_EV_ACT[a.key] || [a.key, 'muted']; return h('span', { class: `badge ${c}` }, `${t} ${a.count.toLocaleString()}`); }),
        h('span', { class: 'hint' }, r.truncated ? `최근 1,000건만 집계했습니다 (전체 ${r.total}+)` : `전체 ${r.total}건`)),
      h('div', { class: 'grid-2' },
        box('규칙별', r.byRule, (x) => ({ label: x.label || x.key, count: x.count })),
        box('국가별', r.byCountry, (x) => ({ label: x.key || '?', count: x.count })),
        box('IP별', r.byIP, (x) => ({ label: x.key, sub: x.label, count: x.count })),
        box('경로별', r.byPath, (x) => ({ label: x.key, count: x.count })),
        box('서비스별', r.byHost, (x) => ({ label: svcByHost(x.key) ? svcByHost(x.key).subdomain : x.key, title: x.key, count: x.count })),
        r.byGuard.length ? box('위협 차단 분류', r.byGuard, (x) => ({ label: x.label || x.key, count: x.count })) : null),
      h('details', { open: true }, h('summary', null, `최근 이벤트 ${r.events.length}건`),
        h('div', { class: 'table-wrap' }, h('table', { class: 'compact' },
          h('thead', null, h('tr', null, ['시각', '동작', '규칙', '접속자', '요청', ''].map((t) => h('th', { scope: 'col' }, t)))),
          h('tbody', null, r.events.slice(0, 200).map((e) => {
            const [t, c] = CF_EV_ACT[e.action] || [e.action, 'muted'];
            const b = h('button', { type: 'button', class: 'btn sm', title: `${e.ip} 를 위협 차단 규칙의 차단 IP에 추가` }, '차단');
            b.addEventListener('click', () => denyIP(e.ip));
            return h('tr', null,
              h('td', null, fmtTime(e.time)),
              h('td', null, h('span', { class: `badge ${c}` }, t)),
              h('td', { class: 'small' }, e.rule || e.source, e.guard ? h('div', { class: 'cell-sub' }, (WAF_META && WAF_META.categories[e.guard]) || e.guard) : null),
              h('td', { class: 'mono small' }, e.ip, h('div', { class: 'cell-sub' }, `${e.country || '?'} · AS${e.asn}`)),
              h('td', { class: 'mono small ellipsis', title: `${e.method} ${e.host}${e.path}${e.query || ''}\n${e.ua || ''}` }, `${e.method} ${svcByHost(e.host) ? svcByHost(e.host).subdomain : e.host}${e.path}`, h('div', { class: 'cell-sub ellipsis' }, e.ua || '(User-Agent 없음)')),
              h('td', null, e.action === 'block' && e.managed === 'threat' ? null : b));
          }))))));
  });
  load.addEventListener('click', run);
  return {
    id: 'cfevents', title: '엣지 이벤트', desc: 'Cloudflare가 막거나 챌린지한 요청을 규칙·국가·IP·경로별로 봅니다. 의심 IP는 바로 차단 목록에 넣을 수 있습니다.',
    state: S.state.cfConfigured ? 'opt' : 'opt', stateText: '',
    body: h('div', { class: 'stack' }, h('div', { class: 'row' }, since, load), out),
  };
}

// ======================================================================= CrowdSec tab

function renderCrowdSec(panel) {
  const st = S.state;
  const s = settings();
  let L;
  const getL = () => L;
  const mtls = st.services.filter((x) => x.enabled && !x.dnsOnly && x.exposure === 'public' && x.proxied && x.mtls);
  const gray = st.services.filter((x) => x.enabled && !x.dnsOnly && x.exposure === 'public' && !x.proxied);

  // 1) connection
  const conn = connectionBlock('crowdsec', (r) => L.set('conn', r.status || 'fail', checkStateText(r)));
  const keyHelp = st.csConfigured ? null : callout('warn', h('b', null, 'CrowdSec 바운서 키가 없습니다'),
    h('span', null, '길목 배포 폴더에서 ', h('code', null, 'install.ps1 -CrowdSec'), '(Windows) 또는 compose의 crowdsec 프로필로 CrowdSec을 함께 띄우면 키가 만들어집니다 (deploy/README.md 6장).'));
  const connForm = settingsForm([
    { key: 'crowdsecContainer', label: 'CrowdSec 컨테이너', mono: true, hint: 'docker ps 에 보이는 이름', picker: 'container' },
    { key: 'crowdsecLapi', label: 'LAPI 주소', mono: true, hint: '길목에서 접근하는 주소 (예: http://crowdsec:8080)' },
  ], { actions: [conn.btn], onSaved: () => conn.run(true) });

  // 2) collection
  const flowFig = h('ol', { class: 'flow' },
    h('li', null, 'Caddy가 ', h('b', null, 'mTLS 사이트'), `(${mtls.length}개)의 접근 로그에 Cloudflare가 넘긴 실제 IP(`, h('code', null, 'Cf-Connecting-Ip'), ')를 기록'),
    h('li', null, 'CrowdSec이 docker 로그를 읽어 공격 패턴(탐색, 악성 UA, CVE 시도…)을 판정'),
    h('li', null, '길목이 차단 IP를 Cloudflare IP 목록에 동기화 → 엣지에서 차단'));
  const collectForm = settingsForm([
    { key: 'crowdsecEnabled', type: 'switch', label: 'mTLS 사이트 접근 로그 켜기', hint: '켜면 Caddyfile이 바뀌어 「적용 대기」가 됩니다.' },
  ], { grid: false, onSaved: (p) => L.set('collect', p.crowdsecEnabled ? 'ok' : 'todo', p.crowdsecEnabled ? `${mtls.length}개 사이트` : '꺼짐') });
  const collectBody = h('div', { class: 'stack' }, flowFig,
    h('div', { class: 'grid-2' },
      h('div', { class: 'section-box' }, h('h3', null, icon('lock'), '분석 대상'),
        mtls.length ? h('div', { class: 'chips' }, mtls.map((x) => h('span', { class: 'badge ok' }, x.subdomain))) : h('p', { class: 'small muted' }, 'Proxied + mTLS 서비스가 없습니다.')),
      h('div', { class: 'section-box' }, h('h3', null, icon('cloud', 'fill cloud-gray'), '제외 (DNS only)'),
        gray.length ? h('div', { class: 'chips' }, gray.map((x) => h('span', { class: 'badge muted' }, x.subdomain))) : h('p', { class: 'small muted' }, '없음'),
        h('p', { class: 'hint' }, 'Docker Desktop이 접속자 IP를 172.18.0.1로 바꾸고, DNS only은 헤더를 위조할 수 있어 IP를 믿을 수 없습니다. 이 사이트들은 Caddy WAF로 보호하세요.'))),
    collectForm);

  // 3) sync
  const syncStatus = h('div', null);
  const syncNow = h('button', { type: 'button', class: 'btn' }, icon('refresh'), '지금 동기화');
  const syncForm = settingsForm([
    { key: 'crowdsecSync', type: 'switch', label: 'Cloudflare에 차단 동기화', hint: '로컬 판정(시나리오·수동)만 보냅니다. 커뮤니티 차단 목록은 보내지 않습니다 (Cloudflare 목록 한도 10,000).' },
    { key: 'crowdsecInterval', type: 'number', label: '동기화 주기 (초)', attrs: { min: '15', max: '3600' } },
  ], { actions: [syncNow], onSaved: () => setTimeout(loadDecisions, 800) });
  const cfRuleLink = h('button', { type: 'button', class: 'btn sm' }, 'Cloudflare 탭 › WAF 규칙');
  cfRuleLink.addEventListener('click', () => gotoTab('cloudflare', 'waf'));

  // 4) decisions
  const decBox = h('div', { class: 'stack' }, spinnerRow('차단 목록 읽는 중…'));
  const banIp = h('input', { type: 'text', class: 'mono', placeholder: '203.0.113.7 또는 203.0.113.0/24', autocomplete: 'off', spellcheck: 'false' });
  const banDur = h('input', { type: 'text', class: 'mono', value: '24h', autocomplete: 'off' });
  const banReason = h('input', { type: 'text', placeholder: '사유 (선택)', autocomplete: 'off' });
  const banBtn = h('button', { type: 'submit', class: 'btn danger' }, '차단 추가');
  const banForm = h('form', { class: 'row wrap', novalidate: true },
    field('IP / 대역', banIp), field('기간', banDur, '예: 4h, 168h'), field('사유', banReason), banBtn);
  banForm.addEventListener('submit', (e) => {
    e.preventDefault();
    busy(banBtn, async () => {
      try {
        await api('POST', '/api/crowdsec/decisions', { ip: banIp.value.trim(), duration: banDur.value.trim(), reason: banReason.value.trim() });
        toast(`${banIp.value.trim()} 차단 추가됨`);
        banIp.value = '';
        setTimeout(loadDecisions, 600);
      } catch (ex) { toast(ex.message, 'err'); }
    });
  });

  const renderSync = (sy) => {
    if (!sy) return;
    const items = [];
    if (!settings().crowdsecSync) items.push(callout('', '동기화가 꺼져 있습니다. 차단은 CrowdSec 안에만 기록되고 Cloudflare에는 반영되지 않습니다.'));
    else if (!S.state.cfConfigured) items.push(callout('danger', h('b', null, 'Cloudflare 토큰이 없습니다'), h('span', null, '길목에 토큰이 있어야 차단 목록을 Cloudflare에 보낼 수 있습니다.')));
    else if (sy.error) items.push(callout('danger', h('b', null, '동기화 실패'), h('span', null, sy.error), h('div', null, cfRuleLink)));
    else if (sy.lastPush && !sy.lastPush.startsWith('0001')) items.push(callout('ok', h('b', null, `✓ Cloudflare 목록 $gilmok_crowdsec — ${sy.pushed}건`), h('span', { class: 'small' }, `마지막 반영 ${fmtTime(sy.lastPush)} · 확인 ${fmtTime(sy.lastRun)}`)));
    else items.push(callout('warn', '아직 동기화하지 않았습니다. Cloudflare 탭에서 「CrowdSec 차단 목록」 규칙을 먼저 적용하세요.', h('div', null, cfRuleLink)));
    if (sy.dropped) items.push(callout('warn', `Cloudflare 목록 한도(1만 개)를 넘어 오래된 차단 IP ${sy.dropped}개는 보내지 않았습니다 — 최근 판정이 먼저 들어갑니다.`));
    syncStatus.replaceChildren(...items);
    if (settings().crowdsecSync && !S.state.cfConfigured) { L.set('sync', 'fail', '토큰 없음'); return; }
    L.set('sync', !settings().crowdsecSync ? 'opt' : sy.error ? 'fail' : sy.lastPush && !sy.lastPush.startsWith('0001') ? 'ok' : 'warn',
      !settings().crowdsecSync ? '꺼짐' : sy.error ? '실패' : sy.lastPush && !sy.lastPush.startsWith('0001') ? `${sy.pushed}건` : '대기');
  };
  syncNow.addEventListener('click', () => busy(syncNow, async () => {
    try { renderSync(await api('POST', '/api/crowdsec/sync')); } catch (ex) { toast(ex.message, 'err'); }
  }));

  async function loadDecisions() {
    let r;
    try { r = await api('GET', '/api/crowdsec'); } catch (ex) { decBox.replaceChildren(errorBox(ex.message)); return; }
    if (!decBox.isConnected) return;
    renderSync(r.sync);
    if (r.decisionsError) { decBox.replaceChildren(callout('danger', r.decisionsError)); L.set('bans', 'fail', '연결 실패'); return; }
    const ds = r.decisions || [];
    const alerts = (r.metrics && r.metrics.alerts) || {};
    const rows = ds.map((d) => {
      const del = h('button', { type: 'button', class: 'btn sm' }, '해제');
      del.addEventListener('click', async () => {
        const ok = await confirmDialog({ title: '차단 해제', message: `${d.value} 차단을 해제할까요?\n동기화가 켜져 있으면 Cloudflare 목록에서도 빠집니다.`, okText: '해제' });
        if (!ok) return;
        await busy(del, async () => {
          try { await api('DELETE', `/api/crowdsec/decisions/${d.id}`); toast(`${d.value} 해제됨`); setTimeout(loadDecisions, 600); } catch (ex) { toast(ex.message, 'err'); }
        });
      });
      return h('tr', null,
        h('td', { class: 'mono' }, d.value),
        h('td', null, d.scenario || '—'),
        h('td', null, d.origin === 'cscli' ? h('span', { class: 'badge' }, '수동') : h('span', { class: 'badge accent' }, '자동')),
        h('td', null, d.duration),
        h('td', null, del));
    });
    decBox.replaceChildren(
      h('div', { class: 'row' },
        h('span', { class: 'badge danger' }, `차단 ${ds.length}건`),
        use('cloudflare') ? h('span', { class: 'badge' }, `Cloudflare 대상 ${r.cloudflareItems ?? 0}건`) : null,
        Object.keys(alerts).length ? h('span', { class: 'hint' }, `시나리오별 경보: ${Object.entries(alerts).map(([k, v]) => `${k.replace('crowdsecurity/', '')} ${v}`).join(' · ')}`) : null),
      ds.length ? h('div', { class: 'table-wrap glass-inner' }, h('table', { class: 'compact' },
        h('thead', null, h('tr', null, ['IP', '시나리오 / 사유', '출처', '남은 시간', ''].map((t) => h('th', { scope: 'col' }, t)))),
        h('tbody', null, rows))) : callout('ok', '현재 차단된 IP가 없습니다.'),
      h('hr', { class: 'sep' }), banForm);
    L.set('bans', 'info', `${ds.length}건`);
  }

  const noCF = !use('cloudflare');
  const noCaddy = !use('caddy');
  const csSteps = [
    { id: 'conn', title: '연결 확인', desc: noCaddy ? 'CrowdSec 컨테이너와 바운서 키.' : 'CrowdSec 컨테이너, 바운서 키, 길목 파서, Caddy 로그 수집.', state: 'wait',
      body: h('div', { class: 'stack' }, typeof stackCard === 'function' ? stackCard('crowdsec', () => conn.run(true)) : null, keyHelp, conn.box, h('hr', { class: 'sep' }), connForm) },
  ];
  if (!noCF && !noCaddy) {
    csSteps.push(
      { id: 'collect', title: '로그 수집 (mTLS 사이트)', desc: 'Cloudflare만 접속할 수 있는 사이트의 로그만 분석해 IP 위조를 막습니다.',
        state: s.crowdsecEnabled ? 'ok' : 'todo', stateText: s.crowdsecEnabled ? `${mtls.length}개 사이트` : '꺼짐', body: collectBody },
      { id: 'sync', title: 'Cloudflare 동기화', desc: '차단 IP → Cloudflare 계정 IP 목록 → 「CrowdSec 차단 목록」 규칙(차단).', state: 'wait',
        body: h('div', { class: 'stack' }, syncStatus, syncForm) });
  }
  csSteps.push({ id: 'bans', title: '차단 목록', aside: true, desc: '로컬 판정 목록. 수동으로 추가·해제할 수 있습니다.', state: 'wait', body: decBox });
  L = stepsLayout(panel, {
    title: 'CrowdSec',
    steps: csSteps,
    lead: use('cloudflare') ? '공격 IP 자동 차단 (Cloudflare 연동형). 판정은 CrowdSec이, 차단은 Cloudflare 엣지가 합니다 — Docker Desktop처럼 서버가 접속자 IP를 직접 볼 수 없는 환경에서도 동작하는 방식입니다.' : 'CrowdSec 공격 IP 판정. Cloudflare를 쓰지 않는 구성이라 판정 결과는 기록·확인만 하고 자동 차단은 하지 않습니다 (Cloudflare를 켜면 엣지 차단까지).',
  });
  if (noCF || noCaddy) panel.querySelector('.tab-head').append(callout('warn', h('b', null, noCaddy ? 'Caddy를 쓰지 않는 구성입니다' : 'Cloudflare를 쓰지 않는 구성입니다'),
    h('span', null, noCaddy ? 'CrowdSec이 읽을 Caddy 접근 로그가 없어 자동 판정이 일어나지 않습니다. 수동 차단 목록만 관리할 수 있습니다.'
      : '길목의 CrowdSec 연동은 Cloudflare가 넘겨주는 실제 접속자 IP로 판정하고 Cloudflare 엣지에서 차단합니다. Cloudflare 없이는 판정 결과를 기록·확인만 합니다.')));

  if (!s.crowdsecEnabled && !s.crowdsecSync && !st.csConfigured) {
    decBox.replaceChildren(h('p', { class: 'muted' }, 'CrowdSec이 연결되면 차단 목록이 보입니다.'));
    L.set('bans', 'opt', ''); L.set('sync', 'opt', '꺼짐');
  } else loadDecisions();
}
