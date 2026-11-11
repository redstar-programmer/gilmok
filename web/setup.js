'use strict';
// 첫 설정 (setup.go): 새 설치·초기화 뒤 처음 접속하면 「빠른 설정」 또는 「설정 마법사」를 고르게 한다.
// - 빠른 설정: 자동으로 찾은 값(컨테이너·파일·도메인)을 한 화면에서 확인하고 바로 시작
// - 설정 마법사: 구성요소 → 도메인 → 구성요소별 연결 → 가져오기 → 확인, 한 단계씩
// 감지는 제안일 뿐이고 저장은 사용자가 「다음」·「시작」을 누를 때만 한다.

const SETUP_CONN_TARGETS = ['caddy', 'authelia', 'cloudflare', 'crowdsec'];

/** after login: offer the setup once per page load while it is not finished */
function maybeOfferSetup() {
  const st = S.state || {};
  if (st.setupDone || S.setupOffered) return;
  if (typeof can === 'function' && !(can('config') && can('system'))) return;
  S.setupOffered = true;
  openSetupChooser();
}

async function setupDetect() {
  try { return await api('GET', '/api/setup/detect'); } catch (ex) { return { error: ex.message, containers: {}, files: {}, suggest: {} }; }
}

async function setupSave(patch) {
  await api('PUT', '/api/settings', { ...settings(), ...patch });
  await refreshState();
}

async function setupFinish() {
  await api('POST', '/api/setup/done', { done: true });
  await refreshState();
}

function setupIcon(name) {
  const el = sv('svg', { viewBox: '0 0 26 26', width: 26, height: 26, class: 'wz-ico', 'aria-hidden': 'true' });
  el.append(topoIcon(name, 13, 13, 24, TC.accentText));
  return el;
}

// ---------------------------------------------------------------- chooser

function openSetupChooser() {
  const choice = (ico, title, desc, points, primary) => h('button', { type: 'button', class: `setup-choice ${primary ? 'primary' : ''}` },
    h('span', { class: 'sc-head' }, setupIcon(ico), h('b', null, title)),
    h('span', { class: 'sc-desc' }, desc),
    h('ul', { class: 'sc-points' }, points.map((p) => h('li', null, p))));
  const quick = choice('bolt', '빠른 설정', '길목이 찾은 값을 한 화면에서 확인하고 바로 시작합니다.',
    ['Docker 컨테이너·설정 파일·도메인을 자동으로 찾음', '기존 Caddyfile이 있으면 서비스 목록도 가져옴', '1분이면 끝 — 나중에 각 탭에서 고칠 수 있음'], true);
  const wizard = choice('steps', '설정 마법사', '한 단계씩 고르며 차근차근 설정합니다.',
    ['구성요소 → 도메인 → 연결 → 가져오기 → 확인', '단계마다 연결을 바로 시험', '처음 쓰거나 구성이 특이할 때']);
  const later = h('button', { type: 'button', class: 'btn ghost' }, '나중에');
  const never = h('button', { type: 'button', class: 'btn ghost' }, '다시 묻지 않기');
  const d = openDialog({
    title: '길목 설정을 시작할까요?',
    size: 'wide',
    body: h('div', { class: 'stack' },
      h('p', { class: 'muted' }, '아직 설정하지 않은 길목입니다. 진행 방식을 고르세요. 어느 쪽이든 「적용」을 누르기 전에는 Caddy·Authelia·DNS가 바뀌지 않습니다.'),
      h('div', { class: 'setup-choices' }, quick, wizard)),
    footer: [never, h('span', { class: 'grow' }), later],
  });
  quick.addEventListener('click', () => { d.close(); openQuickSetup(); });
  wizard.addEventListener('click', () => { d.close(); openSetupWizard(); });
  later.addEventListener('click', () => d.close());
  never.addEventListener('click', async () => {
    try { await setupFinish(); d.close(); toast('설정 탭 › 구성요소에서 언제든 설정 마법사를 다시 열 수 있습니다'); } catch (ex) { toast(ex.message, 'err'); }
  });
}

// ---------------------------------------------------------------- shared pieces

/** 「Tailscale에서 찾기」 next to a Tailscale IP input: suggestion + tailnet device picker (tsdetect.go) */
function tsFinder(input) {
  const btn = h('button', { type: 'button', class: 'btn sm' }, 'Tailscale에서 찾기');
  const out = h('div', { class: 'ts-find' });
  const set = (ip) => { input.value = ip; input.dispatchEvent(new Event('input', { bubbles: true })); input.dispatchEvent(new Event('change', { bubbles: true })); };
  btn.addEventListener('click', () => busy(btn, async () => {
    try {
      const r = await api('GET', '/api/tailscale/detect');
      const kids = [];
      if (r.ip) { set(r.ip); kids.push(h('small', { class: 'setup-found' }, `찾음: ${r.ip} — ${r.source}`)); }
      const devs = r.devices || [];
      if (devs.length) {
        const sel = h('select', { 'aria-label': 'tailnet 기기에서 이 서버 고르기' },
          h('option', { value: '' }, r.ip ? `다른 기기면 고르세요 (${devs.length}대)` : `tailnet 기기 ${devs.length}대 중 이 서버를 고르세요`),
          devs.map((d) => h('option', { value: d.ip, selected: d.ip === input.value }, `${d.online ? '●' : '○'} ${d.name} — ${d.ip}${d.os ? ` · ${d.os}` : ''}${d.match ? ' (이름 일치)' : ''}`)));
        sel.addEventListener('change', () => { if (sel.value) set(sel.value); });
        kids.push(sel);
      }
      if (!r.ip && !devs.length) kids.push(h('small', { class: 'hint' }, `찾지 못했습니다 (시도: ${(r.tried || []).join(', ')}). 이 서버에서 「tailscale ip -4」를 실행해 나온 100.x 주소를 넣으세요.`));
      out.replaceChildren(...kids);
    } catch (ex) { out.replaceChildren(h('small', { class: 'form-error' }, ex.message)); }
  }));
  return h('div', { class: 'ts-finder' }, btn, out);
}

/** a text input with a <datalist> of detected values (+ container picker for containers) */
function setupInput(key, label, value, opts = {}) {
  const el = h('input', { type: 'text', class: 'mono', value: value ?? '', autocomplete: 'off', spellcheck: 'false', placeholder: opts.placeholder || '' });
  let dl = null;
  if (opts.list && opts.list.length) {
    const id = uid('dl');
    el.setAttribute('list', id);
    dl = h('datalist', { id }, opts.list.map((v) => h('option', { value: v })));
  }
  const f = field(label, el, opts.hint);
  if (dl) f.append(dl);
  if (opts.container) f.append(containerPicker(el));
  if (opts.file) f.append(filePicker(el, label));
  if (opts.found) f.append(h('small', { class: 'setup-found' }, opts.found));
  f.dataset.key = key;
  return { f, el };
}

function compCards(sel, onChange) {
  return h('div', { class: 'comp-cards' }, COMPONENTS.map((c) => {
    const cb = h('input', { type: 'checkbox', checked: !!sel[c.key] });
    const card = h('label', { class: `comp-card ${sel[c.key] ? 'on' : ''}` }, cb,
      h('span', { class: 'cc-head' }, setupIcon(c.icon), h('span', null, h('b', null, c.name), h('small', null, c.role))),
      h('small', { class: 'cc-desc' }, c.desc));
    cb.addEventListener('change', () => { sel[c.key] = cb.checked; card.classList.toggle('on', cb.checked); onChange && onChange(); });
    return card;
  }));
}

function foundText(det, kind) {
  const list = (det.containers || {})[kind] || [];
  return list.length ? `찾음: ${list.join(', ')}` : '';
}

// checks that are not a problem to fix now (they fill in by themselves once traffic arrives)
const SETUP_INFO_CHECKS = { 'crowdsec/acq': '요청이 들어오면 채워집니다 — 지금 고칠 것은 없습니다.' };

/** Cloudflare token entry: reuse the Caddy container's token (never shown) or paste one. */
function setupTokenFix(det, onDone) {
  const err = h('p', { class: 'form-error', role: 'alert', hidden: true });
  const inp = h('input', { type: 'password', class: 'mono', autocomplete: 'off', spellcheck: 'false', placeholder: 'Cloudflare에서 만든 API 토큰 붙여넣기' });
  const save = h('button', { type: 'button', class: 'btn primary' }, '확인 후 저장');
  const run = (body, btn) => busy(btn, async () => {
    err.hidden = true;
    try { await api('POST', '/api/cloudflare/token', body); await refreshState(); toast('Cloudflare 토큰을 확인하고 저장했습니다'); onDone && onDone(); } catch (ex) { err.textContent = ex.message; err.hidden = false; }
  });
  save.addEventListener('click', () => { const v = inp.value.trim(); if (!v) { err.textContent = '토큰을 붙여넣으세요.'; err.hidden = false; inp.focus(); return; } run({ token: v }, save); });
  const kids = [];
  if (det && det.caddyToken) {
    const fromCaddy = h('button', { type: 'button', class: 'btn primary' }, 'Caddy 컨테이너의 토큰 사용');
    fromCaddy.addEventListener('click', () => run({ fromCaddy: true }, fromCaddy));
    kids.push(h('div', { class: 'row' }, fromCaddy, h('span', { class: 'hint' }, 'Caddy가 이미 쓰는 토큰을 확인한 뒤 길목에 저장합니다 (값은 화면에 나오지 않음).')), h('p', { class: 'hint' }, '또는 새 토큰:'));
  }
  kids.push(h('div', { class: 'row' }, h('span', { class: 'grow' }, inp), save),
    h('p', { class: 'hint' }, 'Cloudflare 대시보드 › 내 프로필 › API 토큰 › 「영역 DNS 편집」 템플릿 + 「영역 · 영역 · 읽기」 권한. 저장 전에 존·DNS 접근을 실제로 확인합니다.'), err);
  return h('div', { class: 'fix-box stack tight' }, ...kids);
}

/** one inline fix for a check that is not ok — or null when only a tab can fix it */
function setupFixFor(target, c, det, rerun, leave) {
  const st = settings();
  const key = `${target}/${c.id}`;
  const saveBtn = (label, patch, all) => {
    const b = h('button', { type: 'button', class: 'btn sm primary' }, label);
    b.addEventListener('click', () => busy(b, async () => {
      try { await setupSave(typeof patch === 'function' ? patch() : patch); rerun(all); } catch (ex) { toast(ex.message, 'err'); }
    }));
    return b;
  };
  const inputFix = (label, k, ph, all) => {
    const inp = h('input', { type: 'text', class: 'mono', value: st[k] || '', placeholder: ph });
    return h('div', { class: 'fix-box row' }, h('b', null, label), h('span', { class: 'grow' }, inp), saveBtn('저장', () => ({ [k]: inp.value.trim() }), all));
  };
  if (SETUP_INFO_CHECKS[key]) return h('p', { class: 'hint' }, SETUP_INFO_CHECKS[key]);
  const noToken = !(S.state || {}).cfConfigured;
  // problems that only exist because the Cloudflare token is missing: one token form fixes them all
  if (noToken && (key === 'caddy/cftoken' || key === 'crowdsec/sync') && use('cloudflare')) return h('p', { class: 'hint' }, '아래(또는 위) Cloudflare의 「API 토큰」을 넣으면 함께 해결됩니다.');
  if (key === 'cloudflare/token' || (key === 'caddy/cftoken' && noToken)) return setupTokenFix(det, () => rerun(true));
  if (key === 'crowdsec/key') {
    const b = h('button', { type: 'button', class: 'btn sm primary' }, '바운서 키 만들기');
    b.addEventListener('click', () => busy(b, async () => {
      try { await api('POST', '/api/crowdsec/bouncer'); toast('CrowdSec에 길목 바운서를 등록하고 키를 저장했습니다'); rerun(false); } catch (ex) { toast(ex.message, 'err', 9000); }
    }));
    return h('div', { class: 'fix-box row' }, h('span', { class: 'grow' }, `${st.crowdsecContainer || 'CrowdSec'} 컨테이너에서 cscli bouncers add 로 길목용 키를 만들어 저장합니다 (키는 화면에 나오지 않음).`), b);
  }
  if (key === 'cloudflare/zone' && !st.domain) return inputFix('도메인', 'domain', '예: example.com', true);
  if (key === 'cloudflare/ts') {
    const box = inputFix(use('tailscale') ? 'Tailscale IP' : '사설 IP', 'tailscaleIp', '예: 100.64.0.10', false);
    if (use('tailscale')) box.append(tsFinder(box.querySelector('input')));
    return box;
  }
  if (key === 'crowdsec/logging' && !st.crowdsecEnabled) return h('div', { class: 'fix-box row' }, h('span', { class: 'grow' }, 'mTLS 사이트의 접근 로그(실제 IP 포함)를 CrowdSec에 보냅니다. 「적용」하면 반영됩니다.'), saveBtn('켜기', { crowdsecEnabled: true }));
  if (key === 'crowdsec/sync' && !st.crowdsecSync && use('cloudflare')) return h('div', { class: 'fix-box row' }, h('span', { class: 'grow' }, 'CrowdSec이 판정한 공격 IP를 Cloudflare 엣지에서 차단합니다.'), saveBtn('켜기', { crowdsecSync: true }));
  if (c.id === 'write') return h('div', { class: 'fix-box row' }, h('span', { class: 'grow' }, '길목 컨테이너에 이 폴더를 쓰기 가능하게(:ro 없이) 마운트해야 합니다 — 배포 compose의 volumes를 확인하세요.'), leave(target));
  return h('div', { class: 'fix-box row' }, h('span', { class: 'grow muted' }, c.detail || ''), leave(target));
}

/** connection results for the chosen components (end of both flows), with inline fixes */
function setupChecks(sel, det, closeDialog) {
  const box = h('div', { class: 'stack' });
  const targets = SETUP_CONN_TARGETS.filter((k) => sel[k]);
  if (!targets.length) { box.append(callout('', '연결을 확인할 구성요소가 없습니다.')); return box; }
  const leave = (target) => {
    const b = h('button', { type: 'button', class: 'btn sm' }, `${COMPONENTS.find((x) => x.key === target).name} 탭에서 고치기`);
    b.addEventListener('click', () => { closeDialog && closeDialog(); gotoTab(target, 'conn'); });
    return b;
  };
  const slots = {};
  const draw = (k) => {
    const c = COMPONENTS.find((x) => x.key === k);
    const slot = slots[k];
    slot.replaceChildren(spinnerRow(`${c.name} 확인 중…`));
    loadCheck(k, true).then((r) => {
      const todo = (r.checks || []).filter((x) => (x.status === 'warn' || x.status === 'fail' || (x.status === 'skip' && x.id === 'sync' && use('cloudflare') && !settings().crowdsecSync)));
      const real = todo.filter((x) => !SETUP_INFO_CHECKS[`${k}/${x.id}`]);
      slot.replaceChildren(
        real.length ? callout(real.some((x) => x.status === 'fail') ? 'danger' : 'warn', `확인 필요 ${real.length}건 — 아래에서 바로 고칠 수 있습니다`) : callout('ok', '연결 정상'),
        checkList(r),
        ...todo.map((x) => h('div', { class: 'fix-row stack tight' }, h('b', { class: 'small' }, `→ ${x.label}`), setupFixFor(k, x, det, (all) => (all ? targets.forEach(draw) : draw(k)), leave))));
    }).catch((ex) => slot.replaceChildren(callout('danger', ex.message)));
  };
  for (const k of targets) {
    slots[k] = h('div');
    box.append(h('div', { class: 'stack tight' }, h('h3', null, COMPONENTS.find((x) => x.key === k).name), slots[k]));
    draw(k);
  }
  return box;
}

function validDomain(v) {
  v = String(v || '').trim().toLowerCase().replace(/^https?:\/\//, '').replace(/\/.*$/, '').replace(/\.$/, '');
  return { v, ok: !v || /^([a-z0-9-]+\.)+[a-z]{2,}$/.test(v) };
}

// ---------------------------------------------------------------- quick setup

async function openQuickSetup() {
  const body = h('div', { class: 'stack' }, spinnerRow('Docker 컨테이너와 설정 파일을 찾는 중…'));
  const back = h('button', { type: 'button', class: 'btn ghost' }, '← 방식 다시 고르기');
  const start = h('button', { type: 'button', class: 'btn primary', disabled: true }, '이대로 시작');
  const d = openDialog({ title: '빠른 설정', size: 'wide', body, footer: [back, h('span', { class: 'grow' }), start] });
  back.addEventListener('click', () => { d.close(); openSetupChooser(); });

  const det = await setupDetect();
  const sg = det.suggest || {};
  const st = settings();
  const sel = Object.fromEntries(COMPONENTS.map((c) => [c.key, sg[c.flag] ?? !!st[c.flag]]));
  const files = det.files || {};
  let stacks = {};
  try { stacks = (await loadStacks()).stacks || {}; } catch { /* older server or no Docker */ }
  // per container component: connect to what is there, or let Gilmok install it
  const STACKED = ['caddy', 'authelia', 'crowdsec'];
  const installed = Object.fromEntries(STACKED.map((k) => [k, !!(stacks[k] && stacks[k].record)]));
  const mode = Object.fromEntries(STACKED.map((k) => [k, !det.docker || installed[k] || ((det.containers || {})[k] || []).length ? 'connect' : 'install']));

  const fields = {
    domain: setupInput('domain', '도메인', sg.domain || st.domain, { placeholder: '예: example.com', hint: '모든 서비스 주소의 기준입니다. 나중에 정해도 되지만, 정하기 전에는 「적용」이 막힙니다.', found: sg.domain ? 'Caddyfile 사이트 주소에서 알아냄' : '' }),
    tailscaleIp: setupInput('tailscaleIp', 'Tailscale IP', sg.tailscaleIp || st.tailscaleIp, { placeholder: '예: 100.64.0.10', hint: '사설 전용 서비스의 DNS 값 — 이 서버의 Tailscale 주소(tailscale ip -4)', found: sg.tailscaleIp ? `찾음 — ${sg.tailscaleSrc || 'Caddyfile'}` : '' }),
    caddyContainer: setupInput('caddyContainer', 'Caddy 컨테이너', sg.caddyContainer || st.caddyContainer, { container: true, found: foundText(det, 'caddy') }),
    caddyfilePath: setupInput('caddyfilePath', 'Caddyfile 경로 (길목이 보는 위치)', sg.caddyfilePath || st.caddyfilePath, { list: files.caddyfile, file: true, found: (files.caddyfile || []).length ? `찾음: ${files.caddyfile.length}개` : '찾지 못함 — 길목 컨테이너에 Caddy 폴더를 마운트했는지 확인하세요' }),
    autheliaContainer: setupInput('autheliaContainer', 'Authelia 컨테이너', sg.autheliaContainer || st.autheliaContainer, { container: true, found: foundText(det, 'authelia') }),
    autheliaConfig: setupInput('autheliaConfig', 'configuration.yml', sg.autheliaConfig || st.autheliaConfig, { list: files.autheliaConfig, file: true }),
    autheliaUsers: setupInput('autheliaUsers', 'users_database.yml', sg.autheliaUsers || st.autheliaUsers, { list: files.autheliaUsers, file: true }),
    crowdsecContainer: setupInput('crowdsecContainer', 'CrowdSec 컨테이너', sg.crowdsecContainer || st.crowdsecContainer, { container: true, found: foundText(det, 'crowdsec') }),
    crowdsecLapi: setupInput('crowdsecLapi', 'CrowdSec LAPI 주소', sg.crowdsecLapi || st.crowdsecLapi),
  };
  const owner = { tailscaleIp: 'tailscale', caddyContainer: 'caddy', caddyfilePath: 'caddy', autheliaContainer: 'authelia', autheliaConfig: 'authelia', autheliaUsers: 'authelia', crowdsecContainer: 'crowdsec', crowdsecLapi: 'crowdsec' };
  const inst = {};
  const compBoxes = {};
  const domainNow = () => validDomain(fields.domain.el.value).v;
  for (const k of STACKED) {
    const c = COMPONENTS.find((x) => x.key === k);
    inst[k] = stackInstallFields(k, (stacks[k] && stacks[k].defaultContainer) || `gilmok-${k}`, { followCaddy: true, domain: domainNow });
    const connBox = h('div', { class: 'grid-2' }, Object.entries(owner).filter(([, comp]) => comp === k).map(([f]) => fields[f].f));
    const instBox = h('div', { class: 'stack' }, inst[k].fields);
    const seg = segmented(uid(`m-${k}`), `${c.name} 준비 방식`, [
      { value: 'connect', label: installed[k] ? '길목이 설치한 것 사용' : '이미 있는 컨테이너에 연결' },
      { value: 'install', label: '길목이 새로 설치', disabled: !det.docker || installed[k] },
    ], mode[k]);
    const note = h('p', { class: 'hint' });
    const paint = () => {
      mode[k] = seg.get();
      connBox.hidden = mode[k] !== 'connect' || installed[k];
      instBox.hidden = mode[k] !== 'install';
      note.textContent = installed[k] ? `길목이 이미 설치한 ${c.name}가 있습니다 — 그대로 씁니다.`
        : mode[k] === 'install' ? `「이대로 시작」을 누르면 길목이 ${c.name}를 옆 컨테이너로 설치하고 연결합니다${k === 'caddy' ? ' (이미지 빌드 2~5분)' : ''}.`
          : !det.docker ? 'Docker에 연결하지 못해 설치는 고를 수 없습니다.' : '';
      syncAll();
    };
    seg.onChange(paint);
    compBoxes[k] = { el: h('div', { class: 'section-box comp-setup' }, h('h3', null, c.name), seg, note, connBox, instBox), paint };
  }
  let syncAll = () => {};
  const imp = switchCtl(det.sites ? `기존 Caddyfile에서 서비스 ${det.sites}개 가져오기` : '기존 Caddyfile에서 서비스 가져오기', det.sites > 0,
    '사이트 블록을 서비스 목록으로, 전역 옵션·스니펫을 기본 골격으로 만듭니다. 실제 파일은 바뀌지 않습니다.');
  // Cloudflare token: asked here, saved (after verification) when the setup starts
  const tokMode = det.caddyToken ? 'caddy' : 'paste';
  const tokRadios = h('div', { class: 'choice-cards', role: 'radiogroup', 'aria-label': 'Cloudflare 토큰' },
    [det.caddyToken && ['caddy', 'Caddy 컨테이너의 토큰 사용', 'Caddy가 이미 쓰는 토큰을 확인한 뒤 길목에 저장 (값은 보이지 않음)'],
      ['paste', '새 토큰 붙여넣기', 'Cloudflare › 내 프로필 › API 토큰 › 「영역 DNS 편집」 템플릿 + 「영역 · 영역 · 읽기」'],
      ['later', '나중에', '토큰 없이 시작 — DNS 동기화·DDNS·엣지 규칙은 건너뜀']].filter(Boolean).map(([v, l, dsc]) =>
      h('label', { class: 'choice' }, h('input', { type: 'radio', name: 'gm-tok', value: v, checked: v === tokMode }), h('span', { class: 'ch-body' }, h('span', { class: 'ch-head' }, h('b', null, l)), h('small', null, dsc)))));
  const tokInput = h('input', { type: 'password', class: 'mono', autocomplete: 'off', spellcheck: 'false', placeholder: 'API 토큰 붙여넣기' });
  const tokField = field('Cloudflare API 토큰', tokInput);
  const tokBox = h('div', { class: 'stack tight' }, h('h3', null, 'Cloudflare API 토큰'), tokRadios, tokField);
  const tokVal = () => (tokRadios.querySelector('input:checked') || {}).value || 'later';
  tokRadios.addEventListener('change', () => { tokField.hidden = tokVal() !== 'paste'; });
  tokField.hidden = tokMode !== 'paste';
  // CrowdSec options that otherwise show up as 「확인 필요」 afterwards
  const csLog = switchCtl('mTLS 사이트 접근 로그를 CrowdSec에 보내기', true, '실제 접속 IP(Cf-Connecting-Ip)로 공격을 판정합니다. Cloudflare 경유(mTLS) 사이트에만 붙습니다.');
  const csSync = switchCtl('판정한 공격 IP를 Cloudflare에서 차단', true, 'Cloudflare 계정 IP 목록 + 차단 규칙으로 엣지에서 막습니다 (토큰에 「영역 WAF 편집」·「계정 필터 목록 편집」 권한 필요).');
  const csKeyMk = det.csKey ? null : switchCtl('길목용 바운서 키 만들기', true, 'CrowdSec 컨테이너에서 cscli bouncers add 로 키를 만들어 길목에 저장합니다 (키는 화면에 나오지 않음). 판정 결과를 읽는 데 필요합니다.');
  const csBox = h('div', { class: 'stack tight' }, h('h3', null, 'CrowdSec'), csKeyMk, csLog, csSync);
  const sync = () => {
    fields.tailscaleIp.f.hidden = !sel.tailscale;
    for (const k of STACKED) compBoxes[k].el.hidden = !sel[k];
    imp.hidden = !sel.caddy || mode.caddy !== 'connect' || installed.caddy;
    if (csKeyMk) csKeyMk.hidden = mode.crowdsec !== 'connect';
    tokBox.hidden = !sel.cloudflare || !!det.cfToken;
    csBox.hidden = !sel.crowdsec;
    csSync.hidden = !sel.cloudflare;
    fields.tailscaleIp.el.classList.toggle('need', sel.tailscale && !fields.tailscaleIp.el.value.trim());
  };
  syncAll = () => sync();
  fields.tailscaleIp.el.addEventListener('input', sync);
  fields.tailscaleIp.f.append(tsFinder(fields.tailscaleIp.el));
  const err = h('p', { class: 'form-error', role: 'alert', hidden: true });
  const summary = det.error
    ? callout('warn', h('b', null, '자동 감지를 하지 못했습니다'), h('span', { class: 'small' }, det.error))
    : callout('ok', h('b', null, '찾은 것'), h('ul', { class: 'tight' },
      h('li', null, det.docker ? `Docker 컨테이너 — Caddy ${(det.containers.caddy || []).length} · Authelia ${(det.containers.authelia || []).length} · CrowdSec ${(det.containers.crowdsec || []).length}` : `Docker에 연결하지 못함${det.dockerErr ? ` (${det.dockerErr})` : ''}`),
      h('li', null, `설정 파일 — Caddyfile ${(files.caddyfile || []).length} · Authelia ${(files.autheliaConfig || []).length}`),
      h('li', null, sg.domain ? `도메인 — ${sg.domain}` : '도메인 — 찾지 못함'),
      h('li', null, det.cfToken ? 'Cloudflare 토큰 — 있음' : 'Cloudflare 토큰 — 없음')));
  body.replaceChildren(
    summary,
    h('h3', null, '쓸 구성요소'),
    compCards(sel, sync),
    h('h3', null, '기본 정보'),
    h('div', { class: 'grid-2' }, fields.domain.f, fields.tailscaleIp.f),
    ...STACKED.map((k) => compBoxes[k].el),
    tokBox, csBox, imp, err);
  for (const k of STACKED) compBoxes[k].paint();
  sync();
  start.disabled = false;

  start.addEventListener('click', () => busy(start, async () => {
    err.hidden = true;
    const dom = validDomain(fields.domain.el.value);
    if (!dom.ok) { err.textContent = '도메인 형식이 아닙니다 (예: example.com)'; err.hidden = false; fields.domain.el.focus(); return; }
    if (!dom.v && (sel.caddy || sel.cloudflare)) { err.textContent = '도메인을 넣으세요 (예: example.com) — 서비스 주소와 Cloudflare 존의 기준입니다.'; err.hidden = false; fields.domain.el.focus(); return; }
    const tv = sel.cloudflare && !det.cfToken ? tokVal() : 'later';
    if (tv === 'paste' && !tokInput.value.trim()) { err.textContent = 'Cloudflare 토큰을 붙여넣거나 「나중에」를 고르세요.'; err.hidden = false; tokInput.focus(); return; }
    if (tv !== 'later' && !dom.v) { err.textContent = 'Cloudflare 토큰을 확인하려면 도메인이 필요합니다.'; err.hidden = false; fields.domain.el.focus(); return; }
    const patch = { domain: dom.v };
    for (const c of COMPONENTS) patch[c.flag] = !!sel[c.key];
    for (const [k, comp] of Object.entries(owner)) {
      if (sel[comp] && (comp === 'tailscale' || (mode[comp] === 'connect' && !installed[comp]))) patch[k] = fields[k].el.value.trim();
    }
    const toInstall = STACKED.filter((k) => sel[k] && mode[k] === 'install' && !installed[k]);
    if (toInstall.includes('authelia') && !inst.authelia.pwOk()) { err.textContent = 'Authelia 관리자 비밀번호 확인이 다릅니다.'; err.hidden = false; return; }
    if (toInstall.includes('authelia') && !dom.v) { err.textContent = 'Authelia를 설치하려면 도메인이 필요합니다.'; err.hidden = false; fields.domain.el.focus(); return; }
    if (sel.crowdsec) { patch.crowdsecEnabled = csLog.input.checked; patch.crowdsecSync = sel.cloudflare && csSync.input.checked; }
    try {
      d.lock(true);
      await setupSave(patch);
      // the token is verified against the zone before it is stored — stop here if it is wrong
      if (tv !== 'later') {
        try {
          await api('POST', '/api/cloudflare/token', tv === 'caddy' ? { fromCaddy: true } : { token: tokInput.value.trim() });
          tokInput.value = '';
          det.cfToken = 'ui';
          sync();
        } catch (ex) {
          d.lock(false);
          err.textContent = `Cloudflare 토큰: ${ex.message} (다른 설정은 저장됐습니다 — 토큰을 고치거나 「나중에」를 고른 뒤 다시 시작하세요)`;
          err.hidden = false;
          return;
        }
      }
      // import the existing Caddyfile first: an Authelia installed next repoints the imported snippet
      let imported = null;
      if (sel.caddy && mode.caddy === 'connect' && !imp.hidden && imp.input.checked) {
        try { imported = await api('POST', '/api/import'); } catch (ex) { imported = { error: ex.message }; }
      }
      // installs, in order (CrowdSec reads the Caddy that exists by then; Authelia repoints Caddy's snippet)
      for (const k of toInstall) {
        const c = COMPONENTS.find((x) => x.key === k);
        const pre = h('pre', { class: 'log-view stack-log', 'aria-live': 'polite' });
        const head = h('div', { class: 'row' }, h('b', null, `${c.name} 설치`), h('span', { class: 'badge warn' }, '진행 중…'));
        const pulse = jobPulse();
        err.before(h('div', { class: 'stack tight' }, head, pre, pulse));
        pulse.update({ state: 'running', started: new Date().toISOString() });
        pre.scrollIntoView({ block: 'nearest' });
        let j;
        try {
          j = await runStackInstall(k, inst[k].opts(), (x, now) => {
            if (!x) return;
            const atEnd = pre.scrollHeight - pre.scrollTop - pre.clientHeight < 24;
            pre.textContent = (x.log || []).join('\n');
            if (atEnd) pre.scrollTop = pre.scrollHeight;
            pulse.update(x, now);
          }, (msg) => pulse.lost(msg));
        } catch (ex) { j = { state: 'fail', error: ex.message }; }
        if (!j.started) pulse.update(null);
        head.lastChild.replaceWith(h('span', { class: `badge ${j.state === 'ok' ? 'ok' : 'danger'}` }, j.state === 'ok' ? '완료' : '실패'));
        if (j.state !== 'ok') {
          d.lock(false);
          err.textContent = `${c.name} 설치 실패: ${j.error || ''} — 원인을 고친 뒤 다시 「이대로 시작」 (이미 끝난 단계는 건너뜁니다)`;
          err.hidden = false;
          return;
        }
        installed[k] = true;
        compBoxes[k].paint();
      }
      await refreshState();
      if (sel.crowdsec && mode.crowdsec === 'connect' && csKeyMk && csKeyMk.input.checked && !det.csKey) {
        try { await api('POST', '/api/crowdsec/bouncer'); det.csKey = true; } catch (ex) { toast(`CrowdSec 바운서 키: ${ex.message}`, 'err', 9000); }
      }
      await setupFinish();
      d.lock(false);
      showSetupResult(d, sel, imported, det);
      start.remove();
      back.remove();
    } catch (ex) {
      d.lock(false);
      err.textContent = ex.message; err.hidden = false;
    }
  }));
}

/** last page of both flows: what was done + live connection checks */
function showSetupResult(d, sel, imported, det) {
  const done = h('button', { type: 'button', class: 'btn primary' }, '서비스 보기');
  const items = [];
  if (imported && imported.error) items.push(callout('danger', h('b', null, '가져오기 실패'), h('span', null, imported.error)));
  else if (imported) items.push(callout('ok', h('b', null, `서비스 ${imported.imported}개를 가져왔습니다.`), (imported.warnings || []).length ? h('ul', { class: 'tight' }, imported.warnings.map((w) => h('li', null, w))) : null));
  items.push(callout('', h('b', null, '아직 실제로 바뀐 것은 없습니다'), h('span', { class: 'small' }, '서비스를 확인한 뒤 위쪽 「적용」에서 미리보기 → 적용하세요. 설정은 각 탭에서 언제든 고칠 수 있습니다.')));
  items.push(h('h3', null, '연결 확인'), setupChecks(sel, det, () => d.close(true)));
  d.body.replaceChildren(h('div', { class: 'stack' }, ...items));
  const foot = d.panel.querySelector('.dlg-foot');
  if (foot) foot.replaceChildren(h('span', { class: 'grow' }), done);
  done.addEventListener('click', () => { d.close(); S.checks = {}; selectTab('services'); });
  done.focus();
}

// ---------------------------------------------------------------- wizard

async function openSetupWizard() {
  const body = h('div', { class: 'stack' }, spinnerRow('준비하는 중…'));
  const prev = h('button', { type: 'button', class: 'btn ghost' }, '← 이전');
  const skip = h('button', { type: 'button', class: 'btn ghost' }, '건너뛰기');
  const next = h('button', { type: 'button', class: 'btn primary' }, '다음 →');
  const d = openDialog({ title: '설정 마법사', size: 'wide', body, footer: [prev, h('span', { class: 'grow' }), skip, next],
    beforeClose: () => confirmDialog({ title: '마법사 닫기', message: '지금까지 「다음」으로 저장한 단계는 남습니다. 다음에 접속하면 다시 물어봅니다.\n닫을까요?', okText: '닫기' }) });

  const det = await setupDetect();
  const sg = det.suggest || {};
  const fresh = !(S.state || {}).setupDone;
  const sel = Object.fromEntries(COMPONENTS.map((c) => [c.key, fresh && sg[c.flag] !== undefined ? !!sg[c.flag] : use(c.key)]));
  const sug = (k) => (fresh && sg[k] ? sg[k] : settings()[k]);
  let imported = null;
  let idx = 0;
  // components installed by Gilmok during this wizard: their settings are set, detection must not overwrite them
  const managedNow = {};
  try {
    const st0 = (await loadStacks()).stacks || {};
    for (const k of ['caddy', 'authelia', 'crowdsec']) if (st0[k] && st0[k].record) managedNow[k] = true;
  } catch { /* older server or no Docker */ }
  const stackTop = (k) => (typeof stackCard === 'function' ? stackCard(k, () => {
    // installed (or removed) here: Gilmok already set the connection — re-read it and redraw the step
    loadStacks().then((r) => { managedNow[k] = !!(r.stacks[k] && r.stacks[k].record); }).catch(() => {}).finally(() => render());
  }) : null);
  // a component Gilmok installed: the connection is set automatically, so the fields fold away
  // and 「다음」 does not save them (nothing to pick from the container list)
  const connBlock = (k, label, f, extra) => (managedNow[k]
    ? h('div', { class: 'stack tight' },
      callout('ok', h('b', null, `길목이 설치한 ${label}에 연결되어 있습니다`), h('span', { class: 'small' }, '컨테이너 이름·설정 파일 경로는 설치할 때 자동으로 맞췄습니다 — 따로 고를 필요가 없습니다. 「다음」으로 넘어가세요.')),
      h('details', null, h('summary', { class: 'small muted' }, '연결 정보 보기 (자동 설정됨)'), h('div', { class: 'grid-2' }, f.els)))
    : h('div', { class: 'stack' }, h('div', { class: 'grid-2' }, f.els), extra || null));
  const saveUnlessManaged = (k, f) => () => (managedNow[k] ? Promise.resolve() : setupSave(f.read()));

  const steps = () => [
    { id: 'comp', title: '구성요소' },
    { id: 'domain', title: '도메인' },
    sel.caddy && { id: 'caddy', title: 'Caddy' },
    sel.authelia && { id: 'authelia', title: 'Authelia' },
    sel.cloudflare && { id: 'cloudflare', title: 'Cloudflare' },
    sel.crowdsec && { id: 'crowdsec', title: 'CrowdSec' },
    sel.caddy && !managedNow.caddy && { id: 'import', title: '가져오기' },
    { id: 'done', title: '확인' },
  ].filter(Boolean);

  const checkBtn = (target, save) => {
    const out = h('div');
    const b = h('button', { type: 'button', class: 'btn' }, '저장하고 연결 확인');
    b.addEventListener('click', () => busy(b, async () => {
      try {
        await save();
        const r = await loadCheck(target, true);
        out.replaceChildren(r.status === 'ok' ? callout('ok', '연결 정상') : callout(r.status === 'fail' ? 'danger' : 'warn', checkStateText(r)), checkList(r));
      } catch (ex) { out.replaceChildren(callout('danger', ex.message)); }
    }));
    return h('div', { class: 'stack tight' }, h('div', { class: 'row' }, b), out);
  };

  // each step: { lead, body, save() } — save runs on 「다음」
  const build = {
    comp() {
      const warn = h('div');
      const sync = () => fill(warn,
        sel.crowdsec && !sel.cloudflare ? callout('warn', 'CrowdSec만 켜면 공격 IP를 판정만 하고 차단은 하지 않습니다 (차단은 Cloudflare 엣지에서).') : null,
        !Object.values(sel).some(Boolean) ? callout('', '아무것도 고르지 않으면 길목은 대시보드·로그·보안 기능만 씁니다.') : null);
      sync();
      return {
        lead: '이 서버에서 실제로 쓰는 것만 고르세요. 고르지 않은 구성요소는 탭과 설정이 숨겨지고 길목이 건드리지 않습니다.' + (det.docker ? ' (찾은 컨테이너를 보고 미리 골라 두었습니다)' : ''),
        body: h('div', { class: 'stack' }, compCards(sel, () => { sync(); drawRail(); }), warn),
        save: () => setupSave(Object.fromEntries(COMPONENTS.map((c) => [c.flag, !!sel[c.key]]))),
      };
    },
    domain() {
      const dom = setupInput('domain', '도메인', sug('domain'), { placeholder: '예: example.com', hint: '서비스 「photo」 → photo.<도메인>. Cloudflare를 쓰면 그 존과 같아야 합니다.', found: fresh && sg.domain ? 'Caddyfile 사이트 주소에서 알아냄' : '' });
      const ts = sel.tailscale ? setupInput('tailscaleIp', 'Tailscale IP', settings().tailscaleIp || (fresh ? sg.tailscaleIp : ''), { placeholder: '예: 100.64.0.10', hint: '사설 전용 서비스의 DNS(A 레코드) 값 — 이 서버의 Tailscale 주소', found: !settings().tailscaleIp && fresh && sg.tailscaleIp ? `찾음 — ${sg.tailscaleSrc || ''}` : '' }) : null;
      if (ts) ts.f.append(tsFinder(ts.el));
      return {
        lead: '모든 서비스 주소의 기준입니다. 정하기 전에는 「적용」이 막힙니다.',
        body: h('div', { class: 'grid-2' }, dom.f, ts && ts.f),
        save: async () => {
          const v = validDomain(dom.el.value);
          if (!v.ok) throw new Error('도메인 형식이 아닙니다 (예: example.com)');
          if (!v.v && (sel.caddy || sel.cloudflare)) throw new Error('도메인을 넣으세요 (예: example.com) — 서비스 주소와 Cloudflare 존의 기준입니다.');
          await setupSave({ domain: v.v, ...(ts ? { tailscaleIp: ts.el.value.trim() } : {}) });
        },
      };
    },
    caddy() {
      const f = settingsFields([
        { key: 'caddyMode', type: 'choice', label: 'Caddy 위치', options: [
          { value: 'docker', icon: 'box', label: 'Docker 컨테이너', desc: '길목이 docker exec로 검증·적용' },
          { value: 'api', icon: 'host', label: 'PC에 설치 · 길목은 Docker', desc: 'Caddy 관리 API(:2019)로 검증·적용' },
          { value: 'native', icon: 'server', label: 'PC에 설치 · 길목도 같은 PC', desc: 'caddy 명령을 직접 실행',
            disabled: !!det.selfName && settings().caddyMode !== 'native', disabledWhy: det.selfName ? '길목이 Docker 안에서 실행 중' : '' },
        ] },
        { key: 'caddyContainer', label: 'Caddy 컨테이너', mono: true, picker: 'container' },
        { key: 'caddyAdmin', label: 'Caddy 관리 API 주소', mono: true, placeholder: 'http://host.docker.internal:2019' },
        { key: 'caddyBin', label: 'caddy 실행 파일', mono: true, placeholder: '예: C:\\Caddy\\caddy.exe' },
        { key: 'caddyfilePath', label: 'Caddyfile 경로 — 길목이 보는 위치', mono: true, picker: 'file' },
        { key: 'caddyfileInCtr', label: 'Caddyfile 경로 — Caddy 컨테이너 안', mono: true },
      ]);
      for (const k of ['caddyContainer', 'caddyfilePath']) if (fresh && !managedNow.caddy && sg[k]) f.inputs[k].value = sg[k];
      const hint = foundText(det, 'caddy');
      if (hint) f.inputs.caddyContainer.closest('.field').append(h('small', { class: 'setup-found' }, hint));
      const show = () => {
        const m = f.inputs.caddyMode.value;
        const vis = { caddyContainer: m === 'docker', caddyfileInCtr: m === 'docker', caddyAdmin: m === 'api', caddyBin: m === 'native' };
        for (const [k, v] of Object.entries(vis)) f.inputs[k].closest('.field').hidden = !v;
      };
      f.inputs.caddyMode.addEventListener('change', show);
      show();
      const save = saveUnlessManaged('caddy', f);
      return { lead: 'Caddy가 어디서 실행되는지와 Caddyfile 위치를 정합니다. 아직 Caddy가 없으면 위에서 길목이 설치할 수 있습니다.', body: h('div', { class: 'stack' }, stackTop('caddy'), connBlock('caddy', 'Caddy', f), checkBtn('caddy', save)), save };
    },
    authelia() {
      const f = settingsFields([
        { key: 'autheliaContainer', label: 'Authelia 컨테이너', mono: true, picker: 'container' },
        { key: 'autheliaConfig', label: 'configuration.yml — 길목 컨테이너 안', mono: true, picker: 'file' },
        { key: 'autheliaUsers', label: 'users_database.yml — 길목 컨테이너 안', mono: true, picker: 'file' },
        { key: 'autheliaCtrDir', label: 'config 폴더 — Authelia 컨테이너 안', mono: true },
      ]);
      for (const k of ['autheliaContainer', 'autheliaConfig', 'autheliaUsers']) if (fresh && !managedNow.authelia && sg[k]) f.inputs[k].value = sg[k];
      const hint = foundText(det, 'authelia');
      if (hint) f.inputs.autheliaContainer.closest('.field').append(h('small', { class: 'setup-found' }, hint));
      const save = saveUnlessManaged('authelia', f);
      return { lead: '길목은 configuration.yml의 access_control 블록과 사용자 파일만 고칩니다. 아직 Authelia가 없으면 위에서 길목이 설치할 수 있습니다.', body: h('div', { class: 'stack' }, stackTop('authelia'), connBlock('authelia', 'Authelia', f), checkBtn('authelia', save)), save };
    },
    cloudflare() {
      const holder = h('div');
      const draw = () => holder.replaceChildren(
        // the quickest path first: reuse the token the Caddy container already has
        !(S.state || {}).cfConfigured && det.caddyToken ? setupTokenFix(det, draw) : cfTokenCard(async () => { await refreshState(); draw(); }));
      draw();
      return { lead: 'DNS 레코드를 자동으로 관리하려면 API 토큰이 필요합니다. 지금 없으면 「건너뛰기」하고 나중에 Cloudflare 탭에서 넣어도 됩니다.', body: holder, save: async () => {} };
    },
    crowdsec() {
      const f = settingsFields([
        { key: 'crowdsecContainer', label: 'CrowdSec 컨테이너', mono: true, picker: 'container' },
        { key: 'crowdsecLapi', label: 'LAPI 주소', mono: true, hint: '길목에서 접근하는 주소 (예: http://crowdsec:8080)' },
      ]);
      for (const k of ['crowdsecContainer', 'crowdsecLapi']) if (fresh && !managedNow.crowdsec && sg[k]) f.inputs[k].value = sg[k];
      const save = saveUnlessManaged('crowdsec', f);
      let keyRow = null;
      if (!det.csKey && !managedNow.crowdsec) {
        const kb = h('button', { type: 'button', class: 'btn' }, '바운서 키 만들기');
        kb.addEventListener('click', () => busy(kb, async () => {
          try { await save(); await api('POST', '/api/crowdsec/bouncer'); det.csKey = true; keyRow.replaceChildren(callout('ok', '길목 바운서를 등록하고 키를 저장했습니다.')); } catch (ex) { toast(ex.message, 'err', 9000); }
        }));
        keyRow = h('div', { class: 'row' }, kb, h('span', { class: 'hint' }, '길목이 판정 결과를 읽을 키가 없습니다 — CrowdSec 컨테이너에서 cscli bouncers add 로 만들어 저장합니다 (키는 화면에 나오지 않음).'));
      }
      return { lead: 'CrowdSec이 판정한 공격 IP를 읽어 옵니다. 아직 CrowdSec이 없으면 위에서 길목이 설치할 수 있습니다.', body: h('div', { class: 'stack' }, stackTop('crowdsec'), connBlock('crowdsec', 'CrowdSec', f, keyRow), checkBtn('crowdsec', save)), save };
    },
    import() {
      const out = h('div');
      const path = settings().caddyfilePath || '';
      const b = h('button', { type: 'button', class: 'btn primary' }, icon('download'), det.sites ? `서비스 ${det.sites}개 가져오기` : '설정한 경로에서 가져오기');
      const pc = h('button', { type: 'button', class: 'btn' }, icon('folder'), 'PC에서 Caddyfile 고르기…');
      const run = (btn, body) => busy(btn, async () => {
        try {
          imported = await api('POST', '/api/import', body);
          await refreshState();
          out.replaceChildren(callout('ok', h('b', null, `서비스 ${imported.imported}개를 가져왔습니다.`), (imported.warnings || []).length ? h('ul', { class: 'tight' }, imported.warnings.map((w) => h('li', null, w))) : null));
        } catch (ex) { out.replaceChildren(callout('danger', ex.message)); }
      });
      b.addEventListener('click', () => run(b));
      pc.addEventListener('click', async () => { const f = await pickLocalText(); if (f) run(pc, f); });
      return {
        lead: '지금 쓰는 Caddyfile을 읽어 서비스 목록과 기본 골격(전역 옵션·스니펫)을 만듭니다. 실제 파일은 바뀌지 않습니다. 새로 시작한다면 건너뛰세요.',
        body: h('div', { class: 'stack' }, (S.state.services || []).length ? callout('warn', `이미 서비스 ${S.state.services.length}개가 있습니다 — 가져오면 대체됩니다.`) : null,
          h('p', { class: 'small muted' }, '설정한 경로: ', h('span', { class: 'mono' }, path || '(없음)')),
          h('div', { class: 'row' }, b, pc),
          h('p', { class: 'hint' }, 'PC에서 고른 파일은 서비스 목록을 만드는 데만 씁니다. 길목이 그 Caddyfile을 고치고 적용하려면 Caddy 단계의 경로가 길목에서 보이는 실제 파일이어야 합니다(「찾아보기…」).'),
          out),
        save: async () => {},
      };
    },
    done() {
      return {
        lead: '설정한 구성요소의 연결을 확인합니다. 문제가 있으면 해당 탭에서 고칠 수 있습니다.',
        body: h('div', { class: 'stack' },
          imported && !imported.error ? callout('ok', `서비스 ${imported.imported}개를 가져왔습니다.`) : null,
          setupChecks(sel, det, () => d.close(true)),
          callout('', h('b', null, '아직 실제로 바뀐 것은 없습니다'), h('span', { class: 'small' }, '서비스를 확인한 뒤 위쪽 「적용」에서 미리보기 → 적용하세요.'))),
        save: () => setupFinish(),
      };
    },
  };

  const rail = h('ol', { class: 'wz-rail' });
  const drawRail = () => {
    const list = steps();
    rail.replaceChildren(...list.map((s, i) => h('li', { class: i === idx ? 'cur' : i < idx ? 'past' : '' }, h('span', { class: 'n' }, String(i + 1)), s.title)));
  };
  let cur = null;
  const err = h('p', { class: 'form-error', role: 'alert', hidden: true });
  const render = () => {
    const list = steps();
    if (idx >= list.length) idx = list.length - 1;
    const s = list[idx];
    cur = build[s.id]();
    err.hidden = true;
    drawRail();
    body.replaceChildren(rail, h('div', { class: 'stack' }, h('h3', null, `${idx + 1}. ${s.title}`), h('p', { class: 'muted' }, cur.lead), cur.body, err));
    prev.disabled = idx === 0;
    skip.hidden = s.id === 'comp' || s.id === 'domain' || s.id === 'done';
    next.textContent = s.id === 'done' ? '마치기' : '다음 →';
  };
  prev.addEventListener('click', () => { idx = Math.max(0, idx - 1); render(); });
  skip.addEventListener('click', () => { idx++; render(); });
  next.addEventListener('click', () => busy(next, async () => {
    try {
      await cur.save();
      if (steps()[idx].id === 'done') { d.close(true); S.checks = {}; toast('설정을 마쳤습니다 — 서비스를 확인하고 「적용」하세요'); selectTab('services'); return; }
      idx++;
      render();
    } catch (ex) { err.textContent = ex.message; err.hidden = false; }
  }));
  render();
}
