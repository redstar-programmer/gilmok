// Gilmok web UI — accounts: login gates (temporary password / mandatory 2FA), 내 계정, 계정 관리 (accounts, roles).
'use strict';

const me = () => (S.state && S.state.me) || {};
const can = (perm) => (me().perms || []).includes(perm);

// ---- shared pieces

/** Recovery codes, shown once: copy / download, and a confirmation before going on. */
function recoveryView(codes, onDone, doneLabel = '저장했습니다 — 계속') {
  const text = `길목(Gilmok) 2단계 인증 복구 코드 — ${me().name || ''} @ ${settings().domain || location.host}\n각 코드는 한 번만 쓸 수 있습니다.\n\n${codes.join('\n')}\n`;
  const copy = h('button', { type: 'button', class: 'btn sm' }, '복사');
  copy.addEventListener('click', async () => { try { await navigator.clipboard.writeText(text); toast('복사했습니다'); } catch { toast('복사하지 못했습니다 — 직접 선택해 복사하세요', 'err'); } });
  const dl = h('button', { type: 'button', class: 'btn sm' }, '파일로 저장');
  dl.addEventListener('click', () => {
    const a = h('a', { href: URL.createObjectURL(new Blob([text], { type: 'text/plain' })), download: `gilmok-recovery-${me().name || 'codes'}.txt` });
    document.body.append(a); a.click(); a.remove();
  });
  const ok = h('input', { type: 'checkbox' });
  const go = h('button', { type: 'button', class: 'btn primary', disabled: true }, doneLabel);
  ok.addEventListener('change', () => { go.disabled = !ok.checked; });
  go.addEventListener('click', () => onDone && onDone());
  return h('div', { class: 'stack' },
    callout('warn', h('b', null, '복구 코드 10개 — 지금만 보입니다'),
      h('span', { class: 'small' }, '휴대폰을 잃어버리거나 인증 앱을 지웠을 때 6자리 코드 대신 하나씩 넣어 로그인합니다. 비밀번호 관리자나 종이에 따로 보관하세요.')),
    h('div', { class: 'recovery-grid mono' }, codes.map((c) => h('span', null, c))),
    h('div', { class: 'row' }, copy, dl),
    h('label', { class: 'radio-inline' }, ok, ' 복구 코드를 안전한 곳에 저장했습니다'),
    h('div', { class: 'row' }, h('span', { class: 'grow' }), go));
}

/** TOTP enrolment: QR + key + code → recovery codes. onDone() after the codes were saved. */
function enrollView(onDone, { cancel } = {}) {
  const box = h('div', { class: 'stack' }, spinnerRow('2단계 인증 키를 만드는 중…'));
  (async () => {
    let r;
    try { r = await api('POST', '/api/auth/totp/begin'); } catch (ex) { box.replaceChildren(errorBox(ex.message)); return; }
    const code = h('input', { type: 'text', inputmode: 'numeric', maxlength: '6', autocomplete: 'one-time-code', placeholder: '123456', class: 'mono code-input' });
    const ok = h('button', { type: 'submit', class: 'btn primary' }, '확인하고 켜기');
    const err = h('p', { class: 'form-error', role: 'alert', hidden: true });
    const showKey = h('details', null, h('summary', { class: 'small' }, 'QR을 찍을 수 없나요? 키 직접 입력'),
      h('div', { class: 'stack tight', style: { marginTop: '8px' } },
        h('div', { class: 'totp-key mono', 'aria-label': '비밀 키' }, r.secret.match(/.{1,4}/g).join(' ')),
        h('p', { class: 'hint' }, '인증 앱에서 「키 직접 입력」 → 계정 이름: 길목, 종류: 시간 기반(TOTP), 6자리, 30초.')));
    const form = h('form', { class: 'stack', novalidate: true },
      h('div', { class: 'enroll-grid' },
        r.qr ? h('img', { src: r.qr, alt: '2단계 인증 등록용 QR 코드', class: 'totp-qr', width: '200', height: '200' }) : null,
        h('ol', { class: 'flow' },
          h('li', null, '휴대폰에 인증 앱을 엽니다 (Google Authenticator, Microsoft Authenticator, 1Password, Bitwarden 등).'),
          h('li', null, '「+」 → 「QR 코드 스캔」으로 왼쪽 QR을 찍습니다.'),
          h('li', null, '앱에 나온 6자리 숫자를 아래에 넣습니다 (30초마다 바뀝니다).'))),
      showKey,
      h('div', { class: 'row code-row' }, field('앱의 현재 코드', code), ok, cancel || null),
      err);
    form.addEventListener('submit', (e) => {
      e.preventDefault();
      err.hidden = true;
      busy(ok, async () => {
        try {
          const res = await api('POST', '/api/auth/totp/enable', { code: code.value.trim() });
          box.replaceChildren(callout('ok', h('b', null, '✓ 2단계 인증을 켰습니다')), recoveryView(res.recovery, onDone));
        } catch (ex) { err.textContent = ex.message; err.hidden = false; code.select(); }
      });
    });
    box.replaceChildren(form);
    code.focus();
  })();
  return box;
}

// ---- login gates (shown instead of the app until done)

// the gate currently on screen ('' = none): a second call for the same gate must not redraw it,
// or the 2FA enrolment would ask the server for a new secret and the QR on screen would go stale
let gateOpen = '';

async function showGate(meInfo) {
  if (gateOpen && gateOpen === meInfo.gate) return;
  gateOpen = meInfo.gate;
  $('#app').hidden = true;
  for (const d of [...dialogStack]) d.close(true);
  const auth = $('#auth');
  auth.hidden = false;
  $('#auth-form').hidden = true;
  let gate = $('#auth-gate');
  if (!gate) { gate = h('section', { id: 'auth-gate', class: 'glass auth-card gate-card' }); auth.append(gate); }
  gate.hidden = false;
  const logout = h('button', { type: 'button', class: 'btn ghost sm' }, '로그아웃');
  logout.addEventListener('click', async () => { try { await api('POST', '/api/auth/logout'); } catch { /* ignore */ } gateOpen = ''; gate.hidden = true; showAuth(false); });
  const head = (title, sub) => h('div', { class: 'stack tight' },
    h('div', { class: 'brand brand-lg' }, h('span', { class: 'logo', 'aria-hidden': 'true' }), h('span', null, '길목'), ' ', h('span', { class: 'brand-en' }, 'Gilmok')),
    h('h2', null, title), h('p', { class: 'muted small' }, sub));
  const next = async () => {
    const st = await api('GET', '/api/auth/state');
    gateOpen = '';
    if (st.me && st.me.gate) showGate(st.me);
    else { gate.hidden = true; $('#auth-form').hidden = false; showApp(); }
  };
  if (meInfo.gate === 'bootstrap') {
    const name = h('input', { type: 'text', autocomplete: 'username', autocapitalize: 'off', spellcheck: 'false', class: 'mono', placeholder: '예: kim' });
    const display = h('input', { type: 'text', maxlength: '40', autocomplete: 'off', placeholder: '예: 김철수' });
    const nw = h('input', { type: 'password', autocomplete: 'new-password' });
    const nw2 = h('input', { type: 'password', autocomplete: 'new-password' });
    const err = h('p', { class: 'form-error', role: 'alert', hidden: true });
    const save = h('button', { type: 'submit', class: 'btn primary block' }, '관리자 계정 만들고 시작');
    const form = h('form', { class: 'stack', novalidate: true },
      head('새 관리자 계정을 만드세요', '지금은 모두가 아는 초기 계정(admin/admin)으로 들어와 있습니다. 본인의 관리자 계정을 만들면 admin/admin 은 바로 비활성화되어 다시는 로그인할 수 없습니다.'),
      h('div', { class: 'grid-2' }, field('아이디', name, 'admin 말고 다른 아이디 (영문 소문자·숫자·. _ -)'), field('이름', display, '화면·로그에 표시 (선택)')),
      field('비밀번호', nw, '12자 이상, 아이디를 넣지 마세요'), field('비밀번호 확인', nw2),
      callout('', h('span', { class: 'small' }, '2단계 인증은 들어간 뒤 설정 탭 › 내 계정에서 켤 수 있습니다 (선택, 권장).')),
      err, save,
      h('div', { class: 'row' }, h('span', { class: 'grow' }), logout));
    form.addEventListener('submit', (e) => {
      e.preventDefault();
      err.hidden = true;
      const bad = (m, el) => { err.textContent = m; err.hidden = false; el && el.focus(); };
      const n = name.value.trim().toLowerCase();
      if (!n) { bad('아이디를 입력하세요', name); return; }
      if (n === 'admin') { bad('admin 말고 다른 아이디를 쓰세요', name); return; }
      if (nw.value.length < 12) { bad('비밀번호는 12자 이상이어야 합니다', nw); return; }
      if (nw.value !== nw2.value) { bad('비밀번호 확인이 일치하지 않습니다', nw2); return; }
      busy(save, async () => {
        try {
          await api('POST', '/api/auth/bootstrap', { name: n, display: display.value.trim(), password: nw.value });
          localStorage.setItem('gm.user', n);
          toast(`관리자 계정 ${n} 을 만들었습니다 — admin/admin 은 이제 쓸 수 없습니다`, 'ok', 8000);
          await next();
        } catch (ex) { bad(ex.message); }
      });
    });
    gate.replaceChildren(form);
    name.focus();
    return;
  }
  if (meInfo.gate === 'password') {
    const cur = h('input', { type: 'password', autocomplete: 'current-password' });
    const nw = h('input', { type: 'password', autocomplete: 'new-password' });
    const nw2 = h('input', { type: 'password', autocomplete: 'new-password' });
    const err = h('p', { class: 'form-error', role: 'alert', hidden: true });
    const save = h('button', { type: 'submit', class: 'btn primary block' }, '비밀번호 바꾸고 계속');
    const form = h('form', { class: 'stack', novalidate: true },
      head('새 비밀번호를 정하세요', `${meInfo.display || meInfo.name} 님, 관리자가 만든 임시 비밀번호로 로그인했습니다. 계속하려면 본인만 아는 비밀번호로 바꿔야 합니다.`),
      field('임시 비밀번호', cur), field('새 비밀번호', nw, '12자 이상, 아이디를 넣지 마세요'), field('새 비밀번호 확인', nw2), err, save,
      h('div', { class: 'row' }, h('span', { class: 'grow' }), logout));
    form.addEventListener('submit', (e) => {
      e.preventDefault();
      err.hidden = true;
      if (nw.value.length < 12) { err.textContent = '새 비밀번호는 12자 이상이어야 합니다'; err.hidden = false; nw.focus(); return; }
      if (nw.value !== nw2.value) { err.textContent = '새 비밀번호 확인이 일치하지 않습니다'; err.hidden = false; nw2.focus(); return; }
      busy(save, async () => {
        try { await api('POST', '/api/auth/password', { current: cur.value, new: nw.value }); toast('비밀번호를 바꿨습니다'); await next(); } catch (ex) { err.textContent = ex.message; err.hidden = false; }
      });
    });
    gate.replaceChildren(form);
    cur.focus();
    return;
  }
  // 2fa
  gate.replaceChildren(
    head('2단계 인증을 설정하세요', `${meInfo.display || meInfo.name} 님, 관리자가 이 계정에 2단계 인증(TOTP)을 요구했습니다. 비밀번호가 새도 휴대폰의 6자리 코드 없이는 들어올 수 없게 됩니다. 1분이면 됩니다.`),
    enrollView(() => next()),
    h('div', { class: 'row' }, h('span', { class: 'grow' }), logout));
}

// ---- 설정 탭 › 내 계정

function myAccountStep() {
  const m = me();
  const body = h('div', { class: 'stack' });
  const permChips = (m.perms || []).length
    ? h('div', { class: 'chips' }, m.perms.map((p) => h('span', { class: 'badge accent' }, (PERM_NAMES[p] || p))))
    : h('span', { class: 'muted' }, '보기만 가능');

  // password
  const cur = h('input', { type: 'password', autocomplete: 'current-password' });
  const nw = h('input', { type: 'password', autocomplete: 'new-password' });
  const nw2 = h('input', { type: 'password', autocomplete: 'new-password' });
  const pwErr = h('p', { class: 'form-error', role: 'alert', hidden: true });
  const pwSave = h('button', { type: 'submit', class: 'btn primary' }, '비밀번호 변경');
  const pwForm = h('form', { class: 'stack', novalidate: true }, pwErr,
    h('div', { class: 'grid-2' }, field('현재 비밀번호', cur), field('새 비밀번호', nw, '12자 이상, 아이디를 넣지 마세요'), field('새 비밀번호 확인', nw2)),
    h('div', { class: 'row' }, h('p', { class: 'hint grow' }, '바꾸면 이 계정의 다른 브라우저 로그인은 모두 끊깁니다.'), pwSave));
  pwForm.addEventListener('submit', (e) => {
    e.preventDefault();
    pwErr.hidden = true;
    const bad = (msg, el) => { pwErr.textContent = msg; pwErr.hidden = false; el && el.focus(); };
    if (nw.value.length < 12) { bad('새 비밀번호는 12자 이상이어야 합니다', nw); return; }
    if (nw.value !== nw2.value) { bad('새 비밀번호 확인이 일치하지 않습니다', nw2); return; }
    busy(pwSave, async () => {
      try { await api('POST', '/api/auth/password', { current: cur.value, new: nw.value }); cur.value = nw.value = nw2.value = ''; toast('비밀번호를 바꿨습니다'); } catch (ex) { bad(ex.message, cur); }
    });
  });

  // 2FA
  const tfa = h('div', { class: 'section-box stack' });
  const drawTfa = () => {
    const mm = me();
    tfa.replaceChildren(h('h3', null, icon('key'), '2단계 인증 (TOTP)'));
    if (!mm.totp) {
      const start = h('button', { type: 'button', class: 'btn primary' }, '2단계 인증 설정…');
      start.addEventListener('click', () => {
        const cancel = h('button', { type: 'button', class: 'btn ghost' }, '취소');
        cancel.addEventListener('click', drawTfa);
        tfa.replaceChildren(h('h3', null, icon('key'), '2단계 인증 설정'), enrollView(async () => { await refreshState(); renderPanel(); }, { cancel }));
      });
      tfa.append(callout('', h('span', null, '꺼져 있습니다 (선택). 켜면 로그인할 때 비밀번호와 함께 휴대폰 인증 앱의 6자리 코드를 묻습니다 — 비밀번호가 새도 들어올 수 없게 됩니다.')), h('div', { class: 'row' }, start));
      return;
    }
    const redo = h('button', { type: 'button', class: 'btn' }, '다른 기기로 다시 설정…');
    redo.addEventListener('click', () => {
      const cancel = h('button', { type: 'button', class: 'btn ghost' }, '취소');
      cancel.addEventListener('click', drawTfa);
      tfa.replaceChildren(h('h3', null, icon('key'), '새 기기로 2단계 인증 설정'),
        callout('', h('span', { class: 'small' }, '새 기기에서 확인을 마치는 순간 예전 기기의 코드와 예전 복구 코드는 쓸 수 없게 됩니다. 확인 전에 취소하면 그대로입니다.')),
        enrollView(async () => { await refreshState(); renderPanel(); }, { cancel }));
    });
    const regen = h('button', { type: 'button', class: 'btn' }, '복구 코드 새로 만들기…');
    regen.addEventListener('click', async () => {
      if (!(await confirmDialog({ title: '복구 코드 새로 만들기', message: '새 코드 10개를 만들고 예전 코드는 모두 무효로 합니다. 계속할까요?', okText: '새로 만들기' }))) return;
      try {
        const r = await busy(regen, () => api('POST', '/api/auth/recovery'));
        const d = openDialog({ title: '새 복구 코드', body: recoveryView(r.recovery, async () => { d.close(); await refreshState(); renderPanel(); }, '저장했습니다 — 닫기') });
      } catch (ex) { toast(ex.message, 'err'); }
    });
    const kids = [h('span', { class: 'badge ok' }, '켜짐'), h('span', { class: `badge ${mm.recovery <= 2 ? 'warn' : 'muted'}` }, `남은 복구 코드 ${mm.recovery}개`)];
    let off = null;
    if (!mm.require2fa) {
      off = h('button', { type: 'button', class: 'btn danger' }, '끄기…');
      off.addEventListener('click', async () => {
        if (!(await confirmDialog({ title: '2단계 인증 끄기', message: '이 계정은 비밀번호만으로 들어올 수 있게 됩니다. 끌까요?', okText: '끄기', danger: true }))) return;
        try { await busy(off, () => api('POST', '/api/auth/totp/disable')); await refreshState(); toast('2단계 인증을 껐습니다', 'warn'); renderPanel(); } catch (ex) { toast(ex.message, 'err'); }
      });
    }
    append(tfa, [h('div', { class: 'row' }, ...kids),
      mm.recovery <= 2 ? callout('warn', h('span', { class: 'small' }, '복구 코드가 거의 남지 않았습니다. 새로 만들어 두세요.')) : null,
      h('p', { class: 'small muted' }, mm.require2fa ? '관리자가 이 계정에 2단계 인증을 요구하고 있어 끌 수 없습니다. 휴대폰을 바꿀 때는 「다른 기기로 다시 설정」을 쓰세요.' : '로그인·재인증 때 인증 앱의 6자리 코드를 묻습니다. 끄면 비밀번호만으로 로그인합니다.'),
      h('div', { class: 'row' }, redo, regen, h('span', { class: 'grow' }), off)]);
  };
  drawTfa();

  body.append(
    h('dl', { class: 'kv' },
      h('dt', null, '아이디'), h('dd', null, h('b', { class: 'mono' }, m.name || '—')),
      h('dt', null, '이름'), h('dd', null, m.display || '—'),
      h('dt', null, '역할'), h('dd', null, m.roleName || m.role || '—'),
      h('dt', null, '권한'), h('dd', null, permChips)),
    tfa,
    h('div', { class: 'section-box stack' }, h('h3', null, icon('lock'), '비밀번호'), pwForm));
  return { id: 'me', title: '내 계정', desc: '내 비밀번호와 2단계 인증(선택). 다른 사람 계정은 「계정 관리」에서 다룹니다.',
    state: m.totp ? 'ok' : 'info', stateText: `${m.name || ''}${m.totp ? ' · 2단계 켜짐' : ' · 2단계 꺼짐'}`, body };
}

const PERM_NAMES = { config: '구성 변경', apply: '적용·외부 반영', authelia_users: 'Authelia 사용자', security: '차단 관리', logs: '로그 관리', accounts: '계정·접근 보안', system: '연결·시스템' };

// ---- 설정 탭 › 계정 관리

function showSecretOnce(title, label, secret, note) {
  const copy = h('button', { type: 'button', class: 'btn sm' }, '복사');
  copy.addEventListener('click', async () => { try { await navigator.clipboard.writeText(secret); toast('복사했습니다'); } catch { toast('복사하지 못했습니다', 'err'); } });
  const close = h('button', { type: 'button', class: 'btn primary' }, '전달했습니다 — 닫기');
  const d = openDialog({ title, body: h('div', { class: 'stack' },
    h('p', null, label), h('div', { class: 'row' }, h('div', { class: 'totp-key mono grow' }, secret), copy),
    callout('warn', h('span', { class: 'small' }, note))), footer: [h('span', { class: 'spacer' }), close] });
  close.addEventListener('click', () => d.close());
}

function accountDialog(acct, roles, onDone) {
  const isNew = !acct;
  const name = h('input', { type: 'text', value: acct ? acct.name : '', disabled: !isNew, autocomplete: 'off', spellcheck: 'false', autocapitalize: 'off', placeholder: '예: kim', class: 'mono' });
  const display = h('input', { type: 'text', value: acct ? acct.display || '' : '', maxlength: '40', autocomplete: 'off', placeholder: '예: 김철수' });
  const role = h('select', null, roles.map((r) => h('option', { value: r.id, selected: (acct ? acct.role : 'viewer') === r.id }, `${r.name}${r.builtin ? '' : ' (사용자 역할)'}`)));
  const disabled = switchCtl('사용 중지', acct ? acct.disabled : false, '켜면 바로 로그아웃되고 로그인할 수 없습니다 (계정과 기록은 남음).');
  const req2fa = switchCtl('2단계 인증 요구', acct ? acct.require2fa : false, '켜면 이 계정은 2단계 인증을 설정하기 전에는 아무것도 할 수 없고, 본인이 끌 수도 없습니다.');
  const pwMode = uid('pw');
  const auto = h('input', { type: 'radio', name: pwMode, value: 'auto', checked: true });
  const manual = h('input', { type: 'radio', name: pwMode, value: 'manual' });
  const pw = h('input', { type: 'password', autocomplete: 'new-password', placeholder: '12자 이상', hidden: true });
  const pwBox = h('div', { class: 'stack tight' },
    h('span', { class: 'field-label' }, '처음 비밀번호'),
    h('label', { class: 'radio-inline' }, auto, ' 임시 비밀번호 자동 생성 (권장)'),
    h('label', { class: 'radio-inline' }, manual, ' 직접 입력'), pw,
    h('p', { class: 'hint' }, '어느 쪽이든 그 사람이 처음 로그인할 때 자기 비밀번호로 바꾸게 됩니다.'));
  pwBox.addEventListener('change', () => { pw.hidden = !manual.checked; if (manual.checked) pw.focus(); });
  const roleDesc = h('p', { class: 'hint' });
  const syncRole = () => {
    const r = roles.find((x) => x.id === role.value);
    roleDesc.textContent = r ? (r.perms.length ? `권한: ${r.perms.map((p) => PERM_NAMES[p] || p).join(', ')}` : '권한: 보기만') : '';
  };
  role.addEventListener('change', syncRole);
  syncRole();
  const err = h('p', { class: 'form-error', role: 'alert', hidden: true });
  const form = h('form', { class: 'stack', novalidate: true }, err,
    h('div', { class: 'grid-2' }, field('아이디', name, isNew ? '영문 소문자·숫자·. _ - (로그인에 씀, 나중에 못 바꿈)' : '아이디는 바꿀 수 없습니다'), field('이름', display, '화면·로그에 함께 표시')),
    h('div', { class: 'field' }, h('label', null, '역할'), role, roleDesc),
    req2fa,
    isNew ? pwBox : disabled);
  const save = h('button', { type: 'submit', class: 'btn primary' }, isNew ? '계정 추가' : '저장');
  const cancel = h('button', { type: 'button', class: 'btn ghost' }, '취소');
  save.setAttribute('form', form.id = uid('form'));
  const d = openDialog({ title: isNew ? '계정 추가' : `${acct.name} 계정 편집`, body: form, footer: [h('span', { class: 'spacer' }), cancel, save] });
  cancel.addEventListener('click', () => d.close());
  form.addEventListener('submit', (e) => {
    e.preventDefault();
    err.hidden = true;
    busy(save, async () => {
      try {
        if (isNew) {
          const r = await api('POST', '/api/accounts', { name: name.value.trim(), display: display.value.trim(), role: role.value, password: manual.checked ? pw.value : '', require2fa: req2fa.input.checked });
          d.close();
          if (r.tempPassword) showSecretOnce('임시 비밀번호', `${name.value.trim().toLowerCase()} 계정의 임시 비밀번호입니다. 안전한 방법으로 본인에게 전달하세요.`, r.tempPassword, '이 창을 닫으면 다시 볼 수 없습니다. 처음 로그인하면 새 비밀번호로 바꾸고, 2단계 인증을 설정하게 됩니다.');
          else toast('계정을 추가했습니다');
        } else {
          await api('PUT', `/api/accounts/${encodeURIComponent(acct.name)}`, { display: display.value.trim(), role: role.value, disabled: disabled.input.checked, require2fa: req2fa.input.checked });
          d.close();
          toast('저장했습니다');
        }
        onDone && onDone();
      } catch (ex) { err.textContent = ex.message; err.hidden = false; }
    });
  });
}

function roleDialog(role, perms, onDone) {
  const isNew = !role;
  const name = h('input', { type: 'text', value: role ? role.name : '', maxlength: '30', autocomplete: 'off', placeholder: '예: DNS 담당' });
  const on = new Set(role ? role.perms : []);
  const boxes = perms.map((p) => h('label', { class: 'check-item' },
    h('input', { type: 'checkbox', value: p.id, checked: on.has(p.id) }),
    h('span', null, h('b', null, p.name), h('small', null, p.desc))));
  const err = h('p', { class: 'form-error', role: 'alert', hidden: true });
  const form = h('form', { class: 'stack', novalidate: true }, err, field('역할 이름', name),
    h('div', { class: 'field' }, h('span', { class: 'field-label' }, '권한 (체크하지 않은 것은 보기만)'), h('div', { class: 'check-grid one-col' }, boxes)));
  const save = h('button', { type: 'submit', class: 'btn primary' }, isNew ? '역할 추가' : '저장');
  const cancel = h('button', { type: 'button', class: 'btn ghost' }, '취소');
  save.setAttribute('form', form.id = uid('form'));
  const d = openDialog({ title: isNew ? '역할 추가' : `「${role.name}」 역할 편집`, body: form, footer: [h('span', { class: 'spacer' }), cancel, save] });
  cancel.addEventListener('click', () => d.close());
  form.addEventListener('submit', (e) => {
    e.preventDefault();
    err.hidden = true;
    const body = { name: name.value.trim(), perms: boxes.map((b) => b.querySelector('input')).filter((i) => i.checked).map((i) => i.value) };
    busy(save, async () => {
      try {
        if (isNew) await api('POST', '/api/roles', body);
        else await api('PUT', `/api/roles/${encodeURIComponent(role.id)}`, body);
        d.close();
        toast('저장했습니다');
        onDone && onDone();
      } catch (ex) { err.textContent = ex.message; err.hidden = false; }
    });
  });
}

function accountsStep(getL) {
  const body = h('div', { class: 'stack' }, spinnerRow('계정 불러오는 중…'));
  const picked = new Set();
  // a change that touches my own account (2FA requirement, name, role, my role's permissions) must
  // refresh S.state.me too — 내 계정, the top bar and permission checks all read it
  async function afterChange(touchesMe) {
    if (!touchesMe) { load(); return; }
    try { await refreshState(); } catch { return; } // e.g. 2FA now required: the gate takes over — don't redraw behind it
    renderPanel();
  }
  async function load() {
    let r;
    try { r = await api('GET', '/api/accounts'); } catch (ex) { body.replaceChildren(errorBox(ex.message)); return; }
    const roles = r.roles || [];
    const roleName = (id) => (roles.find((x) => x.id === id) || {}).name || id;
    const add = h('button', { type: 'button', class: 'btn primary' }, icon('plus'), '계정 추가');
    add.addEventListener('click', () => accountDialog(null, roles, load));
    const act = (label, cls, fn) => { const b = h('button', { type: 'button', class: `btn sm ${cls || ''}` }, label); b.addEventListener('click', () => fn(b)); return b; };
    const setRequire = async (names, require, btn) => {
      const self = names.includes(r.me);
      const meNoTotp = self && require && !(r.accounts.find((x) => x.name === r.me) || {}).totp;
      if (meNoTotp && !(await confirmDialog({ title: '내 계정에도 2단계 인증 요구', message: '내 계정은 아직 2단계 인증이 없습니다. 요구하면 저장 즉시 설정 화면으로 넘어가고, 설정을 마쳐야 다시 쓸 수 있습니다. 계속할까요?', okText: '요구' }))) return false;
      try {
        const x = await busy(btn, () => api('POST', '/api/accounts/require-2fa', { names, require }));
        const n = (x.changed || []).length;
        toast(n ? `${n}개 계정 2단계 인증 ${require ? '요구' : '요구 해제'}${(x.skipped || []).length ? ` · 건너뜀: ${x.skipped.join(', ')} (초기 계정)` : ''}` : '바뀐 것이 없습니다', n ? 'ok' : 'warn');
        picked.clear();
        // turning the requirement off does not remove an authenticator already registered
        if (!require) {
          const still = (x.changed || []).filter((nm) => (r.accounts.find((a) => a.name === nm) || {}).totp);
          if (still.length) {
            const mine = still.includes(r.me);
            const go = h('button', { type: 'button', class: 'btn sm' }, '내 계정에서 끄기');
            go.addEventListener('click', () => { d0.close(); gotoTab('gilmok', 'me'); });
            const ok0 = h('button', { type: 'button', class: 'btn primary' }, '알겠습니다');
            const d0 = openDialog({ title: '요구만 풀었습니다', body: h('div', { class: 'stack' },
              h('p', null, `${still.join(', ')} 계정은 이미 인증 앱을 등록해 두어서, 로그인할 때 2단계 코드를 계속 묻습니다.`),
              h('ul', { class: 'small' },
                h('li', null, '「2단계 요구」는 관리자가 설정을 강제하는 스위치입니다. 끄면 강제만 풀리고 등록은 그대로입니다.'),
                h('li', null, mine ? '내 계정이라면 설정 탭 › 내 계정 › 2단계 인증 › 「끄기」로 직접 끕니다.' : '본인이 내 계정에서 「끄기」로 끄거나, 관리자가 이 표의 「2단계 초기화」로 등록을 지웁니다.'))),
              footer: [mine ? go : null, h('span', { class: 'spacer' }), ok0].filter(Boolean) });
            ok0.addEventListener('click', () => d0.close());
          }
        }
        await afterChange(self);
        return true;
      } catch (ex) { toast(ex.message, 'err'); return false; }
    };
    const selectable = r.accounts.filter((a) => !a.bootstrap);
    const allCb = h('input', { type: 'checkbox', 'aria-label': '모든 계정 선택', checked: selectable.length > 0 && selectable.every((a) => picked.has(a.name)) });
    const bulkCount = h('b', { class: 'bulk-count' });
    const bulkOn = h('button', { type: 'button', class: 'btn sm primary' }, '선택한 계정에 2단계 인증 요구');
    const bulkOff = h('button', { type: 'button', class: 'btn sm' }, '요구 해제');
    const updBulk = () => {
      bulkCount.textContent = picked.size ? `${picked.size}개 선택` : '일괄: 표 왼쪽에서 계정을 고르세요';
      bulkOn.disabled = bulkOff.disabled = !picked.size;
      bulkBar.classList.toggle('active', picked.size > 0);
      allCb.checked = selectable.length > 0 && selectable.every((a) => picked.has(a.name));
      allCb.indeterminate = picked.size > 0 && !allCb.checked;
    };
    const bulkBar = h('div', { class: 'bulk-bar' }, h('div', { class: 'bulk-head' }, bulkCount, h('span', { class: 'grow' }), bulkOff, bulkOn));
    bulkOn.addEventListener('click', () => setRequire([...picked], true, bulkOn));
    bulkOff.addEventListener('click', () => setRequire([...picked], false, bulkOff));
    const rowCbs = [];
    allCb.addEventListener('change', () => {
      for (const a of selectable) { if (allCb.checked) picked.add(a.name); else picked.delete(a.name); }
      for (const cb of rowCbs) cb.checked = picked.has(cb.value);
      updBulk();
    });
    const rows = r.accounts.map((a) => {
      const self = a.name === r.me;
      if (a.bootstrap) {
        const del = act('삭제…', 'ghost', async (b) => {
          if (!(await confirmDialog({ title: '초기 계정 삭제', message: 'admin/admin 초기 계정(이미 비활성화됨)을 목록에서 지웁니다. 지울까요?', okText: '삭제', danger: true }))) return;
          try { await busy(b, () => api('DELETE', `/api/accounts/${encodeURIComponent(a.name)}`)); load(); } catch (ex) { toast(ex.message, 'err'); }
        });
        return h('tr', { class: 'disabled' },
          h('td', { class: 'sel-cell' }),
          h('td', null, h('b', { class: 'mono' }, a.name), h('div', { class: 'cell-sub' }, '초기 계정 (admin/admin)')),
          h('td', null, '—'), h('td', null, '—'), h('td', null, '—'),
          h('td', null, h('span', { class: 'badge muted', title: '첫 관리자 계정을 만들 때 비활성화되었고, 비밀번호도 무작위로 바뀌어 다시 쓸 수 없습니다' }, a.disabled ? '비활성화됨' : '초기 설정 전')),
          h('td', { class: 'small' }, '—'),
          h('td', null, a.disabled ? del : null));
      }
      const cb = h('input', { type: 'checkbox', value: a.name, checked: picked.has(a.name), 'aria-label': `${a.name} 선택` });
      cb.addEventListener('change', () => { if (cb.checked) picked.add(a.name); else picked.delete(a.name); updBulk(); });
      rowCbs.push(cb);
      const reqSw = h('input', { type: 'checkbox', role: 'switch', checked: !!a.require2fa, 'aria-label': `${a.name} 2단계 인증 요구` });
      reqSw.addEventListener('change', async () => {
        const ok = await setRequire([a.name], reqSw.checked, reqSw);
        if (!ok) reqSw.checked = !reqSw.checked;
      });
      const tfa = a.totp ? h('span', { class: 'badge ok', title: '인증 앱 등록됨 — 로그인 때 코드를 묻습니다' }, `등록됨 · 복구 ${a.recovery}`)
        : a.require2fa ? h('span', { class: 'badge warn', title: '다음 로그인(또는 다음 작업) 때 설정 화면이 먼저 나옵니다' }, '설정 대기')
          : h('span', { class: 'badge muted' }, '없음 (선택)');
      const status = a.disabled ? h('span', { class: 'badge muted' }, '사용 중지')
        : a.mustChange ? h('span', { class: 'badge warn' }, '임시 비밀번호') : h('span', { class: 'badge ok' }, '사용 중');
      const btns = [act('편집', '', () => accountDialog(a, roles, () => afterChange(self)))];
      if (!self) {
        btns.push(act('임시 비밀번호…', '', async (b) => {
          if (!(await confirmDialog({ title: `${a.name} 비밀번호 재설정`, message: '새 임시 비밀번호를 만들고, 이 계정의 로그인을 모두 끊습니다. 본인이 다음 로그인 때 비밀번호를 바꾸게 됩니다.', okText: '재설정' }))) return;
          try { const x = await busy(b, () => api('POST', `/api/accounts/${encodeURIComponent(a.name)}/password`)); showSecretOnce('임시 비밀번호', `${a.name} 계정의 새 임시 비밀번호입니다.`, x.tempPassword, '이 창을 닫으면 다시 볼 수 없습니다.'); load(); } catch (ex) { toast(ex.message, 'err'); }
        }));
      }
      if (a.totp) {
        btns.push(act('2단계 초기화…', '', async (b) => {
          if (!(await confirmDialog({ title: `${a.name} 2단계 인증 초기화`, message: '휴대폰을 잃어버린 경우 등에 씁니다. 등록된 인증 앱과 복구 코드를 지우고 이 계정의 로그인을 끊습니다. 다음 로그인 때 새로 설정합니다.', okText: '초기화', danger: true }))) return;
          try { await busy(b, () => api('POST', `/api/accounts/${encodeURIComponent(a.name)}/reset-2fa`)); toast(`${a.name} 2단계 인증을 초기화했습니다`, 'warn'); if (self) { await refreshState(); renderPanel(); } else load(); } catch (ex) { toast(ex.message, 'err'); }
        }));
      }
      if (!self) {
        btns.push(act('삭제…', 'ghost', async (b) => {
          if (!(await confirmDialog({ title: `${a.name} 계정 삭제`, message: '계정을 지우고 로그인을 모두 끊습니다. 감사 로그의 기록은 남습니다. 지울까요?', okText: '삭제', danger: true }))) return;
          try { await busy(b, () => api('DELETE', `/api/accounts/${encodeURIComponent(a.name)}`)); toast(`${a.name} 계정을 지웠습니다`, 'warn'); load(); } catch (ex) { toast(ex.message, 'err'); }
        }));
      }
      return h('tr', { class: a.disabled ? 'disabled' : '' },
        h('td', { class: 'sel-cell' }, cb),
        h('td', null, h('b', { class: 'mono' }, a.name), self ? h('span', { class: 'badge accent', style: { marginLeft: '6px' } }, '나') : null, a.display ? h('div', { class: 'cell-sub' }, a.display) : null),
        h('td', null, roleName(a.role)),
        h('td', null, h('label', { class: 'switch mini' }, reqSw)),
        h('td', null, tfa),
        h('td', null, status),
        h('td', { class: 'small' }, a.lastLogin && !a.lastLogin.startsWith('0001') ? fmtTime(a.lastLogin) : '—', a.sessions ? h('div', { class: 'cell-sub' }, `세션 ${a.sessions}개`) : null),
        h('td', null, h('div', { class: 'row wrap acct-acts' }, btns)));
    });
    // roles × permissions
    const addRole = h('button', { type: 'button', class: 'btn' }, icon('plus'), '역할 추가');
    addRole.addEventListener('click', () => roleDialog(null, r.perms, load));
    const roleRows = roles.map((ro) => {
      const used = r.accounts.filter((a) => a.role === ro.id && !a.bootstrap).length;
      const acts = [];
      if (ro.id !== 'admin') acts.push(act('편집', '', () => roleDialog(ro, r.perms, () => afterChange(ro.id === (r.accounts.find((x) => x.name === r.me) || {}).role))));
      if (!ro.builtin) {
        acts.push(act('삭제', 'ghost', async (b) => {
          if (!(await confirmDialog({ title: `「${ro.name}」 역할 삭제`, message: '이 역할을 지울까요? (쓰고 있는 계정이 있으면 지울 수 없습니다)', okText: '삭제', danger: true }))) return;
          try { await busy(b, () => api('DELETE', `/api/roles/${encodeURIComponent(ro.id)}`)); load(); } catch (ex) { toast(ex.message, 'err'); }
        }));
      }
      return h('tr', null,
        h('td', null, h('b', null, ro.name), h('div', { class: 'cell-sub' }, ro.id === 'admin' ? '항상 모든 권한' : ro.builtin ? '기본 역할' : '사용자 역할')),
        ...r.perms.map((p) => h('td', { class: 'perm-cell', title: p.name }, ro.perms.includes(p.id) ? h('span', { class: 'perm-yes', 'aria-label': '있음' }, '✓') : h('span', { class: 'perm-no', 'aria-label': '없음' }, '·'))),
        h('td', { class: 'small' }, `${used}명`),
        h('td', null, h('div', { class: 'row nowrap' }, acts)));
    });
    const active = r.accounts.filter((a) => !a.bootstrap && !a.disabled);
    const pendingN = active.filter((a) => a.require2fa && !a.totp).length;
    fill(body,
      h('p', { class: 'hint' }, '2단계 인증은 기본으로 각자 「내 계정」에서 켜는 선택 사항입니다. 「2단계 요구」를 켠 계정은 설정을 마쳐야 쓸 수 있고, 본인이 끌 수 없습니다. 요구를 꺼도 이미 등록한 인증 앱은 그대로라 로그인 때 계속 묻습니다 — 없애려면 본인이 「내 계정」에서 끄거나 「2단계 초기화」를 씁니다. 여러 계정은 왼쪽에서 골라 한꺼번에 바꿉니다.'),
      pendingN ? callout('', h('b', null, `2단계 인증 설정 대기 ${pendingN}개`), h('span', { class: 'small' }, '요구를 받았지만 아직 설정하지 않은 계정입니다. 다음 로그인 때 설정 화면이 먼저 나옵니다.')) : null,
      h('div', { class: 'row' }, h('h3', { class: 'grow' }, `계정 ${r.accounts.filter((a) => !a.bootstrap).length}개`), add),
      bulkBar,
      h('div', { class: 'table-wrap glass-inner' }, h('table', { class: 'compact acct-table' },
        h('thead', null, h('tr', null, h('th', { scope: 'col', class: 'sel-cell' }, allCb), [['아이디'], ['역할'], ['2단계 요구', '관리자가 이 계정에 2단계 인증 설정을 강제합니다 (끄면 본인 선택)'], ['2단계 인증', '이 계정에 인증 앱이 등록되어 있는지 — 등록되어 있으면 요구와 상관없이 로그인 때 코드를 묻습니다'], ['상태'], ['마지막 로그인'], ['']].map(([t, tip]) => h('th', { scope: 'col', title: tip || null }, t, tip ? h('span', { class: 'th-tip', 'aria-hidden': 'true' }, ' ⓘ') : null)))),
        h('tbody', null, rows))),
      h('hr', { class: 'sep' }),
      h('div', { class: 'row' }, h('h3', { class: 'grow' }, '역할과 권한'), addRole),
      h('p', { class: 'hint' }, '모든 역할은 화면을 볼 수 있습니다. 체크한 권한이 있어야 그 작업을 할 수 있습니다. 「계정·접근 보안」이 있는 사용 중 계정은 항상 하나 이상 남깁니다.'),
      h('div', { class: 'table-wrap glass-inner' }, h('table', { class: 'compact role-table' },
        h('thead', null, h('tr', null, h('th', { scope: 'col' }, '역할'), ...r.perms.map((p) => h('th', { scope: 'col', class: 'perm-cell', title: p.desc }, p.name)), h('th', { scope: 'col' }, '계정'), h('th', { scope: 'col' }, ''))),
        h('tbody', null, roleRows))),
      h('details', { class: 'preset' }, h('summary', null, '권한 설명'),
        h('dl', { class: 'kv' }, r.perms.map((p) => [h('dt', null, p.name), h('dd', { class: 'small' }, p.desc)]))));
    updBulk();
    const withTotp = active.filter((a) => a.totp).length;
    getL && getL() && getL().set('accounts', 'ok', `계정 ${active.length}개 · 2단계 ${withTotp}/${active.length}`);
  }
  load();
  return { id: 'accounts', title: '계정 관리', desc: '길목에 로그인하는 사람과 역할(권한), 계정별 2단계 인증 요구를 관리합니다.', state: 'wait', body };
}
