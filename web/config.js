'use strict';
// 설정 백업·복원: 길목 설정값(설정·서비스·그룹·역할·대시보드)을 파일로 내보내고 되돌린다 (config.go).
// 계정·비밀값은 파일에 들어가지 않으므로 복원해도 로그인 정보는 그대로다.

function configBackupStep() {
  const canCfg = typeof can !== 'function' || can('config');
  const body = h('div', { class: 'stack' },
    callout('', h('b', null, '무엇이 담기나요'),
      h('ul', { class: 'tight' },
        h('li', null, '설정 · 서비스 · Authelia 그룹 · 역할 · 대시보드 · Cloudflare 규칙 식별자 · 관리 DNS 목록'),
        h('li', null, h('b', null, '담기지 않는 것: '), '계정과 비밀번호·2단계 비밀·복구 코드, 프록시 비밀, 세션 — 복원해도 로그인 정보는 그대로입니다.'))),
    exportBlock(canCfg),
    h('hr', { class: 'sep' }),
    importBlock(canCfg));
  return { id: 'config', title: '설정 백업·복원', desc: '길목 설정값 전체를 파일로 내보내고, 그 파일로 되돌립니다 (계정·비밀값 제외).', state: 'info', stateText: '', body };
}

// 초기화: 서비스·설정을 새로 설치한 상태로 (reset.go). 계정 포함 여부는 사용자가 고른다.
function resetStep() {
  const allowed = typeof can !== 'function' || (can('config') && can('system'));
  const canAcct = typeof can !== 'function' || can('accounts');
  const summary = h('div', { class: 'stack tight' }, spinnerRow('지금 상태를 읽는 중…'));
  const acct = switchCtl('로그인 계정도 초기화', false,
    '모든 계정·사용자 역할을 지우고 초기 계정(admin / admin)만 남깁니다. 지금 로그인한 사람 모두 로그아웃되고, 다시 로그인하면 새 관리자를 만드는 화면이 나옵니다.',
    { disabled: !allowed || !canAcct });
  const word = h('input', { type: 'text', placeholder: '초기화', autocomplete: 'off', disabled: !allowed, 'aria-label': '확인 문구' });
  const go = h('button', { type: 'button', class: 'btn danger solid', disabled: true }, '초기화');
  const err = h('div');
  const sync = () => { go.disabled = !allowed || word.value.trim() !== '초기화'; };
  word.addEventListener('input', sync);

  api('GET', '/api/reset/plan').then((p) => {
    const li = (t) => h('li', null, t);
    summary.replaceChildren(
      h('b', null, '지워지는 것'),
      h('ul', { class: 'tight' },
        li(`등록된 서비스 ${p.services}개${p.domain ? ` (도메인 ${p.domain})` : ''}`),
        li(`모든 설정값을 처음 설치한 값으로 — 도메인·컨테이너 이름·파일 경로(예: Caddy 컨테이너 ${p.caddy || '-'} → caddy)·구성요소·WAF·Cloudflare 규칙 설정·로그 보존·접근 보안·구성도 앞단 정보`),
        li(`Authelia 그룹 목록 ${p.groups}개 · 대시보드 배치 · 적용 대기 ${p.pending}건 · DDNS·업데이트 상태`),
        li(`로그 기록 전부 ${Number(p.logRows || 0).toLocaleString()}건 (요청·지표·감사·보안·시스템)과 대시보드 통계·인증서·서비스 상태`),
        li(`길목이 관리하던 DNS 목록 ${p.managedDns}개 · Cloudflare 규칙 연결 ${p.cfRules}개 (길목의 기억만 지움)`),
        p.cfTokenUi ? li('화면에서 넣은 Cloudflare API 토큰') : null,
        li(`계정 ${p.accounts}개 · 사용자 역할 ${p.roles}개 — 「로그인 계정도 초기화」를 켰을 때만`)),
      h('b', null, '그대로인 것'),
      h('ul', { class: 'tight' },
        li('길목 밖의 것 — 실제 Caddyfile · Authelia 설정·사용자 파일 · Cloudflare DNS 레코드와 규칙 · 컨테이너. 다음 「적용」 때만 바뀝니다'),
        p.cfTokenCtr ? li('컨테이너에 넣어 준 Cloudflare 토큰(GM_CF_TOKEN 등) — compose에서 빼야 합니다') : null,
        li('초기화 직전 데이터의 백업 1개 (백업 폴더)')));
  }).catch((ex) => summary.replaceChildren(callout('warn', ex.message)));

  go.addEventListener('click', async () => {
    const withAcct = acct.input.checked;
    const ok = await confirmDialog({
      title: '길목 초기화',
      message: `서비스와 설정값을 모두 지우고 처음 설치한 상태로 되돌립니다.${withAcct ? '\n로그인 계정도 모두 지워지고, 모두 로그아웃됩니다.' : '\n계정은 그대로 둡니다.'}\n\n지금 데이터는 백업 폴더에 남지만, 화면에서 되돌리는 기능은 없습니다.\n되돌릴 수 있게 먼저 「설정 파일 내보내기」를 받아 두세요.\n\n초기화할까요?`,
      okText: '초기화', danger: true,
    });
    if (!ok) return;
    err.replaceChildren();
    try {
      const res = await busy(go, () => api('POST', '/api/reset', { confirm: word.value.trim(), accounts: withAcct }));
      if (res.loggedOut) { location.hash = ''; location.reload(); return; }
      toast(`초기화했습니다 — 이전 데이터는 백업 ${String(res.plan.backup || '').split(/[\\/]/).pop()}`);
      word.value = '';
      await refreshState();
      S.setupOffered = false;
      maybeOfferSetup();
    } catch (ex) { err.replaceChildren(callout('danger', ex.message)); }
  });

  const body = h('div', { class: 'stack' },
    callout('danger', h('b', null, '되돌릴 수 없는 작업입니다'),
      h('span', null, '초기화한 뒤 서비스 없이 「적용」하면 Caddyfile에서 사이트가 모두 빠집니다. 다시 쓰려면 「설정 백업·복원」으로 파일을 받아 두거나, 초기화 후 「가져오기」로 지금 Caddyfile을 다시 읽으세요.')),
    summary,
    allowed ? null : callout('warn', '초기화에는 「구성 변경」과 「연결·시스템」 권한이 필요합니다.'),
    acct,
    !canAcct && allowed ? h('p', { class: 'hint' }, '계정까지 초기화하려면 「계정·접근 보안」 권한이 필요합니다.') : null,
    field('확인을 위해 「초기화」를 입력하세요', word),
    err,
    h('div', { class: 'row' }, go));
  return { id: 'reset', title: '초기화', desc: '서비스와 설정값을 모두 지우고 처음 설치한 상태로 되돌립니다. 로그인 계정 포함 여부를 고를 수 있습니다.', state: 'opt', stateText: '', body };
}

function exportBlock(canCfg) {
  const dl = h('a', { class: 'btn primary', href: '/api/config/export', download: '', title: '지금 설정을 JSON 파일로 받습니다' }, icon('download'), '설정 파일 내보내기');
  if (!canCfg) { dl.classList.add('disabled'); dl.removeAttribute('href'); }
  return h('div', { class: 'stack tight' },
    h('h3', null, '내보내기'),
    h('p', { class: 'hint' }, '받은 파일을 안전한 곳에 보관하세요. 다른 길목 설치로 옮기거나, 설정을 되돌릴 때 씁니다.'),
    h('div', { class: 'row' }, dl));
}

function importBlock(canCfg) {
  let file = null;
  let plan = null;
  const input = h('input', { type: 'file', accept: '.json,application/json', class: 'sr-only', id: uid('cfgfile') });
  const pick = h('button', { type: 'button', class: 'btn', disabled: !canCfg }, icon('upload'), '파일 고르기');
  const fname = h('span', { class: 'muted small' }, 'gilmok-config-*.json');
  const drop = h('div', { class: 'drop-zone' }, h('p', null, '여기에 설정 파일을 끌어다 놓거나'), h('div', { class: 'row' }, pick, fname));
  const result = h('div', { class: 'stack' });
  const apply = h('button', { type: 'button', class: 'btn primary', disabled: true }, '이 파일로 되돌리기');
  pick.addEventListener('click', () => input.click());

  const showPlan = (p, err) => {
    plan = p;
    const items = [];
    if (err) items.push(callout('danger', h('b', null, '이 파일을 복원할 수 없습니다'), h('span', null, err)));
    if (p) {
      const line = (label, arr) => (arr && arr.length ? h('li', null, h('b', null, `${label} ${arr.length}: `), arr.join(', ')) : null);
      items.push(h('div', { class: 'stack tight' },
        h('b', null, '되돌리면 이렇게 바뀝니다'),
        h('ul', { class: 'tight' },
          line('서비스 추가', p.servicesAdd), line('서비스 수정', p.servicesUpdate), line('서비스 삭제', p.servicesRemove),
          p.settingsKeys && p.settingsKeys.length ? h('li', null, h('b', null, `설정 ${p.settingsKeys.length}: `), p.settingsKeys.join(', ')) : null,
          h('li', null, `Authelia 그룹 ${p.groups}개 · 역할 ${p.roles}개 · 대시보드 ${p.dashboard ? '교체' : '그대로'}`)),
        (p.servicesRemove || []).length ? callout('warn', `삭제되는 서비스 ${p.servicesRemove.length}개가 있습니다.`) : null,
        callout('', '복원해도 「적용」 전까지는 Caddy·Authelia·DNS가 바뀌지 않습니다. 계정·로그인 정보는 건드리지 않습니다.')));
    }
    result.replaceChildren(...items.filter(Boolean));
    apply.disabled = !p || !!err;
  };

  const load = async (fl) => {
    if (!fl) return;
    if (fl.size > 1400 * 1024) { showPlan(null, '파일이 너무 큽니다 (최대 약 1.4 MB)'); return; }
    file = fl;
    fname.textContent = fl.name;
    result.replaceChildren(spinnerRow('읽는 중…'));
    apply.disabled = true;
    try {
      file.data = await fileToBase64(fl);
      showPlan(await api('POST', '/api/config/import', { name: fl.name, data: file.data, dry: true }));
    } catch (ex) { showPlan(null, ex.message); }
  };
  input.addEventListener('change', () => load(input.files[0]));
  drop.addEventListener('dragover', (e) => { e.preventDefault(); drop.classList.add('over'); });
  drop.addEventListener('dragleave', () => drop.classList.remove('over'));
  drop.addEventListener('drop', (e) => { e.preventDefault(); drop.classList.remove('over'); load(e.dataTransfer.files[0]); });

  apply.addEventListener('click', async () => {
    if (!file || !plan) return;
    const ok = await confirmDialog({
      title: '설정 되돌리기',
      message: `${file.name} 의 설정으로 되돌립니다.\n지금 설정(서비스·그룹·역할·대시보드)이 파일 내용으로 바뀌고 「적용 대기」가 됩니다.\n계정·로그인 정보는 그대로입니다.\n\n계속할까요?`,
      okText: '되돌리기', danger: true,
    });
    if (!ok) return;
    try {
      await busy(apply, () => api('POST', '/api/config/import', { name: file.name, data: file.data, dry: false }));
      toast('설정을 되돌렸습니다 — 「적용」으로 실제 반영하세요');
      await refreshState();
      renderPanel();
    } catch (ex) { showPlan(plan, ex.message); }
  });

  return h('div', { class: 'stack tight' },
    h('h3', null, '복원'),
    h('p', { class: 'hint' }, canCfg ? '「설정 내보내기」로 받은 파일을 올리면 먼저 미리보기가 나오고, 되돌려도 「적용」 전까지는 실제로 바뀌지 않습니다.' : '설정 복원에는 「구성 변경」 권한이 필요합니다.'),
    drop, input, result,
    canCfg ? h('div', { class: 'row' }, apply) : null);
}
