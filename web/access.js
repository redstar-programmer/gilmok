// Gilmok web UI — access security (길목 tab › 접근 보안): path policy, SSO, TOTP, sessions.
'use strict';

function securityStep() {
  const st = S.state;
  const set = settings();
  const sec = st.security || {};
  const box = h('div', { class: 'stack' });

  // where am I coming from
  const via = sec.via === 'proxy' ? `Caddy 경유${sec.ssoUser ? ` · Authelia 사용자 ${sec.ssoUser}` : ''}` : sec.via === 'direct' ? '호스트 포트 직접 (127.0.0.1)' : '알 수 없음';
  const selfSvc = st.services.find((s) => s.id === set.secSelfService);

  const layers = h('ul', { class: 'checks' },
    secRow(true, '접근 경로 제한', use('caddy')
      ? `지금 접속: ${via}. 호스트 포트 직접 접속${set.secAllowDirect ? '' : '(꺼짐)'} 또는 Caddy가 붙인 비밀 헤더가 있는 요청만 받습니다 — 같은 Docker 네트워크의 다른 컨테이너는 차단`
      : `지금 접속: ${via}. 길목이 도는 서버의 호스트 포트로 직접 들어온 요청만 받습니다 — 같은 Docker 네트워크의 다른 컨테이너는 차단`),
    !use('caddy') ? null : secRow(!!selfSvc, '원격 접속 (다른 기기에서)', selfSvc
      ? `https://${fqdn(selfSvc.subdomain)} 으로 들어옵니다 (Caddy 경유). 이 사이트에만 Caddy가 비밀 헤더를 붙이고, 그 헤더가 있는 요청만 받습니다.`
      : '아직 없음 (선택) — 지금은 길목이 도는 서버 안에서만 열 수 있습니다. 휴대폰·다른 PC에서도 쓰려면 아래 「길목 사이트 만들기」로 길목용 주소를 하나 만드세요.'),
    !use('caddy') ? null : !use('authelia') ? secRow(false, 'Authelia 로그인 필수 (Caddy 경유 시)', 'Authelia를 쓰지 않는 구성 — 해당 없음. Caddy를 거친 사람은 길목 계정(아이디·비밀번호, +2단계 인증)으로 들어옵니다.') :
    secRow(set.secRequireSso, 'Authelia 로그인 필수 (Caddy 경유 시)', set.secRequireSso ? `Remote-User가 있어야 들어옵니다${set.secSsoGroups ? ` · 그룹 ${set.secSsoGroups}` : ''}${selfSvc && !(selfSvc.authelia && selfSvc.authelia.enabled) ? ' — ⚠ 길목 사이트에 Authelia가 꺼져 있어 원격 접속이 막힙니다' : ''}` : '꺼짐 — Caddy를 거친 사람은 길목 계정 로그인만으로 들어옵니다'),
    secRow(!!sec.totp, '2단계 인증 (TOTP)', `계정마다 선택 (내 계정: ${sec.totp ? '켜짐' : '꺼짐'}) — 각자 「내 계정」에서 켜고, 관리자는 「계정 관리」에서 계정별·일괄로 요구할 수 있습니다`),
    secRow(true, '계정·권한', '사람마다 계정(아이디·비밀번호·2단계 인증)과 역할이 따로 있고, 작업은 역할의 권한 안에서만 됩니다. 모든 변경은 누가 했는지 감사 로그에 남습니다'),
    secRow(true, '세션', `유휴 ${set.secIdleMin}분 · 최대 ${set.secAbsHours}시간 후 만료, HttpOnly + SameSite=Strict 쿠키`),
    secRow(true, '중요 작업 재인증', `적용·사용자·로그 삭제·보안 설정 변경 등은 ${set.secReauthMin}분 안에 비밀번호를 다시 확인한 경우에만`),
    secRow(true, '무차별 대입 방어', '5회 실패마다 잠금 (5분 → 10분 → … 최대 1시간), 실패는 보안 로그에 기록'));

  // sessions
  const sessBox = h('div', { class: 'section-box' }, h('h3', null, icon('user'), '로그인 세션'), spinnerRow('불러오는 중…'));
  const loadSess = async () => {
    try {
      const r = await api('GET', '/api/auth/sessions');
      const list = r.sessions || [];
      const others = list.filter((s) => !s.current).length;
      const mine = list.filter((s) => !s.current && s.user === (me().name || '')).length;
      const killAll = h('button', { type: 'button', class: 'btn sm danger', disabled: !mine }, `내 다른 세션 모두 종료 (${mine})`);
      killAll.addEventListener('click', () => busy(killAll, async () => { try { await api('DELETE', '/api/auth/sessions/others'); toast('다른 세션을 모두 끊었습니다'); loadSess(); } catch (ex) { toast(ex.message, 'err'); } }));
      sessBox.replaceChildren(h('h3', null, icon('user'), '로그인 세션'),
        h('div', { class: 'table-wrap glass-inner' }, h('table', { class: 'compact' },
          h('thead', null, h('tr', null, ['계정', '경로', 'Authelia', '브라우저', '로그인', '마지막 활동', '만료', ''].map((t) => h('th', { scope: 'col' }, t)))),
          h('tbody', null, list.map((s) => {
            const kill = s.current ? h('span', { class: 'badge accent' }, '이 브라우저') : h('button', { type: 'button', class: 'btn sm' }, '종료');
            if (!s.current) kill.addEventListener('click', () => busy(kill, async () => { try { await api('DELETE', `/api/auth/sessions/${s.id}`); loadSess(); } catch (ex) { toast(ex.message, 'err'); } }));
            return h('tr', null, h('td', null, h('b', { class: 'mono' }, s.user || '—')), h('td', null, s.via === 'proxy' ? 'Caddy 경유' : '직접'), h('td', null, s.ssoUser || '—'),
              h('td', { class: 'ellipsis', title: s.ua }, uaShort(s.ua)), h('td', null, fmtTime(s.created)), h('td', null, fmtTime(s.lastSeen)), h('td', null, fmtTime(s.expires)), h('td', null, kill));
          })))),
        h('div', { class: 'row' }, killAll));
    } catch (ex) { sessBox.replaceChildren(errorBox(ex.message)); }
  };
  loadSess();

  // policy form (step-up on save)
  const svcOpts = [['', '(없음 — 원격 접속 안 씀)'], ...st.services.filter((s) => !s.dnsOnly).map((s) => [s.id, `${fqdn(s.subdomain)} → ${s.upstream || ''}`])];
  const form = settingsForm([
    { key: 'secAllowDirect', type: 'switch', label: '호스트 포트 직접 접속 허용', hint: '길목이 도는 서버에서 바로 (예: http://127.0.0.1:8088) — SSO나 프록시가 고장 났을 때의 비상 통로' },
    { key: 'secAllowProxy', type: 'switch', label: '원격 접속 허용 (Caddy 경유)', hint: '아래 「길목 사이트」 주소로 들어오는 것만 허용' },
    { key: 'secSelfService', type: 'select', label: '길목 사이트 (원격 접속 주소)', options: svcOpts, hint: '다른 기기에서 길목에 들어올 주소. 길목 컨테이너(:8080)를 가리키는 서비스를 저장하면 자동으로 정해집니다. 바꾸면 적용해야 반영됩니다' },
    { key: 'secRequireSso', type: 'switch', label: 'Caddy 경유 시 Authelia 로그인 필수', hint: 'Authelia가 넘긴 Remote-User가 없으면 거부' },
    { key: 'secSsoGroups', label: '허용 Authelia 그룹 (쉼표)', placeholder: '비우면 모든 사용자 (예: admins)', mono: true },
    { key: 'secIdleMin', type: 'number', label: '유휴 만료 (분)', attrs: { min: '5', max: '1440' } },
    { key: 'secAbsHours', type: 'number', label: '최대 세션 길이 (시간)', attrs: { min: '1', max: '720' } },
    { key: 'secReauthMin', type: 'number', label: '재인증 유효 시간 (분)', attrs: { min: '1', max: '120' } },
  ].filter((f) => f && (use('authelia') || !['secRequireSso', 'secSsoGroups'].includes(f.key)) && (use('caddy') || !['secAllowProxy', 'secSelfService', 'secRequireSso', 'secSsoGroups'].includes(f.key))), {
    validate: (p) => (p.secAllowDirect === false && p.secAllowProxy === false ? '직접 접속과 Caddy 경유 접속을 모두 끌 수는 없습니다' : ''),
    onSaved: () => renderPanel(),
  });

  // remote access: explain + create Gilmok's own site with sensible defaults
  let remoteBox = null;
  if (use('caddy') && !selfSvc) {
    const self = (st.security && st.security.selfName) || 'gilmok';
    const priv = privOn() || use('tailscale');
    const mk = h('button', { type: 'button', class: 'btn primary' }, icon('plus'), '길목 사이트 만들기…');
    mk.addEventListener('click', () => openServiceDrawer(null, {
      subdomain: 'gilmok', upstream: `${self}:8080`,
      exposure: priv ? 'tailscale' : 'public', proxied: false, mtls: false,
      authelia: { enabled: use('authelia'), policy: 'two_factor', groups: [] },
      notes: '길목 관리 화면 (원격 접속용)',
    }));
    remoteBox = h('div', { class: 'section-box stack' },
      h('h3', null, icon('globe'), '다른 기기에서 길목 쓰기 (선택)'),
      h('p', { class: 'small' }, `지금 길목은 이 서버 안에서만 열립니다 (예: http://127.0.0.1:8088). 휴대폰이나 다른 PC에서도 쓰려면, 다른 서비스처럼 길목 자신을 서비스로 하나 등록해 Caddy를 거쳐 들어오게 합니다.`),
      h('ol', { class: 'flow' },
        h('li', null, '「길목 사이트 만들기」를 누르면 서비스 추가 창이 권장값으로 채워져 열립니다: ', h('b', null, `gilmok.${settings().domain || '도메인'}`), ' → ', h('code', null, `${self}:8080`),
          priv ? ' · 사설 전용(Tailscale)' : ' · 공개', use('authelia') ? ' · Authelia 2단계 로그인' : ''),
        h('li', null, '저장하고 「적용」하면 그 주소로 들어올 수 있습니다. 길목 로그인은 그대로 한 번 더 거칩니다.')),
      priv ? null : callout('warn', h('span', { class: 'small' }, '이 구성에는 사설 경로(Tailscale 등)가 없어 공개 주소가 됩니다. 관리 화면을 인터넷에 여는 것이므로 Authelia 로그인과 길목 2단계 인증을 꼭 켜세요.')),
      h('div', { class: 'row' }, mk));
  }
  append(box, [layers, remoteBox, sessBox, h('hr', { class: 'sep' }), h('h3', null, '접근 정책'), form]);
  const warn = false;
  return { id: 'security', title: '접근 보안', desc: '경로 제한 · SSO · 2단계 인증 정책 · 세션 · 재인증 · 잠금', state: warn ? 'warn' : 'ok', stateText: sec.totp ? '내 2단계 켜짐' : '내 2단계 꺼짐', body: box };
}

function secRow(on, title, detail, force) {
  const stt = force || (on ? 'ok' : 'skip');
  return h('li', { class: `chk ${stt}` }, h('span', { class: 'chk-mark', 'aria-hidden': 'true' }, stt === 'ok' ? '✓' : stt === 'warn' ? '!' : '–'),
    h('div', { class: 'chk-text' }, h('b', null, title), h('span', { class: 'chk-detail' }, detail)));
}

function uaShort(ua) {
  if (!ua) return '—';
  const b = /Edg\//.test(ua) ? 'Edge' : /Chrome\//.test(ua) ? 'Chrome' : /Firefox\//.test(ua) ? 'Firefox' : /Safari\//.test(ua) ? 'Safari' : ua.split(' ')[0];
  const os = /Windows/.test(ua) ? 'Windows' : /Android/.test(ua) ? 'Android' : /iPhone|iPad/.test(ua) ? 'iOS' : /Mac OS/.test(ua) ? 'macOS' : /Linux/.test(ua) ? 'Linux' : '';
  return `${b}${os ? ` · ${os}` : ''}`;
}
