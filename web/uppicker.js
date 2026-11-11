'use strict';
// 서비스 편집 › 대상(upstream): Docker 컨테이너와 포트를 골라 바로 넣는다 (GET /api/docker/upstreams)

const UP_REACH = {
  network: ['Caddy와 같은 네트워크 — 바로 연결', '컨테이너 이름으로 연결합니다 (Docker 내부 DNS). 가장 권장하는 방식입니다.'],
  published: ['포트만 게시됨 — 호스트를 거쳐 연결', 'Caddy와 네트워크가 달라 호스트에 게시된 포트로 연결합니다. 가능하면 Caddy 네트워크에 붙이세요.'],
  none: ['Caddy에서 연결할 수 없음', 'Caddy와 같은 네트워크도 아니고 게시한 포트도 없습니다.'],
};

/** openUpstreamPicker({ current, onPick(upstream, container) }) */
function openUpstreamPicker({ current = '', onPick }) {
  const q = h('input', { type: 'search', placeholder: '컨테이너·서비스·이미지 검색', 'aria-label': '컨테이너 검색' });
  const showAll = switchCtl('중지된 컨테이너도 보기', false);
  const list = h('div', { class: 'up-list', 'aria-live': 'polite' }, h('p', { class: 'muted' }, '컨테이너 목록을 불러오는 중…'));
  const close = h('button', { type: 'button', class: 'btn ghost' }, '닫기');
  const d = openDialog({
    title: 'Docker 컨테이너에서 선택', size: 'wide',
    body: h('div', { class: 'stack' }, h('div', { class: 'toolbar' }, h('div', { class: 'search' }, icon('search'), q), showAll), list),
    footer: [h('span', { class: 'spacer' }), close],
  });
  close.addEventListener('click', () => d.close());
  let data = null;

  const pick = (upstream, c) => { d.close(); onPick(upstream, c); };

  const card = (c) => {
    const used = (c.usedBy || []).length ? h('span', { class: 'badge accent', title: `이미 이 컨테이너를 가리키는 서비스: ${c.usedBy.map(fqdn).join(', ')}` }, `사용 중: ${c.usedBy.join(', ')}`) : null;
    const ports = (c.ports || []).map((p) => {
      const label = p.upstream || `${p.port}${p.hostPort ? ` (게시 ${p.hostPort})` : ''}`;
      const b = h('button', { type: 'button', class: `btn sm ${p.upstream && p.upstream === current ? 'primary' : ''}`, disabled: !p.upstream, title: p.upstream ? `대상에 ${p.upstream} 입력` : 'Caddy에서 이 포트로 연결할 수 없습니다' }, label);
      b.addEventListener('click', () => pick(p.upstream, c));
      return b;
    });
    if (c.reach === 'network' && !ports.length) { // image without EXPOSE: let the user type the port
      const manual = h('button', { type: 'button', class: 'btn sm ghost', title: '포트를 직접 입력합니다' }, `${c.name}:포트 직접 입력`);
      manual.addEventListener('click', () => pick(`${c.name}:`, c));
      ports.push(manual);
    }
    const nets = c.reach === 'network' ? `네트워크 ${(c.shared || []).join(', ')}` : `네트워크 ${(c.networks || []).join(', ') || '없음'}`;
    return h('div', { class: `up-card ${c.state === 'running' ? '' : 'stopped'}` },
      h('div', { class: 'up-head' },
        h('span', { class: `dot ${c.state === 'running' ? 'ok' : 'off'}`, title: c.state, 'aria-label': c.state === 'running' ? '실행 중' : '중지됨' }),
        h('b', { class: 'mono up-name', title: c.name }, c.name),
        c.self ? h('span', { class: 'badge accent' }, '길목') : null,
        used),
      h('div', { class: 'small muted up-meta', title: c.image }, [c.service && c.service !== c.name ? `서비스 ${c.service}` : '', c.project ? `compose ${c.project}` : '', nets, c.image].filter(Boolean).join(' · ')),
      ports.length ? h('div', { class: 'up-ports' }, ports) : h('p', { class: 'small muted' }, '열린 포트가 없습니다'));
  };

  const draw = () => {
    if (!data) return;
    const term = q.value.trim().toLowerCase();
    const items = (data.containers || []).filter((c) => !c.isCaddy && (showAll.input.checked || c.state === 'running')
      && (!term || [c.name, c.service, c.project, c.image].some((x) => String(x || '').toLowerCase().includes(term))));
    const out = [];
    if (data.mode !== 'docker') out.push(callout('', 'Caddy가 Docker 밖(PC)에서 실행 중이라 호스트에 게시된 포트(localhost:포트)로 연결합니다.'));
    for (const reach of ['network', 'published', 'none']) {
      const g = items.filter((c) => c.reach === reach);
      if (!g.length) continue;
      const [title, desc] = UP_REACH[reach];
      const body = h('div', { class: 'up-group' }, g.map(card));
      if (reach === 'none') {
        const caddyNets = ((data.containers.find((c) => c.isCaddy) || {}).networks || []);
        out.push(h('details', { class: 'preset' }, h('summary', null, `${title} (${g.length})`),
          h('p', { class: 'hint' }, desc, caddyNets.length && data.mode === 'docker'
            ? h('span', null, ' 연결하려면 Caddy 네트워크에 붙이세요 — 예: ', h('code', null, `docker network connect ${caddyNets[0]} <컨테이너>`), ' (compose라면 networks에 추가)') : null),
          body));
      } else {
        out.push(h('section', { class: 'stack' }, h('h3', { class: 'up-title' }, `${title} (${g.length})`), h('p', { class: 'hint' }, desc), body));
      }
    }
    if (!out.length) out.push(h('p', { class: 'muted' }, term ? '검색 결과가 없습니다.' : '실행 중인 컨테이너가 없습니다.'));
    list.replaceChildren(...out);
  };
  q.addEventListener('input', draw);
  showAll.input.addEventListener('change', draw);
  api('GET', '/api/docker/upstreams').then((r) => { data = r; draw(); q.focus(); })
    .catch((ex) => list.replaceChildren(callout('danger', h('b', null, 'Docker 컨테이너 목록을 읽지 못했습니다'), h('span', null, ex.message),
      h('span', { class: 'small' }, '길목 컨테이너에 docker.sock이 연결되어 있어야 합니다. 대상은 직접 입력해도 됩니다.'))));
}
