// Gilmok web UI — network map (서비스 탭 › 네트워크). A free-form diagram of the whole network:
// what Gilmok knows (internet, Cloudflare, the front devices, this host, Caddy, the services, Gilmok /
// Authelia / CrowdSec, Tailscale — ids "auto:…", drawn from the current settings) plus devices the
// user adds (switches, access points, NAS, PCs, VMs …), links of a kind (wired · fiber · Wi-Fi · VPN ·
// virtual), zones (LAN · DMZ · VLAN · subnet …), positions saved by dragging, a layered automatic
// layout, status checks (ping · TCP · HTTP, run by Gilmok), a minimap, and SVG / PNG / JSON export.
// Display only — nothing here changes Caddy, DNS or Authelia.
'use strict';

// device kinds: [label, icon]
const NM_KINDS = {
  router: ['공유기·라우터', 'router'], firewall: ['방화벽', 'wall'], modem: ['모뎀·ONT', 'modem'], switch: ['스위치', 'switch'],
  ap: ['무선 AP', 'wifi'], server: ['서버', 'server'], nas: ['NAS', 'nas'], pc: ['PC', 'host'], laptop: ['노트북', 'laptop'],
  phone: ['휴대폰', 'phone'], tablet: ['태블릿', 'tablet'], tv: ['TV·셋톱', 'tv'], vm: ['가상 머신', 'vm'], container: ['컨테이너', 'box'],
  iot: ['IoT·스마트홈', 'iot'], camera: ['카메라', 'camera'], printer: ['프린터', 'printer'], ups: ['UPS·전원', 'bolt'],
  cloud: ['클라우드', 'cloud'], internet: ['인터넷', 'globe'], other: ['기타', 'app'],
};
// link kinds: [label, stroke dash, width, color token]
const NM_LINKS = {
  eth: ['유선 (이더넷)', '', 2, '--fg-2'], fiber: ['광 (SFP·광케이블)', '', 3.2, '--orange'], wifi: ['무선 (Wi-Fi)', '6 5', 2, '--ts'],
  vpn: ['VPN·터널', '2 5', 2.2, '--accent'], virtual: ['가상 (같은 호스트)', '3 4', 1.4, '--gray-cloud'],
};
// zone kinds: [label, color token]
const NM_ZONES = {
  lan: ['LAN', '--blue'], dmz: ['DMZ', '--warn'], vlan: ['VLAN', '--accent'], subnet: ['서브넷', '--ts'], wifi: ['무선망', '--ok'],
  cloud: ['클라우드', '--orange'], other: ['기타', '--gray-cloud'],
};
// icons the network map needs beyond the topology set (24×24 strokes, drawn for Gilmok)
Object.assign(TOPO_ICONS, {
  switch: ['M3 8h18v8H3z', 'M6.5 12h.01M9.5 12h.01M12.5 12h.01M15.5 12h.01', 'M18 12h.01'],
  wifi: ['M2.5 9a14 14 0 0 1 19 0', 'M5.5 12.5a9.5 9.5 0 0 1 13 0', 'M8.5 16a5 5 0 0 1 7 0', 'M12 19.5h.01'],
  modem: ['M4 12h16v7H4z', 'M8 15.5h.01M11 15.5h.01', 'M7 12l-2-6M17 12l2-6'],
  nas: ['M5 3h14v18H5z', 'M5 9h14M5 15h14', 'M8 6h.01M8 12h.01M8 18h.01'],
  laptop: ['M5 5h14v10H5z', 'M2 19h20l-2-4H4z'],
  phone: ['M7 2.5h10v19H7z', 'M11 18.5h2'],
  tablet: ['M4 3h16v18H4z', 'M11 18h2'],
  tv: ['M3 5h18v12H3z', 'M8 21h8', 'M12 17v4'],
  vm: ['M4 4h16v12H4z', 'M8 20h8', 'M8 8h8v4H8z'],
  iot: ['M12 3a6 6 0 0 1 4 10.5V17H8v-3.5A6 6 0 0 1 12 3z', 'M9.5 20h5'],
  camera: ['M3 7h12v10H3z', 'M15 10l6-3v10l-6-3'],
  printer: ['M7 3h10v5H7z', 'M4 8h16v8H4z', 'M7 13h10v8H7z'],
});

const nmId = (p) => `${p}_${Math.random().toString(36).slice(2, 10)}`;
const NW_ = 176, NH_ = 52, XGAP = 250, YGAP = 74;

// ======================================================================= model

/** the nodes and links Gilmok knows from its own settings (ids "auto:…") */
function nmAutoGraph(info) {
  const st = S.state;
  const set = settings();
  const N = [], L = [];
  const add = (id, kind, name, sub, extra = {}) => N.push({ id, kind, name, sub, auto: true, ...extra });
  const link = (from, to, kind, label) => L.push({ id: `auto:${from}>${to}`, from, to, kind, label, auto: true });
  const svcs = st.services;
  const pub = svcs.filter((s) => s.exposure === 'public' && !s.dnsOnly);
  const proxied = use('cloudflare') && pub.some((s) => s.proxied);
  const direct = pub.some((s) => !(use('cloudflare') && s.proxied));
  const hops = topoHops(set);
  add('auto:internet', 'internet', '인터넷', info && info.publicIp ? info.publicIp : '외부 접속자');
  if (proxied) add('auto:cf', 'cloud', 'Cloudflare', 'WAF · 프록시');
  hops.forEach((hp, i) => add(`auto:hop:${i}`, hp.kind === 'router' ? 'router' : hp.kind === 'firewall' ? 'firewall' : hp.kind === 'tunnel' ? 'cloud' : 'server',
    hopName(hp), hp.extPort && hp.fwdPort ? `:${hp.extPort} → :${hp.fwdPort}` : (HOP_KINDS[hp.kind] || {}).label || '', { hop: i }));
  add('auto:host', 'server', (set.topoHostName || '').trim() || '이 서버', info && info.dockerOs ? info.dockerOs : 'Docker 호스트');
  if (use('caddy')) add('auto:caddy', 'container', 'Caddy', set.caddyContainer || 'caddy', { ctr: 'caddy' });
  add('auto:gilmok', 'container', '길목', '관리 화면');
  if (use('authelia')) add('auto:authelia', 'container', 'Authelia', set.autheliaContainer || 'authelia', { ctr: 'authelia' });
  if (use('crowdsec')) add('auto:crowdsec', 'container', 'CrowdSec', set.crowdsecContainer || 'crowdsec', { ctr: 'crowdsec' });
  const tsOn = privOn() && svcs.some((s) => s.exposure !== 'public');
  if (tsOn) add('auto:tailnet', 'cloud', use('tailscale') ? 'Tailscale' : 'VPN', use('tailscale') ? (set.tailscaleIp || 'tailnet') : '사설 접속');
  for (const s of svcs) {
    if (s.dnsOnly) continue;
    add(`auto:svc:${s.id}`, 'container', s.subdomain === '@' ? (set.domain || '@') : s.subdomain, s.upstream || '', { svc: s });
  }
  // the path in: internet → (Cloudflare) → devices → this host
  const first = hops.length ? 'auto:hop:0' : 'auto:host';
  if (proxied) { link('auto:internet', 'auto:cf', 'eth'); link('auto:cf', first, 'eth', 'Proxied'); }
  if (direct || !proxied) link('auto:internet', first, 'eth', proxied ? 'DNS only' : '');
  hops.forEach((_, i) => { if (i) link(`auto:hop:${i - 1}`, `auto:hop:${i}`, 'eth'); });
  if (hops.length) link(`auto:hop:${hops.length - 1}`, 'auto:host', 'eth');
  if (tsOn) link('auto:tailnet', 'auto:host', 'vpn', use('tailscale') ? 'WireGuard' : 'VPN');
  for (const id of ['auto:caddy', 'auto:gilmok', 'auto:authelia', 'auto:crowdsec']) if (N.some((n) => n.id === id)) link('auto:host', id, 'virtual');
  for (const s of svcs) if (!s.dnsOnly) link(use('caddy') ? 'auto:caddy' : 'auto:host', `auto:svc:${s.id}`, 'virtual');
  return { N, L };
}

/** the whole graph: auto + user devices, minus what the user hid */
function nmGraph(M, info) {
  const auto = nmAutoGraph(info);
  const hidden = new Set(M.hidden || []);
  const nodes = [...auto.N.filter((n) => !hidden.has(n.id)), ...M.nodes.map((n) => ({ ...n, auto: false, sub: n.ip || (NM_KINDS[n.kind] || NM_KINDS.other)[0] }))];
  const ids = new Set(nodes.map((n) => n.id));
  const links = [...auto.L, ...M.links].filter((l) => ids.has(l.from) && ids.has(l.to));
  return { nodes, links, hiddenAuto: auto.N.filter((n) => hidden.has(n.id)) };
}

// ======================================================================= layout
// layered (left → right): ranks by the longest path from the sources (cycles broken by DFS order),
// order inside a rank by the barycenter of the neighbours (a few sweeps), zone members kept together,
// nodes without links on a row below.

function nmLayout(nodes, links, member) {
  const idx = new Map(nodes.map((n, i) => [n.id, i]));
  const out = nodes.map(() => []), inn = nodes.map(() => []);
  const linked = new Set();
  for (const l of links) {
    const a = idx.get(l.from), b = idx.get(l.to);
    if (a == null || b == null || a === b) continue;
    out[a].push(b);
    inn[b].push(a);
    linked.add(a).add(b);
  }
  // break cycles
  const state = nodes.map(() => 0), dag = nodes.map(() => []);
  const visit = (u) => {
    state[u] = 1;
    for (const v of out[u]) {
      if (state[v] === 1) continue; // back edge
      dag[u].push(v);
      if (!state[v]) visit(v);
    }
    state[u] = 2;
  };
  const roots = nodes.map((_, i) => i).filter((i) => linked.has(i) && !inn[i].length);
  for (const r of roots) if (!state[r]) visit(r);
  for (const i of linked) if (!state[i]) visit(i);
  // longest-path ranks
  const rank = nodes.map(() => 0), indeg = nodes.map(() => 0);
  dag.forEach((vs) => vs.forEach((v) => indeg[v]++));
  const q = [...linked].filter((i) => !indeg[i]);
  while (q.length) {
    const u = q.shift();
    for (const v of dag[u]) {
      rank[v] = Math.max(rank[v], rank[u] + 1);
      if (!--indeg[v]) q.push(v);
    }
  }
  const layers = [];
  for (const i of linked) (layers[rank[i]] ||= []).push(i);
  const pos = new Map();
  layers.forEach((ly) => ly.forEach((i, k) => pos.set(i, k)));
  const zoneOf = (i) => (member || {})[nodes[i].id] || '';
  const sortLayer = (ly, key) => {
    const kv = new Map(ly.map((i) => [i, key(i)]));
    const zAvg = new Map();
    for (const i of ly) {
      const z = zoneOf(i);
      if (!z) continue;
      const a = zAvg.get(z) || [0, 0];
      zAvg.set(z, [a[0] + kv.get(i), a[1] + 1]);
    }
    const k1 = (i) => { const z = zoneOf(i); return z ? zAvg.get(z)[0] / zAvg.get(z)[1] : kv.get(i); };
    ly.sort((a, b) => k1(a) - k1(b) || (zoneOf(a) < zoneOf(b) ? -1 : zoneOf(a) > zoneOf(b) ? 1 : 0) || kv.get(a) - kv.get(b) || a - b);
    ly.forEach((i, k) => pos.set(i, k));
  };
  const bary = (i, nb) => { const ps = nb[i].filter((j) => pos.has(j)).map((j) => pos.get(j)); return ps.length ? ps.reduce((a, b) => a + b, 0) / ps.length : pos.get(i); };
  for (let it = 0; it < 6; it++) {
    for (let r = 1; r < layers.length; r++) if (layers[r]) sortLayer(layers[r], (i) => bary(i, inn));
    for (let r = layers.length - 2; r >= 0; r--) if (layers[r]) sortLayer(layers[r], (i) => bary(i, out));
  }
  const xy = new Map();
  let maxY = 0;
  layers.forEach((ly, r) => {
    if (!ly) return;
    ly.forEach((i, k) => {
      const y = (k - (ly.length - 1) / 2) * YGAP;
      xy.set(nodes[i].id, [r * XGAP, y]);
    });
  });
  const ys = [...xy.values()].map((p) => p[1]);
  const minY = ys.length ? Math.min(...ys) : 0;
  for (const [k, p] of xy) { p[1] -= minY; maxY = Math.max(maxY, p[1]); }
  // devices without links: a row below
  let col = 0;
  nodes.forEach((n, i) => {
    if (linked.has(i)) return;
    xy.set(n.id, [col * (NW_ + 30), maxY + YGAP * 1.6]);
    col++;
  });
  return xy;
}

// ======================================================================= view

function netMapPanel(onOpenService) {
  const box = h('div', { class: 'glass nmap-wrap' }, spinnerRow('네트워크 맵을 읽는 중…'));
  (async () => {
    let r;
    try {
      [r] = await Promise.all([api('GET', '/api/netmap'), S.topoInfo ? null : api('GET', '/api/topology').then((x) => { S.topoInfo = x; }).catch(() => { /* no docker */ })]);
    } catch (ex) { box.replaceChildren(errorBox(ex.message)); return; }
    netMapView(box, r, onOpenService);
  })();
  return box;
}

function netMapView(box, init, onOpenService) {
  const ed = typeof can !== 'function' || can('config');
  const M = { nodes: [], links: [], zones: [], member: {}, pos: {}, hidden: [], ...init.map };
  M.member ||= {};
  M.pos ||= {};
  M.hidden ||= [];
  let status = init.status || {};
  const pingOK = !!init.ping;
  const V = { x: 0, y: 0, k: 1, fitted: false }; // viewport: world = (screen - (x, y)) / k
  let sel = new Set(), selLink = null, selZone = null, connectFrom = null;
  let G = null, XY = null;

  const svg = sv('svg', { class: 'nmap-svg', role: 'application', 'aria-label': '네트워크 맵 — 끌어서 이동, 휠로 확대' });
  const world = sv('g', { class: 'nm-world' });
  svg.append(world);
  const mini = sv('svg', { class: 'nm-mini', 'aria-hidden': 'true' });
  const hint = h('div', { class: 'nm-hint', hidden: true });
  const side = h('aside', { class: 'nm-side', hidden: true, 'aria-label': '선택한 항목' });
  const stage = h('div', { class: 'nm-stage' }, svg, mini, hint, side);

  // ---- save (debounced for drags)
  let saveT = 0;
  const persist = (now) => {
    if (!ed) return Promise.resolve();
    clearTimeout(saveT);
    const go = () => api('PUT', '/api/netmap', M).then((r) => { Object.assign(M, r.map, { member: r.map.member || {}, pos: r.map.pos || {}, hidden: r.map.hidden || [] }); }).catch((ex) => toast(ex.message, 'err'));
    if (now) return go();
    saveT = setTimeout(go, 500);
    return Promise.resolve();
  };

  // ---- status of a node: ok / down / wait / null
  const ctrStates = (S.topoInfo && S.topoInfo.ctrStates) || {};
  function nodeStatus(n) {
    if (n.svc) { const hx = healthOf(n.svc); return hx ? { st: hx.st === 'ok' ? 'ok' : hx.st === 'down' ? 'down' : 'wait', title: hx.title } : null; }
    if (n.ctr && n.ctr in ctrStates) return ctrStates[n.ctr] === 'running' ? { st: 'ok', title: '컨테이너 실행 중' } : { st: 'down', title: `컨테이너: ${ctrStates[n.ctr] || '없음'}` };
    if (!n.auto && n.check) {
      const x = status[n.id];
      if (!x) return { st: 'wait', title: '확인 중 (30초마다)' };
      return x.ok ? { st: 'ok', title: `${n.check.toUpperCase()} ${n.target} — ${x.ms < 1 ? '<1' : Math.round(x.ms)}ms` } : { st: 'down', title: `${n.check.toUpperCase()} ${n.target} — ${x.err || '응답 없음'}` };
    }
    return null;
  }
  const stColor = (st) => (st === 'ok' ? TC.ok : st === 'down' ? TC.danger : TC.muted);

  // ---- hidden auto nodes (a button in the toolbar lists them)
  const hiddenBtn = h('button', { type: 'button', class: 'btn sm ghost' });
  const paintHidden = () => { hiddenBtn.textContent = T(`숨긴 칸 ${M.hidden.length}`); hiddenBtn.hidden = !M.hidden.length; };

  // ---- geometry
  const layout = () => {
    G = nmGraph(M, S.topoInfo);
    const auto = nmLayout(G.nodes, G.links, M.member);
    XY = new Map();
    for (const n of G.nodes) XY.set(n.id, M.pos[n.id] ? [...M.pos[n.id]] : auto.get(n.id) || [0, 0]);
    paintHidden();
  };
  const bbox = () => {
    let x0 = Infinity, y0 = Infinity, x1 = -Infinity, y1 = -Infinity;
    for (const [x, y] of XY.values()) { x0 = Math.min(x0, x); y0 = Math.min(y0, y); x1 = Math.max(x1, x + NW_); y1 = Math.max(y1, y + NH_); }
    for (const z of zoneBoxes()) { x0 = Math.min(x0, z.x); y0 = Math.min(y0, z.y); x1 = Math.max(x1, z.x + z.w); y1 = Math.max(y1, z.y + z.h); }
    return Number.isFinite(x0) ? { x: x0, y: y0, w: x1 - x0, h: y1 - y0 } : { x: 0, y: 0, w: 400, h: 300 };
  };
  function zoneBoxes() {
    const out = [];
    for (const z of M.zones) {
      const ps = G.nodes.filter((n) => M.member[n.id] === z.id).map((n) => XY.get(n.id)).filter(Boolean);
      if (!ps.length) continue;
      const x = Math.min(...ps.map((p) => p[0])) - 18, y = Math.min(...ps.map((p) => p[1])) - 38;
      out.push({ z, x, y, w: Math.max(...ps.map((p) => p[0])) + NW_ + 18 - x, h: Math.max(...ps.map((p) => p[1])) + NH_ + 18 - y });
    }
    return out;
  }
  const zoneColor = (z) => z.color || cssVar((NM_ZONES[z.kind] || NM_ZONES.other)[1]);

  // ---- drawing
  function edgePath(a, b) {
    const ax = a[0], ay = a[1], bx = b[0], by = b[1];
    if (bx >= ax + NW_ + 20) { // left → right
      const x1 = ax + NW_, y1 = ay + NH_ / 2, x2 = bx, y2 = by + NH_ / 2, dx = Math.max(40, (x2 - x1) / 2);
      return [`M${x1} ${y1} C${x1 + dx} ${y1} ${x2 - dx} ${y2} ${x2} ${y2}`, (x1 + x2) / 2, (y1 + y2) / 2];
    }
    if (ax >= bx + NW_ + 20) { // right → left
      const x1 = ax, y1 = ay + NH_ / 2, x2 = bx + NW_, y2 = by + NH_ / 2, dx = Math.max(40, (x1 - x2) / 2);
      return [`M${x1} ${y1} C${x1 - dx} ${y1} ${x2 + dx} ${y2} ${x2} ${y2}`, (x1 + x2) / 2, (y1 + y2) / 2];
    }
    const down = by > ay; // stacked: bottom → top
    const x1 = ax + NW_ / 2, y1 = down ? ay + NH_ : ay, x2 = bx + NW_ / 2, y2 = down ? by : by + NH_, dy = Math.max(24, Math.abs(y2 - y1) / 2) * (down ? 1 : -1);
    return [`M${x1} ${y1} C${x1} ${y1 + dy} ${x2} ${y2 - dy} ${x2} ${y2}`, (x1 + x2) / 2, (y1 + y2) / 2];
  }

  function draw() {
    world.replaceChildren();
    world.setAttribute('transform', `translate(${V.x} ${V.y}) scale(${V.k})`);
    const gZ = sv('g'), gE = sv('g'), gN = sv('g'), gL = sv('g');
    world.append(gZ, gE, gN, gL);
    // zones
    for (const zb of zoneBoxes()) {
      const c = zoneColor(zb.z);
      const on = selZone === zb.z.id;
      const g = sv('g', { class: `nm-zone ${on ? 'sel' : ''}`, 'data-zone': zb.z.id },
        sv('title', null, `${zb.z.name}${zb.z.cidr ? ` · ${zb.z.cidr}` : ''}${zb.z.note ? `\n${zb.z.note}` : ''}`),
        sv('rect', { x: zb.x, y: zb.y, width: zb.w, height: zb.h, rx: 18, fill: c, 'fill-opacity': 0.06, stroke: c, 'stroke-opacity': on ? 0.9 : 0.45, 'stroke-width': on ? 2 : 1.3, 'stroke-dasharray': '6 5' }),
        sv('rect', { class: 'nm-zone-head', x: zb.x + 10, y: zb.y + 8, width: textW(zb.z.name, 12) + (zb.z.cidr ? textW(zb.z.cidr, 11) + 14 : 0) + 22, height: 22, rx: 11, fill: c, 'fill-opacity': 0.18, stroke: c, 'stroke-opacity': 0.6 }),
        sv('text', { x: zb.x + 21, y: zb.y + 23, fill: c, 'font-size': 12, 'font-weight': 700 }, zb.z.name),
        zb.z.cidr ? sv('text', { x: zb.x + 21 + textW(zb.z.name, 12) + 10, y: zb.y + 23, fill: cssVar('--muted'), 'font-size': 11, 'font-family': 'ui-monospace, monospace' }, zb.z.cidr) : null);
      gZ.append(g);
    }
    // links
    for (const l of G.links) {
      const a = XY.get(l.from), b = XY.get(l.to);
      if (!a || !b) continue;
      const [d, mx, my] = edgePath(a, b);
      const K = NM_LINKS[l.kind] || NM_LINKS.eth;
      const c = cssVar(K[3]);
      const on = selLink === l.id;
      const g = sv('g', { class: `nm-link ${l.auto ? 'auto' : 'user'} ${on ? 'sel' : ''}`, 'data-link': l.id },
        sv('title', null, `${K[0]}${l.label ? ` · ${l.label}` : ''}${l.auto ? ' (길목이 아는 연결)' : ''}`),
        sv('path', { d, class: 'nm-hit', fill: 'none', stroke: 'transparent', 'stroke-width': 12 }),
        sv('path', { d, fill: 'none', stroke: c, 'stroke-width': on ? K[2] + 1.5 : K[2], 'stroke-dasharray': K[1] || null, 'stroke-opacity': l.auto ? 0.65 : 0.9, 'stroke-linecap': 'round' }));
      gE.append(g);
      if (l.label) {
        const w = textW(l.label, 10.5) + 12;
        gL.append(sv('g', { transform: `translate(${mx - w / 2} ${my - 9})`, class: 'nm-elabel' },
          sv('rect', { width: w, height: 18, rx: 9, fill: TC.pill, stroke: c, 'stroke-opacity': 0.5 }),
          sv('text', { x: w / 2, y: 12.5, 'text-anchor': 'middle', fill: c, 'font-size': 10.5 }, l.label)));
      }
    }
    // nodes
    for (const n of G.nodes) {
      const [x, y] = XY.get(n.id);
      const K = NM_KINDS[n.kind] || NM_KINDS.other;
      const zs = M.member[n.id] && M.zones.find((z) => z.id === M.member[n.id]);
      const color = zs ? zoneColor(zs) : n.auto ? TC.accent : TC.blue;
      const stx = nodeStatus(n);
      const on = sel.has(n.id) || connectFrom === n.id;
      const g = sv('g', { class: `nm-node ${n.auto ? 'auto' : 'user'} ${on ? 'sel' : ''} ${stx && stx.st === 'down' ? 'down' : ''}`, transform: `translate(${x} ${y})`, 'data-node': n.id, tabindex: 0, role: 'button',
        'aria-label': `${n.name} (${T(K[0])})${stx ? ` — ${stx.st === 'ok' ? '정상' : stx.st === 'down' ? '응답 없음' : '확인 중'}` : ''}` },
      sv('title', null, `${n.name} — ${K[0]}${n.sub ? `\n${n.sub}` : ''}${n.note ? `\n${n.note}` : ''}${stx ? `\n${stx.title}` : ''}${n.auto ? '\n(길목 설정에서 자동으로 그림)' : ''}`),
      sv('rect', { class: 'nm-bg', width: NW_, height: NH_, rx: 13, fill: cssVar('--surf'), stroke: stx && stx.st === 'down' ? TC.danger : color, 'stroke-width': on ? 2.4 : 1.3, 'stroke-opacity': on ? 1 : 0.6, 'stroke-dasharray': n.auto ? null : null }),
      sv('circle', { cx: 26, cy: NH_ / 2, r: 16, fill: color, 'fill-opacity': 0.16, stroke: color, 'stroke-opacity': 0.55 }),
      topoIcon(K[1], 26, NH_ / 2, 18, color),
      sv('text', { x: 50, y: n.sub ? 22 : 31, fill: cssVar('--fg'), 'font-size': 13, 'font-weight': 700 }, clip(n.name, 15)),
      n.sub ? sv('text', { x: 50, y: 38, fill: cssVar('--muted'), 'font-size': 10.5, 'font-family': 'ui-monospace, monospace' }, clip(n.sub, 20)) : null,
      stx ? sv('circle', { cx: NW_ - 12, cy: 12, r: 5, fill: stColor(stx.st), stroke: cssVar('--surf'), 'stroke-width': 2 }) : null,
      n.auto ? sv('text', { x: NW_ - 10, y: NH_ - 8, 'text-anchor': 'end', fill: cssVar('--muted'), 'font-size': 9 }, '자동') : null);
      gN.append(g);
    }
    drawMini();
  }

  // ---- minimap
  function drawMini() {
    const b = bbox();
    const W = 180, H = 120;
    const k = Math.min(W / (b.w + 80), H / (b.h + 80));
    const ox = (W - b.w * k) / 2 - b.x * k, oy = (H - b.h * k) / 2 - b.y * k;
    mini.setAttribute('viewBox', `0 0 ${W} ${H}`);
    mini.replaceChildren(sv('rect', { width: W, height: H, rx: 8, fill: cssVar('--surf'), 'fill-opacity': 0.92, stroke: cssVar('--line-2') }));
    for (const zb of zoneBoxes()) mini.append(sv('rect', { x: ox + zb.x * k, y: oy + zb.y * k, width: zb.w * k, height: zb.h * k, rx: 3, fill: zoneColor(zb.z), 'fill-opacity': 0.12 }));
    for (const n of G.nodes) {
      const [x, y] = XY.get(n.id);
      const s = nodeStatus(n);
      mini.append(sv('rect', { x: ox + x * k, y: oy + y * k, width: Math.max(2, NW_ * k), height: Math.max(2, NH_ * k), rx: 1.5, fill: s && s.st === 'down' ? TC.danger : n.auto ? TC.accent : TC.blue, 'fill-opacity': 0.75 }));
    }
    const r = svg.getBoundingClientRect();
    const vx = (-V.x / V.k), vy = (-V.y / V.k), vw = r.width / V.k, vh = r.height / V.k;
    mini.append(sv('rect', { x: ox + vx * k, y: oy + vy * k, width: vw * k, height: vh * k, fill: 'none', stroke: TC.accent, 'stroke-width': 1.5, rx: 2 }));
    mini.dataset.k = k; mini.dataset.ox = ox; mini.dataset.oy = oy;
  }
  mini.addEventListener('pointerdown', (e) => {
    const move = (ev) => {
      const rr = mini.getBoundingClientRect();
      const k = +mini.dataset.k, sx = (ev.clientX - rr.left) * (180 / rr.width), sy = (ev.clientY - rr.top) * (120 / rr.height);
      const wx = (sx - +mini.dataset.ox) / k, wy = (sy - +mini.dataset.oy) / k;
      const r = svg.getBoundingClientRect();
      V.x = r.width / 2 - wx * V.k;
      V.y = r.height / 2 - wy * V.k;
      draw();
    };
    move(e);
    const up = () => { window.removeEventListener('pointermove', move); window.removeEventListener('pointerup', up); };
    window.addEventListener('pointermove', move);
    window.addEventListener('pointerup', up);
    e.preventDefault();
  });

  // ---- viewport
  function fit() {
    const b = bbox();
    const r = svg.getBoundingClientRect();
    if (!r.width) return;
    const room = r.width > 700 ? 200 : 0; // the minimap at the bottom right
    V.k = Math.max(0.25, Math.min(1.4, Math.min((r.width - 60 - room) / b.w, (r.height - 60) / b.h)));
    V.x = (r.width - room - b.w * V.k) / 2 - b.x * V.k;
    V.y = (r.height - b.h * V.k) / 2 - b.y * V.k;
    V.fitted = true;
    draw();
  }
  function zoomAt(f, cx, cy) {
    const k = Math.max(0.2, Math.min(3, V.k * f));
    V.x = cx - (cx - V.x) * (k / V.k);
    V.y = cy - (cy - V.y) * (k / V.k);
    V.k = k;
    draw();
  }
  svg.addEventListener('wheel', (e) => {
    e.preventDefault();
    const r = svg.getBoundingClientRect();
    zoomAt(e.deltaY < 0 ? 1.12 : 1 / 1.12, e.clientX - r.left, e.clientY - r.top);
  }, { passive: false });
  const toWorld = (e) => { const r = svg.getBoundingClientRect(); return [(e.clientX - r.left - V.x) / V.k, (e.clientY - r.top - V.y) / V.k]; };

  // ---- pointer: pan the background, drag a node / a zone (its members), click to select
  svg.addEventListener('pointerdown', (e) => {
    if (e.button !== 0) return;
    const nodeEl = e.target.closest('[data-node]');
    const zoneEl = !nodeEl && e.target.closest('.nm-zone-head, .nm-zone text') ? e.target.closest('[data-zone]') : null;
    const linkEl = !nodeEl && e.target.closest('[data-link]');
    const sx = e.clientX, sy = e.clientY;
    let moved = false;
    const id = nodeEl && nodeEl.dataset.node;
    const zid = zoneEl && zoneEl.dataset.zone;
    const members = zid ? G.nodes.filter((n) => M.member[n.id] === zid).map((n) => n.id) : [];
    const dragIds = id ? (sel.has(id) && sel.size > 1 ? [...sel] : [id]) : members;
    const start = new Map(dragIds.map((k) => [k, [...XY.get(k)]]));
    const v0 = { x: V.x, y: V.y };
    try { svg.setPointerCapture(e.pointerId); } catch { /* not a live pointer */ }
    const move = (ev) => {
      const dx = ev.clientX - sx, dy = ev.clientY - sy;
      if (!moved && Math.hypot(dx, dy) < 4) return;
      moved = true;
      if (dragIds.length && ed && !connectFrom) {
        for (const [k, p] of start) XY.set(k, [Math.round((p[0] + dx / V.k) / 10) * 10, Math.round((p[1] + dy / V.k) / 10) * 10]);
        svg.classList.add('dragging');
      } else if (!dragIds.length || !ed) {
        V.x = v0.x + dx; V.y = v0.y + dy;
        svg.classList.add('panning');
      }
      draw();
    };
    const up = (ev) => {
      svg.removeEventListener('pointermove', move);
      svg.removeEventListener('pointerup', up);
      svg.classList.remove('dragging', 'panning');
      if (moved) {
        if (dragIds.length && ed && !connectFrom) {
          for (const k of dragIds) M.pos[k] = XY.get(k);
          persist(false);
        }
        return;
      }
      // a click
      if (id) clickNode(id, ev.shiftKey);
      else if (zid) { selZone = zid; sel = new Set(); selLink = null; draw(); openSide(); }
      else if (linkEl) { selLink = linkEl.dataset.link; sel = new Set(); selZone = null; draw(); openSide(); }
      else { sel = new Set(); selLink = null; selZone = null; connectFrom = null; showHint(''); draw(); openSide(); }
    };
    svg.addEventListener('pointermove', move);
    svg.addEventListener('pointerup', up);
  });
  svg.addEventListener('keydown', (e) => {
    const nodeEl = e.target.closest && e.target.closest('[data-node]');
    if (e.key === 'Escape') { connectFrom = null; sel = new Set(); selLink = null; selZone = null; showHint(''); draw(); openSide(); return; }
    if (!nodeEl) return;
    const id = nodeEl.dataset.node;
    if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); clickNode(id, e.shiftKey); return; }
    const d = { ArrowLeft: [-10, 0], ArrowRight: [10, 0], ArrowUp: [0, -10], ArrowDown: [0, 10] }[e.key];
    if (d && ed) {
      e.preventDefault();
      const p = XY.get(id);
      XY.set(id, [p[0] + d[0] * (e.shiftKey ? 5 : 1), p[1] + d[1] * (e.shiftKey ? 5 : 1)]);
      M.pos[id] = XY.get(id);
      persist(false);
      draw();
      const again = svg.querySelector(`[data-node="${CSS.escape(id)}"]`);
      if (again) again.focus();
    }
  });

  function clickNode(id, shift) {
    if (connectFrom && connectFrom !== id) {
      const exists = [...M.links].some((l) => (l.from === connectFrom && l.to === id) || (l.from === id && l.to === connectFrom));
      if (!exists) M.links.push({ id: nmId('l'), from: connectFrom, to: id, kind: 'eth', label: '' });
      const made = M.links[M.links.length - 1];
      connectFrom = null;
      showHint('');
      selLink = exists ? null : made.id;
      sel = new Set();
      persist(true).then(() => { layout(); draw(); openSide(); });
      return;
    }
    selLink = null; selZone = null;
    if (shift) { if (sel.has(id)) sel.delete(id); else sel.add(id); } else sel = new Set([id]);
    draw();
    openSide();
  }
  function showHint(t) { hint.hidden = !t; hint.textContent = t; }

  // ---- side panel: the selected device / link / zone / several devices
  const nodeById = (id) => G.nodes.find((n) => n.id === id);
  function openSide() {
    side.replaceChildren();
    const close = h('button', { type: 'button', class: 'icon-btn sm nm-side-x', 'aria-label': '닫기' }, icon('x'));
    close.addEventListener('click', () => { sel = new Set(); selLink = null; selZone = null; draw(); openSide(); });
    let body = null;
    if (sel.size > 1) body = multiPanel();
    else if (sel.size === 1) body = nodePanel(nodeById([...sel][0]));
    else if (selLink) body = linkPanel([...G.links].find((l) => l.id === selLink));
    else if (selZone) body = zonePanel(M.zones.find((z) => z.id === selZone));
    side.hidden = !body;
    if (body) side.append(close, body);
  }
  const zoneSelect = (cur) => h('select', null, [h('option', { value: '' }, '(영역 없음)'), ...M.zones.map((z) => h('option', { value: z.id, selected: z.id === cur }, z.name))]);

  function nodePanel(n) {
    if (!n) return null;
    const K = NM_KINDS[n.kind] || NM_KINDS.other;
    const stx = nodeStatus(n);
    const links = G.links.filter((l) => l.from === n.id || l.to === n.id);
    const head = h('div', { class: 'nm-side-head' }, h('b', null, n.name), h('span', { class: 'muted small' }, `${T(K[0])}${n.auto ? ' · 자동' : ''}`),
      stx ? h('span', { class: `badge ${stx.st === 'ok' ? 'ok' : stx.st === 'down' ? 'danger' : ''}`, title: stx.title }, stx.st === 'ok' ? '정상' : stx.st === 'down' ? '응답 없음' : '확인 중') : null);
    const zs = zoneSelect(M.member[n.id] || '');
    zs.disabled = !ed;
    zs.addEventListener('change', () => { if (zs.value) M.member[n.id] = zs.value; else delete M.member[n.id]; persist(true).then(() => { layout(); draw(); }); });
    const connect = h('button', { type: 'button', class: 'btn sm', disabled: !ed }, '다른 장비와 연결…');
    connect.addEventListener('click', () => { connectFrom = n.id; showHint(`「${n.name}」과 연결할 장비를 누르세요 — Esc: 취소`); draw(); });
    const linkList = links.length ? h('ul', { class: 'nm-links' }, links.map((l) => {
      const other = nodeById(l.from === n.id ? l.to : l.from);
      const b = h('button', { type: 'button', class: 'linkish' }, `${other ? other.name : '?'} · ${T((NM_LINKS[l.kind] || NM_LINKS.eth)[0])}${l.auto ? ' · 자동' : ''}`);
      b.addEventListener('click', () => { selLink = l.id; sel = new Set(); draw(); openSide(); });
      return h('li', null, b);
    })) : h('p', { class: 'muted small' }, '연결 없음');
    const parts = [head];
    if (n.auto) {
      parts.push(h('p', { class: 'muted small' }, n.sub || ''),
        h('p', { class: 'hint' }, '길목 설정에서 자동으로 그린 칸입니다 — 이름·주소는 해당 화면에서 바꿉니다. 영역 지정·위치·연결 추가는 여기서 됩니다.'));
      if (n.svc) {
        const ob = h('button', { type: 'button', class: 'btn sm' }, '서비스 편집');
        ob.addEventListener('click', () => onOpenService(n.svc));
        parts.push(ob);
      }
      if (n.hop != null || n.id === 'auto:host' || n.id === 'auto:tailnet') {
        const eb = h('button', { type: 'button', class: 'btn sm' }, '앞단·호스트 정보 편집');
        eb.addEventListener('click', () => openEdgeWizard(S.topoInfo, n.hop != null ? `hop:${n.hop}` : n.id === 'auto:host' ? 'host' : 'priv', () => { layout(); draw(); openSide(); }));
        parts.push(eb);
      }
      parts.push(field('영역', zs), h('div', { class: 'stack tight' }, h('b', { class: 'small' }, '연결'), linkList), h('div', { class: 'row tight' }, connect));
      if (ed && !['auto:internet', 'auto:host'].includes(n.id)) {
        const hide = h('button', { type: 'button', class: 'btn ghost sm' }, '맵에서 숨기기');
        hide.addEventListener('click', () => { M.hidden.push(n.id); delete M.pos[n.id]; sel = new Set(); persist(true).then(() => { layout(); draw(); openSide(); }); });
        parts.push(hide);
      }
      return h('div', { class: 'stack' }, parts);
    }
    // a user device: the edit form
    const d = M.nodes.find((x) => x.id === n.id);
    const kind = h('select', { disabled: !ed }, Object.entries(NM_KINDS).map(([k, [l]]) => h('option', { value: k, selected: k === d.kind }, l)));
    const name = h('input', { type: 'text', value: d.name, maxlength: 60, disabled: !ed });
    const ip = h('input', { type: 'text', value: d.ip || '', maxlength: 64, placeholder: '예: 192.168.1.10', class: 'mono', disabled: !ed });
    const note = h('textarea', { rows: 2, maxlength: 300, disabled: !ed }, d.note || '');
    const chk = h('select', { disabled: !ed }, [['', '점검 안 함'], ['ping', pingOK ? 'ping (ICMP)' : 'ping (이 환경에서는 안 됨)'], ['tcp', 'TCP 포트'], ['http', 'HTTP(S) 응답']].map(([k, l]) => h('option', { value: k, selected: (d.check || '') === k, disabled: k === 'ping' && !pingOK }, l)));
    const tgt = h('input', { type: 'text', value: d.target || '', class: 'mono', disabled: !ed });
    const tgtF = field('점검 대상', tgt, '');
    const tgtHint = h('p', { class: 'hint' });
    tgtF.append(tgtHint);
    const syncT = () => {
      tgtF.hidden = !chk.value;
      tgtHint.textContent = chk.value === 'ping' ? T('Docker Desktop(Windows·macOS)에서는 컨테이너 밖으로 ping이 안 나갈 수 있습니다 — 안 되면 TCP·HTTP 점검을 쓰세요') : '';
      tgt.placeholder = chk.value === 'ping' ? '비우면 IP 주소' : chk.value === 'tcp' ? '예: 192.168.1.10:22' : '예: http://192.168.1.10:5000';
    };
    chk.addEventListener('change', syncT);
    syncT();
    const err = h('p', { class: 'form-error', role: 'alert', hidden: true });
    const save = h('button', { type: 'button', class: 'btn primary sm', disabled: !ed }, '저장');
    const del = h('button', { type: 'button', class: 'btn danger sm', disabled: !ed }, '삭제');
    save.addEventListener('click', () => busy(save, async () => {
      const before = JSON.stringify(d);
      Object.assign(d, { kind: kind.value, name: name.value.trim(), ip: ip.value.trim(), note: note.value.trim(), check: chk.value, target: tgt.value.trim() });
      if (zs.value) M.member[d.id] = zs.value; else delete M.member[d.id];
      try {
        const r = await api('PUT', '/api/netmap', M);
        Object.assign(M, r.map, { member: r.map.member || {}, pos: r.map.pos || {}, hidden: r.map.hidden || [] });
        err.hidden = true;
        toast('저장했습니다');
        layout(); draw(); openSide();
        refreshStatus(true);
      } catch (ex) { Object.assign(d, JSON.parse(before)); err.textContent = ex.message; err.hidden = false; }
    }));
    del.addEventListener('click', async () => {
      const ok = await confirmDialog({ title: '장비 삭제', message: `「${d.name}」과 그 연결을 맵에서 지웁니다.`, okText: '삭제', danger: true });
      if (!ok) return;
      M.nodes = M.nodes.filter((x) => x.id !== d.id);
      M.links = M.links.filter((l) => l.from !== d.id && l.to !== d.id);
      delete M.member[d.id]; delete M.pos[d.id];
      sel = new Set();
      await persist(true);
      layout(); draw(); openSide();
    });
    parts.push(err, field('종류', kind), field('이름', name), field('IP 주소', ip), field('영역', zs), field('상태 점검', chk), tgtF, field('메모', note),
      h('div', { class: 'row tight' }, save, connect, h('span', { class: 'grow' }), del),
      h('div', { class: 'stack tight' }, h('b', { class: 'small' }, '연결'), linkList));
    return h('div', { class: 'stack' }, parts);
  }

  function linkPanel(l) {
    if (!l) return null;
    const a = nodeById(l.from), b = nodeById(l.to);
    const head = h('div', { class: 'nm-side-head' }, h('b', null, `${a ? a.name : '?'} — ${b ? b.name : '?'}`), h('span', { class: 'muted small' }, l.auto ? '자동 연결' : '연결'));
    if (l.auto) return h('div', { class: 'stack' }, head, h('p', { class: 'muted small' }, `${T((NM_LINKS[l.kind] || NM_LINKS.eth)[0])} — 길목 설정에서 자동으로 그린 연결입니다.`));
    const d = M.links.find((x) => x.id === l.id);
    const kind = h('select', { disabled: !ed }, Object.entries(NM_LINKS).map(([k, [lb]]) => h('option', { value: k, selected: k === d.kind }, lb)));
    const label = h('input', { type: 'text', value: d.label || '', maxlength: 40, placeholder: '예: 10GbE · VLAN 20 · 포트 3', disabled: !ed });
    const save = h('button', { type: 'button', class: 'btn primary sm', disabled: !ed }, '저장');
    const flip = h('button', { type: 'button', class: 'btn sm', disabled: !ed, title: '방향 바꾸기 (자동 배치의 왼쪽·오른쪽)' }, '⇄ 방향');
    const del = h('button', { type: 'button', class: 'btn danger sm', disabled: !ed }, '삭제');
    save.addEventListener('click', () => busy(save, async () => { d.kind = kind.value; d.label = label.value.trim(); await persist(true); draw(); openSide(); }));
    flip.addEventListener('click', () => busy(flip, async () => { [d.from, d.to] = [d.to, d.from]; await persist(true); layout(); draw(); openSide(); }));
    del.addEventListener('click', () => busy(del, async () => { M.links = M.links.filter((x) => x.id !== d.id); selLink = null; await persist(true); layout(); draw(); openSide(); }));
    return h('div', { class: 'stack' }, head, field('종류', kind), field('이름표', label), h('div', { class: 'row tight' }, save, flip, h('span', { class: 'grow' }), del));
  }

  function zonePanel(z) {
    if (!z) return null;
    const n = G.nodes.filter((x) => M.member[x.id] === z.id);
    const edit = h('button', { type: 'button', class: 'btn sm', disabled: !ed }, '영역 편집…');
    edit.addEventListener('click', () => openZoneDialog(z));
    return h('div', { class: 'stack' },
      h('div', { class: 'nm-side-head' }, h('b', null, z.name), h('span', { class: 'muted small' }, `${T((NM_ZONES[z.kind] || NM_ZONES.other)[0])}${z.cidr ? ` · ${z.cidr}` : ''}`)),
      z.note ? h('p', { class: 'small' }, z.note) : null,
      h('p', { class: 'muted small' }, `장비 ${n.length}개 — 영역 이름표를 끌면 안의 장비가 함께 움직입니다`),
      h('ul', { class: 'nm-links' }, n.map((x) => h('li', null, x.name))), edit);
  }

  function multiPanel() {
    const ids = [...sel];
    const zs = zoneSelect('');
    const put = h('button', { type: 'button', class: 'btn primary sm', disabled: !ed }, '영역에 넣기');
    const newZ = h('button', { type: 'button', class: 'btn sm', disabled: !ed }, '새 영역으로 묶기…');
    put.addEventListener('click', () => busy(put, async () => { for (const id of ids) { if (zs.value) M.member[id] = zs.value; else delete M.member[id]; } await persist(true); layout(); draw(); }));
    newZ.addEventListener('click', () => openZoneDialog(null, ids));
    return h('div', { class: 'stack' }, h('div', { class: 'nm-side-head' }, h('b', null, `${ids.length}개 선택`)),
      h('p', { class: 'muted small' }, ids.map((id) => (nodeById(id) || {}).name).join(', ')),
      field('영역', zs), h('div', { class: 'row tight' }, put, newZ),
      h('p', { class: 'hint' }, 'Shift+클릭으로 더 고르거나 빼고, 끌면 함께 움직입니다.'));
  }

  // ---- dialogs: add a device, a zone
  function openDeviceDialog() {
    const kind = h('select', null, Object.entries(NM_KINDS).map(([k, [l]]) => h('option', { value: k, selected: k === 'switch' }, l)));
    const name = h('input', { type: 'text', maxlength: 60, placeholder: '예: 거실 스위치' });
    const ip = h('input', { type: 'text', maxlength: 64, class: 'mono', placeholder: '예: 192.168.1.2' });
    const linkTo = h('select', null, [h('option', { value: '' }, '(나중에)'), ...G.nodes.map((n) => h('option', { value: n.id, selected: n.id === 'auto:host' && !M.nodes.length }, n.name))]);
    const zs = zoneSelect('');
    const err = h('p', { class: 'form-error', role: 'alert', hidden: true });
    const ok = h('button', { type: 'button', class: 'btn primary' }, '추가');
    const cancel = h('button', { type: 'button', class: 'btn ghost' }, '취소');
    const dlg = openDialog({ title: '장비 추가', body: h('div', { class: 'stack' }, err, h('div', { class: 'grid-2' }, field('종류', kind), field('이름', name), field('IP 주소', ip), field('영역', zs)), field('연결할 장비', linkTo, '유선으로 연결됩니다 — 연결을 누르면 종류(무선·광·VPN)를 바꿀 수 있습니다')), footer: [cancel, ok] });
    setTimeout(() => name.focus(), 30);
    cancel.addEventListener('click', () => dlg.close());
    ok.addEventListener('click', () => busy(ok, async () => {
      const id = nmId('n');
      const n = { id, kind: kind.value, name: name.value.trim() || T(NM_KINDS[kind.value][0]), ip: ip.value.trim() };
      const snapshot = JSON.stringify(M);
      M.nodes.push(n);
      if (linkTo.value) M.links.push({ id: nmId('l'), from: linkTo.value, to: id, kind: kind.value === 'ap' || ['phone', 'tablet', 'laptop'].includes(kind.value) ? 'wifi' : 'eth', label: '' });
      if (zs.value) M.member[id] = zs.value;
      try {
        await api('PUT', '/api/netmap', M).then((r) => Object.assign(M, r.map, { member: r.map.member || {}, pos: r.map.pos || {}, hidden: r.map.hidden || [] }));
        dlg.close();
        layout();
        sel = new Set([id]);
        draw(); openSide();
      } catch (ex) { Object.assign(M, JSON.parse(snapshot)); err.textContent = ex.message; err.hidden = false; }
    }));
  }
  function openZoneDialog(z, members) {
    const isNew = !z;
    const name = h('input', { type: 'text', maxlength: 40, value: z ? z.name : '', placeholder: '예: 집 LAN · IoT VLAN' });
    const kind = h('select', null, Object.entries(NM_ZONES).map(([k, [l]]) => h('option', { value: k, selected: k === (z ? z.kind : 'lan') }, l)));
    const cidr = h('input', { type: 'text', maxlength: 64, class: 'mono', value: z ? z.cidr || '' : '', placeholder: '예: 192.168.1.0/24 · VLAN 20' });
    const color = h('input', { type: 'color', value: z && z.color ? z.color : toHex(cssVar((NM_ZONES[z ? z.kind : 'lan'] || NM_ZONES.other)[1])) });
    let custom = !!(z && z.color);
    color.addEventListener('input', () => { custom = true; });
    kind.addEventListener('change', () => { if (!custom) color.value = toHex(cssVar(NM_ZONES[kind.value][1])); });
    const note = h('input', { type: 'text', maxlength: 200, value: z ? z.note || '' : '' });
    const ok = h('button', { type: 'button', class: 'btn primary' }, isNew ? '만들기' : '저장');
    const cancel = h('button', { type: 'button', class: 'btn ghost' }, '취소');
    const del = isNew ? null : h('button', { type: 'button', class: 'btn danger' }, '영역 삭제');
    const err = h('p', { class: 'form-error', role: 'alert', hidden: true });
    const dlg = openDialog({ title: isNew ? '영역 만들기' : '영역 편집', body: h('div', { class: 'stack' }, err, h('div', { class: 'grid-2' }, field('이름', name), field('종류', kind), field('주소 범위', cidr), field('색', color)), field('메모', note),
      isNew ? h('p', { class: 'hint' }, members && members.length ? `선택한 장비 ${members.length}개가 들어갑니다.` : '장비를 Shift+클릭으로 여러 개 고른 뒤 만들면 함께 들어갑니다. 장비 칸의 「영역」에서도 넣을 수 있습니다.') : null),
    footer: [del, h('span', { class: 'spacer' }), cancel, ok] });
    setTimeout(() => name.focus(), 30);
    cancel.addEventListener('click', () => dlg.close());
    if (del) {
      del.addEventListener('click', () => busy(del, async () => {
        M.zones = M.zones.filter((x) => x.id !== z.id);
        for (const k of Object.keys(M.member)) if (M.member[k] === z.id) delete M.member[k];
        selZone = null;
        await persist(true);
        dlg.close(); layout(); draw(); openSide();
      }));
    }
    ok.addEventListener('click', () => busy(ok, async () => {
      const snapshot = JSON.stringify(M);
      const v = { name: name.value.trim(), kind: kind.value, cidr: cidr.value.trim(), color: custom ? color.value : '', note: note.value.trim() };
      let zid = z && z.id;
      if (isNew) { zid = nmId('z'); M.zones.push({ id: zid, ...v }); } else Object.assign(M.zones.find((x) => x.id === z.id), v);
      for (const id of members || []) M.member[id] = zid;
      try {
        const r = await api('PUT', '/api/netmap', M);
        Object.assign(M, r.map, { member: r.map.member || {}, pos: r.map.pos || {}, hidden: r.map.hidden || [] });
        dlg.close(); selZone = zid; sel = new Set(); layout(); draw(); openSide();
      } catch (ex) { Object.assign(M, JSON.parse(snapshot)); err.textContent = ex.message; err.hidden = false; }
    }));
  }

  // ---- export / import
  function standaloneSVG() {
    const b = bbox();
    const pad = 30;
    const out = sv('svg', { xmlns: 'http://www.w3.org/2000/svg', viewBox: `${b.x - pad} ${b.y - pad} ${b.w + pad * 2} ${b.h + pad * 2}`, width: Math.round(b.w + pad * 2), height: Math.round(b.h + pad * 2), 'font-family': 'Pretendard, "Malgun Gothic", "Apple SD Gothic Neo", system-ui, sans-serif' });
    out.append(sv('rect', { x: b.x - pad, y: b.y - pad, width: b.w + pad * 2, height: b.h + pad * 2, fill: cssVar('--chart-bg') }));
    const g = world.cloneNode(true);
    g.removeAttribute('transform');
    for (const t of g.querySelectorAll('title, .nm-hit')) t.remove();
    for (const el of g.querySelectorAll('[tabindex], [role], [aria-label]')) { el.removeAttribute('tabindex'); el.removeAttribute('role'); el.removeAttribute('aria-label'); }
    out.append(g);
    return { text: new XMLSerializer().serializeToString(out), w: b.w + pad * 2, h: b.h + pad * 2 };
  }
  const download = (blob, name) => {
    const a = h('a', { href: URL.createObjectURL(blob), download: name });
    document.body.append(a); a.click(); a.remove();
    setTimeout(() => URL.revokeObjectURL(a.href), 2000);
  };
  const stamp = () => new Date().toISOString().slice(0, 10);
  function exportSVG() { download(new Blob([standaloneSVG().text], { type: 'image/svg+xml' }), `gilmok-network-${stamp()}.svg`); }
  function exportPNG() {
    const s = standaloneSVG();
    const img = new Image();
    img.onload = () => {
      const scale = 2;
      const c = h('canvas', { width: Math.round(s.w * scale), height: Math.round(s.h * scale) });
      const ctx = c.getContext('2d');
      ctx.scale(scale, scale);
      ctx.drawImage(img, 0, 0, s.w, s.h);
      c.toBlob((b) => (b ? download(b, `gilmok-network-${stamp()}.png`) : toast('PNG를 만들지 못했습니다', 'err')), 'image/png');
    };
    img.onerror = () => toast('PNG를 만들지 못했습니다', 'err');
    img.src = `data:image/svg+xml;base64,${btoa(unescape(encodeURIComponent(s.text)))}`;
  }
  function exportJSON() {
    const out = { format: 'gilmok-netmap', version: 1, exported: new Date().toISOString(), map: { nodes: M.nodes, links: M.links, zones: M.zones, member: M.member, pos: M.pos, hidden: M.hidden } };
    download(new Blob([JSON.stringify(out, null, 2)], { type: 'application/json' }), `gilmok-network-${stamp()}.json`);
  }
  function importJSON() {
    const inp = h('input', { type: 'file', accept: '.json,application/json', hidden: true });
    inp.addEventListener('change', async () => {
      const f = inp.files && inp.files[0];
      inp.remove();
      if (!f) return;
      try {
        const j = JSON.parse(await f.text());
        const m = j && j.format === 'gilmok-netmap' ? j.map : null;
        if (!m) throw new Error('길목 네트워크 맵 파일이 아닙니다 (「JSON 내보내기」로 받은 파일)');
        const ok = await confirmDialog({ title: '네트워크 맵 가져오기', message: `지금 맵(장비 ${M.nodes.length}·연결 ${M.links.length}·영역 ${M.zones.length})을 파일의 맵(장비 ${(m.nodes || []).length}·연결 ${(m.links || []).length}·영역 ${(m.zones || []).length})으로 바꿉니다.`, okText: '바꾸기', danger: true });
        if (!ok) return;
        const r = await api('PUT', '/api/netmap', m);
        Object.assign(M, { nodes: [], links: [], zones: [], ...r.map, member: r.map.member || {}, pos: r.map.pos || {}, hidden: r.map.hidden || [] });
        sel = new Set(); selLink = null; selZone = null;
        layout(); fit(); openSide();
        toast('가져왔습니다');
      } catch (ex) { toast(ex.message, 'err'); }
    });
    document.body.append(inp);
    inp.click();
  }

  // ---- toolbar
  const tb = (label, fn, o = {}) => { const b = h('button', { type: 'button', class: `btn sm ${o.cls || ''}`, disabled: !!o.disabled, title: o.title || null }, o.icon ? icon(o.icon) : null, label); b.addEventListener('click', () => fn(b)); return b; };
  hiddenBtn.addEventListener('click', () => popMenuNM(hiddenBtn, [...G.hiddenAuto.map((n) => [`다시 보이기: ${n.name}`, () => { M.hidden = M.hidden.filter((x) => x !== n.id); persist(true).then(() => { layout(); draw(); paintHidden(); }); }]),
    ['모두 다시 보이기', () => { M.hidden = []; persist(true).then(() => { layout(); draw(); paintHidden(); }); }]]));
  const exportBtn = tb('내보내기', (b) => popMenuNM(b, [['SVG 이미지', exportSVG], ['PNG 이미지', exportPNG], ['JSON (맵 백업)', exportJSON]]), { icon: 'download' });
  const toolbar = h('div', { class: 'nm-toolbar', role: 'toolbar', 'aria-label': '네트워크 맵' },
    tb('장비 추가', () => openDeviceDialog(), { icon: 'plus', cls: 'primary', disabled: !ed, title: ed ? '' : '「구성 변경」 권한이 필요합니다' }),
    tb('영역 만들기', () => openZoneDialog(null, [...sel]), { disabled: !ed }),
    tb('자동 배치', async () => {
      const n = Object.keys(M.pos).length;
      if (n && !(await confirmDialog({ title: '자동 배치', message: `직접 옮긴 칸 ${n}개의 위치를 지우고 자동으로 다시 배치합니다.`, okText: '자동 배치' }))) return;
      M.pos = {};
      await persist(true);
      layout(); fit();
    }, { disabled: !ed, title: '계층형 자동 배치 — 인터넷에서 서비스 쪽으로 왼쪽→오른쪽' }),
    h('span', { class: 'grow' }),
    hiddenBtn,
    tb('−', () => { const r = svg.getBoundingClientRect(); zoomAt(1 / 1.2, r.width / 2, r.height / 2); }, { title: '축소' }),
    tb('맞춤', () => fit(), { title: '화면에 맞춤' }),
    tb('+', () => { const r = svg.getBoundingClientRect(); zoomAt(1.2, r.width / 2, r.height / 2); }, { title: '확대' }),
    exportBtn,
    tb('가져오기', () => importJSON(), { icon: 'upload', disabled: !ed, title: 'JSON 맵 파일' }));
  const legend = h('div', { class: 'nm-legend', 'aria-label': '범례' },
    ...Object.entries(NM_LINKS).map(([, [l, dash, w, c]]) => h('span', { class: 'leg' }, (() => {
      const s = sv('svg', { width: 26, height: 8, 'aria-hidden': 'true' }, sv('line', { x1: 1, y1: 4, x2: 25, y2: 4, stroke: cssVar(c), 'stroke-width': w, 'stroke-dasharray': dash || null, 'stroke-linecap': 'round' }));
      return s;
    })(), l)),
    h('span', { class: 'leg' }, h('i', { class: 'l-ok', 'aria-hidden': 'true' }), '정상'), h('span', { class: 'leg' }, h('i', { class: 'l-down', 'aria-hidden': 'true' }), '응답 없음'),
    h('span', { class: 'hint' }, ed ? '칸을 끌어 옮기면 저장됩니다 · 배경 끌기: 이동 · 휠: 확대 · Shift+클릭: 여러 개 · 화살표: 미세 이동' : '보기 전용 — 배경 끌기: 이동 · 휠: 확대'));

  // ---- status refresh
  async function refreshStatus(now) {
    try {
      const r = await api(now ? 'POST' : 'GET', now ? '/api/netmap/check' : '/api/netmap/status');
      status = r.status || {};
      if (!svg.classList.contains('dragging')) draw();
      if (!side.hidden && !side.contains(document.activeElement)) openSide(); // the badge in the panel too
    } catch { /* keep the last */ }
  }
  const tick = () => { if (!box.isConnected) return; refreshStatus(false); setTimeout(tick, 30000); };

  box.replaceChildren(toolbar, stage, legend);
  layout();
  requestAnimationFrame(() => { fit(); openSide(); });
  setTimeout(tick, 30000);
  const onHealth = () => { if (!box.isConnected) { document.removeEventListener('gm:health', onHealth); return; } if (!svg.classList.contains('dragging')) draw(); };
  document.addEventListener('gm:health', onHealth);
  new ResizeObserver(() => { if (box.isConnected && !V.fitted) fit(); else if (box.isConnected) draw(); }).observe(stage);
}

/** a small menu (the dashboard's popMenu when loaded; else a plain list in a dialog) */
function popMenuNM(btn, items) {
  if (typeof popMenu === 'function') return popMenu(btn, items);
  const list = h('div', { class: 'stack' }, items.map(([l, fn]) => { const b = h('button', { type: 'button', class: 'btn' }, l); b.addEventListener('click', () => { d.close(); fn(); }); return b; }));
  const d = openDialog({ title: '', body: list });
  return d;
}
