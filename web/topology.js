// Gilmok web UI — topology map (services tab › 구성도).
// Pure SVG built with createElementNS (no innerHTML). Icons are simple generic drawings.
'use strict';

const TOPO_ICONS = {
  globe: ['M12 3a9 9 0 1 0 0 18 9 9 0 0 0 0-18z', 'M3 12h18', 'M12 3c2.6 2.6 3.9 5.6 3.9 9s-1.3 6.4-3.9 9c-2.6-2.6-3.9-5.6-3.9-9s1.3-6.4 3.9-9z'],
  cloud: ['M7 18.5a4.5 4.5 0 0 1-.5-8.97A6 6 0 0 1 18 9.6a4.4 4.4 0 0 1-.6 8.9H7z'],
  router: ['M4 14h16v5H4z', 'M7.5 16.5h.01M11 16.5h.01', 'M8 14l1.5-5M16 14l-1.5-5', 'M8.5 6.5a5 5 0 0 1 7 0M6.5 4.5a8 8 0 0 1 11 0'],
  server: ['M4 4h16v6H4zM4 14h16v6H4z', 'M8 7h.01M8 17h.01', 'M12 7h5M12 17h5'],
  devices: ['M3 6h12v9H3zM1.5 18h15', 'M18 8h4v12h-4z', 'M20 17.5h.01'],
  tailnet: [],
  shield: ['M12 3l8 3v6c0 4.5-3.4 8.3-8 9-4.6-.7-8-4.5-8-9V6l8-3z', 'M9 12l2 2 4-4'],
  lock: ['M6 11h12v9H6z', 'M8.5 11V8a3.5 3.5 0 0 1 7 0v3'],
  radar: ['M12 21a9 9 0 1 1 9-9', 'M12 16a4 4 0 1 1 4-4', 'M12 12l7-7'],
  photo: ['M4 5h16v14H4z', 'M4 16l5-5 4 4 2-2 5 5', 'M15.5 9.5h.01'],
  play: ['M4 5h16v14H4z', 'M10 9v6l5-3z'],
  book: ['M4 5a2 2 0 0 1 2-2h13v16H6a2 2 0 0 0-2 2z', 'M4 19V5', 'M9 7h6'],
  download: ['M12 3v12', 'M7 10l5 5 5-5', 'M4 20h16'],
  folder: ['M3 6h6l2 2h10v11H3z'],
  note: ['M5 3h10l4 4v14H5z', 'M15 3v4h4', 'M8 12h8M8 16h6'],
  pin: ['M12 21s-6-5.3-6-11a6 6 0 0 1 12 0c0 5.7-6 11-6 11z', 'M12 12.5a2.5 2.5 0 1 0 0-5 2.5 2.5 0 0 0 0 5z'],
  home: ['M3 11l9-7 9 7', 'M5 10v10h14V10', 'M10 20v-6h4v6'],
  box: ['M12 3l8 4.5v9L12 21l-8-4.5v-9z', 'M4 7.5l8 4.5 8-4.5M12 12v9'],
  key: ['M8 20a5 5 0 1 1 0-10 5 5 0 0 1 0 10z', 'M11.5 11.5L20 3M16.5 6.5l3 3'],
  app: ['M4 4h7v7H4zM13 4h7v7h-7zM4 13h7v7H4zM13 13h7v7h-7z'],
  dns: ['M4 6h16M4 12h16M4 18h10'],
  tunnel: ['M3 19a9 9 0 0 1 18 0', 'M7.5 19a4.5 4.5 0 0 1 9 0', 'M2 19h20'],
  wall: ['M3 5h18v14H3z', 'M3 9.7h18M3 14.3h18', 'M9 5v4.7M15 5v4.7M6 9.7v4.6M12 9.7v4.6M18 9.7v4.6M9 14.3V19M15 14.3V19'],
  question: ['M12 21a9 9 0 1 0 0-18 9 9 0 0 0 0 18z', 'M9.5 9.2a2.6 2.6 0 0 1 5 .8c0 1.8-2.5 2.2-2.5 3.8', 'M12 17h.01'],
  host: ['M3 4h18v12H3z', 'M8 20h8M12 16v4'],
  lb: ['M4 4h16v6H4z', 'M8 7h.01', 'M12 10v3', 'M5 20v-3h14v3', 'M12 13v7', 'M5 17h14'],
  bolt: ['M13 2L4.5 13.5H11L10 22l8.5-11.5H12z'],
  steps: ['M4 6h.01M4 12h.01M4 18h.01', 'M8 6h12M8 12h12M8 18h8'],
  gilmok: ['M12 2.5v19', 'M12 5h7l2.2 2.5L19 10h-7', 'M12 12.5H5l-2.2 2.5L5 17.5h7', 'M9 21.5h6'],
};

// ---- the part in front of this host: Gilmok cannot detect it, the user describes it as a chain of
//      devices (Settings.topoHops, internet side first). tailnet = Tailscale / VPN also passes it.
const HOP_KINDS = {
  router: { label: '공유기', icon: 'router', name: '공유기', desc: '포트포워딩 — 집·사무실 공유기', exName: '예: ipTIME AX3000', exNote: '예: TCP 443만 · 국가 허용 KR', tailnet: true, ports: true },
  firewall: { label: '방화벽', icon: 'wall', name: '방화벽', desc: '하드웨어 방화벽·UTM·클라우드 보안 그룹·ufw', exName: '예: FortiGate / 보안 그룹', exNote: '예: 443만 허용', tailnet: true, ports: true },
  lb: { label: '로드밸런서', icon: 'lb', name: '로드밸런서', desc: 'L4/L7 부하 분산 — HAProxy, 클라우드 LB 등', exName: '예: HAProxy / NLB', exNote: '예: TCP 패스스루', tailnet: false, ports: true },
  proxy: { label: '리버스 프록시', icon: 'server', name: '앞단 프록시', desc: '다른 서버의 nginx 등이 넘겨줌', exName: '예: VPS의 nginx', exNote: '예: SNI 패스스루', tailnet: false, ports: true },
  tunnel: { label: 'Cloudflare Tunnel', icon: 'tunnel', name: 'cloudflared', desc: '포트를 열지 않고 바깥으로 연결', exName: '예: cloudflared 컨테이너', exNote: '예: 아웃바운드만', tailnet: false, ports: false },
  other: { label: '기타 장비', icon: 'box', name: '장비', desc: 'IPS·WAF 어플라이언스 등', exName: '예: IPS', exNote: '', tailnet: false, ports: true },
};
const topoHops = (set) => (set.topoHops || []).filter((x) => HOP_KINDS[x.kind]);
const hopName = (x) => (x.name || '').trim() || HOP_KINDS[x.kind].name;
const PRIV_KINDS = {
  ts_serve: { label: 'tailscale serve', icon: 'tailnet', src: 'Tailscale 기기', name: 'tailscale serve', exNote: '예: --tcp 443 → 127.0.0.1:8443' },
  ts_direct: { label: 'Tailscale IP로 직접', icon: 'tailnet', src: 'Tailscale 기기', name: 'Tailscale', exNote: '예: 100.x.y.z:8443 으로 접속' },
  vpn: { label: '다른 VPN (WireGuard 등)', icon: 'lock', src: 'VPN 클라이언트', name: 'VPN', exNote: '예: WireGuard 서버 → 8443' },
};

const isLoop = (ip) => ip === '127.0.0.1' || ip === '::1' || ip === 'localhost';
const anyIp = (ip) => !ip || ip === '0.0.0.0' || ip === '::';
function bindsFor(info, ctrPort) {
  return ((info && info.ports) || []).filter((b) => b.ctrPort === ctrPort && b.proto === 'tcp');
}
function bindText(binds) {
  const set = new Set(binds.map((b) => `${anyIp(b.hostIp) ? '*' : b.hostIp}:${b.hostPort}`));
  return [...set].join(', ');
}

/** Detected facts + user description → what to draw and what does not add up. */
function topoModel(info, set, groups) {
  const pubPort = (info && info.publicPort) || 443;
  const tsPort = set.tailscalePort || 8443;
  const pubB = bindsFor(info, pubPort);
  const tsB = bindsFor(info, tsPort);
  const hasPub = groups.some((g) => g.id !== 'ts');
  const hasGray = groups.some((g) => g.id === 'gray');
  const hasTs = groups.some((g) => g.id === 'ts');
  const hops = topoHops(set);
  const tunnelOnly = hops.length > 0 && hops.every((x) => x.kind === 'tunnel');
  const lastHop = hops[hops.length - 1];
  const pk = PRIV_KINDS[set.topoPrivKind] && (use('tailscale') || set.topoPrivKind === 'vpn') ? set.topoPrivKind : '';
  const pubHostPort = (pubB.find((b) => !isLoop(b.hostIp)) || pubB[0] || {}).hostPort || 0;
  const tsHostPort = (tsB[0] || {}).hostPort || 0;
  const warns = [];
  const w = (text, where) => warns.push({ text, where });
  if (info && !info.caddyRunning) w('Caddy 컨테이너가 실행 중이 아니라 게시 포트를 확인하지 못했습니다.', 'caddy');
  else if (info) {
    if (hasPub && !tunnelOnly) {
      if (!pubB.length) w(`Caddy :${pubPort}가 호스트에 게시되어 있지 않습니다 (Caddy compose의 ports 확인).`, 'pub');
      else if (pubB.every((b) => isLoop(b.hostIp)) && hops.some((x) => x.kind === 'router' || x.kind === 'firewall')) w(`Caddy :${pubPort}가 ${bindText(pubB)}에만 열려 있어 외부에서 들어올 수 없습니다.`, 'pub');
      if (lastHop && lastHop.kind !== 'tunnel' && lastHop.fwdPort && pubB.length && !pubB.some((b) => b.hostPort === lastHop.fwdPort)) {
        w(`${hopName(lastHop)}는 :${lastHop.fwdPort}로 넘기는데, Caddy는 호스트 ${bindText(pubB)}에 게시되어 있습니다.`, 'pub');
      }
    }
    if (hasTs) {
      if (!use('tailscale') && pk === '') w(`Tailscale을 쓰지 않는데 ${privName()} 서비스가 있습니다 — 들어올 경로(VPN 등)가 없다면 공개로 바꾸거나 Tailscale을 다시 켜세요.`, 'ts');
      if (!tsB.length && pk !== '') w(`${privName()} 포트 :${tsPort}가 호스트에 게시되어 있지 않습니다.`, 'ts');
      if (tsB.some((b) => anyIp(b.hostIp)) && (pk === 'ts_serve' || pk === '')) w(`${privName()} 포트 :${tsPort}가 모든 인터페이스(${bindText(tsB)})에 열려 있어 LAN에서도 접속됩니다. 127.0.0.1로만 게시하는 것을 권장합니다.`, 'ts');
      if (pk === 'ts_direct' && tsB.length && tsB.every((b) => isLoop(b.hostIp))) w(`Tailscale IP로 직접 접속하려면 :${tsPort}를 127.0.0.1이 아닌 주소에 게시해야 합니다 (지금 ${bindText(tsB)}). 또는 「tailscale serve」를 고르세요.`, 'ts');
    }
  }
  if (tunnelOnly && hasGray) w('Cloudflare Tunnel로는 DNS only(공인 IP 직접) 서비스에 접속할 수 없습니다.', 'gray');
  return { hops, tunnelOnly, pk, pubPort, tsPort, pubB, tsB, pubHostPort, tsHostPort, warns, hasPub, hasTs,
    unknownEdge: (hasPub || hasTs) && !hops.length, unknownPriv: hasTs && !pk };
}

const TOPO_KEYWORDS = [
  [/immich|photo|gallery/, 'photo'], [/plex|jellyfin|emby|video|media/, 'play'],
  [/komga|manga|book|kavita|calibre/, 'book'], [/^jd$|jdownload|transmission|qbit|download|torrent|aria/, 'download'],
  [/webdav|list|sftp|file|cloud|nextcloud|share/, 'folder'], [/joplin|note|memo|wiki/, 'note'],
  [/traccar|map|gps|track/, 'pin'], [/^home|homepage|dash/, 'home'], [/dock|portainer|container/, 'box'],
  [/^auth|authelia|sso|login/, 'key'], [/caddy|proxy/, 'server'],
];
function serviceIcon(s) {
  const k = `${s.subdomain} ${(s.upstream || '').split(':')[0]}`.toLowerCase();
  for (const [re, name] of TOPO_KEYWORDS) if (re.test(s.subdomain.toLowerCase()) || re.test(k)) return name;
  return 'app';
}

// map colors follow the theme: read from CSS variables at draw time (the map is redrawn on a theme change)
const TC = {};
for (const [k, v] of Object.entries({ orange: '--orange', gray: '--gray-cloud', ts: '--ts', accent: '--accent', ok: '--ok', danger: '--danger', warn: '--warn', blue: '--blue',
  accentText: '--t-accent', muted: '--muted', surface: '--chart-bg', surfaceAccent: '--surf-accent', pill: '--surf' })) {
  Object.defineProperty(TC, k, { get: () => cssVar(v), enumerable: true });
}

function sv(tag, attrs, ...kids) {
  const el = document.createElementNS(SVG_NS, tag);
  for (const [k, v] of Object.entries(attrs || {})) if (v != null && v !== false) el.setAttribute(k, String(v));
  for (const k of kids.flat(Infinity)) if (k != null && k !== false) el.append(k instanceof Node ? k : document.createTextNode(String(k)));
  return el;
}

function topoIcon(name, x, y, size, color) {
  const g = sv('g', { transform: `translate(${x - size / 2} ${y - size / 2}) scale(${size / 24})`, class: 'ti', stroke: color });
  if (name === 'tailnet') {
    for (let i = 0; i < 3; i++) for (let j = 0; j < 3; j++) {
      const on = (i === 1) || (j === 1 && i !== 0);
      g.append(sv('circle', { cx: 5 + j * 7, cy: 5 + i * 7, r: 2.3, fill: color, 'fill-opacity': on ? 1 : 0.35, stroke: 'none' }));
    }
    return g;
  }
  for (const d of TOPO_ICONS[name] || TOPO_ICONS.app) g.append(sv('path', { d }));
  return g;
}

const textW = (s, size) => [...String(s)].reduce((w, ch) => w + (/[ㄱ-힝]/.test(ch) ? size * 0.95 : /[A-Z0-9]/.test(ch) ? size * 0.64 : size * 0.56), 0);
const clip = (s, n) => (String(s).length > n ? `${String(s).slice(0, n - 1)}…` : String(s));

function topologyView(onOpen, info, onEdit) {
  const st = S.state;
  const set0 = settings();
  // components not in use are drawn as if their options were off
  const set = { ...set0, crowdsecEnabled: use('crowdsec') && use('cloudflare') && set0.crowdsecEnabled, crowdsecSync: use('crowdsec') && use('cloudflare') && set0.crowdsecSync, cfAsnRule: use('cloudflare') && set0.cfAsnRule };
  const all = st.services.map((s) => ({ ...s,
    proxied: use('cloudflare') && s.proxied, mtls: use('cloudflare') && s.mtls,
    authelia: use('authelia') ? s.authelia : { ...(s.authelia || {}), enabled: false },
    waf: use('caddy') ? s.waf : '' }));
  if (!all.length) return h('div', { class: 'empty' }, use('caddy') ? '서비스가 없습니다. 「기존 설정 가져오기」나 「서비스 추가」로 시작하세요.' : '서비스가 없습니다. 「서비스 추가」로 시작하세요.');
  if (!use('caddy')) {
    return h('div', { class: 'glass topo' }, callout('', h('b', null, 'Caddy를 쓰지 않는 구성입니다'),
      h('span', null, '구성도는 Caddy를 중심으로 그립니다. 지금은 서비스마다 DNS 레코드와 연결 상태만 관리합니다 — 목록 보기를 쓰세요.')));
  }

  // ---- groups (tree level 2)
  const GROUPS = [
    { id: 'orange', label: 'Proxied · mTLS', sub: 'Cloudflare 경유만', color: TC.orange, icon: 'lock', test: (s) => s.exposure === 'public' && s.proxied && s.mtls },
    { id: 'orangeOpen', label: 'Proxied', sub: 'Cloudflare 프록시', color: TC.orange, icon: 'cloud', test: (s) => s.exposure === 'public' && s.proxied && !s.mtls },
    { id: 'gray', label: use('cloudflare') ? 'DNS only' : '공개', sub: '공인 IP 직접', color: TC.gray, icon: 'cloud', test: (s) => s.exposure === 'public' && !s.proxied },
    { id: 'ts', label: privName(), sub: use('tailscale') ? `:${set.tailscalePort || 8443} · ${set.tailscaleIp || '100.x'}` : `:${set.tailscalePort || 8443}`, color: TC.ts, icon: use('tailscale') ? 'tailnet' : 'lock', test: (s) => s.exposure !== 'public' },
  ].map((g) => ({ ...g, items: all.filter(g.test).sort((a, b) => (b.enabled - a.enabled) || a.subdomain.localeCompare(b.subdomain)) }))
    .filter((g) => g.items.length);
  const M = topoModel(info, set, GROUPS);

  // ---- geometry
  // columns: outside (internet / tailnet devices, Cloudflare, the front device) → this host
  // (Tailscale / VPN endpoint, Caddy, groups, services)
  const HOPX = 190; // one column per front device
  const hshift = Math.max(0, M.hops.length - 1) * HOPX;
  const X = { src: 24, edge: 220, router: 410, tsd: 640 + hshift, caddy: 870 + hshift, group: 1110 + hshift, leaf: 1390 + hshift };
  const NW = 150, NH = 54, CW = 196, GW = 182, GH = 50, LW = 268, LH = 54, ROW = 66, GAP = 30;
  const CADDY_HEAD = 74, SOCK = 38;
  let y = 0;
  const leafPos = new Map();
  for (const g of GROUPS) {
    const ys = g.items.map((s) => { const yy = y; leafPos.set(s.id, yy); y += ROW; return yy; });
    g.y = (ys[0] + ys[ys.length - 1]) / 2;
    y += GAP;
  }
  const pub = GROUPS.filter((g) => g.id !== 'ts');
  const ts = GROUPS.find((g) => g.id === 'ts');
  const orangeGroups = pub.filter((g) => g.id !== 'gray');
  const grayGroup = pub.find((g) => g.id === 'gray');
  const mean = (arr) => arr.reduce((a, b) => a + b, 0) / arr.length;
  const pin443 = pub.length ? mean(pub.map((g) => g.y)) : null;
  const pin8443 = ts ? ts.y : null;
  const cfY = pin443 != null ? pin443 - (grayGroup ? 70 : 0) : null;
  const directY = pin443 != null ? pin443 + 70 : null;

  const csOn = !!set.crowdsecEnabled;
  // shift everything so the topmost element sits below the header row
  const portRows = [pin443, pin8443].filter((v) => v != null);
  const tops = [0, cfY != null ? cfY - NH / 2 - 26 : 0, portRows.length ? Math.min(...portRows) - SOCK / 2 - CADDY_HEAD - 10 : 0].filter((v) => v != null);
  const minY = Math.min(...tops);
  const top = csOn ? 186 : 86; // room for the host label (+ CrowdSec row)
  const dy = top - minY;
  const Y = (v) => v + dy;
  const height = Y(Math.max(y - GAP, directY != null ? directY + 40 : 0, pin8443 != null ? pin8443 + 60 : 0)) + 40;
  const width = X.leaf + LW + 24;

  const svg = sv('svg', { viewBox: `0 0 ${width} ${height}`, class: 'topo-svg', role: 'group', 'aria-label': '서비스 구성도' });
  const defs = sv('defs');
  for (const [k, c] of Object.entries(TC)) {
    defs.append(sv('marker', { id: `ah-${k}`, viewBox: '0 0 10 10', refX: 8.5, refY: 5, markerWidth: 7, markerHeight: 7, orient: 'auto-start-reverse' },
      sv('path', { d: 'M0 0L10 5L0 10z', fill: c })));
    defs.append(sv('linearGradient', { id: `gr-${k}`, x1: 0, y1: 0, x2: 1, y2: 1 },
      sv('stop', { offset: '0', 'stop-color': c, 'stop-opacity': 0.95 }), sv('stop', { offset: '1', 'stop-color': c, 'stop-opacity': 0.45 })));
  }
  defs.append(sv('filter', { id: 'topo-glow', x: '-30%', y: '-30%', width: '160%', height: '160%' },
    sv('feGaussianBlur', { stdDeviation: 6, result: 'b' }), sv('feMerge', null, sv('feMergeNode', { in: 'b' }), sv('feMergeNode', { in: 'SourceGraphic' }))));
  svg.append(defs);
  const gBack = sv('g', { class: 'back' });
  const gEdges = sv('g', { class: 'edges' });
  const gLabels = sv('g', { class: 'labels' });
  const gNodes = sv('g', { class: 'nodes' });
  svg.append(gBack, gEdges, gNodes, gLabels);

  const keys = (list) => list.map((s) => `k-${s.id}`).join(' ');
  const alive = (s) => s.enabled && !s.dnsOnly && (healthOf(s) || {}).st !== 'down';
  const colorKey = (c) => Object.keys(TC).find((k) => TC[k] === c) || 'accent';

  function edge(x1, y1, x2, y2, color, list, opts = {}) {
    const dx = Math.max(30, (x2 - x1) * 0.5);
    const d = opts.d || `M${x1} ${y1} C${x1 + dx} ${y1} ${x2 - dx} ${y2} ${x2} ${y2}`;
    const live = list.some(alive) && !opts.static; // nothing flows to stopped / unreachable services
    const idle = list.length > 0 && !list.some(alive); // leads only to services not serving → still dotted line
    const p = sv('path', {
      d, class: `edge ${live ? 'flow' : ''} ${opts.dashed ? 'dashed' : ''} ${idle ? 'idle' : ''} ${keys(list)}`, stroke: color,
      'marker-end': opts.noArrow ? null : `url(#ah-${colorKey(color)})`, 'stroke-width': opts.w || 2,
    });
    gEdges.append(sv('path', { d, class: `edge-base ${keys(list)}`, stroke: color, 'stroke-width': (opts.w || 2) + 5 }), p);
    if (opts.label) label((x1 + x2) / 2, (y1 + y2) / 2 + (opts.labelDy || 0), opts.label, color, list);
    return p;
  }
  function label(x, y, text, color, list = []) {
    const w = textW(text, 11) + 16;
    gLabels.append(sv('g', { class: `elabel ${keys(list)}`, transform: `translate(${x - w / 2} ${y - 10})` },
      sv('rect', { width: w, height: 20, rx: 10, fill: TC.pill, stroke: color, 'stroke-opacity': 0.5 }),
      sv('text', { x: w / 2, y: 14, 'text-anchor': 'middle', fill: color, 'font-size': 11 }, text)));
  }
  function pill(g, x, y, text, color, filled) {
    const w = textW(text, 10.5) + 14;
    g.append(sv('rect', { x, y, width: w, height: 18, rx: 9, fill: color, 'fill-opacity': filled ? 0.22 : 0.08, stroke: color, 'stroke-opacity': 0.55 }),
      sv('text', { x: x + w / 2, y: y + 12.6, 'text-anchor': 'middle', fill: color, 'font-size': 10.5, 'font-weight': 600 }, text));
    return w;
  }
  function node(x, cy, w, hgt, { title, sub, iconName, color, list = [], dim, title2, extra, edit, unknown }) {
    const yy = cy - hgt / 2;
    const g = sv('g', { class: `node ${dim ? 'dim' : ''} ${unknown ? 'unknown' : ''} ${edit ? 'editable' : ''} ${keys(list)}`, transform: `translate(${x} ${yy})` },
      title2 ? sv('title', null, title2) : null,
      sv('rect', { class: 'node-bg', width: w, height: hgt, rx: 14, stroke: color }),
      sv('rect', { class: 'node-shine', x: 1, y: 1, width: w - 2, height: hgt / 2, rx: 13 }),
      sv('circle', { cx: 27, cy: Math.min(hgt / 2, 27), r: 17, fill: `url(#gr-${colorKey(color)})`, 'fill-opacity': 0.22, stroke: color, 'stroke-opacity': 0.6 }),
      topoIcon(iconName, 27, Math.min(hgt / 2, 27), 20, color),
      sv('text', { x: 52, y: sub ? Math.min(hgt / 2, 27) - 3 : hgt / 2 + 5, class: 'n-title' }, title),
      sub ? sv('text', { x: 52, y: Math.min(hgt / 2, 27) + 13, class: 'n-sub' }, sub) : null);
    if (extra) extra(g);
    if (edit && onEdit) {
      g.setAttribute('tabindex', '0');
      g.setAttribute('role', 'button');
      g.setAttribute('aria-label', `${title} — 앞단 구성 입력`);
      g.addEventListener('click', () => onEdit(edit));
      g.addEventListener('keydown', (e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); onEdit(edit); } });
    }
    gNodes.append(g);
    return g;
  }
  const warnAt = (where) => M.warns.filter((x) => x.where === where);

  const pubItems = pub.flatMap((g) => g.items);
  const pubItemsOf = () => pubItems;
  const tsItemsOf = () => (ts ? ts.items : []);
  const orangeItems = orangeGroups.flatMap((g) => g.items);
  const grayItems = grayGroup ? grayGroup.items : [];
  const tsItems = ts ? ts.items : [];

  // ---- Caddy: ONE container, a socket per listener port (:443 public, :8443 private)
  const wafN = all.filter((s) => s.enabled && !s.dnsOnly && s.waf).length;
  const authN = all.filter((s) => s.enabled && !s.dnsOnly && s.authelia && s.authelia.enabled).length;
  const ports = [
    pin443 != null && { y: Y(pin443), port: String(M.pubPort), c: TC.blue, list: pubItems, what: '공개', binds: M.pubB },
    pin8443 != null && { y: Y(pin8443), port: String(M.tsPort), c: TC.ts, list: tsItems, what: use('tailscale') ? 'Tailscale' : '사설', binds: M.tsB },
  ].filter(Boolean);
  const caddyBox = {
    top: Math.min(...ports.map((p) => p.y)) - SOCK / 2 - CADDY_HEAD,
    bottom: Math.max(...ports.map((p) => p.y)) + SOCK / 2 + 14,
  };
  {
    const H = caddyBox.bottom - caddyBox.top;
    const g = sv('g', { class: `node caddy-box ${keys(all)}`, transform: `translate(${X.caddy} ${caddyBox.top})` },
      sv('title', null, `Caddy (${set.caddyContainer || 'caddy'}) — 한 컨테이너가 ${ports.map((p) => `:${p.port} ${p.what}`).join(', ')} 포트에서 받습니다`),
      sv('rect', { class: 'node-bg', width: CW, height: H, rx: 16, stroke: TC.accent }),
      sv('rect', { class: 'node-shine', x: 1, y: 1, width: CW - 2, height: 36, rx: 15 }),
      sv('circle', { cx: 27, cy: 27, r: 17, fill: 'url(#gr-accent)', 'fill-opacity': 0.22, stroke: TC.accent, 'stroke-opacity': 0.6 }),
      topoIcon('server', 27, 27, 20, TC.accent),
      sv('text', { x: 52, y: 24, class: 'n-title' }, 'Caddy'),
      sv('text', { x: 52, y: 40, class: 'n-sub' }, clip(set.caddyContainer || 'caddy', 18)));
    let xx = 12;
    if (wafN) xx += pill(g, xx, 50, `WAF ${wafN}`, TC.danger, true) + 4;
    if (authN) pill(g, xx, 50, `Authelia ${authN}`, TC.accent, true);
    for (const p of ports) {
      const ly = p.y - caddyBox.top;
      const host = p.binds.length ? `호스트 ${bindText(p.binds)}` : (info ? '호스트 게시 없음' : `사이트 ${p.list.length}개`);
      g.append(
        sv('g', { class: keys(p.list) },
          sv('title', null, `:${p.port} — ${p.what} 사이트 ${p.list.length}개\n호스트 게시: ${p.binds.length ? bindText(p.binds) : '없음'}`),
          sv('rect', { x: 10, y: ly - SOCK / 2, width: CW - 20, height: SOCK, rx: 10, fill: p.c, 'fill-opacity': 0.09, stroke: p.c, 'stroke-opacity': 0.6 }),
          sv('text', { x: 22, y: ly - 3, class: 'sock-port', fill: p.c }, `:${p.port}`),
          sv('text', { x: 22 + textW(`:${p.port}`, 13.5) + 8, y: ly - 3, class: 'n-sub' }, p.what),
          sv('text', { x: 22, y: ly + 12, class: 'n-sub mono' }, clip(host, 25))),
        sv('circle', { cx: 0, cy: ly, r: 4, fill: p.c }), sv('circle', { cx: CW, cy: ly, r: 4, fill: p.c }));
    }
    gNodes.append(g);
  }
  const boxTop = caddyBox.top;

  // ---- in front of the host: a chain of devices (internet side first). Public traffic passes all
  //      of them; Tailscale / VPN only those marked tailnet. No devices yet → one 「?」 to add.
  const P = PRIV_KINDS[M.pk];
  const hopsDraw = M.hops.length ? M.hops : [null];
  const tsHopIdx = ts ? hopsDraw.map((x, i) => (x === null || x.tailnet ? i : -1)).filter((i) => i >= 0) : [];
  const viaHops = tsHopIdx.length > 0;
  const rY = pin443 != null && viaHops ? (Y(pin443) + Y(pin8443)) / 2 : pin443 != null ? Y(pin443) : ts ? Y(pin8443) : 0;
  const pw = warnAt('pub').length > 0;
  const exPort = M.pubHostPort || M.pubPort;
  const HW = NW + 10;
  const hx = (i) => X.router + i * HOPX;
  const pubDy = pin443 != null && viaHops ? -8 : 0; // public / private lanes through the same device
  const tsDy = pin443 != null && viaHops ? 10 : 0;
  const lastI = hopsDraw.length - 1;
  // a link that has to jump over devices it does not pass dips below the row
  const hop = (x1, y1, x2, y2, color, list, opts = {}) => {
    const jump = opts.over;
    if (!jump) return edge(x1, y1, x2, y2, color, list, opts);
    const dip = rY + NH / 2 + 46;
    return edge(0, 0, 0, 0, color, list, { ...opts, d: `M${x1} ${y1} C${x1 + 50} ${dip} ${x2 - 50} ${dip} ${x2} ${y2}` });
  };
  if (pin443 != null || ts) {
    hopsDraw.forEach((hp, i) => {
      const lists = [...(pin443 != null ? pubItems : []), ...(tsHopIdx.includes(i) ? tsItems : [])];
      if (!hp) {
        node(hx(i), rY, HW, NH, { title: '앞단 미설정', sub: '눌러서 추가', iconName: 'question', color: TC.gray, list: lists, unknown: true, edit: 'hop:new',
          title2: `인터넷과 이 서버 사이의 장비(공유기·방화벽·로드밸런서·프록시·터널 …)는 길목이 알 수 없습니다. 눌러서 추가하세요.\n예: 공유기 :443 → :${exPort}` });
        return;
      }
      const K = HOP_KINDS[hp.kind];
      const sub = hp.kind === 'tunnel' ? '아웃바운드 터널' : hp.extPort && hp.fwdPort ? `:${hp.extPort} → :${hp.fwdPort}` : hp.extPort ? `:${hp.extPort} 받음` : hp.fwdPort ? `→ :${hp.fwdPort}` : K.label;
      const note = (hp.note || '').trim();
      node(hx(i), rY, HW, NH + (note ? 20 : 0), {
        title: clip(hopName(hp), 13), sub, iconName: K.icon, color: hp.kind === 'tunnel' ? TC.orange : pw && i === lastI ? TC.warn : TC.blue, list: lists, edit: `hop:${i}`,
        title2: `${i + 1}. ${K.label}${hp.name ? ` · ${hp.name}` : ''}\n${sub}${ts && hp.tailnet ? `\n${use('tailscale') ? 'Tailscale' : 'VPN'} 연결도 지납니다` : ''}${note ? `\n${note}` : ''}\n(눌러서 수정·삭제·순서 변경)`,
        extra: note ? (g) => pill(g, 12, NH - 4, clip(note, 16), TC.blue, false) : null,
      });
      if (i > 0 && pin443 != null) edge(hx(i - 1) + HW, rY + pubDy, hx(i), rY + pubDy, TC.blue, pubItems);
    });
    // add another device after the last one
    if (M.hops.length && M.hops.length < 8) {
      const ax = hx(lastI) + HW / 2, ay = rY - NH / 2 - 26;
      const w = 118;
      const add = sv('g', { class: 'node editable unknown add-hop', transform: `translate(${ax - w / 2} ${ay - 13})`, tabindex: 0, role: 'button', 'aria-label': '앞단 장비 추가' },
        sv('title', null, '앞단 장비 추가 (방화벽·로드밸런서·프록시 …)'),
        sv('rect', { class: 'node-bg', width: w, height: 26, rx: 13, stroke: TC.gray, 'stroke-dasharray': '4 4' }),
        sv('text', { x: w / 2, y: 17.5, 'text-anchor': 'middle', class: 'n-sub' }, '+ 앞단 장비 추가'));
      const go = () => onEdit && onEdit('hop:new');
      add.addEventListener('click', go);
      add.addEventListener('keydown', (e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); go(); } });
      gNodes.append(add);
    }
  }

  // ---- public path: internet → (Cloudflare) → devices → Caddy :443
  if (pin443 != null) {
    const srcY = Y(pin443);
    const inY = rY + pubDy;
    const hasTunnel = M.hops.some((x) => x.kind === 'tunnel');
    node(X.src, srcY, NW, NH, { title: '인터넷', sub: info && info.publicIp ? info.publicIp : '외부 접속자', title2: info && info.publicIp ? `이 서버의 공인 IP: ${info.publicIp}` : null, iconName: 'globe', color: TC.blue, list: pubItems });
    if (orangeItems.length) {
      const cy = Y(cfY);
      const asn = set.cfAsnRule ? (set.cfAsnAction === 'block' ? 'ISP 차단' : 'ISP 챌린지') : null;
      node(X.edge, cy, NW, NH + (asn || set.crowdsecSync ? 20 : 0), {
        title: 'Cloudflare', sub: hasTunnel ? 'WAF · 터널' : 'WAF · 프록시', iconName: 'cloud', color: TC.orange, list: orangeItems,
        title2: `Proxied: Cloudflare 엣지를 거쳐 들어옵니다 (${set.domain || ''})`,
        extra: (g) => {
          let xx = 12;
          const yy = NH + 20 - 24;
          if (asn) xx += pill(g, xx, yy, asn, TC.orange, true) + 4;
          if (set.crowdsecSync) pill(g, xx, yy, 'CrowdSec', TC.danger, true);
        },
      });
      edge(X.src + NW, srcY - 8, X.edge, cy, TC.orange, orangeItems, { label: '프록시', labelDy: -12 });
      edge(X.edge + NW, cy, hx(0), inY - 6, TC.orange, orangeItems, { label: hasTunnel ? '터널' : null, labelDy: -8 });
    }
    if (grayItems.length) {
      const by = Y(directY);
      const bad = M.tunnelOnly;
      const tx = bad ? X.caddy : hx(0);
      const ty = bad ? Y(pin443) + 10 : inY + 8;
      const d = `M${X.src + NW} ${srcY + 10} C${X.src + NW + 60} ${by} ${tx - 60} ${by} ${tx} ${ty}`;
      edge(0, 0, 0, 0, bad ? TC.danger : TC.gray, grayItems, { d, dashed: true, static: bad });
      label((X.src + NW + tx) / 2, by - 14, bad ? 'DNS only · 터널로 불가' : (use('cloudflare') ? 'DNS only · 직접 연결' : '직접 연결'), bad ? TC.danger : TC.gray, grayItems);
    }
    const lastHop = M.hops[M.hops.length - 1];
    edge(hx(lastI) + HW, inY, X.caddy, Y(pin443), pw ? TC.warn : TC.blue, pubItems, { label: lastHop && lastHop.kind === 'tunnel' ? null : `:${exPort}`, labelDy: -10 });
  }

  // ---- private path: tailnet devices → (devices marked tailnet) → Tailscale / VPN on this host → Caddy :8443
  if (ts) {
    const cy = Y(pin8443);
    const tw = warnAt('ts').length > 0;
    const hp = M.tsHostPort || M.tsPort;
    const wire = M.pk === 'vpn' || !use('tailscale') ? 'VPN' : 'WireGuard';
    node(X.src, cy, NW, NH, { title: P ? P.src : (use('tailscale') ? 'Tailscale 기기' : '사설 접속 기기'), sub: use('tailscale') ? 'tailnet 안' : 'VPN 안', iconName: 'devices', color: TC.ts, list: tsItems });
    if (viaHops) {
      const ty = rY + tsDy;
      edge(X.src + NW, cy, hx(tsHopIdx[0]), ty, TC.ts, tsItems, { label: wire, labelDy: -10 });
      for (let k = 1; k < tsHopIdx.length; k++) {
        const a = tsHopIdx[k - 1], b = tsHopIdx[k];
        hop(hx(a) + HW, ty, hx(b), ty, TC.ts, tsItems, { over: b - a > 1 });
      }
      const exitI = tsHopIdx[tsHopIdx.length - 1];
      hop(hx(exitI) + HW, ty, X.tsd, cy, TC.ts, tsItems, { over: exitI < lastI });
    } else {
      edge(X.src + NW, cy, X.tsd, cy, TC.ts, tsItems, { label: wire, labelDy: -12 });
    }
    const TW = NW + 10;
    if (!P) {
      node(X.tsd, cy, TW, NH, { title: use('tailscale') ? 'Tailscale 미설정' : '사설 경로 없음', sub: '눌러서 추가', iconName: 'question', color: use('tailscale') ? TC.gray : TC.warn, list: tsItems, unknown: true, edit: 'priv',
        title2: use('tailscale') ? `${privName()} 서비스에 어떻게 들어오는지(tailscale serve, Tailscale IP 직접, 다른 VPN) 눌러서 추가하세요.\n예: tailscale serve → :${hp}` : 'Tailscale을 쓰지 않습니다. VPN 등 다른 사설 경로가 있으면 눌러서 추가하세요.' });
    } else {
      const sub = M.pk === 'ts_serve' ? `:443 → :${hp}` : M.pk === 'ts_direct' ? `${clip(set.tailscaleIp || '100.x', 13)}:${hp}` : `→ :${hp}`;
      const note = (set.topoPrivNote || '').trim();
      node(X.tsd, cy, TW, NH + (note ? 20 : 0), {
        title: clip(set.topoPrivName || P.name, 15), sub, iconName: P.icon, color: tw ? TC.warn : TC.ts, list: tsItems, edit: 'priv',
        title2: `${P.label} — 이 서버에서 실행\n${sub}${note ? `\n${note}` : ''}\n(눌러서 수정·삭제)`,
        extra: note ? (g) => pill(g, 12, NH - 4, clip(note, 16), TC.ts, false) : null,
      });
    }
    edge(X.tsd + TW, cy, X.caddy, cy, tw ? TC.warn : TC.ts, tsItems);
  }

  // ---- CrowdSec loop (logs → decisions → Cloudflare list)
  if (csOn) {
    const cx = X.router, cy = 54;
    node(cx, cy, NW + 20, NH, { title: 'CrowdSec', sub: set.crowdsecSync ? '차단 → Cloudflare' : '분석만', iconName: 'radar', color: TC.danger, list: orangeItems, title2: 'mTLS 사이트 접근 로그(실제 IP)를 분석해 공격 IP를 판정' });
    edge(X.caddy + CW / 2, boxTop, cx + NW + 20, cy, TC.danger, orangeItems, { dashed: true, static: true, d: `M${X.caddy + CW / 2} ${boxTop} C${X.caddy + CW / 2} ${cy} ${X.caddy + CW / 2} ${cy} ${cx + NW + 22} ${cy}`, label: '접근 로그', labelDy: 0 });
    if (set.crowdsecSync && cfY != null && orangeItems.length) {
      const ty = Y(cfY) - NH / 2 - 10;
      edge(cx, cy, X.edge + NW / 2, ty, TC.danger, orangeItems, { dashed: true, static: true, d: `M${cx} ${cy} C${X.edge + NW / 2} ${cy} ${X.edge + NW / 2} ${cy} ${X.edge + NW / 2} ${ty}`, label: '차단 목록' });
    }
  }

  // ---- groups + leaves
  for (const g of GROUPS) {
    const gy = Y(g.y);
    const pinY = Y(g.id === 'ts' ? pin8443 : pin443);
    node(X.group, gy, GW, GH, { title: `${g.label} (${g.items.length})`, sub: g.sub, iconName: g.icon, color: g.color, list: g.items });
    edge(X.caddy + CW, pinY, X.group, gy, g.color, g.items);
    for (const s of g.items) {
      const ly = Y(leafPos.get(s.id));
      const prot = !s.dnsOnly && s.authelia && s.authelia.enabled;
      edge(X.group + GW, gy, X.leaf, ly, g.color, [s], { dashed: s.dnsOnly, static: !alive(s) });
      if (prot) {
        const gx = X.leaf - 40;
        gLabels.append(sv('g', { class: `gate k-${s.id}`, transform: `translate(${gx} ${ly})` },
          sv('title', null, `Authelia ${s.authelia.policy === 'one_factor' ? '1단계' : '2단계'} 로그인${(s.authelia.groups || []).length ? ` · ${(s.authelia.groups || []).join(', ')}` : ''}`),
          sv('circle', { r: 13, fill: TC.surfaceAccent, stroke: TC.accent, 'stroke-width': 1.5, filter: 'url(#topo-glow)' }),
          topoIcon('shield', 0, 0, 15, TC.accent)));
      }
      const leaf = sv('g', {
        class: `node leaf ${s.enabled ? '' : 'dim'} k-${s.id}`, transform: `translate(${X.leaf} ${ly - LH / 2})`, tabindex: 0, role: 'button',
        'aria-label': `${fqdn(s.subdomain)} 편집${s.enabled ? '' : ' (중지됨)'}`, 'data-key': `k-${s.id}`,
      },
      sv('title', null, `${fqdn(s.subdomain)}${s.upstream ? ` → ${s.upstream}` : ''}${healthOf(s) ? `\n${healthOf(s).text} — ${healthOf(s).title}` : ''}${s.notes ? `\n${s.notes}` : ''}`),
      sv('rect', { class: 'node-bg', width: LW, height: LH, rx: 13, stroke: (healthOf(s) || {}).st === 'down' ? TC.danger : g.color, 'stroke-opacity': (healthOf(s) || {}).st === 'down' ? 0.95 : null }),
      sv('rect', { class: 'node-shine', x: 1, y: 1, width: LW - 2, height: LH / 2, rx: 12 }),
      sv('circle', { cx: 27, cy: LH / 2, r: 17, fill: `url(#gr-${colorKey(g.color)})`, 'fill-opacity': 0.2, stroke: g.color, 'stroke-opacity': 0.55 }),
      topoIcon(serviceIcon(s), 27, LH / 2, 19, g.color),
      (() => {
        const hx = healthOf(s);
        if (!hx) return null;
        const c = hx.st === 'ok' ? TC.ok : hx.st === 'down' ? TC.danger : TC.muted;
        return sv('g', { class: 'hdot' }, sv('title', null, hx.title), sv('circle', { cx: 40, cy: 14, r: 5.5, fill: c, stroke: TC.surface, 'stroke-width': 2 }));
      })(),
      sv('text', { x: 52, y: 22, class: 'n-title' }, clip(s.subdomain === '@' ? set.domain : s.subdomain, 18)),
      sv('text', { x: 52, y: 39, class: 'n-sub mono' }, s.dnsOnly ? 'DNS 레코드만' : clip(s.upstream || '(사용자 지시어)', 22)));
      // badges (right side)
      const bs = [];
      const hl = healthOf(s);
      if (hl && hl.st === 'down') bs.push(['응답 없음', TC.danger]);
      if (!s.enabled) bs.push(['중지', TC.gray]);
      if (s.waf && !s.dnsOnly) bs.push([s.waf === 'block' ? 'WAF' : 'WAF 탐지', s.waf === 'block' ? TC.danger : TC.warn]);
      if (prot) bs.push([s.authelia.policy === 'one_factor' ? '1FA' : '2FA', TC.accent]);
      if (s.id === set.secSelfService) bs.unshift(['길목', TC.accent]);
      let bx = LW - 8;
      for (const [t, c] of bs.reverse()) {
        const w = textW(t, 10.5) + 14;
        bx -= w;
        pill(leaf, bx, 8, t, c, true);
        bx -= 4;
      }
      const open = () => onOpen(s);
      leaf.addEventListener('click', open);
      leaf.addEventListener('keydown', (e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); open(); } });
      gNodes.append(leaf);
    }
  }

  // ---- Gilmok itself: the admin app on this host. It is the source of the settings above:
  //      it writes the Caddyfile and reloads Caddy, Authelia's access_control and users, Cloudflare
  //      DNS / WAF rules. People reach it directly on the host, or remotely through its own site.
  let hostExtraBottom = 0;
  {
    const selfSvc = all.find((x) => x.id === set.secSelfService) || null;
    const contentBottom = Math.max(...[...leafPos.values()].map((v) => Y(v) + LH / 2), caddyBox.bottom);
    const GLW = 196, GLH = 76, ROWB = 96;
    const gilX = X.caddy, gilY = contentBottom + 100;
    const selfName = (info && info.selfName) || (st.security && st.security.selfName) || '';
    const direct = ((info && info.selfPorts) || []).filter((x) => x.ctrPort === 8080);
    const VIOLET = TC.accent;
    // d = path; (lx, ly) = where its label sits (paths given as `d` carry no endpoints of their own)
    const manage = (d, lbl, lx, ly) => { edge(0, 0, 0, 0, VIOLET, [], { d, dashed: true, static: true }); if (lbl) label(lx, ly, lbl, VIOLET); };
    const toSettings = () => gotoTab('gilmok', typeof can === 'function' && can('accounts') ? 'accounts' : 'me');

    // the node
    const gil = node(gilX, gilY, GLW, GLH, {
      title: '길목', sub: selfName ? `${clip(selfName, 14)} · 관리 화면` : '관리 화면', iconName: 'gilmok', color: VIOLET,
      title2: `길목 — 이 구성의 설정 원본입니다.\n${[use('caddy') ? 'Caddyfile을 만들고 Caddy를 reload' : null, use('authelia') ? 'Authelia 접근 정책·사용자' : null, use('cloudflare') ? 'Cloudflare DNS·WAF 규칙' : null, use('crowdsec') ? 'CrowdSec 차단 동기화' : null].filter(Boolean).join(' · ')}\n로그인: 계정 + (선택) 2단계 인증 — 눌러서 계정·접근 보안`,
      extra: (g) => {
        let xx = 12;
        const yy = GLH - 26;
        xx += pill(g, xx, yy, '계정·2단계', VIOLET, true) + 4;
        pill(g, xx, yy, selfSvc ? '원격 접속' : '서버에서만', selfSvc ? TC.ok : TC.gray, !!selfSvc);
      },
    });
    gil.classList.add('editable', 'gil-node');
    gil.setAttribute('tabindex', '0');
    gil.setAttribute('role', 'button');
    gil.setAttribute('aria-label', '길목 — 계정·접근 보안 설정 열기');
    gil.addEventListener('click', toSettings);
    gil.addEventListener('keydown', (e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); toSettings(); } });

    // manages Caddy (up)
    {
      const cx = X.caddy + CW / 2;
      manage(`M${cx} ${gilY - GLH / 2} L${cx} ${caddyBox.bottom + 4}`, 'Caddyfile · reload', cx, (gilY - GLH / 2 + caddyBox.bottom) / 2);
    }
    // manages Authelia (right)
    if (use('authelia')) {
      const ax = X.group + 64;
      node(ax, gilY, GW, NH, { title: 'Authelia', sub: `로그인 관문 · ${authN}개 사이트`, iconName: 'shield', color: VIOLET,
        title2: `Authelia (${set.autheliaContainer || ''}) — 길목이 access_control과 users_database.yml을 씁니다` });
      manage(`M${gilX + GLW} ${gilY} L${ax - 2} ${gilY}`, '정책·사용자', (gilX + GLW + ax) / 2, gilY - 16);
    }
    // manages Cloudflare over its API (down-left)
    if (use('cloudflare')) {
      const cy = gilY + ROWB;
      node(X.edge, cy, NW, NH, { title: 'Cloudflare API', sub: 'DNS · WAF 규칙', iconName: 'cloud', color: TC.orange,
        title2: `길목이 API 토큰으로 ${set.domain || '도메인'} 존의 DNS 레코드와 WAF 규칙을 바꿉니다${use('crowdsec') && set.crowdsecSync ? ' (CrowdSec 차단 목록 포함)' : ''}` });
      manage(`M${gilX + 30} ${gilY + GLH / 2} C${gilX + 30} ${cy} ${gilX + 30} ${cy} ${X.edge + NW + 2} ${cy}`, use('crowdsec') && set.crowdsecSync ? 'DNS·WAF·차단 목록' : 'DNS·WAF 규칙', (X.edge + NW + gilX + 30) / 2, cy - 14);
      hostExtraBottom = Math.max(hostExtraBottom, cy + NH / 2);
    }
    // people reach it: directly on the host …
    {
      const txt = direct.length ? `호스트 ${bindText(direct)}` : '호스트 포트 (예: 127.0.0.1:8088)';
      node(X.src, gilY, NW, NH, { title: '이 서버에서', sub: clip(txt, 21), iconName: 'host', color: TC.gray,
        title2: `길목이 도는 서버에서 바로 엽니다 — ${txt}. 프록시·SSO가 고장 나도 쓰는 비상 통로입니다.` });
      edge(X.src + NW, gilY, gilX, gilY, TC.gray, [], { static: true, label: '직접 접속', labelDy: -12 });
    }
    // … or remotely through its own site (a service whose upstream is this container)
    if (selfSvc && leafPos.has(selfSvc.id)) {
      const ly = Y(leafPos.get(selfSvc.id));
      const tx = gilX + GLW - 24, ty = gilY - GLH / 2;
      const d = `M${X.leaf} ${ly + 10} C${X.leaf - 70} ${ly + 10} ${tx} ${ty - 80} ${tx} ${ty - 2}`;
      edge(0, 0, 0, 0, TC.ok, [selfSvc], { d, dashed: true });
      label(tx + 46, ty - 40, '원격 접속', TC.ok, [selfSvc]);
    } else if (use('caddy')) {
      const nx = X.leaf, ny = gilY;
      const g = node(nx, ny, LW - 40, NH, { title: '원격 접속 없음', sub: '선택 — 눌러서 만들기', iconName: 'question', color: TC.gray, unknown: true,
        title2: '휴대폰·다른 PC에서 길목을 쓰려면 길목용 사이트를 만듭니다 (설정 탭 › 접근 보안 › 길목 사이트 만들기).' });
      g.classList.add('editable');
      g.setAttribute('tabindex', '0');
      g.setAttribute('role', 'button');
      const goSec = () => gotoTab('gilmok', 'security');
      g.addEventListener('click', goSec);
      g.addEventListener('keydown', (e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); goSec(); } });
      if (use('authelia')) {
        // keep clear of the Authelia node on the same row
        g.setAttribute('transform', `translate(${nx + 20} ${ny - NH / 2})`);
      }
    }
    hostExtraBottom = Math.max(hostExtraBottom, gilY + GLH / 2);
    const newH = hostExtraBottom + 50;
    if (newH > height) svg.setAttribute('viewBox', `0 0 ${width} ${newH}`);
  }

  // ---- host boundary: everything from Caddy to the services runs on this host
  {
    const leafTops = [...leafPos.values()].map((v) => Y(v) - LH / 2);
    const rTop = Math.min(boxTop, ...leafTops) - 40;
    const rBot = Math.max(...[...leafPos.values()].map((v) => Y(v) + LH / 2), caddyBox.bottom, hostExtraBottom) + 16;
    const rx = (ts ? X.tsd : X.caddy) - 22; // the Tailscale / VPN endpoint runs on this host too
    const hostName = (set.topoHostName || '').trim();
    const hostNote = (set.topoHostNote || '').trim();
    const env = info && info.dockerOs ? info.dockerOs : '';
    const lbl = sv('g', { class: `host-label ${onEdit ? 'editable' : ''}`, transform: `translate(${rx + 16} ${rTop + 8})`, tabindex: onEdit ? 0 : null, role: onEdit ? 'button' : null, 'aria-label': '호스트 정보 입력' },
      sv('title', null, `${hostName || '호스트 이름 미설정'}${hostNote ? `\n${hostNote}` : ''}${env ? `\nDocker: ${env}` : ''}${info && info.dockerDesktop ? `\nDocker Desktop은 외부 접속자 IP를 브리지 게이트웨이로 바꿉니다${use('cloudflare') ? ' — IP 기반 차단은 Cloudflare 엣지에서 합니다.' : ' — IP 기반 차단은 이 서버에서는 쓸 수 없습니다.'}` : ''}`),
      topoIcon('host', 9, 10, 17, hostName ? TC.accent : TC.gray),
      sv('text', { x: 24, y: 15, class: hostName ? 'h-title' : 'h-title unknown' }, hostName ? clip(hostName, 22) : '이 서버 (눌러서 이름 추가)'),
      sv('text', { x: 24 + textW(hostName ? clip(hostName, 22) : '이 서버 (눌러서 이름 추가)', 13) + 12, y: 15, class: 'h-sub' }, [hostNote, env].filter(Boolean).map((x) => clip(x, 26)).join(' · ')));
    if (onEdit) {
      lbl.addEventListener('click', () => onEdit('host'));
      lbl.addEventListener('keydown', (e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); onEdit('host'); } });
    }
    gBack.append(sv('rect', { class: 'host-region', x: rx, y: rTop, width: width - rx - 8, height: rBot - rTop, rx: 22 }), lbl);
  }

  // ---- hover / focus highlight of a service's whole path
  const hl = (key) => {
    svg.classList.toggle('focus', !!key);
    for (const el of svg.querySelectorAll('.hl')) el.classList.remove('hl');
    if (key) for (const el of svg.getElementsByClassName(key)) el.classList.add('hl');
  };
  for (const leaf of svg.querySelectorAll('.leaf')) {
    leaf.addEventListener('mouseenter', () => hl(leaf.dataset.key));
    leaf.addEventListener('focus', () => hl(leaf.dataset.key));
    leaf.addEventListener('mouseleave', () => hl(null));
    leaf.addEventListener('blur', () => hl(null));
  }

  // ---- summary + legend
  const en = all.filter((s) => s.enabled);
  const sum = h('div', { class: 'topo-sum' },
    h('span', { class: 'badge' }, `서비스 ${en.length}/${all.length}`),
    (() => { const hs = all.map(healthOf).filter(Boolean); const down = hs.filter((x) => x.st === 'down').length; return hs.length ? h('span', { class: `badge ${down ? 'danger' : 'ok'}` }, down ? `✗ 응답 없음 ${down}` : `● 모두 정상 ${hs.length}`) : null; })(),
    h('span', { class: 'badge public' }, `공개 ${en.filter((s) => s.exposure === 'public').length}`),
    privOn() ? h('span', { class: 'badge ts' }, `${use('tailscale') ? 'Tailscale' : '사설'} ${en.filter((s) => s.exposure !== 'public').length}`) : null,
    use('authelia') ? h('span', { class: 'badge accent' }, icon('shield'), `Authelia ${authN}`) : null,
    wafN ? h('span', { class: 'badge danger' }, `WAF ${wafN}`) : null,
    set.crowdsecEnabled ? h('span', { class: 'badge danger' }, set.crowdsecSync ? 'CrowdSec → Cloudflare' : 'CrowdSec (분석만)') : null,
    set.cfAsnRule ? h('span', { class: 'badge' }, icon('cloud', 'fill cloud-orange'), `ISP(ASN) 규칙 · ${CF_ACTION[set.cfAsnAction] || set.cfAsnAction}`) : null);
  const leg = (cls, text) => h('span', { class: 'leg' }, h('i', { class: cls, 'aria-hidden': 'true' }), text);
  const legend = h('div', { class: 'topo-legend', 'aria-label': '범례' },
    use('cloudflare') ? leg('l-orange', 'Proxied (Cloudflare 경유)') : null, leg('l-gray', use('cloudflare') ? 'DNS only (직접 연결)' : '직접 연결'), privOn() ? leg('l-ts', use('tailscale') ? 'Tailscale' : '사설 경로') : null,
    use('authelia') ? leg('l-gate', 'Authelia 로그인 관문') : null, use('crowdsec') ? leg('l-cs', 'CrowdSec 로그·차단') : null, leg('l-gil', '길목이 관리'), leg('l-ok', '연결 정상'), leg('l-down', '응답 없음'),
    h('span', { class: 'hint' }, '서비스에 마우스를 올리면 경로가 강조되고, 누르면 편집합니다. 공유기·Tailscale·호스트 칸도 눌러서 고칩니다.'));
  const notes = [];
  if (M.unknownEdge || M.unknownPriv) {
    notes.push(callout('', h('b', null, '길목이 알 수 없는 부분은 「?」로 그렸습니다 — 그 칸을 눌러 바로 추가하세요.'),
      h('span', { class: 'small' }, '공유기·방화벽·터널, Tailscale 경로, 호스트 이름은 구성도에서 눌러 추가·수정·삭제합니다. 포트는 Caddy 컨테이너에서 자동으로 읽습니다.')));
  }
  if (M.warns.length) notes.push(callout('warn', h('b', null, `구성 확인 ${M.warns.length}건`), h('ul', null, M.warns.map((x) => h('li', null, x.text)))));
  return h('div', { class: 'glass topo' }, sum, notes.length ? h('div', { class: 'stack topo-notes' }, notes) : null, h('div', { class: 'topo-scroll' }, svg), legend);
}

// ======================================================================= panel + wizard

/** Services tab › 구성도: loads detected facts (/api/topology) and draws. */
function topologyPanel(onOpen) {
  const box = h('div', null, spinnerRow('구성 정보를 읽는 중…'));
  const draw = async (force) => {
    if (force || !S.topoInfo) {
      try { S.topoInfo = await api('GET', '/api/topology'); } catch (ex) { S.topoInfo = null; toast(`구성 감지 실패: ${ex.message}`, 'err'); }
    }
    if (!box.isConnected && !force) return;
    box.replaceChildren(topologyView(onOpen, S.topoInfo, (focus) => openEdgeWizard(S.topoInfo, focus, () => draw(false))));
  };
  draw(false);
  return box;
}

/**
 * Edit ONE part of the map in place — display only; Caddy and DNS are not touched.
 *   'hop:<i>' / 'hop:new'  a device in front of this host (chain, internet side first)
 *   'priv'                 the Tailscale / VPN endpoint on this host
 *   'host'                 this server's name
 */
function openEdgeWizard(info, focus, onSaved) {
  const set = settings();
  const hops = topoHops(set).map((x) => ({ ...x }));
  let which = String(focus || '');
  if (which === 'edge') which = hops.length ? 'hop:0' : 'hop:new';
  if (!/^hop:(new|\d+)$/.test(which) && which !== 'priv' && which !== 'host') which = 'hop:new';
  const pubPort = (info && info.publicPort) || 443;
  const tsPort = set.tailscalePort || 8443;
  const pubB = bindsFor(info, pubPort);
  const tsB = bindsFor(info, tsPort);
  const detectedFwd = (pubB.find((b) => !isLoop(b.hostIp)) || pubB[0] || {}).hostPort || 0;

  const ico = (name, color, size = 22) => {
    const s = sv('svg', { viewBox: `0 0 ${size} ${size}`, width: size, height: size, class: 'wz-ico', 'aria-hidden': 'true' });
    s.append(topoIcon(name, size / 2, size / 2, size - 2, color));
    return s;
  };
  const chip = (label, value, warn) => h('span', { class: `wz-chip ${warn ? 'warn' : ''}` }, h('small', null, label), h('b', { class: 'mono' }, value));
  const choices = (name, opts, value) => {
    const wrap = h('div', { class: 'choice-cards wz-choices', role: 'radiogroup' }, opts.filter(Boolean).map((o) => h('label', { class: 'choice' },
      h('input', { type: 'radio', name, value: o.value, checked: (value || '') === o.value }),
      h('span', { class: 'ch-body' }, h('span', { class: 'ch-head' }, ico(o.icon, o.color || TC.accentText), h('b', null, o.label)), h('small', null, o.desc)))));
    Object.defineProperty(wrap, 'value', { get: () => (wrap.querySelector('input:checked') || {}).value || '' });
    return wrap;
  };
  const flowBox = () => h('div', { class: 'wz-flow', 'aria-live': 'polite' });
  const fnode = (icon, color, title, sub) => h('span', { class: 'wz-node' }, ico(icon, color, 18), h('span', null, h('b', null, title), sub ? h('small', { class: 'mono' }, sub) : null));
  const arrow = () => h('span', { class: 'wz-arrow', 'aria-hidden': 'true' }, '→');
  const hopSub = (x) => (x.kind === 'tunnel' ? '아웃바운드' : x.extPort && x.fwdPort ? `:${x.extPort} → :${x.fwdPort}` : x.extPort ? `:${x.extPort}` : x.fwdPort ? `→ :${x.fwdPort}` : '');
  const warnBox = h('div');
  let body, read, sync, has, clearPatch, title;

  if (which.startsWith('hop:')) {
    const isNew = which === 'hop:new';
    const idx = isNew ? hops.length : Math.min(parseInt(which.slice(4), 10), hops.length - 1);
    const cur = isNew ? { kind: '', name: '', note: '', extPort: 0, fwdPort: 0, tailnet: false } : hops[idx];
    title = isNew ? '앞단 장비 추가' : `앞단 장비 ${idx + 1} — ${hopName(cur)}`;
    has = !isNew;
    const kind = choices(uid('hk'), Object.entries(HOP_KINDS).map(([value, K]) => ({ value, icon: K.icon, label: K.label, desc: K.desc, color: value === 'tunnel' ? TC.orange : TC.blue })), cur.kind);
    const name = h('input', { type: 'text', value: cur.name || '', autocomplete: 'off', maxlength: '40' });
    const note = h('input', { type: 'text', value: cur.note || '', autocomplete: 'off', maxlength: '80' });
    const ext = h('input', { type: 'number', min: '1', max: '65535', class: 'wz-port', value: cur.extPort || '', placeholder: '443', 'aria-label': '받는 포트' });
    const fwd = h('input', { type: 'number', min: '1', max: '65535', class: 'wz-port', value: cur.fwdPort || '', placeholder: idx === hops.length - (isNew ? 0 : 1) ? String(detectedFwd || 443) : '443', 'aria-label': '넘기는 포트' });
    const portRow = h('div', { class: 'field' }, h('span', { class: 'field-label' }, '포트'),
      h('div', { class: 'wz-ports' }, h('span', { class: 'muted small' }, '받는 포트'), ext, h('span', { class: 'wz-arrow' }, '→'), h('span', { class: 'muted small' }, '넘기는 포트'), fwd));
    const tailnet = switchCtl(`${use('tailscale') ? 'Tailscale' : 'VPN'} 연결도 이 장비를 지남`, isNew ? false : !!cur.tailnet, '공유기·방화벽은 보통 지나갑니다. 로드밸런서·프록시·터널은 보통 지나지 않습니다.');
    tailnet.hidden = !privOn();
    // position in the chain
    const total = hops.length + (isNew ? 1 : 0);
    const order = h('select', { 'aria-label': '순서' }, Array.from({ length: total }, (_, i) => h('option', { value: String(i), selected: i === idx },
      `${i + 1}번째${i === 0 ? ' (인터넷 쪽)' : ''}${i === total - 1 ? ' (이 서버 쪽)' : ''}`)));
    const orderField = field('순서', order, '인터넷에서 이 서버로 가는 순서');
    orderField.hidden = total < 2;
    let kindTouched = !isNew;
    const fields = h('div', { class: 'wz-fields' }, h('div', { class: 'grid-2' }, field('이름', name), field('메모 (구성도에 작게 표시)', note)), portRow, tailnet, orderField);
    const fl = flowBox();
    const detected = h('div', { class: 'wz-chips' },
      chip(`Caddy :${pubPort} → 호스트`, pubB.length ? bindText(pubB) : '게시 안 됨', !pubB.length), chip('공인 IP', (info && info.publicIp) || '—'));
    const draft = () => ({ kind: kind.value, name: name.value.trim(), note: note.value.trim(), extPort: parseInt(ext.value, 10) || 0, fwdPort: parseInt(fwd.value, 10) || 0, tailnet: tailnet.input.checked });
    const chainWith = () => {
      const list = hops.filter((_, i) => isNew || i !== idx);
      list.splice(Math.min(parseInt(order.value, 10) || 0, list.length), 0, draft());
      return list;
    };
    sync = () => {
      const K = HOP_KINDS[kind.value];
      fields.hidden = !K;
      portRow.hidden = !K || !K.ports;
      name.placeholder = K ? K.exName : '';
      note.placeholder = K ? K.exNote : '';
      fl.replaceChildren(fnode('globe', TC.blue, '인터넷'), arrow(),
        ...chainWith().flatMap((x, i, arr) => {
          const KK = HOP_KINDS[x.kind];
          const mine = i === Math.min(parseInt(order.value, 10) || 0, arr.length - 1);
          const n = KK ? fnode(KK.icon, x.kind === 'tunnel' ? TC.orange : mine ? TC.accentText : TC.blue, KK ? (x.name || KK.name) : '?', hopSub(x)) : fnode('question', TC.muted, '?', '종류를 고르세요');
          if (mine) n.classList.add('mine');
          return [n, arrow()];
        }),
        fnode('server', TC.accentText, 'Caddy', `호스트 ${pubB.length ? bindText(pubB) : `:${pubPort}`}`));
      warnBox.replaceChildren();
      const chain = chainWith();
      const last = chain[chain.length - 1];
      if (K && last && last.kind !== 'tunnel' && last.fwdPort && pubB.length && !pubB.some((b) => b.hostPort === last.fwdPort)) {
        warnBox.append(callout('warn', h('b', null, `포트가 맞지 않습니다 — 마지막 장비(${hopName(last)})는 :${last.fwdPort}로 넘기는데 Caddy는 호스트 ${bindText(pubB)}에 열려 있습니다.`)));
      }
    };
    kind.addEventListener('change', () => {
      const K = HOP_KINDS[kind.value];
      if (K && !kindTouched) tailnet.input.checked = !!K.tailnet; // sensible default for a new device
      kindTouched = true;
      sync();
    });
    for (const el of [name, ext, fwd, note]) el.addEventListener('input', sync);
    order.addEventListener('change', sync);
    tailnet.input.addEventListener('change', sync);
    read = () => {
      if (!kind.value) throw new Error('종류를 고르세요');
      return { topoHops: chainWith() };
    };
    clearPatch = { topoHops: hops.filter((_, i) => i !== idx) };
    body = h('div', { class: 'stack wz' }, detected, kind, fields, fl, warnBox);
  } else if (which === 'priv') {
    title = `${privName()} 경로`;
    has = !!set.topoPrivKind;
    const kind = choices(uid('pk'), [
      use('tailscale') && { value: 'ts_serve', icon: 'tailnet', label: 'tailscale serve', desc: `Tailscale :443을 이 서버 :${tsPort}로 넘김`, color: TC.ts },
      use('tailscale') && { value: 'ts_direct', icon: 'tailnet', label: 'Tailscale IP 직접', desc: `기기에서 ${set.tailscaleIp || '100.x'}:${tsPort}로 바로 접속`, color: TC.ts },
      { value: 'vpn', icon: 'lock', label: '다른 VPN', desc: 'WireGuard·OpenVPN 등으로 접속', color: TC.ts },
    ], set.topoPrivKind);
    const name = h('input', { type: 'text', value: set.topoPrivName || '', autocomplete: 'off' });
    const note = h('input', { type: 'text', value: set.topoPrivNote || '', autocomplete: 'off' });
    const fields = h('div', { class: 'wz-fields' }, h('div', { class: 'grid-2' }, field('이름', name), field('메모', note)),
      h('p', { class: 'hint' }, '중간 장비(공유기·방화벽 등)를 지나는지는 각 앞단 장비의 「연결도 이 장비를 지남」에서 정합니다.'));
    const fl = flowBox();
    const detected = h('div', { class: 'wz-chips' },
      chip(`Caddy :${tsPort} → 호스트`, tsB.length ? bindText(tsB) : '게시 안 됨', !tsB.length), use('tailscale') ? chip('Tailscale IP', set.tailscaleIp || '—') : null);
    sync = () => {
      const pk = kind.value;
      const P = PRIV_KINDS[pk];
      fields.hidden = !P;
      name.placeholder = P ? `예: ${P.name}` : '';
      note.placeholder = P ? P.exNote : '';
      const tsHost = tsB.length ? bindText(tsB) : `:${tsPort}`;
      const via = hops.filter((x) => x.tailnet).flatMap((x) => [fnode(HOP_KINDS[x.kind].icon, TC.blue, hopName(x), '지나감'), arrow()]);
      fl.replaceChildren(fnode('devices', TC.ts, P ? P.src : '기기'), arrow(), ...via,
        P ? fnode(P.icon, TC.ts, name.value.trim() || P.name, pk === 'ts_serve' ? `:443 → ${tsHost}` : pk === 'ts_direct' ? `${set.tailscaleIp || '100.x'}:${tsPort}` : `→ ${tsHost}`) : fnode('question', TC.muted, '?', '고르세요'),
        arrow(), fnode('server', TC.accentText, 'Caddy', `호스트 ${tsHost}`));
      warnBox.replaceChildren();
      if (pk === 'ts_direct' && tsB.length && tsB.every((b) => isLoop(b.hostIp))) {
        warnBox.append(callout('warn', h('b', null, `Caddy :${tsPort}가 ${bindText(tsB)}에만 열려 있어 Tailscale IP로 직접 들어올 수 없습니다 — 「tailscale serve」가 맞을 수 있습니다.`)));
      } else if (pk === 'ts_serve' && tsB.some((b) => anyIp(b.hostIp))) {
        warnBox.append(callout('warn', h('b', null, `Caddy :${tsPort}가 모든 주소(${bindText(tsB)})에 열려 있어 LAN에서도 들어올 수 있습니다. 127.0.0.1로만 여는 것을 권장합니다.`)));
      }
    };
    kind.addEventListener('change', sync);
    name.addEventListener('input', sync);
    read = () => {
      if (!kind.value) throw new Error('종류를 고르세요');
      return { topoPrivKind: kind.value, topoPrivName: name.value.trim(), topoPrivNote: note.value.trim() };
    };
    clearPatch = { topoPrivKind: '', topoPrivName: '', topoPrivNote: '' };
    body = h('div', { class: 'stack wz' }, detected, kind, fields, fl, warnBox);
  } else {
    title = '이 서버 (호스트)';
    has = !!((set.topoHostName || '').trim() || (set.topoHostNote || '').trim());
    const name = h('input', { type: 'text', value: set.topoHostName || '', autocomplete: 'off', placeholder: '예: home-nas' });
    const note = h('input', { type: 'text', value: set.topoHostNote || '', autocomplete: 'off', placeholder: '예: 192.168.1.10 · Windows 11' });
    sync = () => {};
    read = () => {
      if (!name.value.trim() && !note.value.trim()) throw new Error('이름이나 메모를 입력하세요 (지우려면 「삭제」)');
      return { topoHostName: name.value.trim(), topoHostNote: note.value.trim() };
    };
    clearPatch = { topoHostName: '', topoHostNote: '' };
    body = h('div', { class: 'stack wz' },
      h('div', { class: 'wz-chips' }, chip('Docker', (info && info.dockerOs) || '—'), chip('공인 IP', (info && info.publicIp) || '—')),
      h('div', { class: 'grid-2' }, field('이름', name), field('메모 (LAN IP, OS 등)', note)));
  }
  sync();

  const errEl = h('p', { class: 'form-error', role: 'alert', hidden: true });
  const save = h('button', { type: 'button', class: 'btn primary' }, has ? '저장' : '추가');
  const cancel = h('button', { type: 'button', class: 'btn ghost' }, '취소');
  const del = has ? h('button', { type: 'button', class: 'btn danger' }, '삭제') : null;
  const d = openDialog({
    title, body: h('div', { class: 'stack' }, errEl, body, h('p', { class: 'hint' }, '구성도에 그리는 데만 씁니다. Caddy·DNS 설정은 바뀌지 않습니다.')),
    footer: [del, h('span', { class: 'spacer' }), cancel, save],
  });
  cancel.addEventListener('click', () => d.close());
  setTimeout(() => { const f = body.querySelector('input:checked') || body.querySelector('input'); if (f) f.focus(); }, 50);
  const run = (btn, patch, msg) => busy(btn, async () => {
    errEl.hidden = true;
    try {
      // the single-device fields of older versions are replaced by the chain
      const p = typeof patch === 'function' ? patch() : patch;
      if (p.topoHops) Object.assign(p, { topoEdgeKind: '', topoEdgeName: '', topoEdgeNote: '', topoEdgeExtPort: 0, topoEdgeFwdPort: 0 });
      await saveSettingsPatch(p);
      d.close();
      toast(msg);
      onSaved && onSaved();
    } catch (ex) { errEl.textContent = ex.message; errEl.hidden = false; }
  });
  save.addEventListener('click', () => run(save, read, has ? '구성도 정보를 저장했습니다' : '구성도에 추가했습니다'));
  if (del) del.addEventListener('click', () => run(del, clearPatch, '구성도에서 삭제했습니다'));
}
