'use strict';
/* Gilmok — who sent a request (IP · country) and the Caddy country block (Caddy tab › 보호 › 국가 차단). */

/** country name in the UI language ("KR" → 대한민국); the code itself when unknown */
const GEO_NAMES = (() => { try { return new Intl.DisplayNames([typeof gmLocale === 'function' ? gmLocale() : 'ko'], { type: 'region' }); } catch { return null; } })();
function geoName(cc) {
  if (!cc) return '';
  try { return (GEO_NAMES && GEO_NAMES.of(cc)) || cc; } catch { return cc; }
}

/** "1.2.3.4 · KR 대한민국" with the source as a tooltip; Docker Desktop's gateway shows as unknown */
const VIA_TEXT = {
  cf: 'Cloudflare가 전달한 접속자 주소·국가',
  direct: 'Caddy가 직접 본 주소 (국가는 GeoIP DB)',
  lan: '내부망 주소',
  tailnet: 'Tailscale 주소',
  hidden: 'Docker Desktop(Windows·macOS)은 외부 접속자 주소를 Docker 내부 주소로 바꿔서 실제 접속자를 알 수 없습니다. Proxied 사이트는 Cloudflare가 알려 준 주소가 기록됩니다.',
};
/** where the client is, in words: country name, or what kind of address it is */
function clientPlace(x) {
  if (x.cc) return geoName(x.cc);
  return x.via === 'tailnet' ? 'Tailscale' : x.via === 'lan' ? '내부망' : '국가 미상';
}
/** "211.222.111.111 | 중국" on one line; the source of the address as a tooltip */
function clientCell(x) {
  if (!x || !x.ip) return h('span', { class: 'muted' }, '—');
  if (x.via === 'hidden') return h('span', { class: 'client-cell muted', title: `${x.ip} — ${CLIENT_WHY}` }, '알 수 없음 (Docker 내부 주소)');
  return h('span', { class: 'client-cell', title: [VIA_TEXT[x.via], x.cc ? `${geoName(x.cc)} (${x.cc})` : ''].filter(Boolean).join(' — ') },
    h('span', { class: 'mono' }, x.ip), h('span', { class: 'cc-sep', 'aria-hidden': 'true' }, '|'),
    h('span', { class: x.cc ? '' : 'muted' }, clientPlace(x)));
}
/** one line for tooltips: "1.2.3.4 | 대한민국" */
function clientText(x) {
  if (!x || !x.ip) return '';
  if (x.via === 'hidden') return '접속자 알 수 없음 (Docker 내부 주소)';
  return `${x.ip} | ${clientPlace(x)}`;
}

/** why some requests have no client address — a short line for tooltips; the box below explains it for this server */
const CLIENT_WHY = 'Docker가 포트를 전달하면서 접속자 주소를 Docker 내부 주소(예: 172.18.0.1)로 바꿔, 실제 접속자 IP와 국가를 알 수 없습니다.';

/** how this server's Caddy gets client addresses (GET /api/client-env, cached 2 min) */
function clientEnv() {
  if (!S.clientEnvP || Date.now() - (S.clientEnvAt || 0) > 120_000) {
    S.clientEnvAt = Date.now();
    S.clientEnvP = api('GET', '/api/client-env').catch(() => ({ kind: 'unknown' }));
  }
  return S.clientEnvP;
}

/** the explanation for this server: { cause, fixes[], blocks } — blocks: what the Caddy country block can do here
 *  ("none" = blocks nothing, "v4" = IPv4 only, "all") */
function clientEnvText(env) {
  const nets = (env.networks || []).filter((n) => n !== 'bridge');
  const net = nets.length ? nets.join(', ') : 'bridge';
  switch (env.kind) {
    case 'desktop':
      return {
        cause: `이 서버의 Docker는 Docker Desktop${env.dockerOS ? ` (${env.dockerOS})` : ''}입니다. Docker Desktop은 컨테이너를 가상 머신 안에서 돌리고 바깥 연결을 대신 넘겨 주기 때문에, 모든 외부 접속자 주소가 Docker 내부 주소로 바뀝니다.`,
        fixes: ['서버 안에서는 고칠 방법이 없습니다.', '접속자를 알아야 하는 사이트는 Proxied로 바꾸세요 — Cloudflare가 실제 IP·국가를 알려 줍니다.', '국가 차단은 Cloudflare 국가 규칙이나 공유기의 국가 차단을 쓰세요.', '리눅스 서버의 Docker Engine으로 옮기면 실제 주소가 보입니다.'],
        blocks: 'none',
      };
    case 'rootless':
      return {
        cause: '이 서버의 Docker는 rootless 모드입니다. rootless의 기본 포트 전달 방식(RootlessKit builtin)은 접속자 주소를 바꿉니다.',
        fixes: ['포트 전달을 slirp4netns로 바꾸세요 — 환경변수 DOCKERD_ROOTLESS_ROOTLESSKIT_PORT_DRIVER=slirp4netns 로 Docker를 다시 시작 (속도는 조금 느려짐).', '또는 일반(rootful) Docker에서 Caddy를 실행하세요.', '접속자를 알아야 하는 사이트는 Proxied로 바꾸는 방법도 있습니다.'],
        blocks: 'none',
      };
    case 'ingress':
      return {
        cause: 'Caddy가 Docker Swarm 서비스로 실행되고, 포트가 라우팅 메시(ingress)로 게시돼 접속자 주소가 바뀝니다.',
        fixes: ['Caddy 서비스의 포트를 mode: host 로 게시하세요 (published: 443, target: 443, mode: host).'],
        blocks: 'none',
      };
    case 'bridge':
      return env.ipv6 ? {
        cause: `이 서버는 리눅스 Docker Engine이고 Caddy 네트워크(${net})에 IPv6도 켜져 있어, 외부 접속은 보통 실제 주소가 보입니다. 그래도 내부 주소로 기록되는 요청은 다음 중 하나입니다.`,
        fixes: ['같은 서버(또는 같은 Docker 네트워크)에서 Caddy로 보낸 요청 — 정상이며 외부 접속과 무관합니다.', 'Docker 데몬의 iptables가 꺼져 있으면(daemon.json "iptables": false) 모든 연결이 docker-proxy를 거쳐 주소가 바뀝니다 — 켜세요.', 'Caddy 앞에 다른 프록시(터널·로드밸런서)가 있다면 그 프록시의 주소입니다 — X-Forwarded-For를 넘기게 하고 Caddy trusted_proxies에 그 주소를 넣으세요.'],
        blocks: 'all',
      } : {
        cause: `이 서버는 리눅스 Docker Engine이라 IPv4 접속은 실제 주소가 보입니다. 알 수 없는 요청은 대부분 IPv6 접속입니다 — Caddy 네트워크(${net})에 IPv6가 꺼져 있어 Docker(docker-proxy)가 IPv6 연결을 IPv4로 대신 넘기면서 주소를 바꿉니다.`,
        fixes: [`Caddy 네트워크에서 IPv6를 켜세요 — compose의 networks.${nets[0] || '<이름>'}.enable_ipv6: true (Docker 27 이상은 ip6tables가 기본으로 켜짐). 기존 네트워크는 다시 만들어야 합니다.`, '또는 Caddy를 network_mode: host 로 실행하세요 (포트 전달 자체가 없어짐).', 'DNS only 사이트에 AAAA(IPv6) 레코드를 두지 않으면 IPv6 접속이 생기지 않습니다.', '같은 서버에서 Caddy로 보낸 요청도 이렇게 보입니다 — 외부 접속과 무관합니다.'],
        blocks: 'v4',
      };
    case 'hostnet':
    case 'outside':
      return {
        cause: env.kind === 'hostnet' ? 'Caddy가 host 네트워크로 실행돼 Docker가 접속자 주소를 바꾸지 않습니다.' : 'Caddy가 Docker 밖에서 실행돼 Docker가 접속자 주소를 바꾸지 않습니다.',
        fixes: ['그래도 내부 주소로 기록된다면 Caddy 앞의 다른 프록시(터널·로드밸런서·NAS 역방향 프록시)가 주소를 바꾸는 것입니다 — 그 프록시가 X-Forwarded-For를 넘기게 하고 Caddy trusted_proxies에 그 주소를 넣으세요.', '같은 서버에서 Caddy로 보낸 요청은 외부 접속과 무관합니다.'],
        blocks: 'all',
      };
    default:
      return {
        cause: `${CLIENT_WHY} 이 서버의 Docker 환경을 확인하지 못해 가능한 경우를 모두 적습니다.`,
        fixes: ['Docker Desktop(Windows·macOS): 서버 안에서는 고칠 방법이 없습니다 — Proxied(Cloudflare)로 바꾸거나 공유기 국가 차단을 쓰세요.', '리눅스 Docker Engine: IPv4는 실제 주소가 보입니다. IPv6 접속이 가려지면 Caddy 네트워크에 IPv6를 켜거나 Caddy를 network_mode: host 로 실행하세요.', 'rootless Docker: 포트 전달을 slirp4netns로 바꾸세요.', 'Docker Swarm: 포트를 mode: host 로 게시하세요.'],
        blocks: 'all',
      };
  }
}

function clientWhyBox(unknown, total) {
  const body = h('div', { class: 'small muted' }, '이 서버의 환경을 확인하는 중…');
  const box = h('details', { class: 'callout warn geo-why' },
    h('summary', null, total ? `접속자를 알 수 없는 요청 ${fmtNum(unknown)}건 / ${fmtNum(total)}건 — 왜 그런가요?` : '접속자를 알 수 없는 요청이 있습니다 — 왜 그런가요?'),
    body);
  clientEnv().then((env) => {
    const t = clientEnvText(env);
    fill(body, h('p', null, t.cause), h('ul', null, t.fixes.map((x) => h('li', null, x))),
      h('p', { class: 'small muted' }, 'Proxied(Cloudflare 경유) 사이트는 어느 환경이든 Cloudflare가 실제 접속자 IP·국가를 알려 줍니다.'));
    body.className = '';
  });
  return box;
}

// ======================================================================= dashboard: where requests come from

const VIA_ORDER = [['cf', 'Cloudflare 경유'], ['direct', '직접'], ['lan', '내부망'], ['tailnet', 'Tailscale'], ['hidden', '알 수 없음'], ['unknown', '기록 없음']];
const GEO_MAP_MODE = { get: () => { try { return localStorage.getItem('gm.geoMapMode') || 'all'; } catch { return 'all'; } }, set: (v) => { try { localStorage.setItem('gm.geoMapMode', v); } catch { /* private mode */ } } };

function geoMapWidget(body, w, d, colors, stClasses) {
  const rows = d.countries || [];
  const via = d.via || {};
  const total = d.total || 0;
  const mode = GEO_MAP_MODE.get();
  const val = (r) => (mode === 'blocked' ? r.blocked : r.n);
  const shown = rows.filter((r) => val(r) > 0);
  const max = Math.max(1, ...shown.map(val));
  const ink = cssVar('--ink');
  const svg = sv('svg', { viewBox: '0 0 360 150', class: 'geo-svg', role: 'img', 'aria-label': `접속 지역 지도 — ${shown.length}개 국가` },
    sv('path', { d: WORLD_LAND, fill: `rgb(${ink} / .09)`, stroke: `rgb(${ink} / .18)`, 'stroke-width': '.25', 'vector-effect': 'non-scaling-stroke' }));
  const tip = h('div', { class: 'dtip', hidden: true });
  const wrap = h('div', { class: 'geo-map' }, svg, tip);
  const others = [];
  const surface = colors.surface;
  // biggest first so small bubbles stay on top and reachable
  for (const r of shown.slice().sort((a, b) => val(b) - val(a))) {
    const pos = WORLD_CC[r.cc];
    if (!pos) { others.push(r); continue; }
    const [x, y] = [pos[0] + 180, 90 - pos[1]];
    const rad = 1.6 + Math.sqrt(val(r) / max) * 9;
    const label = `${geoName(r.cc)} (${r.cc}) · 요청 ${fmtNum(r.n)}건${r.blocked ? ` · 거부 ${fmtNum(r.blocked)}건` : ''}`;
    const g = sv('g', { class: 'geo-dot', tabindex: '0', role: 'img', 'aria-label': label },
      sv('circle', { cx: x, cy: y, r: rad + 0.9, fill: 'transparent' }), // bigger hit target
      sv('circle', { cx: x, cy: y, r: rad, fill: mode === 'blocked' ? colors.crit : colors.s1, 'fill-opacity': '.55', stroke: surface, 'stroke-width': '.4' }));
    if (mode === 'all' && r.blocked) {
      g.append(sv('circle', { cx: x, cy: y, r: Math.max(0.9, rad * Math.sqrt(r.blocked / r.n)), fill: colors.crit, 'fill-opacity': '.9', stroke: surface, 'stroke-width': '.3' }));
    }
    const show = () => {
      const st = r.st || [];
      fill(tip, h('b', null, `${geoName(r.cc)} (${r.cc})`),
        h('div', { class: 'small muted' }, `요청 ${fmtNum(r.n)}건 · 접속자 IP ${fmtNum(r.ips || 0)}개 · 전체의 ${Math.round((r.n / Math.max(1, total)) * 1000) / 10}%`),
        r.blocked ? h('div', { class: 'trow' }, h('i', { style: { background: colors.crit } }), `거부 ${fmtNum(r.blocked)}건 (403·429)`) : null,
        h('div', { class: 'geo-tip-st' }, (stClasses || []).map((c, i) => (st[i] ? h('span', { class: 'trow' }, h('i', { style: { background: c.color } }), `${c.name} ${c.title} ${fmtNum(st[i])}`) : null))),
        (r.hosts || []).length ? h('div', { class: 'geo-tip-hosts' }, h('span', { class: 'small muted' }, '많이 들어온 사이트'),
          r.hosts.map((x) => h('div', { class: 'trow small' }, h('span', { class: 'ellipsis' }, x.host), h('b', null, fmtNum(x.n))))) : null);
      tip.hidden = false;
      // the map keeps its aspect inside the box (letterboxed): same scale both ways, centred
      const box = wrap.getBoundingClientRect();
      const s = Math.min(box.width / 360, box.height / 150);
      const ox = (box.width - 360 * s) / 2;
      const oy = (box.height - 150 * s) / 2;
      const left = Math.min(Math.max(ox + x * s + 10, 0), box.width - tip.offsetWidth - 4);
      tip.style.left = `${Math.max(0, left)}px`;
      tip.style.top = `${Math.max(0, oy + y * s - tip.offsetHeight - 8)}px`;
    };
    const hide = () => { tip.hidden = true; };
    g.addEventListener('mouseenter', show); g.addEventListener('mouseleave', hide);
    g.addEventListener('focus', show); g.addEventListener('blur', hide);
    svg.append(g);
  }

  // mode: everything / refused only
  const seg = h('div', { class: 'dlegend st-filter geo-mode', role: 'group', 'aria-label': '지도에 표시할 것' }, [['all', '전체 요청', colors.s1], ['blocked', '거부만 (403·429)', colors.crit]].map(([k, l, c]) => {
    const b = h('button', { type: 'button', class: mode === k ? '' : 'off', 'aria-pressed': String(mode === k) }, h('i', { style: { background: c } }), l);
    b.addEventListener('click', () => { GEO_MAP_MODE.set(k); geoMapWidget(body, w, d, colors, stClasses); });
    return b;
  }));
  // a text list of the top countries (the map's table view)
  const top = shown.slice(0, 6).map((r) => h('span', { class: 'geo-top' }, h('span', { class: 'cc-badge' }, r.cc), ` ${geoName(r.cc)} `, h('b', null, fmtNum(val(r)))));
  if (others.length) top.push(h('span', { class: 'geo-top muted' }, `기타 ${fmtNum(others.reduce((s, r) => s + val(r), 0))}`));
  // coverage: how many requests had a usable client address at all
  const known = (via.cf || 0) + (via.direct || 0);
  const parts = VIA_ORDER.filter(([k]) => via[k]).map(([k, l]) => `${l} ${fmtNum(via[k])}`);
  const unknown = via.hidden || 0;
  fill(body, wrap,
    h('div', { class: 'row tight geo-foot' }, seg, h('span', { class: 'spacer' }), top.length ? top : h('span', { class: 'muted small' }, mode === 'blocked' ? '거부된 요청 없음' : '국가를 아는 요청 없음')),
    total ? h('p', { class: 'hint geo-cov' }, `요청 ${fmtNum(total)}건 중 접속자를 아는 것 ${fmtNum(known)}건${parts.length ? ` — ${parts.join(' · ')}` : ''}`) : h('p', { class: 'hint' }, '요청 없음'),
    unknown ? clientWhyBox(unknown, total) : null,
    d.partial ? h('p', { class: 'hint' }, '최근 요청 2만 건 기준') : null);
}

// ======================================================================= Caddy tab: country block

function geoBlockStep() {
  const st = settings();
  const body = h('div', { class: 'stack' }, spinnerRow('GeoIP 상태를 확인하는 중…'));
  const direct = S.state.services.filter((s) => s.enabled && !s.dnsOnly && s.exposure === 'public' && !(s.proxied && use('cloudflare')));
  const proxied = S.state.services.filter((s) => s.enabled && !s.dnsOnly && s.exposure === 'public' && s.proxied && use('cloudflare'));

  const draw = async () => {
    let g = {};
    try { g = await api('GET', '/api/geoip'); } catch (ex) { fill(body, errorBox(ex.message)); return; }
    const env = await clientEnv();
    const cur = settings();

    // ---- the database
    const upd = h('button', { type: 'button', class: 'btn sm' }, icon('refresh'), '지금 받기');
    upd.addEventListener('click', () => busy(upd, async () => { await api('POST', '/api/geoip/update', {}); toast('GeoIP 국가 DB를 받았습니다'); draw(); }));
    const autoSw = switchCtl('국가 DB 자동 받기', !cur.geoipOff, '한 달에 한 번 DB-IP의 무료 국가 DB(약 8MB)를 받습니다. 끄면 Cloudflare를 거치지 않는 요청의 국가를 알 수 없습니다.');
    autoSw.input.addEventListener('change', async () => {
      try { await saveSettingsPatch({ geoipOff: !autoSw.input.checked }); draw(); } catch (ex) { toast(ex.message, 'err'); }
    });
    const dbCard = h('div', { class: 'ccard ' + (g.loaded ? 'ok' : g.error ? 'warn' : 'info') },
      h('b', null, 'GeoIP 국가 DB'),
      h('span', { class: 'cc-detail' }, g.loaded ? `${new Date(g.built).toLocaleDateString(gmLocale())} 기준 · ${new Date(g.fetched).toLocaleDateString(gmLocale())} 받음` : g.busy ? '받는 중…' : g.off ? '자동 받기 꺼짐' : g.error ? `받지 못함: ${g.error}` : '아직 없음 (곧 받습니다)'),
      h('div', { class: 'row tight' }, upd));

    // ---- the block itself
    const mode = segmented(uid('geo'), '방식', [
      { value: '', label: '끔' }, { value: 'allow', label: '허용 국가만 들어옴' }, { value: 'block', label: '지정 국가 차단' },
    ], cur.geoMode || '');
    const countries = h('input', { type: 'text', class: 'mono', value: cur.geoCountries || '', placeholder: '예: KR JP', autocomplete: 'off', spellcheck: 'false' });
    const ccPreview = h('p', { class: 'hint' });
    const showCC = () => {
      const codes = countries.value.toUpperCase().split(/[\s,]+/).filter(Boolean);
      ccPreview.textContent = codes.length ? codes.map((c) => (/^[A-Z]{2}$/.test(c) ? `${c} ${geoName(c)}` : `${c} ?`)).join(' · ') : '두 글자 국가 코드를 공백으로 구분해 넣습니다 (ISO 3166).';
    };
    countries.addEventListener('input', showCC);
    showCC();
    const scope = new Set(cur.geoHosts || []);
    const scopeAll = h('input', { type: 'checkbox', checked: !scope.size });
    const boxes = direct.map((s) => {
      const cb = h('input', { type: 'checkbox', value: s.id, checked: !scope.size || scope.has(s.id), disabled: !scope.size });
      return h('label', { class: 'radio-inline' }, cb, ` ${fqdn(s.subdomain)}`);
    });
    scopeAll.addEventListener('change', () => { for (const l of boxes) { const cb = l.querySelector('input'); cb.disabled = scopeAll.checked; if (scopeAll.checked) cb.checked = true; } });
    const err = h('p', { class: 'form-error', role: 'alert', hidden: true });
    const save = h('button', { type: 'button', class: 'btn primary' }, '저장');
    save.addEventListener('click', () => busy(save, async () => {
      err.hidden = true;
      const hosts = scopeAll.checked ? [] : boxes.map((l) => l.querySelector('input')).filter((c) => c.checked).map((c) => c.value);
      try {
        await saveSettingsPatch({ geoMode: mode.get() || '', geoCountries: countries.value, geoHosts: hosts });
        draw();
      } catch (ex) { err.textContent = ex.message; err.hidden = false; }
    }));

    // ---- readiness and environment notes
    const notes = [];
    // what the block can do on this server (Docker's port forwarding may hide the client)
    const t = clientEnvText(env);
    const envFixes = h('ul', { class: 'small' }, t.fixes.map((x) => h('li', null, x)));
    if (t.blocks === 'none') {
      notes.push(callout('warn', h('b', null, '이 서버에서는 Caddy가 실제 접속자 주소를 보지 못해, 국가 차단이 아무것도 막지 않습니다.'),
        h('span', { class: 'small' }, `${t.cause} 국가를 알 수 없는 내부 주소는 차단하지 않으므로 모든 요청이 통과합니다.`), envFixes));
    } else if (t.blocks === 'v4') {
      notes.push(callout('', h('b', null, 'IPv4 접속은 막지만, IPv6로 들어오는 접속은 국가를 알 수 없어 막지 못합니다.'),
        h('span', { class: 'small' }, t.cause), envFixes));
    }
    if (cur.geoMode && g.caddy && !g.caddy.ready) {
      const fixes = [];
      if (/모듈/.test(g.caddy.reason || '')) {
        const go = h('button', { type: 'button', class: 'btn sm' }, '이미지 업데이트로 이동');
        go.addEventListener('click', () => gotoTab('caddy', 'update'));
        fixes.push(h('span', { class: 'small' }, '길목이 설치한 Caddy는 이미지 업데이트로 다시 빌드하면 됩니다. 직접 운영하는 Caddy는 Dockerfile의 xcaddy build에 --with github.com/porech/caddy-maxmind-geolocation 을 추가하고 다시 빌드하세요.'), go);
      }
      notes.push(callout('warn', h('b', null, `국가 차단 대기: ${g.caddy.reason}`), h('span', { class: 'small' }, '준비될 때까지 Caddyfile에 넣지 않습니다 (다른 사이트 적용에는 영향 없음).'), ...fixes));
    } else if (cur.geoMode && g.caddy && g.caddy.ready) {
      notes.push(callout('ok', h('b', null, '✓ Caddy가 국가 차단을 쓸 수 있습니다'), h('span', { class: 'small mono' }, g.caddy.path)));
    }
    const cfLink = h('button', { type: 'button', class: 'btn sm' }, 'Cloudflare 국가 규칙');
    cfLink.addEventListener('click', () => gotoTab('cloudflare', 'waf'));

    fill(body,
      h('p', { class: 'small' }, 'Cloudflare를 거치지 않는 공개 사이트(DNS only, 또는 Cloudflare를 쓰지 않는 구성)를 Caddy가 접속자 국가로 막습니다. 막힌 요청은 403이고 「차단 기록」에 국가 차단으로 남습니다. 내부망·Tailscale 주소는 막지 않습니다.'),
      proxied.length ? h('div', { class: 'row tight' }, h('span', { class: 'small muted' }, `Proxied 사이트 ${proxied.length}개는 Caddy가 Cloudflare의 주소를 보므로 여기서 막지 않고 Cloudflare 엣지 규칙으로 막습니다.`), cfLink) : null,
      ...notes,
      h('div', { class: 'grid-2' }, dbCard, h('div', { class: 'stack tight' }, autoSw, h('p', { class: 'hint' }, h('a', { href: g.attributionUrl || 'https://db-ip.com', target: '_blank', rel: 'noopener' }, g.attribution || 'IP Geolocation by DB-IP'), ' — CC BY 4.0'))),
      h('hr', { class: 'sep' }),
      err,
      mode,
      field('국가', countries),
      ccPreview,
      direct.length ? h('div', { class: 'field' }, h('span', { class: 'field-label' }, '적용할 사이트'),
        h('label', { class: 'radio-inline' }, scopeAll, ' Cloudflare를 거치지 않는 공개 사이트 전부'),
        h('div', { class: 'chips' }, boxes)) : h('p', { class: 'muted small' }, 'Cloudflare를 거치지 않는 공개 사이트가 없습니다.'),
      h('div', { class: 'row' }, h('span', { class: 'grow' }), save));
  };
  draw();
  const on = st.geoMode && st.geoCountries;
  return {
    id: 'geo', title: '국가 차단', desc: 'Cloudflare를 거치지 않는 공개 사이트를 접속자 국가로 막습니다 (GeoIP).',
    state: on ? 'ok' : 'opt', stateText: on ? `${st.geoMode === 'allow' ? '허용' : '차단'} ${st.geoCountries}` : '선택', body,
  };
}
