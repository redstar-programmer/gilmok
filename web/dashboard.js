// Gilmok web UI — dashboard (first tab). Panels on a 24-column grid (drag the title bar to move,
// the corner to resize), one time range for the whole dashboard (quick ranges, an absolute window,
// drag on a time chart to zoom in), dashboard variables (sites · status · countries · client paths)
// that filter every request-based panel, a crosshair shared by the time charts. Charts are plain SVG
// (the response-time scatter uses canvas for thousands of points). Colors: validated categorical
// slots + reserved status colors (always paired with a text label).
'use strict';

// ======================================================================= time range

/** quick ranges of the time picker ("최근 15분" by default); an absolute window is From~To (≤ 31 days) */
const DASH_SPANS = [['5m', '최근 5분'], ['15m', '최근 15분'], ['30m', '최근 30분'], ['1h', '최근 1시간'], ['3h', '최근 3시간'], ['6h', '최근 6시간'],
  ['12h', '최근 12시간'], ['24h', '최근 24시간'], ['2d', '최근 2일'], ['7d', '최근 7일'], ['30d', '최근 30일']];
const SPAN_MS = { '5m': 300e3, '15m': 900e3, '30m': 1800e3, '1h': 3600e3, '3h': 3 * 3600e3, '6h': 6 * 3600e3, '12h': 12 * 3600e3, '24h': 24 * 3600e3, '2d': 48 * 3600e3, '7d': 7 * 24 * 3600e3, '30d': 30 * 24 * 3600e3 };
const DASH_SPAN_DEFAULT = '15m';
const DASH_MAX_WINDOW = 31 * 24 * 3600e3;
function dashSpanSaved() {
  try { const v = localStorage.getItem('gm.dashSpan') || ''; return SPAN_MS[v] ? v : DASH_SPAN_DEFAULT; } catch { return DASH_SPAN_DEFAULT; }
}
function dashVarsSaved() {
  try { const v = JSON.parse(localStorage.getItem('gm.dashVars') || '{}'); return { hosts: v.hosts || [], classes: v.classes || [], countries: v.countries || [], vias: v.vias || [] }; } catch { return { hosts: [], classes: [], countries: [], vias: [] }; }
}
// after DASH_SPANS: dashSpanSaved reads them
const DASH = {
  widgets: null, data: null, stream: null, gen: 0, cards: new Map(), lastSize: new Map(),
  span: dashSpanSaved(), from: 0, at: 0, // at > 0: an absolute window from~at (no auto refresh)
  vars: dashVarsSaved(), varChoices: null, charts: [], view: null,
};

function fmtWindow(from, to) {
  const o = { month: 'numeric', day: 'numeric', hour: '2-digit', minute: '2-digit', hour12: false };
  return `${new Date(from).toLocaleString(gmLocale(), o)} ~ ${new Date(to).toLocaleString(gmLocale(), o)}`;
}
const timeLabel = () => (DASH.at ? fmtWindow(DASH.from, DASH.at) : (DASH_SPANS.find((x) => x[0] === DASH.span) || ['', DASH.span])[1]);
/** the window shown now (ms) */
function curWindow() {
  if (DASH.at) return { from: DASH.from, to: DASH.at };
  const to = Date.now();
  return { from: to - (SPAN_MS[DASH.span] || 900e3), to };
}
/** an absolute window (zoom in, ◀ ▶, the picker) — kept within 31 days and not past now */
function setWindow(from, to) {
  to = Math.min(to, Date.now());
  from = Math.max(from, to - DASH_MAX_WINDOW);
  if (to - from < 10e3) from = to - 10e3;
  DASH.from = Math.round(from);
  DASH.at = Math.round(to);
  dashTimeChanged();
}
function setSpan(key) {
  DASH.span = key;
  DASH.from = 0;
  DASH.at = 0;
  try { localStorage.setItem('gm.dashSpan', key); } catch { /* private mode */ }
  dashTimeChanged();
}
/** zoom out: twice as wide around the middle (a relative range goes to the next quick range) */
function zoomOutTime() {
  if (!DASH.at) {
    const i = DASH_SPANS.findIndex((x) => x[0] === DASH.span);
    if (i >= 0 && i < DASH_SPANS.length - 1) setSpan(DASH_SPANS[i + 1][0]);
    return;
  }
  const w = curWindow();
  const mid = (w.from + w.to) / 2;
  const half = w.to - w.from;
  setWindow(mid - half, Math.min(mid + half, Date.now()));
}
function shiftTime(dir) {
  const w = curWindow();
  const d = ((w.to - w.from) / 2) * dir;
  if (dir > 0 && w.to + d >= Date.now() - 5e3) { // moving into "now": back to a relative range
    const key = DASH_SPANS.map((x) => x[0]).find((k) => SPAN_MS[k] >= w.to - w.from) || DASH.span;
    setSpan(key);
    return;
  }
  setWindow(w.from + d, w.to + d);
}
let dashTimeChanged = () => {}; // set by renderDashboard (header + grid + data)

/** the dashboard variables as the API filter ({} = none) */
function dashFilters() {
  const v = DASH.vars;
  const any = v.hosts.length || v.classes.length || v.countries.length || v.vias.length;
  return any ? { hosts: v.hosts, classes: v.classes, countries: v.countries, vias: v.vias } : null;
}

// ======================================================================= look

const C = {
  s1: '#3987e5', s2: '#d95926', s3: '#199e70', s4: '#c98500',
  good: '#0ca30c', warn: '#fab219', serious: '#ec835a', crit: '#d03b3b', neutral: '#898781',
};
// chrome of the charts follows the theme (read at paint time)
for (const [k, v] of Object.entries({ muted: '--muted', ink: '--fg', ink2: '--fg-2', surface: '--chart-bg' })) {
  Object.defineProperty(C, k, { get: () => cssVar(v), enumerable: true });
}
Object.defineProperty(C, 'grid', { get: () => `rgb(${cssVar('--ink')} / .07)`, enumerable: true });
Object.defineProperty(C, 'axis', { get: () => `rgb(${cssVar('--ink')} / .16)`, enumerable: true });
const STATUS_CLASS = [
  { key: 's2', name: '2xx', color: C.s1, title: '성공', desc: '요청을 정상적으로 처리했습니다.', ex: '200 정상 · 204 내용 없음 · 206 일부(동영상·큰 파일 이어 받기)' },
  { key: 's3', name: '3xx', color: C.neutral, title: '이동 · 캐시', desc: '다른 주소로 보내거나(리다이렉트), 브라우저에 있는 것을 그대로 쓰라고 알렸습니다. 대부분 정상입니다.', ex: '301·302 다른 주소로 이동(예: 로그인 화면) · 304 바뀐 것 없음(캐시 사용)' },
  { key: 's4', name: '4xx', color: C.warn, title: '요청 쪽 문제 · 거부', desc: '없는 주소, 로그인 필요, 차단처럼 요청한 쪽 사정으로 처리하지 않았습니다. 스캐너·봇이 많으면 늘어납니다.', ex: '401 로그인 필요 · 403 거부(기본 차단·WAF·국가 차단) · 404 없는 주소 · 429 너무 많은 요청' },
  { key: 's5', name: '5xx', color: C.crit, title: '서버 쪽 오류', desc: '대상 서비스가 꺼져 있거나 오류를 냈습니다. 계속 보이면 서비스 상태를 확인하세요.', ex: '500 서비스 내부 오류 · 502 대상 서비스 연결 실패 · 503 사용 불가 · 504 응답 시간 초과' },
];
/** what a status class means — for the legend's hover help and the map's per-country details */
function statusHelp(c) {
  return h('div', { class: 'st-help' }, h('b', null, `${c.name} — ${c.title}`), h('p', null, c.desc), h('p', { class: 'muted small' }, c.ex));
}
const statusColor = (code) => (code >= 500 ? C.crit : code >= 400 ? C.warn : code >= 300 ? C.neutral : C.s1);

/** status classes hidden by the dashboard's status filter (the clickable legends; remembered per browser) */
const DASH_HIDE_ST = (() => { try { return new Set(JSON.parse(localStorage.getItem('gm.dashHideSt') || '[]')); } catch { return new Set(); } })();
const stKey = (code) => `s${Math.min(5, Math.max(2, Math.floor(code / 100)))}`;
const stShown = (code) => !DASH_HIDE_ST.has(stKey(code));
function statusLegend(counts) {
  return h('div', { class: 'dlegend st-filter', role: 'group', 'aria-label': '상태코드 필터 — 눌러서 숨기기·보이기' }, STATUS_CLASS.map((c) => {
    const off = DASH_HIDE_ST.has(c.key);
    const b = h('button', { type: 'button', class: off ? 'off' : '', 'aria-pressed': String(!off), 'aria-label': `${c.name} ${c.title}` },
      h('i', { style: { background: c.color } }), c.name, counts ? h('b', null, fmtNum(counts[c.key] || 0)) : null);
    b.addEventListener('click', () => {
      if (off) DASH_HIDE_ST.delete(c.key); else DASH_HIDE_ST.add(c.key);
      try { localStorage.setItem('gm.dashHideSt', JSON.stringify([...DASH_HIDE_ST])); } catch { /* private mode */ }
      paintAll();
    });
    return hoverTip(b, () => h('div', null, statusHelp(c), h('p', { class: 'muted small st-help-act' }, off ? '누르면 다시 보입니다' : '누르면 그래프에서 숨깁니다')));
  }));
}

// sizes in grid units (24 columns, one row ≈ 40 px)
const WIDGET_TYPES = {
  stat: { name: '숫자 카드', desc: '지표 하나를 크게, 아래에 작은 추이선', def: { w: 6, h: 4, metric: 'rpm', range: '15m' } },
  series: { name: '추이 차트', desc: '요청 수·상태코드·응답시간·전송량의 시간 흐름', def: { w: 12, h: 8, metric: 'requests', range: '1h' } },
  scatter: { name: '응답시간 분포', desc: '요청 하나하나를 점으로 — 끌어서 고르면 요청 목록 (X-View 방식)', def: { w: 12, h: 10, range: '15m' } },
  top: { name: '상위 목록', desc: '사이트·경로·상태코드·클라이언트·느린 요청 순위', def: { w: 6, h: 8, dim: 'host', range: '1h', limit: 8 } },
  health: { name: '서비스 상태 맵', desc: '서비스마다 upstream 연결 여부와 지연', def: { w: 12, h: 8 } },
  containers: { name: '컨테이너 리소스', desc: 'CPU·메모리 사용량과 추이', def: { w: 6, h: 8 } },
  certs: { name: '인증서 만료', desc: 'Caddy가 내보내는 인증서의 남은 기간', def: { w: 6, h: 6 } },
  events: { name: '최근 이벤트', desc: 'WAF 차단·5xx 오류 (24시간)', def: { w: 6, h: 6 } },
  map: { name: '접속 지역 (세계지도)', desc: '나라별 요청·거부를 지도 위 원 크기로', def: { w: 12, h: 12, range: '1h' } },
};
const STAT_METRICS = [
  ['rpm', '분당 요청 (최근 1분)'], ['requests', '요청 수 (기간 합계)'], ['err5xx', '5xx 오류율'], ['err4xx', '4xx 비율'],
  ['avgMs', '평균 응답시간'], ['p95Ms', '응답시간 p95'], ['bytes', '전송량'], ['waf', 'WAF 차단'],
  ['csBans', 'CrowdSec 차단 IP'], ['healthUp', '정상 서비스 수'], ['certDays', '인증서 최단 남은 일수'],
];
const LOWER_IS_BAD = new Set(['certDays']);
const NO_RANGE_STATS = new Set(['rpm', 'csBans', 'healthUp', 'certDays']);
const SERIES_METRICS = [['requests', '요청 수'], ['status', '상태코드별 요청'], ['latency', '응답시간 (평균·p95)'], ['bytes', '전송량'], ['waf', 'WAF 차단']];
const TOP_DIMS = [['host', '사이트'], ['path', '경로'], ['status', '상태코드'], ['client', '접속자 IP'], ['country', '접속 국가'], ['slow', '느린 요청']];

// ---- formatting
const fmtNum = (v) => {
  if (v == null || isNaN(v)) return '—';
  const a = Math.abs(v);
  if (a >= 1e6) return `${(v / 1e6).toFixed(1)}M`;
  if (a >= 1e4) return `${(v / 1e3).toFixed(1)}k`;
  return Number.isInteger(v) ? v.toLocaleString(gmLocale()) : v.toLocaleString(gmLocale(), { maximumFractionDigits: 1 });
};
const fmtBytes = (v) => {
  if (!v) return '0 B';
  const u = ['B', 'KB', 'MB', 'GB', 'TB'];
  let i = 0;
  while (v >= 1024 && i < u.length - 1) { v /= 1024; i++; }
  return `${v.toFixed(v >= 100 || i === 0 ? 0 : 1)} ${u[i]}`;
};
const fmtMs = (v) => (v >= 1000 ? `${(v / 1000).toFixed(v >= 10000 ? 0 : 2)}s` : `${Math.round(v)}ms`);
const hhmm = (t) => new Date(t).toLocaleTimeString(gmLocale(), { hour: '2-digit', minute: '2-digit', hour12: false });
const hhmmss = (t) => new Date(t).toLocaleTimeString(gmLocale(), { hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false });
/** an axis tick: the time, with the date once the range spans days */
const tickTime = (t, span) => (span > 36 * 3600e3
  ? new Date(t).toLocaleString(gmLocale(), { month: 'numeric', day: 'numeric', hour: '2-digit', hour12: false })
  : span > 600e3 ? hhmm(t) : hhmmss(t));
const ago = (t) => {
  const s = Math.max(0, Math.round((Date.now() - t) / 1000));
  return s < 60 ? `${s}초 전` : s < 3600 ? `${Math.floor(s / 60)}분 전` : `${Math.floor(s / 3600)}시간 전`;
};
function fmtValue(metric, v) {
  if (metric === 'bytes') return fmtBytes(v);
  if (metric === 'avgMs' || metric === 'p95Ms') return fmtMs(v);
  return fmtNum(v);
}

/** replaceChildren that skips null/false children (replaceChildren(null) would print "null"). */
function fill(el, ...kids) { el.replaceChildren(); return append(el, kids); }

// ---- svg helpers (sv() comes from topology.js)
function niceMax(v) {
  if (!(v > 0)) return 1;
  const p = 10 ** Math.floor(Math.log10(v));
  for (const m of [1, 2, 2.5, 5, 10]) if (m * p >= v) return m * p;
  return 10 * p;
}
function statusPill(kind, text) {
  const mark = { good: '✓', warn: '!', serious: '!', crit: '✗' }[kind];
  return h('span', { class: `dpill ${kind}` }, h('span', { 'aria-hidden': 'true' }, mark), text);
}

// ======================================================================= shared crosshair
// every time chart registers { show(t), hide() } while painted; hovering one shows the same moment
// on the others
function dashHover(t, src) {
  for (const c of DASH.charts) if (c !== src) { if (t == null) c.hide(); else c.show(t); }
}

/** Line chart / stacked columns with axes, hover tooltip, a crosshair shared with the other time
 *  charts and drag-to-zoom (the selected stretch becomes the dashboard's time window). */
function timeChart(box, { t, series, stacked, unit, step }) {
  const W = Math.max(box.clientWidth, 200), Hh = Math.max(box.clientHeight, 90);
  const m = { l: 48, r: 12, t: 8, b: 20 };
  const iw = W - m.l - m.r, ih = Hh - m.t - m.b;
  const n = t.length;
  const fmt = unit === 'ms' ? fmtMs : unit === 'bytes' ? fmtBytes : fmtNum;
  const span = n > 1 ? t[n - 1] - t[0] : 0;
  let max = 0;
  for (let i = 0; i < n; i++) {
    if (stacked) max = Math.max(max, series.reduce((a, s) => a + s.values[i], 0));
    else for (const s of series) max = Math.max(max, s.values[i]);
  }
  max = niceMax(max);
  const x = (i) => m.l + (n <= 1 ? iw / 2 : (i / (n - 1)) * iw);
  const y = (v) => m.t + ih - (v / max) * ih;
  const idxAt = (px) => Math.max(0, Math.min(n - 1, Math.round(((px - m.l) / iw) * (n - 1))));
  const svg = sv('svg', { viewBox: `0 0 ${W} ${Hh}`, width: W, height: Hh, class: 'dchart', role: 'img', 'aria-label': `${series.map((s) => s.name).join(', ')} 추이` });
  for (let k = 0; k <= 3; k++) {
    const v = (max / 3) * k;
    svg.append(sv('line', { x1: m.l, x2: W - m.r, y1: y(v), y2: y(v), stroke: k ? C.grid : C.axis, 'stroke-width': 1 }),
      sv('text', { x: m.l - 6, y: y(v) + 3.5, 'text-anchor': 'end', class: 'ax' }, fmt(v)));
  }
  const ticks = Math.min(Math.max(2, Math.floor(iw / 90)), n);
  for (let k = 0; k < ticks; k++) {
    const i = Math.round((k / Math.max(ticks - 1, 1)) * (n - 1));
    svg.append(sv('text', { x: x(i), y: Hh - 5, 'text-anchor': k === 0 ? 'start' : k === ticks - 1 ? 'end' : 'middle', class: 'ax' }, tickTime(t[i], span)));
  }
  if (stacked) {
    const bw = Math.max(1, iw / n - 2);
    for (let i = 0; i < n; i++) {
      let acc = 0;
      series.forEach((s, si) => {
        const v = s.values[i];
        if (!v) return;
        const y0 = y(acc), y1 = y(acc + v);
        acc += v;
        const hgt = Math.max(1, y0 - y1 - (acc > v ? 1 : 0)); // 1px gap between segments
        svg.append(sv('rect', { x: x(i) - bw / 2, y: y1, width: bw, height: hgt, rx: si === series.length - 1 || hgt > 3 ? 1.5 : 0, fill: s.color }));
      });
    }
  } else {
    for (const s of series) {
      let d = '';
      s.values.forEach((v, i) => { d += `${i ? 'L' : 'M'}${x(i).toFixed(1)} ${y(v).toFixed(1)}`; });
      if (series.length === 1) { // a soft fill under a single line
        svg.append(sv('path', { d: `${d}L${x(n - 1).toFixed(1)} ${y(0)}L${x(0).toFixed(1)} ${y(0)}Z`, fill: s.color, 'fill-opacity': 0.12, stroke: 'none' }));
      }
      svg.append(sv('path', { d, fill: 'none', stroke: s.color, 'stroke-width': 2, 'stroke-linejoin': 'round', 'stroke-linecap': 'round' }));
    }
    if (series.length > 1 && series.length <= 4 && ih >= 90) { // direct labels at the line ends (skip if they would collide)
      const used = [];
      for (const s of series) {
        const ly = Math.max(y(s.values[n - 1]) - 5, m.t + 10);
        if (used.some((u) => Math.abs(u - ly) < 12)) continue;
        used.push(ly);
        svg.append(sv('text', { x: W - m.r - 2, y: ly, 'text-anchor': 'end', class: 'ax lbl' }, s.name));
      }
    }
  }
  // hover layer: crosshair + dots + tooltip; drag = zoom in
  const cross = sv('line', { y1: m.t, y2: m.t + ih, stroke: C.ink2, 'stroke-width': 1, opacity: 0 });
  const dots = series.map((s) => sv('circle', { r: 4, fill: s.color, stroke: C.surface, 'stroke-width': 2, opacity: 0 }));
  const brush = sv('rect', { y: m.t, height: ih, fill: C.s1, 'fill-opacity': 0.12, stroke: C.s1, 'stroke-opacity': 0.5, opacity: 0 });
  svg.append(brush, cross, ...dots);
  const tip = h('div', { class: 'dtip', hidden: true });
  const hit = sv('rect', { x: m.l, y: m.t, width: iw, height: ih, fill: 'transparent', class: 'zoomable' });
  svg.append(hit);
  const at = (i, withTip) => {
    cross.setAttribute('x1', x(i)); cross.setAttribute('x2', x(i)); cross.setAttribute('opacity', 0.5);
    let acc = 0;
    series.forEach((s, si) => {
      const v = s.values[i];
      acc += v;
      dots[si].setAttribute('cx', x(i)); dots[si].setAttribute('cy', y(stacked ? acc : v)); dots[si].setAttribute('opacity', stacked || !withTip ? 0 : 1);
    });
    if (!withTip) return;
    const rows = series.map((s) => ({ s, v: s.values[i] })).sort((a, b) => b.v - a.v);
    tip.replaceChildren(h('b', null, `${tickTime(t[i], 0)}${step ? ` (${step >= 60 ? `${step / 60}분` : `${step}초`})` : ''}`),
      ...rows.map(({ s, v }) => h('div', { class: 'trow' }, h('i', { style: { background: s.color } }), h('span', null, s.name), h('b', null, fmt(v)))),
      h('div', { class: 'muted small' }, '끌어서 그 구간 확대'));
    tip.hidden = false;
    const r = svg.getBoundingClientRect();
    const left = (x(i) / W) * r.width;
    tip.style.left = `${Math.min(Math.max(left + 12, 0), r.width - 170)}px`;
    tip.style.top = '6px';
  };
  const clear = () => { tip.hidden = true; cross.setAttribute('opacity', 0); dots.forEach((d) => d.setAttribute('opacity', 0)); };
  const me = {
    show: (tm) => { if (!n) return; let best = 0; for (let i = 1; i < n; i++) if (Math.abs(t[i] - tm) < Math.abs(t[best] - tm)) best = i; at(best, false); },
    hide: clear,
  };
  DASH.charts.push(me);
  const pxOf = (ev) => { const r = svg.getBoundingClientRect(); return ((ev.clientX - r.left) / r.width) * W; };
  let drag0 = null;
  hit.addEventListener('mousemove', (ev) => {
    const px = pxOf(ev);
    const i = idxAt(px);
    if (drag0 != null) {
      const a = Math.max(m.l, Math.min(drag0, px)), b = Math.min(W - m.r, Math.max(drag0, px));
      brush.setAttribute('x', a); brush.setAttribute('width', b - a); brush.setAttribute('opacity', 1);
      tip.hidden = true;
      return;
    }
    at(i, true);
    dashHover(t[i], me);
  });
  hit.addEventListener('mouseleave', () => { clear(); dashHover(null, me); });
  hit.addEventListener('mousedown', (ev) => {
    if (ev.button !== 0 || n < 2) return;
    ev.preventDefault();
    drag0 = pxOf(ev);
    const up = (e2) => {
      window.removeEventListener('mouseup', up);
      const px = pxOf(e2);
      const a = drag0;
      drag0 = null;
      brush.setAttribute('opacity', 0);
      if (Math.abs(px - a) < 6) return;
      const i0 = idxAt(Math.min(a, px)), i1 = idxAt(Math.max(a, px));
      setWindow(t[i0], t[i1] + (step || 0) * 1000);
    };
    window.addEventListener('mouseup', up);
  });
  return h('div', { class: 'dchart-wrap' }, svg, tip);
}

function sparkline(values, w, hgt, color = C.s1) {
  const svg = sv('svg', { viewBox: `0 0 ${w} ${hgt}`, width: w, height: hgt, class: 'spark', 'aria-hidden': 'true' });
  if (!values || values.length < 2) return svg;
  const max = Math.max(...values, 1e-9);
  let d = '';
  values.forEach((v, i) => { d += `${i ? 'L' : 'M'}${((i / (values.length - 1)) * (w - 4) + 2).toFixed(1)} ${(hgt - 2 - (v / max) * (hgt - 4)).toFixed(1)}`; });
  svg.append(sv('path', { d: `${d}L${w - 2} ${hgt - 2}L2 ${hgt - 2}Z`, fill: color, 'fill-opacity': 0.1, stroke: 'none' }),
    sv('path', { d, fill: 'none', stroke: color, 'stroke-width': 1.5, 'stroke-linejoin': 'round', opacity: 0.9 }));
  return svg;
}

function legend(items) {
  return h('div', { class: 'dlegend' }, items.map((it) => h('span', null, h('i', { style: { background: it.color } }), it.name, it.count != null ? h('b', null, fmtNum(it.count)) : null)));
}

function toHex(c) {
  const m = String(c).trim().match(/^#([0-9a-f]{3}|[0-9a-f]{6})$/i);
  if (m) return m[1].length === 3 ? `#${[...m[1]].map((x) => x + x).join('')}` : `#${m[1]}`.toLowerCase();
  const r = String(c).match(/(\d+)\D+(\d+)\D+(\d+)/);
  return r ? `#${[r[1], r[2], r[3]].map((x) => (+x).toString(16).padStart(2, '0')).join('')}` : '#3987e5';
}

/** a ring split into segments ({v, color, label}) with a 2 px gap, the big text in the middle */
function donut(segs, size, big, small, total) {
  const th = Math.max(10, size * 0.13), r = size / 2 - th / 2 - 2, cx = size / 2, cy = size / 2; // the stroke stays inside the box
  const circ = 2 * Math.PI * r;
  const svg = sv('svg', { viewBox: `0 0 ${size} ${size}`, class: 'donut', role: 'img', 'aria-label': segs.map((x) => x.label).join(', ') });
  svg.append(sv('circle', { cx, cy, r, fill: 'none', stroke: C.grid, 'stroke-width': th }));
  const sum = total || segs.reduce((a, x) => a + x.v, 0) || 1;
  let at = 0;
  for (const x of segs) {
    const len = (x.v / sum) * circ;
    const gap = segs.length > 1 ? Math.min(segs.length > 24 ? 0.8 : 2, len / 3) : 0;
    svg.append(sv('circle', {
      cx, cy, r, fill: 'none', stroke: x.color, 'stroke-width': th,
      'stroke-dasharray': `${Math.max(0, len - gap)} ${circ}`, 'stroke-dashoffset': -at, transform: `rotate(-90 ${cx} ${cy})`,
    }, sv('title', null, x.label)));
    at += len;
  }
  svg.append(sv('text', { x: cx, y: cy + (small ? 2 : 6), 'text-anchor': 'middle', class: 'donut-big', 'font-size': Math.round(size * 0.18) }, big));
  if (small) svg.append(sv('text', { x: cx, y: cy + Math.round(size * 0.16), 'text-anchor': 'middle', class: 'donut-small', 'font-size': Math.round(size * 0.075) }, small));
  return svg;
}

/** one value 0..100 % as a ring (over 100 — CPU on several cores — fills it), the label below */
function gauge(pct, size, color, label, value, sub) {
  const v = Math.max(0, pct || 0);
  const th = Math.max(6, size * 0.11), r = size / 2 - th / 2 - 2, cx = size / 2, cy = size / 2;
  const circ = 2 * Math.PI * r;
  const col = v >= 90 ? C.warn : color;
  const svg = sv('svg', { viewBox: `0 0 ${size} ${size}`, class: 'donut gauge-ring', 'aria-hidden': 'true' },
    sv('circle', { cx, cy, r, fill: 'none', stroke: C.grid, 'stroke-width': th }),
    sv('circle', { cx, cy, r, fill: 'none', stroke: col, 'stroke-width': th, 'stroke-linecap': 'round', 'stroke-dasharray': `${(Math.min(v, 100) / 100) * circ} ${circ}`, transform: `rotate(-90 ${cx} ${cy})` }),
    sv('text', { x: cx, y: cy + 4, 'text-anchor': 'middle', class: 'donut-big', 'font-size': Math.round(size * 0.2) }, label));
  return h('div', { class: 'gauge', role: 'img', 'aria-label': `${label} ${value}${sub ? ` (${sub})` : ''}` }, svg,
    h('b', null, value), sub ? h('span', { class: 'muted small' }, sub) : null);
}

// ======================================================================= response-time scatter (X-View)
// every request a dot (time × response time), colored by status; the vertical scale is chosen
// (auto / fixed seconds, Shift+wheel), requests above it sit on the top edge as ▲; a dashed line
// marks "slow" (500 ms); optional p50 / p95 lines; drag a box → those requests (with a summary).
const XV_MAXES = [['auto', '자동'], ['1000', '1s'], ['3000', '3s'], ['5000', '5s'], ['10000', '10s'], ['30000', '30s']];
const XV_SLOW = 500;
const xvPref = (w, k, def) => { try { return localStorage.getItem(`gm.xv.${k}.${w.id}`) || def; } catch { return def; } };
const xvSet = (w, k, v) => { try { localStorage.setItem(`gm.xv.${k}.${w.id}`, v); } catch { /* private mode */ } };

function scatterPanel(body, w, d) {
  const pts = d.points || [];
  const counts = { s2: 0, s3: 0, s4: 0, s5: 0 };
  let sum = 0, mx = 0, errs = 0, shown = 0;
  for (const p of pts) {
    counts[stKey(p[2])]++;
    if (!stShown(p[2])) continue;
    shown++; sum += p[1]; mx = Math.max(mx, p[1]);
    if (p[2] >= 500) errs++;
  }
  const maxPref = xvPref(w, 'max', 'auto');
  const pctOn = xvPref(w, 'pct', '0') === '1';
  const scaleSel = h('select', { class: 'xv-scale', 'aria-label': '세로축 최대값', title: '세로축 최대값 — Shift+마우스 휠로도 바꿉니다' },
    XV_MAXES.map(([v, l]) => h('option', { value: v, selected: v === maxPref }, l)));
  scaleSel.addEventListener('change', () => { xvSet(w, 'max', scaleSel.value); paintOne(w.id); });
  const pctBtn = h('button', { type: 'button', class: `xv-tog ${pctOn ? 'on' : ''}`, 'aria-pressed': String(pctOn), title: '시간대별 p50·p95 선' }, 'p50·p95');
  pctBtn.addEventListener('click', () => { xvSet(w, 'pct', pctOn ? '0' : '1'); paintOne(w.id); });
  const box = h('div', { class: 'chart-box scatter' });
  const summary = h('span', { class: 'xv-sum' }, shown ? `${fmtNum(shown)}건 · 평균 ${fmtMs(sum / shown)} · 최대 ${fmtMs(mx)}${errs ? ` · 5xx ${fmtNum(errs)}` : ''}` : '');
  fill(body, h('div', { class: 'xv-bar' }, statusLegend(counts), h('span', { class: 'grow' }), summary, pctBtn, scaleSel), box,
    d.partial ? h('p', { class: 'hint' }, '요청이 많아 오류는 모두, 나머지는 고르게 골라 표시합니다') : null);
  const W = Math.max(box.clientWidth, 200), Hh = Math.max(box.clientHeight, 90);
  const m = { l: 48, r: 10, t: 10, b: 20 };
  const iw = W - m.l - m.r, ih = Hh - m.t - m.b;
  const sorted = pts.filter((p) => stShown(p[2])).map((p) => p[1]).sort((a, b) => a - b);
  const p99 = sorted.length ? sorted[Math.floor(sorted.length * 0.99)] : 100;
  const ymax = maxPref === 'auto' ? niceMax(Math.max(p99 * 1.15, XV_SLOW * 1.2)) : +maxPref; // auto: the "slow" line always shows
  const span = Math.max(d.to - d.from, 1);
  const x = (t) => m.l + ((t - d.from) / span) * iw;
  const y = (v) => m.t + ih - (Math.min(v, ymax) / ymax) * ih;
  const svg = sv('svg', { viewBox: `0 0 ${W} ${Hh}`, width: W, height: Hh, class: 'dchart' });
  for (let k = 0; k <= 4; k++) {
    const v = (ymax / 4) * k;
    svg.append(sv('line', { x1: m.l, x2: W - m.r, y1: y(v), y2: y(v), stroke: k ? C.grid : C.axis }), sv('text', { x: m.l - 6, y: y(v) + 3.5, 'text-anchor': 'end', class: 'ax' }, fmtMs(v)));
  }
  const ticks = Math.max(2, Math.floor(iw / 90));
  for (let k = 0; k < ticks; k++) {
    const t = d.from + (span * k) / (ticks - 1);
    svg.append(sv('text', { x: x(t), y: Hh - 5, 'text-anchor': k === 0 ? 'start' : k === ticks - 1 ? 'end' : 'middle', class: 'ax' }, tickTime(t, span)));
  }
  if (XV_SLOW < ymax) { // the "slow" line
    svg.append(sv('line', { x1: m.l, x2: W - m.r, y1: y(XV_SLOW), y2: y(XV_SLOW), stroke: C.warn, 'stroke-dasharray': '4 4', 'stroke-opacity': 0.7 }),
      sv('text', { x: W - m.r - 2, y: y(XV_SLOW) - 4, 'text-anchor': 'end', class: 'ax', fill: C.warn }, `느림 ${fmtMs(XV_SLOW)}`));
  }
  // percentile lines over time columns
  if (pctOn && sorted.length > 20) {
    const cols = Math.max(8, Math.min(60, Math.floor(iw / 14)));
    const bins = Array.from({ length: cols }, () => []);
    for (const p of pts) if (stShown(p[2])) bins[Math.min(cols - 1, Math.max(0, Math.floor(((p[0] - d.from) / span) * cols)))].push(p[1]);
    for (const [q, color, dash] of [[0.5, C.ink2, '5 4'], [0.95, C.s3, '']]) {
      let dd = '';
      bins.forEach((b, i) => {
        if (b.length < 3) return;
        b.sort((a, c) => a - c);
        const v = b[Math.min(b.length - 1, Math.floor(b.length * q))];
        dd += `${dd ? 'L' : 'M'}${(m.l + ((i + 0.5) / cols) * iw).toFixed(1)} ${y(v).toFixed(1)}`;
      });
      if (dd) svg.append(sv('path', { d: dd, fill: 'none', stroke: color, 'stroke-width': 2, 'stroke-dasharray': dash, 'stroke-linejoin': 'round' }),
        sv('text', { x: m.l + 4, y: m.t + (q === 0.5 ? 24 : 12), class: 'ax lbl', fill: color }, q === 0.5 ? 'p50' : 'p95'));
    }
  }
  const dpr = devicePixelRatio || 1;
  const cv = h('canvas', { width: Math.round(W * dpr), height: Math.round(Hh * dpr), style: { width: `${W}px`, height: `${Hh}px` } });
  const ctx = cv.getContext('2d');
  ctx.scale(dpr, dpr);
  // normal first, then 4xx, then 5xx on top; above the scale: ▲ on the top edge
  const r = pts.length > 3000 ? 1.8 : 2.3;
  for (const pass of [0, 1, 2]) {
    for (const p of pts) {
      const k = p[2] >= 500 ? 2 : p[2] >= 400 ? 1 : 0;
      if (k !== pass || !stShown(p[2])) continue;
      ctx.fillStyle = statusColor(p[2]);
      ctx.globalAlpha = k ? 0.95 : 0.6;
      const px = x(p[0]);
      if (p[1] > ymax) {
        ctx.beginPath(); ctx.moveTo(px, m.t - 1); ctx.lineTo(px - 3.5, m.t + 5); ctx.lineTo(px + 3.5, m.t + 5); ctx.closePath(); ctx.fill();
        continue;
      }
      ctx.beginPath();
      ctx.arc(px, y(p[1]), k === 2 ? r + 0.8 : r, 0, Math.PI * 2);
      ctx.fill();
    }
  }
  const brush = h('div', { class: 'brush', hidden: true });
  const read = h('div', { class: 'dtip readout', hidden: true });
  const ring = h('div', { class: 'sc-ring', hidden: true, 'aria-hidden': 'true' });
  const xline = h('div', { class: 'xv-cross', hidden: true, 'aria-hidden': 'true' });
  const layer = h('div', { class: 'scatter-layer', title: '끌어서 요청을 골라 보세요 · Shift+휠: 세로 범위' }, cv, svg, xline, ring, brush, read);
  // screen positions of the dots, for "which request is under the mouse"
  const at = [];
  pts.forEach((p, i) => { if (stShown(p[2])) at.push([x(p[0]), p[1] > ymax ? m.t + 3 : y(p[1]), p, i]); });
  const nearest = (mx2, my) => {
    let best = null; let bd = 7 * 7; let near = 0;
    for (const a of at) {
      const dx = a[0] - mx2, dy = a[1] - my, dd = dx * dx + dy * dy;
      if (dd <= 7 * 7) near++;
      if (dd <= bd) { bd = dd; best = a; }
    }
    return best ? { a: best, near } : null;
  };
  box.append(layer);
  if (!pts.length) box.append(h('p', { class: 'muted overlay-note' }, '아직 요청이 없습니다'));
  const me = {
    show: (tm) => { if (tm < d.from || tm > d.to) { xline.hidden = true; return; } xline.hidden = false; xline.style.left = `${x(tm)}px`; },
    hide: () => { xline.hidden = true; },
  };
  DASH.charts.push(me);
  // Shift+wheel: the vertical scale up / down
  layer.addEventListener('wheel', (ev) => {
    if (!ev.shiftKey) return;
    ev.preventDefault();
    const steps = XV_MAXES.slice(1).map(([v]) => +v);
    const cur = maxPref === 'auto' ? ymax : +maxPref;
    let i = steps.findIndex((v) => v >= cur);
    if (i < 0) i = steps.length - 1;
    i = Math.max(0, Math.min(steps.length - 1, i + ((ev.deltaY || ev.deltaX) > 0 ? 1 : -1)));
    xvSet(w, 'max', String(steps[i]));
    paintOne(w.id);
  }, { passive: false });
  const toData = (ev) => {
    const rr = layer.getBoundingClientRect();
    const px = Math.max(m.l, Math.min(ev.clientX - rr.left, W - m.r)), py = Math.max(m.t, Math.min(ev.clientY - rr.top, m.t + ih));
    return { px, py, t: d.from + ((px - m.l) / iw) * span, ms: Math.max(0, ((m.t + ih - py) / ih) * ymax) };
  };
  let start = null;
  layer.addEventListener('mousedown', (ev) => {
    if (ev.button !== 0) return;
    start = toData(ev); DASH.hold = true; ev.preventDefault();
    // finish wherever the button is released (also outside the chart)
    window.addEventListener('mouseup', end, { once: true });
    window.addEventListener('mousemove', drag);
  });
  const drag = (ev) => {
    if (!start) return;
    const p = toData(ev);
    brush.hidden = false;
    Object.assign(brush.style, { left: `${Math.min(start.px, p.px)}px`, top: `${Math.min(start.py, p.py)}px`, width: `${Math.abs(p.px - start.px)}px`, height: `${Math.abs(p.py - start.py)}px` });
  };
  // only over a dot: that request's time, response time and status (empty space shows nothing)
  const hide = () => { read.hidden = true; ring.hidden = true; };
  layer.addEventListener('mousemove', (ev) => {
    if (start) { hide(); return; }
    const rr = layer.getBoundingClientRect();
    const mxp = ev.clientX - rr.left;
    if (mxp >= m.l && mxp <= W - m.r) dashHover(d.from + ((mxp - m.l) / iw) * span, me);
    const hit = nearest(mxp, ev.clientY - rr.top);
    if (!hit) { hide(); return; }
    const [px, py, p, i] = hit.a;
    ring.hidden = false;
    Object.assign(ring.style, { left: `${px}px`, top: `${py}px`, borderColor: statusColor(p[2]) });
    read.hidden = false;
    const host = (d.hosts || [])[p[3]] || '';
    const req = (d.reqs || [])[i] || '';
    fill(read,
      h('div', null, h('b', null, fmtMs(p[1])), ` · ${p[2]} · ${hhmmss(p[0])}`, hit.near > 1 ? h('span', { class: 'muted' }, ` (겹친 요청 ${hit.near}건)`) : null),
      host ? h('div', { class: 'small' }, host) : null,
      req ? h('div', { class: 'mono small ellipsis' }, req) : null,
      (d.who || [])[i] ? h('div', { class: 'small' }, clientText({ ip: d.who[i][0], cc: d.who[i][1], via: d.who[i][2] })) : null,
      h('div', { class: 'muted small' }, '누르면 상세'));
    read.style.left = `${Math.max(0, Math.min(px + 12, W - 270))}px`; read.style.top = `${Math.max(py - 36, 0)}px`;
  });
  layer.addEventListener('mouseleave', () => { hide(); dashHover(null, me); });
  function end(ev) {
    window.removeEventListener('mousemove', drag);
    if (!start) return;
    const p = toData(ev);
    const s = start;
    start = null; DASH.hold = false; brush.hidden = true;
    const small = Math.abs(p.px - s.px) < 6 && Math.abs(p.py - s.py) < 6;
    const dot = small ? nearest(s.px, s.py) : null;
    // a click on a dot: that request (same time and response time); elsewhere ±15 s; a drag: the box
    // (a box reaching the top edge also takes the ▲ requests above the scale)
    const q = dot
      ? { from: dot.a[2][0] - 1, to: dot.a[2][0] + 1, min: Math.max(0, dot.a[2][1] - 0.01), max: dot.a[2][1] + 0.01, host: (d.hosts || [])[dot.a[2][3]] || w.host || '' }
      : small
        ? { from: s.t - 15000, to: s.t + 15000, min: 0, max: 1e12 }
        : { from: Math.min(s.t, p.t), to: Math.max(s.t, p.t), min: Math.min(s.ms, p.ms), max: Math.max(s.ms, p.ms) >= ymax * 0.98 ? 1e12 : Math.max(s.ms, p.ms) };
    openRequests({ host: w.host || '', ...q, st: stParam(), db: !!DASH.at });
  }
}

// ======================================================================= renderers

const RENDER = {
  stat(body, w, d) {
    const unit = d.unit || '';
    const v = d.value;
    let state = null;
    if (w.metric === 'healthUp' && d.caddyDown) state = statusPill('crit', 'Caddy 중단 — 접속 불가');
    else if (w.metric === 'healthUp' && d.down > 0) state = statusPill('crit', `${d.down}개 응답 없음`);
    else if (w.metric === 'certDays' && v >= 0 && v < (w.warn || 14)) state = statusPill(v < 7 ? 'crit' : 'warn', `${v}일 남음`);
    else if (w.warn && !LOWER_IS_BAD.has(w.metric) && v >= w.warn) state = statusPill('warn', `기준 ${fmtValue(w.metric, w.warn)}${unit === '%' ? '%' : ''} 초과`);
    const shown = w.metric === 'certDays' && v < 0 ? '—' : unit === 'ms' || unit === 'bytes' ? fmtValue(w.metric, v) : fmtNum(v);
    const sub = d.error ? d.error : w.metric === 'certDays' && d.fqdn ? d.fqdn : (w.metric === 'err5xx' || w.metric === 'err4xx') && d.count != null ? `${fmtNum(d.count)}건` : '';
    fill(body,
      h('div', { class: 'stat-main' }, h('span', { class: 'stat-val' }, shown), unit && unit !== 'ms' && unit !== 'bytes' ? h('span', { class: 'stat-unit' }, unit) : null),
      h('div', { class: 'stat-sub' }, state, sub ? h('span', { class: 'muted small' }, sub) : null),
      d.spark ? h('div', { class: 'stat-spark' }, sparkline(d.spark, Math.max(body.clientWidth, 120), Math.max(24, Math.min(80, body.clientHeight - 70)))) : null);
  },

  series(body, w, d) {
    const colors = w.metric === 'status' ? STATUS_CLASS.map((x) => x.color) : [C.s1, C.s2, C.s3, C.s4];
    const isSt = w.metric === 'status';
    const all = (d.series || []).map((s, i) => ({ ...s, color: colors[i], key: isSt ? (STATUS_CLASS[i] || {}).key : '' }));
    const series = isSt ? all.filter((s) => !DASH_HIDE_ST.has(s.key)) : all;
    const box = h('div', { class: 'chart-box' });
    const counts = Object.fromEntries(all.map((s) => [s.key, s.values.reduce((a, b) => a + b, 0)]));
    fill(body, isSt ? statusLegend(counts) : series.length > 1 ? legend(series.map((s) => ({ name: s.name, color: s.color }))) : null, box);
    if (!d.t || !d.t.length) { box.append(h('p', { class: 'muted' }, '데이터 없음')); return; }
    if (!series.length) { box.append(h('p', { class: 'muted' }, '모든 상태코드를 숨겼습니다 — 위 범례를 눌러 다시 보이세요')); return; }
    box.append(timeChart(box, { t: d.t, series, stacked: w.metric === 'status', unit: d.unit, step: d.step }));
  },

  scatter: scatterPanel,

  top(body, w, d) {
    if (w.dim === 'slow') {
      const list = d.slow || [];
      fill(body, list.length ? h('ol', { class: 'dlist' }, list.map((r) => h('li', null,
        h('span', { class: 'dl-main mono', title: `${r.host}${r.uri}` }, `${r.host}${r.uri}`),
        h('span', { class: 'dl-meta' }, h('span', { class: 'sdot', style: { background: statusColor(r.status) } }), String(r.status)),
        h('b', { class: 'dl-num' }, fmtMs(r.ms))))) : h('p', { class: 'muted' }, '요청 없음'));
      return;
    }
    const rows = d.rows || [];
    const max = Math.max(1, ...rows.map((r) => r.n));
    // a site / country row is a shortcut to that dashboard variable
    const pickable = w.dim === 'host' || w.dim === 'country';
    fill(body,
      rows.length ? h('ol', { class: 'dlist bars' }, rows.map((r) => {
        const li = h('li', { class: pickable ? 'pickable' : '', title: pickable ? '누르면 이 값으로 대시보드 필터' : null },
          h('div', { class: 'dl-top' },
            h('span', { class: `dl-main ${w.dim === 'host' ? '' : 'mono'}`, title: r.key }, w.dim === 'status' ? h('span', null, h('span', { class: 'sdot', style: { background: statusColor(+r.key) } }), r.key) : w.dim === 'country' ? h('span', null, h('span', { class: 'cc-badge' }, r.key), ` ${geoName(r.key)}`) : r.key),
            h('b', { class: 'dl-num' }, fmtNum(r.n))),
          h('div', { class: 'dl-bar' }, h('i', { style: { width: `${(r.n / max) * 100}%` } })),
          h('div', { class: 'dl-sub' }, `평균 ${fmtMs(r.avgMs)}`, r.errPct ? h('span', { class: 'errtxt' }, ` · 5xx ${r.errPct}%`) : null));
        if (pickable) li.addEventListener('click', () => setVar(w.dim === 'host' ? 'hosts' : 'countries', [r.key]));
        return li;
      }))
        : w.dim === 'client' || w.dim === 'country' ? h('div', { class: 'stack' }, h('p', { class: 'muted' }, '아직 접속자 주소가 기록된 요청이 없습니다'), clientWhyBox(0, 0)) : h('p', { class: 'muted' }, '요청 없음'),
      d.partial ? h('p', { class: 'hint' }, '최근 요청 2만 건 기준') : null);
  },

  map(body, w, d) { geoMapWidget(body, w, d, C, STATUS_CLASS); },

  health(body, w, d) {
    const list = d.services || [];
    if (!list.length) { fill(body, h('p', { class: 'muted' }, '확인 중… (30초마다)')); return; }
    // three states only: 서비스 중 (blue) · 느림 (500 ms or more, yellow) · 응답 없음 (red)
    const stOf = (s) => (!s.ok ? 'down' : s.ms >= 500 ? 'slow' : 'up');
    const look = { up: [optColor(w, 'up'), '서비스 중'], slow: [optColor(w, 'slow'), '느림'], down: [optColor(w, 'down'), '응답 없음'] };
    const n = { up: 0, slow: 0, down: 0 };
    for (const s of list) n[stOf(s)]++;
    const cd = d.caddy && d.caddy.down;
    const open = (s) => { const svc = S.state.services.find((x) => x.id === s.id); if (svc) openServiceDrawer(svc); };
    const caddyPill = cd ? h('div', { class: 'row' }, statusPill('crit', `Caddy 중단 (${caddyStateText(d.caddy)}) — 모든 사이트 접속 불가`)) : null;
    const sum = h('div', { class: 'dlegend hsum' }, ['up', 'slow', 'down'].filter((k) => n[k] || k === 'up').map((k) => h('span', null, h('i', { style: { background: look[k][0], borderRadius: '50%' } }), look[k][1], h('b', null, String(n[k])))));
    const svcBtn = (s, cls, ...kids) => {
      const b = h('button', { type: 'button', class: cls, title: `${s.fqdn}\n→ ${s.upstream}${s.err ? `\n${s.err}` : ''}` }, ...kids);
      b.addEventListener('click', () => open(s));
      return b;
    };
    if (w.view === 'donut' && (w.opts || {}).group === 'each') {
      // one ring per service: its recent checks as segments (oldest at the top, clockwise), the
      // response time inside, availability below
      const px = { s: 64, m: 84, l: 112 }[(w.opts || {}).size] || 84;
      const rows = list.slice().sort((a, b) => ['down', 'slow', 'up'].indexOf(stOf(a)) - ['down', 'slow', 'up'].indexOf(stOf(b)) || a.sub.localeCompare(b.sub));
      fill(body, caddyPill, sum, h('div', { class: 'hrings', style: { '--ring': `${px}px` } }, rows.map((s) => {
        const hist = (s.history || []).length ? s.history : [{ ok: s.ok, ms: s.ms }];
        const ok = hist.filter((x) => x.ok).length;
        const segs = hist.map((x) => { const k = !x.ok ? 'down' : x.ms >= 500 ? 'slow' : 'up'; return { v: 1, color: look[k][0], label: look[k][1] }; });
        const ring = donut(segs, 100, s.ok ? fmtMs(s.ms) : '✗', '', hist.length);
        ring.setAttribute('aria-label', `${s.sub}: ${look[stOf(s)][1]}, ${hist.length}번 중 ${ok}번 응답`);
        return svcBtn(s, 'hring', ring, h('b', { class: 'ellipsis' }, s.sub), h('span', { class: 'muted small' }, `가용 ${Math.round((ok / hist.length) * 100)}%`));
      })), h('p', { class: 'hint' }, '고리 = 최근 점검 기록(맨 위부터 시계 방향), 가운데 = 지금 응답시간'));
      return;
    }
    if (w.view === 'donut') {
      // a ring of the three states; the center: how many answer; beside it: the ones that need a look
      const order = ['down', 'slow', 'up'];
      const segs = order.filter((k) => n[k]).map((k) => ({ v: n[k], color: look[k][0], label: `${look[k][1]} ${n[k]}` }));
      const bad = list.filter((s) => stOf(s) !== 'up').sort((a, b) => (stOf(a) === 'down' ? -1 : 0) - (stOf(b) === 'down' ? -1 : 0) || b.ms - a.ms);
      const ring = donut(segs, 200, `${n.up + n.slow}/${list.length}`, '응답 중', list.length);
      ring.style.maxHeight = `${{ s: 110, m: 160, l: 230 }[(w.opts || {}).size] || 150}px`;
      fill(body, caddyPill, h('div', { class: 'hdonut-wrap' }, ring,
        h('div', { class: 'hdonut-side' }, sum,
          bad.length ? h('ol', { class: 'dlist' }, bad.map((s) => h('li', null,
            svcBtn(s, 'linkish dl-main', h('span', { class: 'sdot', style: { background: look[stOf(s)][0] } }), s.sub),
            h('span', { class: 'dl-num small' }, s.ok ? fmtMs(s.ms) : '응답 없음'))))
            : h('p', { class: 'muted small' }, '모든 서비스가 응답합니다'))));
      return;
    }
    if (w.view === 'bar') {
      // one bar per service: its response time, longest first; no answer = a full red bar
      const rows = list.slice().sort((a, b) => (a.ok === b.ok ? b.ms - a.ms : a.ok ? 1 : -1));
      const max = Math.max(500, ...list.filter((s) => s.ok).map((s) => s.ms)); // a full bar = slow (500 ms) or the slowest
      fill(body, caddyPill, sum, h('ol', { class: 'dlist hbars' }, rows.map((s) => {
        const k = stOf(s);
        return h('li', null, svcBtn(s, 'hbar-row',
          h('span', { class: 'hbar-name' }, s.sub),
          h('span', { class: 'hbar-track' }, h('i', { style: { width: `${s.ok ? Math.max(2, (s.ms / max) * 100) : 100}%`, background: look[k][0] } })),
          h('b', { class: 'hbar-val' }, s.ok ? fmtMs(s.ms) : '응답 없음')));
      })));
      return;
    }
    fill(body, caddyPill, sum,
      h('div', { class: 'hgrid' }, list.map((s) => {
        const k = stOf(s);
        return svcBtn(s, `htile ${k}`,
          h('div', { class: 'ht-top' }, h('span', { class: 'sdot', style: { background: look[k][0] } }), h('b', null, s.sub), h('span', { class: 'ht-ms' }, s.ok ? fmtMs(s.ms) : '응답 없음')));
      })));
  },

  containers(body, w, d) {
    const rows = d.containers || [];
    if (!d.collected) { fill(body, h('p', { class: 'muted' }, '수집 중… (15초마다)')); return; }
    const head = (r) => h('div', { class: 'dl-top' }, h('b', { class: 'mono ellipsis', title: r.name }, r.name), r.running ? null : statusPill('crit', '중지/없음'));
    if (w.view === 'gauge') {
      // per container: CPU and memory as rings (memory = % of its limit, or of the host when unlimited)
      const size = 100; // drawn in a 100-unit box; CSS sets the size (opts.size)
      const cpuC = optColor(w, 'cpu'), memC = optColor(w, 'mem');
      // running ones as cards; the stopped ones on one line at the bottom
      const live = rows.filter((r) => r.running && r.last);
      const down = rows.filter((r) => !(r.running && r.last));
      fill(body, h('div', { class: 'ctr-gauges', style: { '--ring': `${{ s: 46, m: 62, l: 84 }[(w.opts || {}).size] || 62}px` } }, live.map((r) => {
        const l = r.last;
        return h('div', { class: 'ctr-gauge' }, head(r), h('div', { class: 'cg-rings' },
          gauge(l.cpu, size, cpuC, 'CPU', `${l.cpu.toFixed(1)}%`),
          gauge(l.memPct, size, memC, 'MEM', fmtBytes(l.mem), l.memPct ? `${l.memPct.toFixed(0)}%` : '')));
      })), down.length ? h('div', { class: 'cg-down' }, statusPill('crit', `중지/없음 ${down.length}`), h('span', { class: 'mono small ellipsis', title: down.map((r) => r.name).join(', ') }, down.map((r) => r.name).join(', '))) : null);
      return;
    }
    if (w.view === 'bar') {
      const bar = (label, pct, color, val) => h('div', { class: 'cbar' },
        h('span', { class: 'muted small' }, label),
        h('span', { class: 'hbar-track' }, h('i', { style: { width: `${Math.max(1, Math.min(100, pct))}%`, background: pct >= 90 ? C.warn : color } })),
        h('b', { class: 'hbar-val' }, val));
      fill(body, h('div', { class: 'ctr-list' }, rows.map((r) => {
        const l = r.last;
        return h('div', { class: 'ctr-row' }, head(r),
          r.running && l ? h('div', { class: 'cbars' },
            bar('CPU', l.cpu, optColor(w, 'cpu'), `${l.cpu.toFixed(1)}%`),
            bar('MEM', l.memPct, optColor(w, 'mem'), `${fmtBytes(l.mem)}${l.memPct ? ` · ${l.memPct.toFixed(0)}%` : ''}`)) : null);
      })));
      return;
    }
    fill(body, h('div', { class: 'ctr-list' }, rows.map((r) => {
      const l = r.last;
      return h('div', { class: 'ctr-row' }, head(r),
        r.running && l ? h('div', { class: 'ctr-metrics' },
          h('div', null, h('span', { class: 'muted small' }, 'CPU'), h('b', null, `${l.cpu.toFixed(1)}%`), sparkline(r.history.map((p) => p.cpu), 80, 18, optColor(w, 'cpu'))),
          h('div', null, h('span', { class: 'muted small' }, 'MEM'), h('b', null, fmtBytes(l.mem)), sparkline(r.history.map((p) => p.mem), 80, 18, optColor(w, 'mem')))) : null);
    })));
  },

  certs(body, w, d) {
    const list = d.certs || [];
    if (!list.length) { fill(body, h('p', { class: 'muted' }, '확인 중…')); return; }
    fill(body, h('ol', { class: 'dlist' }, list.map((c) => h('li', null,
      h('span', { class: 'dl-main', title: c.err || `${c.issuer} · ${fmtTime(c.notAfter)}` }, c.fqdn),
      c.err ? h('span', { class: 'muted small', title: c.err }, '확인 불가')
        : c.internal ? statusPill('good', `${c.days >= 1 ? `${c.days}일` : `${c.hours}시간`} · 자동 갱신`)
          : statusPill(c.days < 7 ? 'crit' : c.days < 21 ? 'warn' : 'good', c.days >= 1 ? `${c.days}일` : `${c.hours}시간`)))));
  },

  events(body, w, d) {
    const list = d.events || [];
    fill(body, list.length ? h('ol', { class: 'dlist events' }, list.map((e) => h('li', null,
      h('span', { class: 'ev-time' }, ago(e.t)),
      statusPill(e.kind === 'waf' ? 'serious' : 'crit', e.kind === 'waf' ? 'WAF' : '5xx'),
      h('span', { class: 'dl-main', title: e.sub }, e.text)))) : h('p', { class: 'muted' }, '24시간 동안 이벤트 없음'));
  },
};

// ======================================================================= drill-down

/** status classes for the request list: the dashboard's status variable ∩ the legend toggles */
function stParam() {
  const vc = DASH.vars.classes;
  const shown = STATUS_CLASS.filter((c) => !DASH_HIDE_ST.has(c.key) && (!vc.length || vc.includes(+c.key[1])));
  return shown.length === STATUS_CLASS.length ? '' : shown.map((c) => c.key[1]).join(',') || '0';
}

const REQ_COLS = [
  ['t', '시각', (x) => hhmmss(x.t)], ['host', '사이트', (x) => x.host], ['uri', '요청', (x) => `${x.method} ${x.uri}`],
  ['status', '상태', null], ['ms', '응답시간', null], ['size', '크기', (x) => fmtBytes(x.size)], ['ip', '접속자 (IP · 국가)', null],
];
async function openRequests(q) {
  const v = DASH.vars;
  const params = new URLSearchParams({
    from: Math.round(q.from), to: Math.round(q.to), min: q.min, max: q.max, host: q.host, db: q.db ? '1' : '0', st: q.st || '',
    hosts: v.hosts.join(','), cc: v.countries.join(','), via: v.vias.join(','),
  });
  const stTxt = q.st ? STATUS_CLASS.filter((c) => q.st.split(',').includes(c.key[1])).map((c) => c.name).join('·') : '';
  const body = h('div', { class: 'stack' }, spinnerRow('요청을 찾는 중…'));
  const close = h('button', { type: 'button', class: 'btn primary' }, '닫기');
  const dlg = openDialog({ title: `요청 상세 · ${hhmmss(q.from)} ~ ${hhmmss(q.to)}`, body, footer: [close], size: 'wide' });
  close.addEventListener('click', () => dlg.close());
  try {
    const r = await api('GET', `/api/dash/requests?${params}`);
    const list = r.requests || [];
    if (!list.length) { fill(body, h('p', { class: 'muted' }, '선택한 영역에 요청이 없습니다.')); return; }
    let sortKey = 'ms', desc = true;
    const ms = list.map((x) => x.ms);
    const errs = list.filter((x) => x.status >= 500).length;
    const tbody = h('tbody');
    const heads = REQ_COLS.map(([k, label]) => {
      const b = h('button', { type: 'button', class: 'th-sort' }, label);
      b.addEventListener('click', () => { if (sortKey === k) desc = !desc; else { sortKey = k; desc = k !== 'host' && k !== 'uri' && k !== 'ip'; } draw(); });
      return h('th', { scope: 'col', 'data-k': k }, b);
    });
    const draw = () => {
      const kf = (x) => (sortKey === 'uri' ? x.uri : x[sortKey]);
      const sorted = list.slice().sort((a, b) => { const A = kf(a), B = kf(b); const c = A < B ? -1 : A > B ? 1 : 0; return desc ? -c : c; });
      for (const th of heads) th.setAttribute('aria-sort', th.dataset.k === sortKey ? (desc ? 'descending' : 'ascending') : 'none');
      tbody.replaceChildren(...sorted.map((x) => h('tr', null,
        h('td', null, hhmmss(x.t)), h('td', null, x.host),
        h('td', { class: 'mono ellipsis', title: x.uri }, `${x.method} ${x.uri}`),
        h('td', null, h('span', { class: 'sdot', style: { background: statusColor(x.status) } }), String(x.status)),
        h('td', null, h('b', null, fmtMs(x.ms))), h('td', null, fmtBytes(x.size)), h('td', null, clientCell(x)))));
    };
    draw();
    const filt = [v.hosts.length ? v.hosts.join(', ') : q.host, v.countries.length ? v.countries.map(geoName).join(', ') : '', v.vias.length ? v.vias.map(viaLabel).join(', ') : ''].filter(Boolean).join(' · ');
    const note = [q.max < 1e11 ? `응답시간 ${fmtMs(q.min)} ~ ${fmtMs(q.max)}` : '', filt, stTxt ? `${stTxt}만` : '', r.total > list.length ? `느린 순 ${list.length}건만 표시` : ''].filter(Boolean).join(' · ');
    fill(body,
      h('div', { class: 'req-sum' },
        h('span', null, h('b', null, fmtNum(r.total)), '건'),
        h('span', null, '평균 ', h('b', null, fmtMs(ms.reduce((a, b) => a + b, 0) / ms.length))),
        h('span', null, '최대 ', h('b', null, fmtMs(Math.max(...ms)))),
        errs ? h('span', { class: 'errtxt' }, `5xx ${errs}건`) : null,
        note ? h('span', { class: 'muted small' }, note) : null),
      h('div', { class: 'table-wrap glass-inner' }, h('table', { class: 'compact sortable' }, h('thead', null, h('tr', null, heads)), tbody)));
  } catch (ex) { fill(body, errorBox(ex.message)); }
}

// ======================================================================= editor

const VIEWS = {
  health: [['', '타일'], ['donut', '원형'], ['bar', '막대']],
  containers: [['', '목록 (추이선)'], ['gauge', '게이지 (원형)'], ['bar', '막대']],
};
/** the colorable parts of a panel: [part, label, default color getter] */
const COLOR_PARTS = {
  health: [['up', '서비스 중', () => C.s1], ['slow', '느림', () => C.warn], ['down', '응답 없음', () => C.crit]],
  containers: [['cpu', 'CPU', () => C.s1], ['mem', '메모리', () => C.s3]],
};
function optColor(w, part) {
  const v = (w.opts || {})[`c.${part}`];
  if (v) return v;
  const d = (COLOR_PARTS[w.type] || []).find((x) => x[0] === part);
  return d ? d[2]() : C.s1;
}
const OPT_SIZES = [['', '자동'], ['s', '작게'], ['m', '보통'], ['l', '크게']];
const SIZE_W = [['6', '¼ 폭'], ['8', '⅓ 폭'], ['12', '½ 폭'], ['16', '⅔ 폭'], ['18', '¾ 폭'], ['24', '전체 폭']];
const SIZE_H = [['4', '아주 낮게'], ['6', '낮게'], ['8', '보통'], ['10', '조금 높게'], ['12', '높게'], ['16', '아주 높게']];

function openWidgetEditor(existing) {
  const isNew = !existing;
  const wd = existing ? structuredClone(existing) : { type: 'stat', ...WIDGET_TYPES.stat.def, title: '' };
  const hosts = [...new Set(S.state.services.filter((s) => s.enabled && !s.dnsOnly).map((s) => fqdn(s.subdomain)))].sort();

  const typeList = h('div', { class: 'wtypes', role: 'radiogroup', 'aria-label': '패널 종류' });
  for (const [k, t] of Object.entries(WIDGET_TYPES)) {
    typeList.append(h('label', { class: 'wtype' }, h('input', { type: 'radio', name: 'wtype', value: k, checked: wd.type === k }),
      h('span', null, h('b', null, t.name), h('small', null, t.desc))));
  }
  const title = h('input', { type: 'text', value: wd.title || '', maxlength: '40', placeholder: '비우면 자동' });
  const sel = (opts, v) => {
    const s = h('select', null, opts.map(([k, l]) => h('option', { value: k, selected: String(v) === k }, l)));
    if (![...s.options].some((o) => o.selected) && v) s.append(h('option', { value: String(v), selected: true }, `${v}칸`));
    return s;
  };
  const wSel = sel(SIZE_W, wd.w);
  const hSel = sel(SIZE_H, wd.h);
  const statM = sel(STAT_METRICS.filter(([k]) => (k !== 'csBans' || use('crowdsec')) && (!['waf', 'certDays'].includes(k) || use('caddy'))), wd.metric);
  const serM = sel(SERIES_METRICS, wd.metric);
  const hostS = sel([['', '모든 사이트 (대시보드 필터를 따름)'], ...hosts.map((x) => [x, x])], wd.host || '');
  const dimS = sel(TOP_DIMS, wd.dim || 'host');
  const limitI = h('input', { type: 'number', min: '1', max: '50', value: wd.limit || 8 });
  const warnI = h('input', { type: 'number', min: '0', step: 'any', value: wd.warn || '' });
  const known = [...new Set(Object.values(DASH.data || {}).flatMap((x) => (x && x.known) || []))].sort();
  const ctrI = h('input', { type: 'text', class: 'mono', value: (wd.containers || []).join(', '), placeholder: '비우면 Caddy·Authelia·CrowdSec·길목', list: 'ctr-known' });
  const ctrList = h('datalist', { id: 'ctr-known' }, known.map((k) => h('option', { value: k })));
  const viewS = h('select');
  const o0 = wd.opts || {};
  const sizeS = h('select', null, OPT_SIZES.map(([k, l]) => h('option', { value: k, selected: (o0.size || '') === k }, l)));
  const groupS = h('select', null, [['', '전체 묶음 (고리 하나)'], ['each', '서비스별 (고리 여러 개)']].map(([k, l]) => h('option', { value: k, selected: (o0.group || '') === k }, l)));
  const colorBox = h('div', { class: 'color-opts' });
  const colorIn = {};
  const drawColors = (t) => {
    colorBox.replaceChildren(...(COLOR_PARTS[t] || []).map(([part, label, def]) => {
      const cur = wd.type === t ? o0[`c.${part}`] : '';
      const inp = h('input', { type: 'color', value: cur || toHex(def()), 'aria-label': `${label} 색` });
      inp.dataset.custom = cur ? '1' : '';
      inp.addEventListener('input', () => { inp.dataset.custom = '1'; });
      const reset = h('button', { type: 'button', class: 'btn ghost sm', title: '기본 색으로' }, '기본');
      reset.addEventListener('click', () => { inp.value = toHex(def()); inp.dataset.custom = ''; });
      colorIn[part] = inp;
      return h('label', { class: 'color-opt' }, inp, h('span', null, label), reset);
    }));
  };

  const f = {
    statM: field('지표', statM), serM: field('지표', serM), host: field('사이트', hostS),
    view: field('표시 방식', viewS), size: field('크기', sizeS), group: field('원형 묶음', groupS), colors: field('색', colorBox), dim: field('기준', dimS), limit: field('개수', limitI), warn: field('경고 기준값', warnI, ''), ctr: field('컨테이너 (쉼표 구분)', ctrI, known.length ? `수집 중: ${known.slice(0, 8).join(', ')}${known.length > 8 ? ' …' : ''}` : ''),
  };
  const errEl = h('p', { class: 'form-error', role: 'alert', hidden: true });
  const form = h('div', { class: 'stack' }, errEl,
    isNew ? h('div', { class: 'field' }, h('span', { class: 'field-label' }, '종류'), typeList) : h('p', { class: 'muted small' }, `종류: ${WIDGET_TYPES[wd.type].name} — 다른 종류는 「패널 추가」에서 새로 넣으세요`),
    h('div', { class: 'grid-2' }, field('제목', title), h('div', { class: 'grid-2' }, field('너비', wSel), field('높이', hSel))),
    h('p', { class: 'hint' }, '크기·자리는 대시보드에서 제목 줄을 끌어 옮기고, 오른쪽 아래 모서리를 끌어 바꿀 수도 있습니다. 기간은 대시보드 위의 시간 선택을 모든 패널이 함께 씁니다.'),
    h('div', { class: 'grid-2' }, f.statM, f.serM, f.view, f.size, f.group, f.dim, f.host, f.limit, f.warn, f.ctr), f.colors, ctrList);
  const cur = () => (isNew ? typeList.querySelector('input:checked').value : wd.type);
  const sync = (changedType) => {
    const t = cur();
    if (changedType) { const d = WIDGET_TYPES[t].def; wSel.value = String(d.w); hSel.value = String(d.h); }
    f.statM.hidden = t !== 'stat'; f.serM.hidden = t !== 'series'; f.dim.hidden = t !== 'top'; f.limit.hidden = t !== 'top';
    f.host.hidden = !['stat', 'series', 'scatter', 'top', 'map'].includes(t) || (t === 'stat' && ['csBans', 'healthUp', 'certDays'].includes(statM.value));
    f.warn.hidden = t !== 'stat' || ['csBans', 'healthUp'].includes(statM.value);
    f.ctr.hidden = t !== 'containers';
    f.view.hidden = !VIEWS[t];
    f.size.hidden = !VIEWS[t];
    f.colors.hidden = !COLOR_PARTS[t];
    if (colorBox.dataset.t !== t) { colorBox.dataset.t = t; drawColors(t); }
    if (VIEWS[t] && viewS.dataset.t !== t) {
      viewS.dataset.t = t;
      viewS.replaceChildren(...VIEWS[t].map(([k, l]) => h('option', { value: k, selected: (wd.type === t ? wd.view || '' : '') === k }, l)));
    }
    f.group.hidden = !(t === 'health' && viewS.value === 'donut');
    const m = statM.value;
    const hint = f.warn.querySelector('.hint');
    if (hint) hint.textContent = m === 'certDays' ? '이 일수보다 적으면 경고 (비우면 14일)'
      : m === 'p95Ms' || m === 'avgMs' ? '이 값(ms) 이상이면 경고' : m === 'err5xx' || m === 'err4xx' ? '이 비율(%) 이상이면 경고' : '이 값 이상이면 경고 (비우면 없음)';
  };
  if (!f.warn.querySelector('.hint')) f.warn.append(h('p', { class: 'hint' }));
  typeList.addEventListener('change', () => sync(true));
  statM.addEventListener('change', () => sync(false));
  viewS.addEventListener('change', () => sync(false));
  sync(false);

  const save = h('button', { type: 'button', class: 'btn primary' }, isNew ? '추가' : '저장');
  const cancel = h('button', { type: 'button', class: 'btn ghost' }, '취소');
  const del = isNew ? null : h('button', { type: 'button', class: 'btn danger' }, '삭제');
  const dlg = openDialog({ title: isNew ? '패널 추가' : '패널 편집', body: form, footer: [del, h('span', { class: 'spacer' }), cancel, save], size: 'wide' });
  setTimeout(() => { const c = isNew ? typeList.querySelector('input:checked') : title; if (c) c.focus(); }, 30);
  cancel.addEventListener('click', () => dlg.close());
  if (del) del.addEventListener('click', async () => { dlg.close(); await removeWidget(existing); });
  save.addEventListener('click', () => busy(save, async () => {
    const t = cur();
    const out = {
      id: wd.id, type: t, title: title.value.trim(), w: +wSel.value, h: +hSel.value, g: 24,
      x: existing ? existing.x : 0, y: existing ? existing.y : layoutBottom(DASH.widgets),
      metric: t === 'stat' ? statM.value : t === 'series' ? serM.value : '', range: wd.range || '1h', host: hostS.value,
      dim: dimS.value, limit: parseInt(limitI.value, 10) || 8, warn: parseFloat(warnI.value) || 0,
      containers: splitList(ctrI.value), view: VIEWS[t] ? viewS.value : '', opts: {},
    };
    if (VIEWS[t] && sizeS.value) out.opts.size = sizeS.value;
    if (t === 'health' && viewS.value === 'donut' && groupS.value) out.opts.group = groupS.value;
    for (const [part] of COLOR_PARTS[t] || []) if (colorIn[part] && colorIn[part].dataset.custom) out.opts[`c.${part}`] = colorIn[part].value;
    if (out.x + out.w > 24) out.x = 24 - out.w;
    if (!out.title) out.title = autoTitle(out);
    let list = DASH.widgets.slice();
    if (isNew) list.push(out); else list[list.findIndex((x) => x.id === wd.id)] = { ...existing, ...out };
    list = compact(list, out.id || null);
    try {
      await saveLayout(list);
      dlg.close();
      toast(isNew ? '패널을 추가했습니다' : '패널을 저장했습니다');
    } catch (ex) { errEl.textContent = ex.message; errEl.hidden = false; }
  }));
}

function autoTitle(w) {
  const pick = (arr, k) => (arr.find((x) => x[0] === k) || [k, k])[1];
  const host = w.host ? ` · ${w.host.split('.')[0]}` : '';
  switch (w.type) {
    case 'stat': return pick(STAT_METRICS, w.metric).replace(/ \(.+\)$/, '') + host;
    case 'series': return `${pick(SERIES_METRICS, w.metric)} 추이${host}`;
    case 'top': return `상위 ${pick(TOP_DIMS, w.dim).replace(/ \(.+\)$/, '')}${host}`;
    default: return WIDGET_TYPES[w.type].name + host;
  }
}

// ======================================================================= grid layout (24 columns)
// every panel has x / y / w / h in grid cells; panels fall upward into free space (vertical
// compaction); moving or resizing one pushes the others out of the way while the pointer moves.

const GRID_COLS = 24;
const ROW_PX = 30, GAP_PX = 10;
const overlap = (a, b) => a.x < b.x + b.w && b.x < a.x + a.w && a.y < b.y + b.h && b.y < a.y + a.h;
const layoutBottom = (list) => list.reduce((m, x) => Math.max(m, (x.y || 0) + (x.h || 0)), 0);

/** pack every panel upward; `fixedId` stays where it is (the one being moved), the others go around it */
function compact(list, fixedId) {
  const out = list.map((x) => ({ ...x }));
  const fixed = fixedId ? out.find((x) => x.id === fixedId) : null;
  const placed = fixed ? [fixed] : [];
  const rest = out.filter((x) => x !== fixed).sort((a, b) => a.y - b.y || a.x - b.x);
  for (const it of rest) {
    it.x = Math.max(0, Math.min(it.x, GRID_COLS - it.w));
    // push below anything it overlaps, then rise while the cell above is free
    for (let guard = 0; guard < 500; guard++) {
      const hit = placed.find((p) => overlap(p, it));
      if (!hit) break;
      it.y = hit.y + hit.h;
    }
    while (it.y > 0 && !placed.some((p) => overlap(p, { ...it, y: it.y - 1 }))) it.y--;
    placed.push(it);
  }
  if (fixed) { // the fixed one rises too when nothing is above it
    while (fixed.y > 0 && !placed.some((p) => p !== fixed && overlap(p, { ...fixed, y: fixed.y - 1 }))) fixed.y--;
  }
  return out;
}

/** a layout saved by an older version (4 columns, rows of 150 px, no positions) → 24 columns */
function upgradeLayout(list) {
  if (list.every((x) => x.g === 24)) return null;
  const out = [];
  let cx = 0, cy = 0, rowH = 0;
  for (const x of list) {
    const w = x.g === 24 ? x.w : Math.min(GRID_COLS, (x.w || 1) * 6);
    const hh = x.g === 24 ? x.h : (x.h || 1) * 4;
    if (cx + w > GRID_COLS) { cx = 0; cy += rowH; rowH = 0; }
    out.push({ ...x, g: 24, w, h: hh, x: cx, y: cy });
    cx += w;
    rowH = Math.max(rowH, hh);
  }
  return compact(out, null);
}

function placeCard(card, it) {
  card.style.gridColumn = `${it.x + 1} / span ${it.w}`;
  card.style.gridRow = `${it.y + 1} / span ${it.h}`;
  card.style.setProperty('--h', it.h);
}

/** apply new positions to every card, animating the ones that moved (except `skip`) */
function flipLayout(list, skip) {
  const first = new Map();
  for (const [id, c] of DASH.cards) if (c.card !== skip) first.set(c.card, c.card.getBoundingClientRect());
  for (const it of list) { const c = DASH.cards.get(it.id); if (c) { placeCard(c.card, it); c.w = it; } }
  for (const [card, a] of first) {
    const b = card.getBoundingClientRect();
    const dx = a.left - b.left, dy = a.top - b.top;
    if (!dx && !dy) continue;
    card.animate([{ transform: `translate(${dx}px, ${dy}px)` }, { transform: 'none' }], { duration: 180, easing: 'cubic-bezier(.2,.7,.3,1)' });
  }
}

let saveT = 0;
/** save positions after a move / resize (debounced; the grid already shows them) */
function saveLayoutSoon(list) {
  DASH.widgets = list;
  clearTimeout(saveT);
  saveT = setTimeout(() => {
    api('PUT', '/api/dashboard', { widgets: list }).then((r) => { if (DASH.widgets === list) DASH.widgets = r.widgets; })
      .catch((ex) => { toast(ex.message, 'err'); buildGrid(); });
  }, 400);
}

const gridNarrow = () => !dashGrid || dashGrid.clientWidth < 880;
const cellW = () => (dashGrid.clientWidth + GAP_PX) / GRID_COLS;

/** drag a panel by its title bar, or resize it from the corner (mode 'move' | 'size') */
function gridDrag(ev, id, mode) {
  if (ev.button !== 0 || gridNarrow() || !canEditDash()) return;
  if (ev.target.closest('button, a, select, input') && mode === 'move') return;
  const c = DASH.cards.get(id);
  if (!c) return;
  ev.preventDefault();
  const card = c.card;
  const orig = { ...c.w };
  const sx = ev.clientX, sy = ev.clientY;
  const scroll0 = window.scrollY;
  const ph = h('div', { class: 'grid-ph', 'aria-hidden': 'true' });
  placeCard(ph, orig);
  dashGrid.append(ph);
  card.classList.add(mode === 'move' ? 'dragging' : 'resizing');
  document.body.classList.add('grid-busy');
  let target = orig;
  let last = DASH.widgets;
  let raf = 0, scrollT = 0, lastEv = ev;
  const step = () => {
    const e = lastEv;
    const cw = cellW(), rh = ROW_PX + GAP_PX;
    const dx = e.clientX - sx, dy = e.clientY - sy + (window.scrollY - scroll0);
    let next;
    if (mode === 'move') {
      next = { ...orig, x: Math.max(0, Math.min(GRID_COLS - orig.w, Math.round(orig.x + dx / cw))), y: Math.max(0, Math.round(orig.y + dy / rh)) };
    } else {
      next = { ...orig, w: Math.max(3, Math.min(GRID_COLS - orig.x, Math.round(orig.w + dx / cw))), h: Math.max(2, Math.min(40, Math.round(orig.h + dy / rh))) };
    }
    if (next.x !== target.x || next.y !== target.y || next.w !== target.w || next.h !== target.h) {
      target = next;
      last = compact(DASH.widgets.map((x) => (x.id === id ? target : x)), id);
      const mine = last.find((x) => x.id === id);
      placeCard(ph, mine);
      flipLayout(last, card);
      if (mode === 'size') placeCard(card, mine);
    }
    if (mode === 'move') { // the card follows the pointer from its grid cell
      const mine = last.find((x) => x.id === id) || target;
      card.style.transform = `translate(${(orig.x - mine.x) * cw + dx}px, ${(orig.y - mine.y) * rh + dy}px)`;
    }
  };
  const move = (e) => {
    lastEv = e;
    cancelAnimationFrame(raf);
    raf = requestAnimationFrame(step);
    // scroll the page when the pointer is near the top / bottom edge
    clearInterval(scrollT);
    const edge = e.clientY < 60 ? -1 : e.clientY > window.innerHeight - 60 ? 1 : 0;
    if (edge) scrollT = setInterval(() => { window.scrollBy(0, edge * 14); step(); }, 30);
  };
  const up = (e) => {
    window.removeEventListener('pointermove', move);
    window.removeEventListener('pointerup', up);
    window.removeEventListener('pointercancel', up);
    cancelAnimationFrame(raf);
    clearInterval(scrollT);
    if (e && e.type === 'pointerup') { lastEv = e; step(); } // a quick drag: the last move may not have been drawn yet
    ph.remove();
    card.classList.remove('dragging', 'resizing');
    document.body.classList.remove('grid-busy');
    card.style.transform = '';
    const mine = last.find((x) => x.id === id);
    if (mine) placeCard(card, mine);
    const changed = last.some((x) => { const o = DASH.widgets.find((y) => y.id === x.id); return !o || o.x !== x.x || o.y !== x.y || o.w !== x.w || o.h !== x.h; });
    if (changed) { saveLayoutSoon(last); orderCards(); paintOne(id); if (mode === 'size') paintAll(); }
  };
  window.addEventListener('pointermove', move);
  window.addEventListener('pointerup', up);
  window.addEventListener('pointercancel', up);
}

/** Alt+arrows move the focused panel, Alt+Shift+arrows resize it */
function gridKey(ev, id) {
  if (!ev.altKey || !canEditDash() || !['ArrowLeft', 'ArrowRight', 'ArrowUp', 'ArrowDown'].includes(ev.key)) return;
  ev.preventDefault();
  const it = { ...DASH.cards.get(id).w };
  const dx = ev.key === 'ArrowLeft' ? -1 : ev.key === 'ArrowRight' ? 1 : 0;
  const dy = ev.key === 'ArrowUp' ? -1 : ev.key === 'ArrowDown' ? 1 : 0;
  if (ev.shiftKey) { it.w = Math.max(3, Math.min(GRID_COLS - it.x, it.w + dx)); it.h = Math.max(2, it.h + dy); } else {
    it.x = Math.max(0, Math.min(GRID_COLS - it.w, it.x + dx));
    it.y = Math.max(0, it.y + (dy > 0 ? it.h : dy)); // down: jump past the panel below
  }
  const list = compact(DASH.widgets.map((x) => (x.id === id ? it : x)), id);
  flipLayout(list, null);
  saveLayoutSoon(list);
  orderCards();
  if (ev.shiftKey) paintOne(id);
}

/** DOM order = reading order (top-left first): narrow screens stack the panels in that order */
function orderCards() {
  const sorted = [...DASH.cards.values()].sort((a, b) => a.w.y - b.w.y || a.w.x - b.w.x);
  const focused = document.activeElement;
  let prev = null;
  for (const c of sorted) {
    if ((prev ? prev.nextElementSibling : dashGrid.firstElementChild) !== c.card) dashGrid.insertBefore(c.card, prev ? prev.nextElementSibling : dashGrid.firstElementChild);
    prev = c.card;
  }
  if (focused && focused.isConnected && focused !== document.activeElement) focused.focus();
}

// ======================================================================= gallery

// sizes in grid cells (24 columns)
const WIDGET_PRESETS = [
  { id: 'rpm', w: { type: 'stat', metric: 'rpm', title: '분당 요청', w: 6, h: 4 }, look: 'stat', desc: '최근 1분 동안 들어온 요청 수' },
  { id: 'err5xx', w: { type: 'stat', metric: 'err5xx', title: '5xx 오류율', w: 6, h: 4, warn: 1 }, look: 'stat', desc: '서버 쪽 오류 비율 — 1% 넘으면 경고' },
  { id: 'p95', w: { type: 'stat', metric: 'p95Ms', title: '응답시간 p95', w: 6, h: 4, warn: 1000 }, look: 'stat', desc: '느린 쪽 5% 요청의 응답시간' },
  { id: 'requests', w: { type: 'stat', metric: 'requests', title: '요청 수', w: 6, h: 4 }, look: 'stat', desc: '기간 동안의 전체 요청 수' },
  { id: 'waf', w: { type: 'stat', metric: 'waf', title: 'WAF 차단', w: 6, h: 4 }, look: 'stat', desc: 'WAF·기본 차단·국가 차단으로 막은 요청', need: 'caddy' },
  { id: 'healthUp', w: { type: 'stat', metric: 'healthUp', title: '정상 서비스 수', w: 6, h: 4 }, look: 'stat', desc: '응답하는 서비스 수 — 응답 없음이 있으면 경고' },
  { id: 'csBans', w: { type: 'stat', metric: 'csBans', title: 'CrowdSec 차단 IP', w: 6, h: 4 }, look: 'stat', desc: 'CrowdSec이 차단 중인 IP 수', need: 'crowdsec' },
  { id: 'certDays', w: { type: 'stat', metric: 'certDays', title: '인증서 최단 남은 일수', w: 6, h: 4, warn: 14 }, look: 'stat', desc: '가장 먼저 만료되는 인증서까지 남은 날', need: 'caddy' },
  { id: 'scatter', w: { type: 'scatter', title: '응답시간 분포', w: 12, h: 10 }, look: 'scatter', desc: '요청 하나하나를 점으로 — 끌어서 고르면 요청 목록 (X-View 방식)' },
  { id: 'status', w: { type: 'series', metric: 'status', title: '요청 추이 (상태코드별)', w: 12, h: 8 }, look: 'series', desc: '2xx·3xx·4xx·5xx 요청 수의 흐름' },
  { id: 'latency', w: { type: 'series', metric: 'latency', title: '응답시간 추이', w: 12, h: 8 }, look: 'series', desc: '평균·p95 응답시간의 흐름' },
  { id: 'bytes', w: { type: 'series', metric: 'bytes', title: '전송량 추이', w: 12, h: 8 }, look: 'series', desc: '보낸 데이터 양의 흐름' },
  { id: 'wafSeries', w: { type: 'series', metric: 'waf', title: 'WAF 차단 추이', w: 12, h: 8 }, look: 'series', desc: '차단 수의 흐름', need: 'caddy' },
  { id: 'map', w: { type: 'map', title: '접속 지역', w: 12, h: 12 }, look: 'map', desc: '나라별 요청·거부를 세계지도 위 원 크기로' },
  { id: 'health', w: { type: 'health', title: '서비스 상태', w: 12, h: 8 }, look: 'health', desc: '서비스마다 서비스 중·느림·응답 없음' },
  { id: 'topHost', w: { type: 'top', dim: 'host', title: '많이 쓰는 사이트', w: 6, h: 8, limit: 8 }, look: 'top', desc: '요청이 많은 사이트 순위' },
  { id: 'topPath', w: { type: 'top', dim: 'path', title: '많이 찾는 경로', w: 6, h: 8, limit: 8 }, look: 'top', desc: '요청이 많은 주소(경로) 순위' },
  { id: 'topCountry', w: { type: 'top', dim: 'country', title: '접속 국가 순위', w: 6, h: 8, limit: 8 }, look: 'top', desc: '요청이 많은 나라 순위' },
  { id: 'topClient', w: { type: 'top', dim: 'client', title: '접속자 IP 순위', w: 6, h: 8, limit: 8 }, look: 'top', desc: '요청이 많은 접속자 IP 순위' },
  { id: 'topStatus', w: { type: 'top', dim: 'status', title: '상태코드 순위', w: 6, h: 8, limit: 8 }, look: 'top', desc: '많이 나온 응답 코드' },
  { id: 'slow', w: { type: 'top', dim: 'slow', title: '느린 요청', w: 6, h: 8, limit: 8 }, look: 'list', desc: '응답이 가장 느렸던 요청' },
  { id: 'healthDonut', w: { type: 'health', view: 'donut', title: '서비스 상태 (원형)', w: 8, h: 7 }, look: 'donut', desc: '서비스 중·느림·응답 없음 비율을 원형으로, 옆에 문제 있는 서비스' },
  { id: 'healthRings', w: { type: 'health', view: 'donut', opts: { group: 'each', size: 's' }, title: '서비스별 상태 고리', w: 12, h: 7 }, look: 'rings', desc: '서비스마다 작은 고리 — 최근 점검 기록과 가용률' },
  { id: 'healthBar', w: { type: 'health', view: 'bar', title: '서비스 응답시간', w: 8, h: 8 }, look: 'hbar', desc: '서비스마다 응답시간 막대 — 느린 것부터' },
  { id: 'containers', w: { type: 'containers', title: '컨테이너 리소스', w: 6, h: 8 }, look: 'containers', desc: 'Caddy·Authelia·CrowdSec·길목의 CPU·메모리' },
  { id: 'ctrGauge', w: { type: 'containers', view: 'gauge', title: '컨테이너 게이지', w: 12, h: 7 }, look: 'gauge', desc: '컨테이너마다 CPU·메모리 사용률을 원형 게이지로' },
  { id: 'ctrBar', w: { type: 'containers', view: 'bar', title: '컨테이너 사용률', w: 6, h: 8 }, look: 'containers', desc: '컨테이너마다 CPU·메모리 사용률 막대' },
  { id: 'certs', w: { type: 'certs', title: '인증서 만료', w: 6, h: 6 }, look: 'list', desc: '사이트 인증서의 남은 기간', need: 'caddy' },
  { id: 'events', w: { type: 'events', title: '최근 이벤트', w: 6, h: 6 }, look: 'list', desc: 'WAF 차단·5xx 오류 (24시간)' },
];
/** an existing widget made from this preset (same kind of data) */
const presetUsed = (p) => DASH.widgets.some((x) => x.type === p.w.type && (x.metric || '') === (p.w.metric || '') && (x.dim || '') === (p.w.dim || '') && (x.view || '') === (p.w.view || '') && ((x.opts || {}).group || '') === ((p.w.opts || {}).group || '') && !x.host);
const sizeText = (w) => (SIZE_W.find((x) => +x[0] === w) || ['', `${w}칸`])[1];

/** a tiny drawing of what the widget looks like (theme colors, no data) */
function widgetPreview(look) {
  const ink = cssVar('--ink');
  const faint = `rgb(${ink} / .14)`;
  const s = sv('svg', { viewBox: '0 0 120 64', class: 'wg-prev', 'aria-hidden': 'true' });
  const line = (pts, color, w = 1.6) => sv('polyline', { points: pts.map((p) => p.join(',')).join(' '), fill: 'none', stroke: color, 'stroke-width': w, 'stroke-linejoin': 'round', 'stroke-linecap': 'round' });
  const rect = (x, y, w, h, fill, r = 1.5) => sv('rect', { x, y, width: w, height: h, rx: r, fill });
  switch (look) {
    case 'stat':
      s.append(rect(10, 12, 46, 16, `rgb(${ink} / .55)`, 3), rect(60, 20, 14, 8, faint, 2),
        line([[10, 52], [24, 46], [36, 49], [50, 40], [64, 43], [78, 34], [92, 38], [110, 28]], C.s1));
      break;
    case 'series':
      s.append(line([[8, 56], [112, 56]], faint, 1), line([[8, 44], [22, 38], [36, 41], [50, 30], [64, 34], [78, 22], [92, 28], [112, 18]], C.s1),
        line([[8, 52], [22, 50], [36, 51], [50, 46], [64, 48], [78, 42], [92, 45], [112, 40]], C.warn), line([[8, 55], [36, 54], [64, 52], [92, 54], [112, 51]], C.crit));
      break;
    case 'scatter': {
      const pts = [[12, 46], [18, 50], [22, 40], [28, 48], [33, 30], [38, 47], [44, 44], [49, 22], [54, 49], [58, 42], [64, 46], [69, 36], [74, 50], [80, 44], [85, 18], [90, 47], [96, 41], [101, 48], [106, 34], [110, 45]];
      pts.forEach(([x, y], i) => s.append(sv('circle', { cx: x, cy: y, r: 2.2, fill: i % 7 === 3 ? C.warn : i % 11 === 7 ? C.crit : C.s1, 'fill-opacity': '.8' })));
      s.append(line([[8, 56], [112, 56]], faint, 1), sv('line', { x1: 8, x2: 112, y1: 28, y2: 28, stroke: C.warn, 'stroke-dasharray': '3 3', 'stroke-opacity': '.7' }));
      break;
    }
    case 'top':
      [[0.95, C.s1], [0.7, C.s1], [0.5, C.s1], [0.32, C.s1]].forEach(([f, c], i) => s.append(rect(10, 9 + i * 13, 34, 4, `rgb(${ink} / .35)`), rect(10, 15 + i * 13, 100 * f, 3, c)));
      break;
    case 'list':
      for (let i = 0; i < 4; i++) s.append(rect(10, 10 + i * 13, 8, 8, i === 1 ? C.warn : faint, 4), rect(24, 12 + i * 13, 62 - i * 6, 4, `rgb(${ink} / .35)`), rect(94, 12 + i * 13, 16, 4, faint));
      break;
    case 'health':
      for (let i = 0; i < 8; i++) s.append(sv('circle', { cx: 16 + (i % 4) * 28, cy: 20 + Math.floor(i / 4) * 24, r: 4, fill: i === 5 ? C.crit : i === 2 ? C.warn : C.s1 }), rect(23 + (i % 4) * 28, 18 + Math.floor(i / 4) * 24, 12, 4, faint));
      break;
    case 'donut': {
      const ring = (len, off, color) => sv('circle', { cx: 34, cy: 32, r: 20, fill: 'none', stroke: color, 'stroke-width': 8, 'stroke-dasharray': `${len} 200`, 'stroke-dashoffset': -off, transform: 'rotate(-90 34 32)' });
      s.append(ring(96, 0, C.s1), ring(17, 98, C.warn), ring(8, 117, C.crit));
      for (let i = 0; i < 3; i++) s.append(sv('circle', { cx: 70, cy: 18 + i * 14, r: 3, fill: [C.crit, C.warn, C.s1][i] }), rect(77, 16 + i * 14, 34 - i * 6, 4, `rgb(${ink} / .35)`));
      break;
    }
    case 'rings':
      for (let i = 0; i < 4; i++) {
        const x = 18 + i * 28;
        s.append(sv('circle', { cx: x, cy: 26, r: 10, fill: 'none', stroke: i === 2 ? C.crit : C.s1, 'stroke-width': 4, 'stroke-dasharray': i === 1 ? '50 6 8 63' : '63 0' }),
          rect(x - 9, 44, 18, 4, `rgb(${ink} / .35)`));
      }
      break;
    case 'gauge':
      [[22, 0.62, C.s1], [60, 0.35, C.s3], [98, 0.8, C.s1]].forEach(([x, f, c]) => s.append(
        sv('circle', { cx: x, cy: 28, r: 14, fill: 'none', stroke: faint, 'stroke-width': 5 }),
        sv('circle', { cx: x, cy: 28, r: 14, fill: 'none', stroke: c, 'stroke-width': 5, 'stroke-linecap': 'round', 'stroke-dasharray': `${f * 88} 88`, transform: `rotate(-90 ${x} 28)` }),
        rect(x - 10, 50, 20, 4, `rgb(${ink} / .35)`)));
      break;
    case 'hbar':
      [[0.9, C.warn], [0.55, C.s1], [0.4, C.s1], [0.22, C.s1]].forEach(([f, c], i) => s.append(rect(8, 10 + i * 13, 22, 4, `rgb(${ink} / .35)`), rect(36, 9 + i * 13, 74 * f, 6, c, 2)));
      break;
    case 'containers':
      for (let i = 0; i < 3; i++) s.append(rect(10, 10 + i * 17, 30, 4, `rgb(${ink} / .35)`), rect(10, 17 + i * 17, 100, 4, faint), rect(10, 17 + i * 17, [62, 30, 81][i], 4, [C.s1, C.s3, C.s1][i]));
      break;
    case 'map': {
      const g = sv('g', { transform: 'translate(0 2) scale(0.3333 0.4)' }, sv('path', { d: WORLD_LAND, fill: `rgb(${ink} / .16)` }));
      s.append(g);
      [[306, 54, 7, C.s1], [82, 51, 5, C.s1], [190, 40, 4, C.crit], [284, 55, 4, C.crit], [318, 54, 3, C.s1], [150, 102, 3, C.s1]].forEach(([x, y, r, c]) => s.append(sv('circle', { cx: x / 3, cy: y * 0.4 + 2, r, fill: c, 'fill-opacity': '.7' })));
      break;
    }
  }
  return s;
}

/** new panels go to the bottom, side by side while they fit */
function placeAtBottom(list, adds) {
  let y = layoutBottom(list), x = 0, rowH = 0;
  return adds.map((a) => {
    if (x + a.w > GRID_COLS) { x = 0; y += rowH; rowH = 0; }
    const out = { ...a, g: 24, x, y };
    x += a.w;
    rowH = Math.max(rowH, a.h);
    return out;
  });
}

function openWidgetGallery() {
  const picked = new Set();
  const shown = WIDGET_PRESETS.filter((p) => !p.need || use(p.need));
  const addBtn = h('button', { type: 'button', class: 'btn primary', disabled: true }, '추가');
  const sync = () => {
    addBtn.disabled = !picked.size;
    addBtn.textContent = picked.size ? `선택한 ${picked.size}개 추가` : '추가할 패널을 고르세요';
  };
  const cards = shown.map((p) => {
    const used = presetUsed(p);
    const b = h('button', { type: 'button', class: 'wg-card', 'aria-pressed': 'false', title: p.desc },
      h('span', { class: 'wg-check', 'aria-hidden': 'true' }, '✓'),
      widgetPreview(p.look),
      h('b', null, p.w.title),
      h('span', { class: 'wg-desc' }, p.desc),
      h('span', { class: 'wg-size' }, sizeText(p.w.w), used ? h('span', { class: 'wg-used' }, '이미 있음') : null));
    b.addEventListener('click', () => {
      if (picked.has(p.id)) picked.delete(p.id); else picked.add(p.id);
      b.setAttribute('aria-pressed', String(picked.has(p.id)));
      b.classList.toggle('on', picked.has(p.id));
      sync();
    });
    return b;
  });
  sync();
  const custom = h('button', { type: 'button', class: 'btn ghost' }, '직접 구성…');
  const cancel = h('button', { type: 'button', class: 'btn ghost' }, '취소');
  const dlg = openDialog({
    title: '패널 추가',
    size: 'wide',
    body: h('div', { class: 'stack' },
      h('p', { class: 'muted small' }, '추가할 패널을 눌러 고르세요 (여러 개 가능). 대시보드 맨 아래에 붙고, 제목 줄을 끌어 옮기거나 모서리를 끌어 크기를 바꿀 수 있습니다.'),
      h('div', { class: 'wg-grid', role: 'group', 'aria-label': '추가할 패널' }, cards)),
    footer: [custom, h('span', { class: 'spacer' }), cancel, addBtn],
  });
  custom.addEventListener('click', () => { dlg.close(); openWidgetEditor(null); });
  cancel.addEventListener('click', () => dlg.close());
  addBtn.addEventListener('click', () => busy(addBtn, async () => {
    const add = placeAtBottom(DASH.widgets, shown.filter((p) => picked.has(p.id)).map((p) => ({ ...structuredClone(p.w), range: '1h', limit: p.w.limit || 8 })));
    await saveLayout([...DASH.widgets, ...add]);
    dlg.close();
    toast(`패널 ${add.length}개를 추가했습니다`);
    const last = DASH.widgets[DASH.widgets.length - 1];
    const el = last && document.querySelector(`[data-wid="${last.id}"]`);
    if (el) el.scrollIntoView({ block: 'nearest', behavior: 'smooth' });
  }));
}

async function saveLayout(list) {
  const r = await api('PUT', '/api/dashboard', { widgets: list });
  DASH.widgets = r.widgets;
  buildGrid();
  pollDash(true);
}

async function removeWidget(w) {
  const ok = await confirmDialog({ title: '패널 삭제', message: `「${w.title}」 패널을 삭제할까요?`, okText: '삭제', danger: true });
  if (!ok) return;
  await saveLayout(compact(DASH.widgets.filter((x) => x.id !== w.id), null));
  toast('패널을 삭제했습니다');
}

async function duplicateWidget(w) {
  const copy = { ...structuredClone(w), id: '', title: `${w.title} (사본)`.slice(0, 40), y: w.y + w.h };
  const list = [...DASH.widgets.map((x) => ({ ...x })), copy];
  // the copy goes right under the original; the panels below move down
  const out = compact(list.map((x) => (x === copy ? x : x.y >= copy.y && x.x < copy.x + copy.w && copy.x < x.x + x.w ? { ...x, y: x.y + copy.h } : x)), null);
  await saveLayout(out);
  toast('패널을 복제했습니다');
}

// ======================================================================= panel menu · view · data

function canEditDash() { return typeof can !== 'function' || can('config'); }

/** a small menu next to a button: items [label, fn, {danger, disabled}] — arrows, Esc, outside click */
function popMenu(btn, items) {
  closePop();
  const menu = h('div', { class: 'pop-menu', role: 'menu' });
  for (const it of items) {
    if (!it) { menu.append(h('hr')); continue; }
    const [label, fn, o = {}] = it;
    const b = h('button', { type: 'button', role: 'menuitem', class: o.danger ? 'danger' : '', disabled: !!o.disabled, title: o.title || null }, label, o.key ? h('kbd', null, o.key) : null);
    b.addEventListener('click', () => { closePop(); fn(); });
    menu.append(b);
  }
  return openPop(btn, menu, { focusFirst: true });
}
/** a popover anchored under `btn` (one at a time) */
let POP = null;
function openPop(btn, el, { focusFirst = false, align = 'right' } = {}) {
  closePop();
  document.body.append(el);
  el.classList.add('pop');
  const r = btn.getBoundingClientRect();
  const w = el.offsetWidth;
  const left = align === 'left' ? r.left : r.right - w;
  el.style.left = `${Math.max(8, Math.min(left, window.innerWidth - w - 8))}px`;
  el.style.top = `${r.bottom + 4 + window.scrollY}px`;
  btn.setAttribute('aria-expanded', 'true');
  const onDown = (e) => { if (!el.contains(e.target) && !btn.contains(e.target)) closePop(); };
  const onKey = (e) => {
    if (e.key === 'Escape') { e.stopPropagation(); closePop(); btn.focus(); return; }
    if (el.classList.contains('pop-menu') && (e.key === 'ArrowDown' || e.key === 'ArrowUp')) {
      const items = [...el.querySelectorAll('button:not([disabled])')];
      const i = items.indexOf(document.activeElement);
      items[(i + (e.key === 'ArrowDown' ? 1 : -1) + items.length) % items.length].focus();
      e.preventDefault();
    }
  };
  setTimeout(() => document.addEventListener('pointerdown', onDown), 0);
  el.addEventListener('keydown', onKey);
  POP = { el, btn, off: () => { document.removeEventListener('pointerdown', onDown); btn.setAttribute('aria-expanded', 'false'); } };
  if (focusFirst) { const f = el.querySelector('button:not([disabled]), input, select'); if (f) f.focus(); }
  return el;
}
function closePop() { if (POP) { POP.off(); POP.el.remove(); POP = null; } }

function panelMenu(btn, w) {
  const ed = canEditDash();
  const noEdit = ed ? {} : { disabled: true, title: '「구성 변경」 권한이 필요합니다' };
  popMenu(btn, [
    ...(VIEWS[w.type] ? [...VIEWS[w.type].map(([k, l]) => [`${(DASH.cards.get(w.id).w.view || '') === k ? '● ' : '○ '}${l}`, () => setView(w.id, k), noEdit]), null] : []),
    ['크게 보기', () => openPanelView(w.id), { key: 'v' }],
    ['데이터 보기', () => openPanelData(w.id), { key: 'i' }],
    null,
    ['편집…', () => openWidgetEditor(DASH.cards.get(w.id).w), { ...noEdit, key: 'e' }],
    ['복제', () => duplicateWidget(DASH.cards.get(w.id).w), noEdit],
    ['삭제', () => removeWidget(DASH.cards.get(w.id).w), { ...noEdit, danger: true }],
  ]);
}

/** change a panel's display style and save */
async function setView(id, view) {
  const c = DASH.cards.get(id);
  if (!c || (c.w.view || '') === view) return;
  const list = DASH.widgets.map((x) => (x.id === id ? { ...x, view } : x));
  c.w = list.find((x) => x.id === id);
  DASH.widgets = list;
  paintOne(id);
  try { DASH.widgets = (await api('PUT', '/api/dashboard', { widgets: list })).widgets; } catch (ex) { toast(ex.message, 'err'); }
}

/** one panel over the whole screen — repainted with every refresh */
function openPanelView(id) {
  const c = DASH.cards.get(id);
  if (!c) return;
  const body = h('div', { class: `w-body view-body w-${c.w.type}` });
  const dlg = openDialog({ title: c.w.title, body, size: 'wide panel-view', onClose: () => { DASH.view = null; } });
  DASH.view = { id, body, dlg };
  requestAnimationFrame(() => paintOne(id));
}

/** the panel's numbers as a table (+ CSV) */
/** a unix-ms time for tables / CSV (fmtTime takes ISO strings) */
const fmtStamp = (t) => new Date(t).toLocaleString(gmLocale(), { hour12: false });
function panelRows(w, d) {
  if (!d) return null;
  if (w.type === 'series' && d.t) return { cols: ['시각', ...d.series.map((s) => s.name)], rows: d.t.map((t, i) => [fmtStamp(t), ...d.series.map((s) => s.values[i])]) };
  if (w.type === 'scatter') return { cols: ['시각', '응답시간(ms)', '상태', '사이트', '요청'], rows: (d.points || []).map((p, i) => [fmtStamp(p[0]), p[1], p[2], (d.hosts || [])[p[3]] || '', (d.reqs || [])[i] || '']) };
  if (w.type === 'top' && w.dim === 'slow') return { cols: ['사이트', '경로', '상태', '응답시간(ms)'], rows: (d.slow || []).map((r) => [r.host, r.uri, r.status, r.ms]) };
  if (w.type === 'top') return { cols: ['값', '요청', '평균 응답(ms)', '5xx %'], rows: (d.rows || []).map((r) => [r.key, r.n, Math.round(r.avgMs), r.errPct || 0]) };
  if (w.type === 'map') return { cols: ['국가', '요청', '거부', '2xx', '3xx', '4xx', '5xx', 'IP 수'], rows: (d.countries || []).map((r) => [`${geoName(r.cc)} (${r.cc})`, r.n, r.blocked, ...(r.st || []), r.ips]) };
  if (w.type === 'stat') {
    const rows = [['값', d.value]];
    if (d.spark && d.t) d.spark.forEach((v, i) => rows.push([fmtStamp(d.t[i]), v]));
    return { cols: ['항목', w.title], rows };
  }
  if (w.type === 'health') return { cols: ['서비스', 'upstream', '상태', '지연(ms)'], rows: (d.services || []).map((s) => [s.fqdn, s.upstream, s.ok ? '응답' : '응답 없음', s.ok ? s.ms : '']) };
  if (w.type === 'containers') return { cols: ['컨테이너', 'CPU %', '메모리'], rows: (d.containers || []).map((r) => [r.name, r.last ? r.last.cpu.toFixed(1) : '', r.last ? fmtBytes(r.last.mem) : '']) };
  if (w.type === 'certs') return { cols: ['이름', '남은 일수', '만료'], rows: (d.certs || []).map((c) => [c.fqdn, c.days, c.notAfter ? fmtTime(c.notAfter) : c.err || '']) };
  if (w.type === 'events') return { cols: ['시각', '종류', '내용'], rows: (d.events || []).map((e) => [fmtStamp(e.t), e.kind, e.text]) };
  return null;
}
const csvCell = (v) => { const s = String(v ?? ''); const t = /^[=+\-@]/.test(s) ? `'${s}` : s; return /[",\n]/.test(t) ? `"${t.replace(/"/g, '""')}"` : t; };
function openPanelData(id) {
  const c = DASH.cards.get(id);
  const t = c && panelRows(c.w, DASH.data && DASH.data[id]);
  const body = !t || !t.rows.length ? h('p', { class: 'muted' }, '표시할 데이터가 없습니다.')
    : h('div', { class: 'table-wrap glass-inner data-view' }, h('table', { class: 'compact' },
      h('thead', null, h('tr', null, t.cols.map((x) => h('th', { scope: 'col' }, x)))),
      h('tbody', null, t.rows.slice(0, 2000).map((r) => h('tr', null, r.map((v) => h('td', { class: typeof v === 'number' ? 'num' : '' }, typeof v === 'number' ? fmtNum(v) : String(v))))))));
  const dl = h('button', { type: 'button', class: 'btn', disabled: !t || !t.rows.length }, icon('download'), 'CSV 받기');
  const close = h('button', { type: 'button', class: 'btn primary' }, '닫기');
  const dlg = openDialog({ title: `${c ? c.w.title : ''} — 데이터`, body: h('div', { class: 'stack' }, t && t.rows.length > 2000 ? h('p', { class: 'hint' }, `${fmtNum(t.rows.length)}행 중 2,000행만 표시 — CSV에는 전부 들어갑니다`) : null, body), footer: [dl, h('span', { class: 'spacer' }), close], size: 'wide' });
  close.addEventListener('click', () => dlg.close());
  dl.addEventListener('click', () => {
    const text = `﻿${[t.cols, ...t.rows].map((r) => r.map(csvCell).join(',')).join('\r\n')}`;
    const a = h('a', { href: URL.createObjectURL(new Blob([text], { type: 'text/csv' })), download: `gilmok-${(c.w.title || c.w.type).replace(/[^\w가-힣-]+/g, '_')}.csv` });
    document.body.append(a); a.click(); a.remove();
    setTimeout(() => URL.revokeObjectURL(a.href), 2000);
  });
}

// ======================================================================= time picker · variables

function timePicker(btn) {
  const w = curWindow();
  const fromIn = h('input', { type: 'datetime-local', 'aria-label': '시작 시각', value: toLocalInput(w.from), max: toLocalInput(Date.now()) });
  const toIn = h('input', { type: 'datetime-local', 'aria-label': '끝 시각', value: toLocalInput(w.to), max: toLocalInput(Date.now()) });
  const err = h('p', { class: 'form-error small', role: 'alert', hidden: true });
  const apply = h('button', { type: 'button', class: 'btn primary sm' }, '이 기간 보기');
  const go = () => {
    const f = fromLocalInput(fromIn.value);
    const t = Math.min(fromLocalInput(toIn.value) || Date.now(), Date.now());
    const bad = !f || !t ? '시작과 끝을 모두 고르세요' : f >= t ? '시작이 끝보다 앞이어야 합니다' : t - f > DASH_MAX_WINDOW ? '기간은 최대 31일입니다' : '';
    if (bad) { err.textContent = bad; err.hidden = false; return; }
    closePop();
    setWindow(f, t);
  };
  apply.addEventListener('click', go);
  for (const x of [fromIn, toIn]) x.addEventListener('keydown', (e) => { if (e.key === 'Enter') go(); });
  const quick = h('div', { class: 'tp-quick', role: 'group', 'aria-label': '빠른 기간' }, DASH_SPANS.map(([k, l]) => {
    const b = h('button', { type: 'button', class: !DASH.at && DASH.span === k ? 'on' : '', 'aria-pressed': String(!DASH.at && DASH.span === k) }, l);
    b.addEventListener('click', () => { closePop(); setSpan(k); });
    return b;
  }));
  const el = h('div', { class: 'time-pop' },
    h('div', { class: 'tp-abs' }, h('b', null, '기간 직접 지정'), field('시작', fromIn), field('끝', toIn), err, apply,
      h('p', { class: 'hint' }, '최대 31일 · 정한 기간은 자동 새로고침하지 않습니다. 차트를 끌어서 고른 구간도 이렇게 정해집니다.')),
    h('div', null, h('b', null, '최근'), quick));
  openPop(btn, el, { focusFirst: false });
  const on = quick.querySelector('.on') || quick.querySelector('button');
  if (on) on.focus();
}

const VIA_LABEL = { cf: 'Cloudflare 경유', direct: '직접', lan: '내부망', tailnet: 'Tailscale', hidden: '알 수 없음 (Docker)' };
const viaLabel = (k) => VIA_LABEL[k] || k;
/** the variables: [key, label, choices() → [[value, text, count?]], search?] */
const DASH_VARS = [
  ['hosts', '사이트', () => (DASH.varChoices ? DASH.varChoices.hosts.map((x) => [x.key, x.key, x.n]) : []), true],
  ['classes', '상태', () => STATUS_CLASS.map((c) => [+c.key[1], `${c.name} ${c.title}`])],
  ['countries', '국가', () => (DASH.varChoices ? DASH.varChoices.countries.map((x) => [x.key, `${geoName(x.key)} (${x.key})`, x.n]) : []), true],
  ['vias', '접속 경로', () => Object.keys(VIA_LABEL).map((k) => [k, viaLabel(k)])],
];
function saveVars() { try { localStorage.setItem('gm.dashVars', JSON.stringify(DASH.vars)); } catch { /* private mode */ } }
function setVar(key, values) {
  DASH.vars = { ...DASH.vars, [key]: values };
  saveVars();
  paintVarBar();
  buildGrid();
  pollDash(true);
}
let dashVarBar = null;
function varText(key, vals) {
  if (!vals.length) return '전체';
  const one = key === 'countries' ? geoName(vals[0]) : key === 'vias' ? viaLabel(vals[0]) : key === 'classes' ? `${vals[0]}xx` : vals[0];
  return vals.length === 1 ? one : `${one} 외 ${vals.length - 1}`;
}
function varPicker(btn, key, label, choices, search) {
  const sel = new Set(DASH.vars[key]);
  const all = choices();
  const list = h('div', { class: 'vp-list', role: 'group', 'aria-label': label });
  const q = search ? h('input', { type: 'search', placeholder: `${label} 찾기`, 'aria-label': `${label} 찾기` }) : null;
  const draw = () => {
    const needle = q ? q.value.trim().toLowerCase() : '';
    const rows = all.filter(([v, t]) => !needle || String(v).toLowerCase().includes(needle) || t.toLowerCase().includes(needle));
    list.replaceChildren(...(rows.length ? rows.slice(0, 200).map(([v, t, n]) => {
      const cb = h('input', { type: 'checkbox', checked: sel.has(v) });
      cb.addEventListener('change', () => { if (cb.checked) sel.add(v); else sel.delete(v); });
      return h('label', { class: 'vp-row' }, cb, h('span', null, t), n != null ? h('span', { class: 'muted small' }, fmtNum(n)) : null);
    }) : [h('p', { class: 'muted small' }, all.length ? '맞는 항목 없음' : '최근 7일 기록이 없습니다')]));
  };
  if (q) q.addEventListener('input', draw);
  draw();
  const ok = h('button', { type: 'button', class: 'btn primary sm' }, '적용');
  const clear = h('button', { type: 'button', class: 'btn ghost sm' }, '전체');
  ok.addEventListener('click', () => { closePop(); setVar(key, [...sel]); });
  clear.addEventListener('click', () => { closePop(); setVar(key, []); });
  openPop(btn, h('div', { class: 'var-pop' }, q, list, h('div', { class: 'row tight' }, clear, h('span', { class: 'grow' }), ok)), { align: 'left' });
  (q || list.querySelector('input') || ok).focus();
}
function paintVarBar() {
  if (!dashVarBar) return;
  const any = DASH_VARS.some(([k]) => DASH.vars[k].length);
  const btns = DASH_VARS.map(([key, label, choices, search]) => {
    const vals = DASH.vars[key];
    const b = h('button', { type: 'button', class: `var-btn ${vals.length ? 'on' : ''}`, 'aria-haspopup': 'true', 'aria-expanded': 'false', title: vals.length ? vals.map((v) => varText(key, [v])).join(', ') : '' },
      h('span', { class: 'var-k' }, label), h('span', { class: 'var-v' }, varText(key, vals)), h('span', { class: 'caret', 'aria-hidden': 'true' }, '▾'));
    b.addEventListener('click', async () => {
      if (search && !DASH.varChoices) { try { DASH.varChoices = await api('GET', '/api/dash/vars'); } catch { DASH.varChoices = { hosts: [], countries: [] }; } }
      varPicker(b, key, label, choices, search);
    });
    return b;
  });
  const clear = any ? h('button', { type: 'button', class: 'btn ghost sm' }, icon('x'), '필터 지우기') : null;
  if (clear) clear.addEventListener('click', () => { DASH.vars = { hosts: [], classes: [], countries: [], vias: [] }; saveVars(); paintVarBar(); buildGrid(); pollDash(true); });
  fill(dashVarBar, h('span', { class: 'var-label muted small' }, '필터'), ...btns, clear,
    any ? h('span', { class: 'muted small' }, '요청 기반 패널(숫자·추이·분포·순위·지도)에 적용') : null);
}

// ======================================================================= page

let dashGrid = null;
let dashHead = null;
let dashEmpty = null; // one notice instead of twelve empty cards while no request has been seen
const REQ_TYPES = new Set(['stat', 'series', 'scatter', 'top', 'map']);

function widgetMeta(w, d) {
  const bits = [];
  if (REQ_TYPES.has(w.type) && !(w.type === 'stat' && NO_RANGE_STATS.has(w.metric))) bits.push(DASH.at ? '선택 기간' : timeLabel());
  if (w.host) bits.push(w.host.split('.')[0]);
  if (d && d.filtered) bits.push('필터');
  return bits.join(' · ');
}

function buildGrid() {
  if (!dashGrid) return;
  closePop();
  dashGrid.replaceChildren();
  DASH.cards.clear();
  if (!DASH.widgets.length) {
    const add = h('button', { type: 'button', class: 'btn primary', disabled: !canEditDash() }, icon('plus'), '패널 추가');
    add.addEventListener('click', () => openWidgetGallery());
    const reset = h('button', { type: 'button', class: 'btn', disabled: !canEditDash() }, '기본 구성 불러오기');
    reset.addEventListener('click', () => busy(reset, async () => { const r = await api('PUT', '/api/dashboard', { reset: true }); DASH.widgets = r.widgets; buildGrid(); pollDash(true); }));
    dashGrid.append(h('div', { class: 'empty glass dash-empty' }, h('p', null, '패널이 없습니다.'), h('div', { class: 'row' }, add, reset)));
    return;
  }
  const up = upgradeLayout(DASH.widgets); // an older layout: convert once and save
  if (up) saveLayoutSoon(up);
  const ed = canEditDash();
  dashGrid.classList.toggle('can-edit', ed);
  const sorted = DASH.widgets.slice().sort((a, b) => a.y - b.y || a.x - b.x);
  for (const w of sorted) {
    const body = h('div', { class: 'w-body' }, spinnerRow(''));
    const more = h('button', { type: 'button', class: 'icon-btn sm w-menu', 'aria-label': `${w.title} 메뉴`, 'aria-haspopup': 'menu', 'aria-expanded': 'false', title: '메뉴' }, '⋮');
    more.addEventListener('click', () => panelMenu(more, w));
    const meta = h('span', { class: 'w-meta' }, widgetMeta(w, null));
    const head = h('header', { class: 'w-head', title: ed ? '끌어서 옮기기 · Alt+화살표' : null }, h('h2', null, w.title), meta, more);
    const grip = ed ? h('span', { class: 'w-resize', 'aria-hidden': 'true', title: '끌어서 크기 바꾸기 · Alt+Shift+화살표' }) : null;
    const card = h('section', { class: `glass widget w-${w.type}`, 'data-wid': w.id, 'aria-label': w.title }, head, body, grip);
    placeCard(card, w);
    head.addEventListener('pointerdown', (e) => gridDrag(e, w.id, 'move'));
    if (grip) grip.addEventListener('pointerdown', (e) => { e.stopPropagation(); gridDrag(e, w.id, 'size'); });
    card.addEventListener('keydown', (e) => {
      gridKey(e, w.id);
      if (e.target === more || e.altKey || e.ctrlKey || e.metaKey) return;
      if (e.target.closest('input, select, textarea')) return;
      if (e.key === 'v') openPanelView(w.id); else if (e.key === 'i') openPanelData(w.id); else if (e.key === 'e' && ed) openWidgetEditor(DASH.cards.get(w.id).w);
    });
    dashGrid.append(card);
    DASH.cards.set(w.id, { card, body, w, meta });
  }
  if (DASH.data) paintAll();
}

/** widgets fed by Caddy's access logs / certificates */
const needsCaddy = (w) => ['series', 'scatter', 'top', 'certs', 'map'].includes(w.type) || (w.type === 'stat' && !['csBans', 'healthUp'].includes(w.metric));

function paintInto(body, w, d) {
  if (d.liveOnly) { fill(body, h('p', { class: 'muted small live-only' }, '실시간 전용 패널 — 정한 기간 보기에서는 표시하지 않습니다')); return; }
  if (needsCaddy(w) && !use('caddy')) { fill(body, h('p', { class: 'muted small live-only' }, 'Caddy를 쓰지 않는 구성이라 데이터가 없습니다')); return; }
  if (w.type === 'stat' && w.metric === 'csBans' && !use('crowdsec')) { fill(body, h('p', { class: 'muted small live-only' }, 'CrowdSec을 쓰지 않는 구성입니다')); return; }
  try { RENDER[w.type](body, w, d); } catch (ex) { fill(body, errorBox(ex.message)); }
}
function paintOne(id) {
  const c = DASH.cards.get(id);
  const d = DASH.data && DASH.data[id];
  if (!c || !d) return;
  DASH.charts = DASH.charts.filter((x) => x.body !== c.body && (!DASH.view || x.body !== DASH.view.body));
  const mark = DASH.charts.length;
  paintInto(c.body, c.w, d);
  for (const x of DASH.charts.slice(mark)) x.body = c.body;
  c.meta.textContent = widgetMeta(c.w, d);
  if (DASH.view && DASH.view.id === id && DASH.view.body.isConnected) {
    const m2 = DASH.charts.length;
    paintInto(DASH.view.body, c.w, d);
    for (const x of DASH.charts.slice(m2)) x.body = DASH.view.body;
  }
}
function paintAll() {
  if (DASH.hold) return; // don't repaint under an active brush
  DASH.charts = [];
  for (const id of DASH.cards.keys()) paintOne(id);
}

function paintStream() {
  if (!dashHead) return;
  const s = DASH.stream || {};
  const chip = dashHead.querySelector('.stream-chip');
  if (!chip) return;
  if (dashEmpty) {
    const none = !DASH.at && s.ok && !s.lastTs && settings().dashLogs && use('caddy');
    dashEmpty.replaceChildren(...(none ? [callout('', h('b', null, '아직 수집된 요청이 없습니다'),
      h('span', { class: 'small' }, 'Caddy 로그 수집은 연결되어 있습니다. 사이트에 접속이 생기면 10초 단위로 요청·응답시간 차트가 채워집니다. 서비스 상태·컨테이너·인증서 패널은 지금도 동작합니다.'))] : []));
  }
  if (DASH.at) { chip.replaceChildren(statusPill('warn', '정한 기간 — 자동 새로고침 안 함')); return; }
  if (!statsSource()) { chip.replaceChildren(h('span', { class: 'muted small' }, '요청 통계 수집 안 함')); return; }
  chip.replaceChildren(s.ok
    ? statusPill('good', `${statsSource() === 'file' ? 'Caddy 접근 로그 파일 수집 중' : 'Caddy 로그 수집 중'}${s.lastTs ? ` · 마지막 요청 ${ago(s.lastTs)}` : ''}`)
    : statusPill('crit', `로그 수집 끊김${s.error ? ` — ${s.error}` : ''}`));
}

async function pollDash(now) {
  const gen = DASH.gen;
  clearTimeout(DASH.timer);
  if (!dashGrid || !dashGrid.isConnected) return;
  if (!document.hidden || now) {
    try {
      const body = DASH.at ? { widgets: DASH.widgets, from: DASH.from, to: DASH.at } : { widgets: DASH.widgets, range: DASH.span || '' };
      const f = dashFilters();
      if (f) body.filters = f;
      const r = await api('POST', '/api/dash/data', body);
      if (gen !== DASH.gen) return;
      DASH.data = r.data;
      DASH.stream = r.stream;
      paintStream();
      paintAll();
    } catch (ex) {
      if (gen !== DASH.gen) return;
      DASH.stream = { ok: false, error: ex.message };
      paintStream();
    }
  }
  const every = +(localStorage.getItem('gm.dashRefresh') || 5);
  if (every > 0 && gen === DASH.gen && !DASH.at) DASH.timer = setTimeout(() => pollDash(false), every * 1000);
}

/** where request statistics come from: 'docker' (container output), 'file' (Caddy outside Docker
 *  writing an access log file Gilmok follows), or '' (none) */
function statsSource() {
  const st = settings();
  if (!use('caddy')) return '';
  if (!st.caddyMode || st.caddyMode === 'docker') return 'docker';
  return st.caddyLogFile ? 'file' : '';
}

function renderDashboard(panel) {
  DASH.gen++;
  clearTimeout(DASH.timer);
  closePop();
  const st = settings();
  const ed = canEditDash();
  const refresh = h('select', { 'aria-label': '새로고침 주기', class: 'auto-w', title: '자동 새로고침' },
    [['5', '5초'], ['10', '10초'], ['30', '30초'], ['60', '1분'], ['0', '끔']].map(([v, l]) => h('option', { value: v, selected: (localStorage.getItem('gm.dashRefresh') || '5') === v }, l)));
  refresh.addEventListener('change', () => { localStorage.setItem('gm.dashRefresh', refresh.value); pollDash(true); });
  const now = h('button', { type: 'button', class: 'icon-btn', 'aria-label': '지금 새로고침', title: '지금 새로고침' }, icon('refresh'));
  now.addEventListener('click', () => pollDash(true));
  const prev = h('button', { type: 'button', class: 'icon-btn', 'aria-label': '이전 구간', title: '이전 구간 (반 칸 앞으로)' }, '◀');
  const next = h('button', { type: 'button', class: 'icon-btn', 'aria-label': '다음 구간', title: '다음 구간 (반 칸 뒤로)' }, '▶');
  const zoomOut = h('button', { type: 'button', class: 'icon-btn', 'aria-label': '기간 넓히기', title: '기간 넓히기 (두 배)' }, '⊖');
  const timeBtn = h('button', { type: 'button', class: 'btn time-btn', 'aria-haspopup': 'dialog', 'aria-expanded': 'false', title: '기간 고르기' }, icon('clock'), h('span', { class: 'time-txt' }, timeLabel()));
  const live = h('button', { type: 'button', class: 'btn sm', hidden: !DASH.at, title: '최근 기간 실시간 보기로' }, '실시간으로');
  prev.addEventListener('click', () => shiftTime(-1));
  next.addEventListener('click', () => shiftTime(1));
  zoomOut.addEventListener('click', () => zoomOutTime());
  timeBtn.addEventListener('click', () => timePicker(timeBtn));
  live.addEventListener('click', () => setSpan(DASH.span));
  const timeBox = h('div', { class: 'time-box', role: 'group', 'aria-label': '기간' }, prev, timeBtn, next, zoomOut);
  const addBtn = h('button', { type: 'button', class: 'btn primary', disabled: !ed, title: ed ? '' : '패널 편집에는 「구성 변경」 권한이 필요합니다' }, icon('plus'), '패널 추가');
  addBtn.addEventListener('click', () => openWidgetGallery());
  const more = h('button', { type: 'button', class: 'icon-btn', 'aria-label': '대시보드 메뉴', 'aria-haspopup': 'menu', 'aria-expanded': 'false', title: '대시보드 메뉴' }, '⋮');
  more.addEventListener('click', () => popMenu(more, [
    ['기본 구성으로 되돌리기…', async () => {
      const ok = await confirmDialog({ title: '기본 구성으로 되돌리기', message: '지금 패널 배치를 지우고 기본 패널로 바꿉니다.', okText: '되돌리기', danger: true });
      if (!ok) return;
      const r = await api('PUT', '/api/dashboard', { reset: true });
      DASH.widgets = r.widgets;
      buildGrid();
      pollDash(true);
    }, ed ? { danger: true } : { disabled: true }],
  ]));
  const sync = () => {
    timeBtn.querySelector('.time-txt').textContent = timeLabel();
    live.hidden = !DASH.at;
    refresh.disabled = !!DASH.at;
    next.disabled = !DASH.at;
  };
  sync();
  dashTimeChanged = () => { sync(); buildGrid(); pollDash(true); };
  dashHead = h('div', { class: 'dash-head' },
    h('h1', null, '대시보드'), h('span', { class: 'stream-chip', 'aria-live': 'polite' }),
    h('span', { class: 'grow' }), live, timeBox, refresh, now, addBtn, more);
  dashVarBar = h('div', { class: 'var-bar', role: 'toolbar', 'aria-label': '대시보드 필터' });
  paintVarBar();
  let banner = null;
  if (!use('caddy')) {
    banner = callout('', h('b', null, '요청 통계 없음'), h('span', { class: 'small' }, 'Caddy를 쓰지 않는 구성이라 요청 관련 패널은 비어 있습니다. 서비스 상태·컨테이너 패널은 동작합니다.'));
  } else if (!statsSource()) {
    const go = h('button', { type: 'button', class: 'btn sm primary' }, '접근 로그 파일 정하기');
    go.addEventListener('click', () => gotoTab('caddy', 'conn'));
    banner = callout('', h('b', null, '요청 통계 없음 — Docker 밖의 Caddy는 접근 로그 파일을 정해야 합니다'),
      h('span', { class: 'small' }, 'Caddy 탭 › 연결의 「접근 로그 파일」에 Caddy가 로그를 쓸 경로를 적고 적용하면, 길목이 그 파일을 읽어 요청 관련 패널을 채웁니다. 서비스 상태·이벤트 패널은 지금도 동작합니다.'),
      h('div', null, go));
  } else if (!st.dashLogs) {
    const on = h('button', { type: 'button', class: 'btn sm primary' }, '접근 로그 켜기');
    on.addEventListener('click', () => busy(on, async () => {
      await saveSettingsPatch({ dashLogs: true });
      renderPanel();
      openApply();
    }));
    banner = callout('warn', h('b', null, '요청 통계가 비어 있습니다 — Caddy 접근 로그가 꺼져 있습니다.'),
      h('span', { class: 'small' }, '켜면 길목이 만드는 모든 사이트에 log 지시어가 붙고(적용 필요), 길목이 Caddy 로그를 실시간으로 집계합니다. Caddy 컨테이너에 로그 크기 제한(logging max-size)을 두는 것을 권장합니다.'),
      h('div', null, on));
  }
  dashGrid = h('div', { class: 'dash-grid' });
  dashEmpty = h('div');
  append(panel, [dashHead, dashVarBar, typeof stacksStrip === 'function' ? stacksStrip() : null, banner, dashEmpty, dashGrid]);
  paintStream();
  const go = async () => {
    if (!DASH.widgets) {
      try { DASH.widgets = (await api('GET', '/api/dashboard')).widgets || []; } catch (ex) { dashGrid.replaceChildren(errorBox(ex.message)); return; }
    }
    buildGrid();
    pollDash(true);
  };
  go();
  // repaint charts when the layout width changes
  if (!DASH.ro) {
    DASH.ro = new ResizeObserver(() => {
      clearTimeout(DASH.roT);
      DASH.roT = setTimeout(() => { if (dashGrid && dashGrid.isConnected && !document.body.classList.contains('grid-busy')) paintAll(); }, 150);
    });
  }
  DASH.ro.disconnect();
  DASH.ro.observe(dashGrid);
}

document.addEventListener('visibilitychange', () => { if (!document.hidden && S.tab === 'dashboard') pollDash(true); });
