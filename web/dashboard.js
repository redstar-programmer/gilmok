// Gilmok web UI — dashboard (first tab). User-defined widgets: add / edit / delete / reorder.
// Charts are plain SVG (scatter uses canvas for thousands of points). Colors: validated dark
// categorical slots + reserved status colors (always paired with a text label).
'use strict';

const DASH = { widgets: null, data: null, stream: null, edit: false, gen: 0, cards: new Map(), lastSize: new Map(), at: 0 };

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
  { key: 's2', name: '2xx', color: C.s1 }, { key: 's3', name: '3xx', color: C.neutral },
  { key: 's4', name: '4xx', color: C.warn }, { key: 's5', name: '5xx', color: C.crit },
];
const statusColor = (code) => (code >= 500 ? C.crit : code >= 400 ? C.warn : code >= 300 ? C.neutral : C.s1);

const WIDGET_TYPES = {
  stat: { name: '숫자 카드', desc: '지표 하나를 크게, 아래에 작은 추이선', def: { w: 1, h: 1, metric: 'rpm', range: '15m' } },
  series: { name: '추이 차트', desc: '요청 수·상태코드·응답시간·전송량의 시간 흐름', def: { w: 2, h: 2, metric: 'requests', range: '1h' } },
  scatter: { name: '응답시간 분포', desc: '요청 하나하나를 점으로 — 드래그로 골라 상세 목록 보기', def: { w: 2, h: 2, range: '15m' } },
  top: { name: '상위 목록', desc: '사이트·경로·상태코드·클라이언트·느린 요청 순위', def: { w: 1, h: 2, dim: 'host', range: '1h', limit: 8 } },
  health: { name: '서비스 상태 맵', desc: '서비스마다 upstream 연결 여부와 지연', def: { w: 2, h: 2 } },
  containers: { name: '컨테이너 리소스', desc: 'CPU·메모리 사용량과 추이', def: { w: 1, h: 2 } },
  certs: { name: '인증서 만료', desc: 'Caddy가 내보내는 인증서의 남은 기간', def: { w: 1, h: 1 } },
  events: { name: '최근 이벤트', desc: 'WAF 차단·5xx 오류 (24시간)', def: { w: 1, h: 1 } },
};
const STAT_METRICS = [
  ['rpm', '분당 요청 (최근 1분)'], ['requests', '요청 수 (기간 합계)'], ['err5xx', '5xx 오류율'], ['err4xx', '4xx 비율'],
  ['avgMs', '평균 응답시간'], ['p95Ms', '응답시간 p95'], ['bytes', '전송량'], ['waf', 'WAF 차단'],
  ['csBans', 'CrowdSec 차단 IP'], ['healthUp', '정상 서비스 수'], ['certDays', '인증서 최단 남은 일수'],
];
const LOWER_IS_BAD = new Set(['certDays']);
const NO_RANGE_STATS = new Set(['rpm', 'csBans', 'healthUp', 'certDays']);
const SERIES_METRICS = [['requests', '요청 수'], ['status', '상태코드별 요청'], ['latency', '응답시간 (평균·p95)'], ['bytes', '전송량'], ['waf', 'WAF 차단']];
const TOP_DIMS = [['host', '사이트'], ['path', '경로'], ['status', '상태코드'], ['client', '클라이언트 IP (mTLS 사이트만)'], ['slow', '느린 요청']];
const RANGES = [['5m', '5분'], ['15m', '15분'], ['1h', '1시간'], ['6h', '6시간'], ['24h', '24시간'], ['7d', '7일'], ['30d', '30일']];
const rangeName = (r) => (RANGES.find((x) => x[0] === r) || [r, r])[1];

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
  const col = { good: C.good, warn: C.warn, serious: C.serious, crit: C.crit }[kind];
  const mark = { good: '✓', warn: '!', serious: '!', crit: '✗' }[kind];
  void col;
  return h('span', { class: `dpill ${kind}` }, h('span', { 'aria-hidden': 'true' }, mark), text);
}

/** Line chart / stacked columns with axes, hover crosshair + tooltip. */
function timeChart(box, { t, series, stacked, unit, step }) {
  const W = Math.max(box.clientWidth, 200), Hh = Math.max(box.clientHeight, 90);
  const m = { l: 44, r: 12, t: 8, b: 20 };
  const iw = W - m.l - m.r, ih = Hh - m.t - m.b;
  const n = t.length;
  const fmt = unit === 'ms' ? fmtMs : unit === 'bytes' ? fmtBytes : fmtNum;
  let max = 0;
  for (let i = 0; i < n; i++) {
    if (stacked) max = Math.max(max, series.reduce((a, s) => a + s.values[i], 0));
    else for (const s of series) max = Math.max(max, s.values[i]);
  }
  max = niceMax(max);
  const x = (i) => m.l + (n <= 1 ? iw / 2 : (i / (n - 1)) * iw);
  const y = (v) => m.t + ih - (v / max) * ih;
  const svg = sv('svg', { viewBox: `0 0 ${W} ${Hh}`, width: W, height: Hh, class: 'dchart', role: 'img', 'aria-label': `${series.map((s) => s.name).join(', ')} 추이` });
  for (let k = 0; k <= 3; k++) {
    const v = (max / 3) * k;
    svg.append(sv('line', { x1: m.l, x2: W - m.r, y1: y(v), y2: y(v), stroke: k ? C.grid : C.axis, 'stroke-width': 1 }),
      sv('text', { x: m.l - 6, y: y(v) + 3.5, 'text-anchor': 'end', class: 'ax' }, fmt(v)));
  }
  const ticks = Math.min(5, n);
  for (let k = 0; k < ticks; k++) {
    const i = Math.round((k / Math.max(ticks - 1, 1)) * (n - 1));
    svg.append(sv('text', { x: x(i), y: Hh - 5, 'text-anchor': k === 0 ? 'start' : k === ticks - 1 ? 'end' : 'middle', class: 'ax' }, hhmm(t[i])));
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
  // hover layer
  const cross = sv('line', { y1: m.t, y2: m.t + ih, stroke: C.ink2, 'stroke-width': 1, opacity: 0 });
  const dots = series.map((s) => sv('circle', { r: 4, fill: s.color, stroke: C.surface, 'stroke-width': 2, opacity: 0 }));
  svg.append(cross, ...dots);
  const tip = h('div', { class: 'dtip', hidden: true });
  const hit = sv('rect', { x: m.l, y: m.t, width: iw, height: ih, fill: 'transparent' });
  svg.append(hit);
  const move = (ev) => {
    const r = svg.getBoundingClientRect();
    const px = ((ev.clientX - r.left) / r.width) * W;
    const i = Math.max(0, Math.min(n - 1, Math.round(((px - m.l) / iw) * (n - 1))));
    cross.setAttribute('x1', x(i)); cross.setAttribute('x2', x(i)); cross.setAttribute('opacity', 0.5);
    let acc = 0;
    series.forEach((s, si) => {
      const v = s.values[i];
      acc += v;
      dots[si].setAttribute('cx', x(i)); dots[si].setAttribute('cy', y(stacked ? acc : v)); dots[si].setAttribute('opacity', stacked ? 0 : 1);
    });
    tip.replaceChildren(h('b', null, `${hhmm(t[i])}${step ? ` (${step >= 60 ? `${step / 60}분` : `${step}초`})` : ''}`),
      ...series.map((s) => h('div', { class: 'trow' }, h('i', { style: { background: s.color } }), h('span', null, s.name), h('b', null, fmt(s.values[i])))));
    tip.hidden = false;
    const left = (x(i) / W) * r.width;
    tip.style.left = `${Math.min(Math.max(left + 12, 0), r.width - 150)}px`;
    tip.style.top = '6px';
  };
  hit.addEventListener('mousemove', move);
  hit.addEventListener('mouseleave', () => { tip.hidden = true; cross.setAttribute('opacity', 0); dots.forEach((d) => d.setAttribute('opacity', 0)); });
  return h('div', { class: 'dchart-wrap' }, svg, tip);
}

function sparkline(values, w, hgt, color = C.s1) {
  const svg = sv('svg', { viewBox: `0 0 ${w} ${hgt}`, width: w, height: hgt, class: 'spark', 'aria-hidden': 'true' });
  if (!values || values.length < 2) return svg;
  const max = Math.max(...values, 1e-9);
  let d = '';
  values.forEach((v, i) => { d += `${i ? 'L' : 'M'}${((i / (values.length - 1)) * (w - 4) + 2).toFixed(1)} ${(hgt - 2 - (v / max) * (hgt - 4)).toFixed(1)}`; });
  svg.append(sv('path', { d, fill: 'none', stroke: color, 'stroke-width': 1.5, 'stroke-linejoin': 'round', opacity: 0.9 }));
  return svg;
}

function legend(items) {
  return h('div', { class: 'dlegend' }, items.map((it) => h('span', null, h('i', { style: { background: it.color } }), it.name, it.count != null ? h('b', null, fmtNum(it.count)) : null)));
}

// ======================================================================= widget renderers

const RENDER = {
  stat(body, w, d) {
    const unit = d.unit || '';
    const v = d.value;
    let state = null;
    if (w.metric === 'healthUp' && d.down > 0) state = statusPill('crit', `${d.down}개 응답 없음`);
    else if (w.metric === 'certDays' && v >= 0 && v < (w.warn || 14)) state = statusPill(v < 7 ? 'crit' : 'warn', `${v}일 남음`);
    else if (w.warn && !LOWER_IS_BAD.has(w.metric) && v >= w.warn) state = statusPill('warn', `기준 ${fmtValue(w.metric, w.warn)}${unit === '%' ? '%' : ''} 초과`);
    const shown = w.metric === 'certDays' && v < 0 ? '—' : unit === 'ms' || unit === 'bytes' ? fmtValue(w.metric, v) : fmtNum(v);
    const sub = d.error ? d.error : w.metric === 'certDays' && d.fqdn ? d.fqdn : (w.metric === 'err5xx' || w.metric === 'err4xx') && d.count != null ? `${fmtNum(d.count)}건` : '';
    fill(body, 
      h('div', { class: 'stat-main' }, h('span', { class: 'stat-val' }, shown), unit && unit !== 'ms' && unit !== 'bytes' ? h('span', { class: 'stat-unit' }, unit) : null),
      h('div', { class: 'stat-sub' }, state, sub ? h('span', { class: 'muted small' }, sub) : null),
      d.spark ? h('div', { class: 'stat-spark' }, sparkline(d.spark, Math.max(body.clientWidth, 120), 30)) : null);
  },

  series(body, w, d) {
    const colors = w.metric === 'status' ? STATUS_CLASS.map((x) => x.color) : [C.s1, C.s2, C.s3, C.s4];
    const series = (d.series || []).map((s, i) => ({ ...s, color: colors[i] }));
    const box = h('div', { class: 'chart-box' });
    fill(body, series.length > 1 ? legend(series.map((s) => ({ name: s.name, color: s.color, count: w.metric === 'status' ? s.values.reduce((a, b) => a + b, 0) : null }))) : null, box);
    if (!d.t || !d.t.length) { box.append(h('p', { class: 'muted' }, '데이터 없음')); return; }
    box.append(timeChart(box, { t: d.t, series, stacked: w.metric === 'status', unit: d.unit, step: d.step }));
  },

  scatter(body, w, d) {
    const pts = d.points || [];
    const counts = { s2: 0, s3: 0, s4: 0, s5: 0 };
    for (const p of pts) counts[p[2] >= 500 ? 's5' : p[2] >= 400 ? 's4' : p[2] >= 300 ? 's3' : 's2']++;
    const box = h('div', { class: 'chart-box scatter' });
    fill(body, legend(STATUS_CLASS.map((s) => ({ ...s, count: counts[s.key] }))), box);
    const W = Math.max(box.clientWidth, 200), Hh = Math.max(box.clientHeight, 90);
    const m = { l: 44, r: 10, t: 8, b: 20 };
    const iw = W - m.l - m.r, ih = Hh - m.t - m.b;
    const sorted = pts.map((p) => p[1]).sort((a, b) => a - b);
    const p99 = sorted.length ? sorted[Math.floor(sorted.length * 0.99)] : 100;
    const ymax = niceMax(Math.max(p99 * 1.1, 100));
    const x = (t) => m.l + ((t - d.from) / Math.max(d.to - d.from, 1)) * iw;
    const y = (v) => m.t + ih - (Math.min(v, ymax) / ymax) * ih;
    const svg = sv('svg', { viewBox: `0 0 ${W} ${Hh}`, width: W, height: Hh, class: 'dchart' });
    for (let k = 0; k <= 3; k++) {
      const v = (ymax / 3) * k;
      svg.append(sv('line', { x1: m.l, x2: W - m.r, y1: y(v), y2: y(v), stroke: k ? C.grid : C.axis }), sv('text', { x: m.l - 6, y: y(v) + 3.5, 'text-anchor': 'end', class: 'ax' }, fmtMs(v)));
    }
    for (let k = 0; k < 4; k++) {
      const t = d.from + ((d.to - d.from) * k) / 3;
      svg.append(sv('text', { x: x(t), y: Hh - 5, 'text-anchor': k === 0 ? 'start' : k === 3 ? 'end' : 'middle', class: 'ax' }, hhmm(t)));
    }
    const cv = h('canvas', { width: Math.round(W * devicePixelRatio), height: Math.round(Hh * devicePixelRatio), style: { width: `${W}px`, height: `${Hh}px` } });
    const ctx = cv.getContext('2d');
    ctx.scale(devicePixelRatio, devicePixelRatio);
    // draw ok first so errors stay on top
    for (const pass of [0, 1]) {
      for (const p of pts) {
        const err = p[2] >= 400;
        if ((pass === 1) !== err) continue;
        ctx.fillStyle = statusColor(p[2]);
        ctx.globalAlpha = err ? 0.95 : 0.7;
        ctx.beginPath();
        ctx.arc(x(p[0]), y(p[1]), p[1] > ymax ? 3.2 : 2.3, 0, Math.PI * 2);
        ctx.fill();
      }
    }
    const brush = h('div', { class: 'brush', hidden: true });
    const read = h('div', { class: 'dtip readout', hidden: true });
    const layer = h('div', { class: 'scatter-layer', title: '드래그해서 요청을 골라 보세요' }, cv, svg, brush, read);
    box.append(layer);
    if (!pts.length) box.append(h('p', { class: 'muted overlay-note' }, '아직 요청이 없습니다'));
    const toData = (ev) => {
      const r = layer.getBoundingClientRect();
      const px = Math.max(m.l, Math.min(ev.clientX - r.left, W - m.r)), py = Math.max(m.t, Math.min(ev.clientY - r.top, m.t + ih));
      return { px, py, t: d.from + ((px - m.l) / iw) * (d.to - d.from), ms: Math.max(0, ((m.t + ih - py) / ih) * ymax) };
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
    layer.addEventListener('mousemove', (ev) => {
      const p = toData(ev);
      read.hidden = false;
      read.textContent = `${hhmmss(p.t)} · ${fmtMs(p.ms)}`;
      read.style.left = `${Math.min(p.px + 12, W - 130)}px`; read.style.top = `${Math.max(p.py - 30, 0)}px`;
    });
    layer.addEventListener('mouseleave', () => { read.hidden = true; });
    function end(ev) {
      window.removeEventListener('mousemove', drag);
      if (!start) return;
      const p = toData(ev);
      const s = start;
      start = null; DASH.hold = false; brush.hidden = true;
      const small = Math.abs(p.px - s.px) < 6 && Math.abs(p.py - s.py) < 6;
      const q = small
        ? { from: s.t - 15000, to: s.t + 15000, min: 0, max: 1e12 }
        : { from: Math.min(s.t, p.t), to: Math.max(s.t, p.t), min: Math.min(s.ms, p.ms), max: Math.max(s.ms, p.ms) >= ymax * 0.98 ? 1e12 : Math.max(s.ms, p.ms) };
      openRequests({ ...q, host: w.host || '', db: !!DASH.at });
    }
  },

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
    fill(body, 
      rows.length ? h('ol', { class: 'dlist bars' }, rows.map((r) => h('li', null,
        h('div', { class: 'dl-top' },
          h('span', { class: `dl-main ${w.dim === 'host' ? '' : 'mono'}`, title: r.key }, w.dim === 'status' ? h('span', null, h('span', { class: 'sdot', style: { background: statusColor(+r.key) } }), r.key) : r.key),
          h('b', { class: 'dl-num' }, fmtNum(r.n))),
        h('div', { class: 'dl-bar' }, h('i', { style: { width: `${(r.n / max) * 100}%` } })),
        h('div', { class: 'dl-sub' }, `평균 ${fmtMs(r.avgMs)}`, r.errPct ? h('span', { class: 'errtxt' }, ` · 5xx ${r.errPct}%`) : null))))
        : h('p', { class: 'muted' }, w.dim === 'client' ? '실제 IP는 mTLS 사이트 + CrowdSec 수집을 켠 경우에만 기록됩니다' : '요청 없음'),
      d.partial ? h('p', { class: 'hint' }, '최근 요청 2만 건 기준') : null);
  },

  health(body, w, d) {
    const list = d.services || [];
    if (!list.length) { fill(body, h('p', { class: 'muted' }, '확인 중… (30초마다)')); return; }
    const down = list.filter((s) => !s.ok).length;
    fill(body, 
      h('div', { class: 'row' }, down ? statusPill('crit', `${down}개 응답 없음`) : statusPill('good', `${list.length}개 모두 정상`)),
      h('div', { class: 'hgrid' }, list.map((s) => {
        const tile = h('button', { type: 'button', class: `htile ${s.ok ? 'ok' : 'down'}`, title: `${s.fqdn}\n→ ${s.upstream}${s.err ? `\n${s.err}` : ''}` },
          h('div', { class: 'ht-top' }, h('span', { class: 'sdot', style: { background: s.ok ? C.good : C.crit } }), h('b', null, s.sub), h('span', { class: 'ht-ms' }, s.ok ? fmtMs(s.ms) : '응답 없음')),
          h('div', { class: 'ht-hist', 'aria-hidden': 'true' }, (s.history || []).map((p) => h('i', { style: { background: p.ok ? (p.ms > 500 ? C.warn : C.good) : C.crit, opacity: p.ok ? 0.75 : 1 } }))));
        tile.addEventListener('click', () => { const svc = S.state.services.find((x) => x.id === s.id); if (svc) openServiceDrawer(svc); });
        return tile;
      })));
  },

  containers(body, w, d) {
    const rows = d.containers || [];
    if (!d.collected) { fill(body, h('p', { class: 'muted' }, '수집 중… (15초마다)')); return; }
    fill(body, h('div', { class: 'ctr-list' }, rows.map((r) => {
      const l = r.last;
      return h('div', { class: 'ctr-row' },
        h('div', { class: 'dl-top' }, h('b', { class: 'mono' }, r.name), r.running ? null : statusPill('crit', '중지/없음')),
        r.running && l ? h('div', { class: 'ctr-metrics' },
          h('div', null, h('span', { class: 'muted small' }, 'CPU'), h('b', null, `${l.cpu.toFixed(1)}%`), sparkline(r.history.map((p) => p.cpu), 80, 18, C.s1)),
          h('div', null, h('span', { class: 'muted small' }, 'MEM'), h('b', null, fmtBytes(l.mem)), sparkline(r.history.map((p) => p.mem), 80, 18, C.s3))) : null);
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

async function openRequests(q) {
  const params = new URLSearchParams({ from: Math.round(q.from), to: Math.round(q.to), min: q.min, max: q.max, host: q.host, db: q.db ? '1' : '0' });
  const body = h('div', { class: 'stack' }, spinnerRow('요청을 찾는 중…'));
  const close = h('button', { type: 'button', class: 'btn primary' }, '닫기');
  const dlg = openDialog({ title: `요청 상세 · ${hhmmss(q.from)} ~ ${hhmmss(q.to)}`, body, footer: [close], size: 'wide' });
  close.addEventListener('click', () => dlg.close());
  try {
    const r = await api('GET', `/api/dash/requests?${params}`);
    const list = r.requests || [];
    fill(body, 
      h('p', { class: 'muted small' }, `${fmtNum(r.total)}건${q.max < 1e11 ? ` · 응답시간 ${fmtMs(q.min)} ~ ${fmtMs(q.max)}` : ''}${q.host ? ` · ${q.host}` : ''}${r.total > list.length ? ` · 느린 순 ${list.length}건만 표시` : ''}`),
      list.length ? h('div', { class: 'table-wrap glass-inner' }, h('table', { class: 'compact' },
        h('thead', null, h('tr', null, ['시각', '사이트', '요청', '상태', '응답시간', '크기', '클라이언트'].map((t) => h('th', { scope: 'col' }, t)))),
        h('tbody', null, list.map((x) => h('tr', null,
          h('td', null, hhmmss(x.t)), h('td', null, x.host),
          h('td', { class: 'mono ellipsis', title: x.uri }, `${x.method} ${x.uri}`),
          h('td', null, h('span', { class: 'sdot', style: { background: statusColor(x.status) } }), String(x.status)),
          h('td', null, h('b', null, fmtMs(x.ms))), h('td', null, fmtBytes(x.size)), h('td', { class: 'mono' }, x.ip || '—')))))) : h('p', { class: 'muted' }, '선택한 영역에 요청이 없습니다.'));
  } catch (ex) { fill(body, errorBox(ex.message)); }
}

// ======================================================================= editor

function openWidgetEditor(existing) {
  const isNew = !existing;
  const wd = existing ? structuredClone(existing) : { type: 'stat', ...WIDGET_TYPES.stat.def, title: '' };
  const hosts = [...new Set(S.state.services.filter((s) => s.enabled && !s.dnsOnly).map((s) => fqdn(s.subdomain)))].sort();

  const typeList = h('div', { class: 'wtypes', role: 'radiogroup', 'aria-label': '위젯 종류' });
  for (const [k, t] of Object.entries(WIDGET_TYPES)) {
    typeList.append(h('label', { class: 'wtype' }, h('input', { type: 'radio', name: 'wtype', value: k, checked: wd.type === k }),
      h('span', null, h('b', null, t.name), h('small', null, t.desc))));
  }
  const title = h('input', { type: 'text', value: wd.title || '', maxlength: '40', placeholder: '비우면 자동' });
  const sel = (opts, v) => h('select', null, opts.map(([k, l]) => h('option', { value: k, selected: String(v) === k }, l)));
  const wSel = sel([['1', '¼ 폭'], ['2', '½ 폭'], ['3', '¾ 폭'], ['4', '전체 폭']], wd.w);
  const hSel = sel([['1', '낮게'], ['2', '보통'], ['3', '높게']], wd.h);
  const statM = sel(STAT_METRICS.filter(([k]) => (k !== 'csBans' || use('crowdsec')) && (!['waf', 'certDays'].includes(k) || use('caddy'))), wd.metric);
  const serM = sel(SERIES_METRICS, wd.metric);
  const rangeS = sel(RANGES, wd.range || '1h');
  const hostS = sel([['', '모든 사이트'], ...hosts.map((x) => [x, x])], wd.host || '');
  const dimS = sel(TOP_DIMS, wd.dim || 'host');
  const limitI = h('input', { type: 'number', min: '1', max: '50', value: wd.limit || 8 });
  const warnI = h('input', { type: 'number', min: '0', step: 'any', value: wd.warn || '' });
  const known = [...new Set(Object.values(DASH.data || {}).flatMap((x) => (x && x.known) || []))].sort();
  const ctrI = h('input', { type: 'text', class: 'mono', value: (wd.containers || []).join(', '), placeholder: '비우면 Caddy·Authelia·CrowdSec·길목', list: 'ctr-known' });
  const ctrList = h('datalist', { id: 'ctr-known' }, known.map((k) => h('option', { value: k })));

  const f = {
    statM: field('지표', statM), serM: field('지표', serM), range: field('기간', rangeS), host: field('사이트', hostS),
    dim: field('기준', dimS), limit: field('개수', limitI), warn: field('경고 기준값', warnI, ''), ctr: field('컨테이너 (쉼표 구분)', ctrI, known.length ? `수집 중: ${known.slice(0, 8).join(', ')}${known.length > 8 ? ' …' : ''}` : ''),
  };
  const errEl = h('p', { class: 'form-error', role: 'alert', hidden: true });
  const form = h('div', { class: 'stack' }, errEl,
    h('div', { class: 'field' }, h('span', { class: 'field-label' }, '종류'), typeList),
    h('div', { class: 'grid-2' }, field('제목', title), h('div', { class: 'grid-2' }, field('너비', wSel), field('높이', hSel))),
    h('div', { class: 'grid-2' }, f.statM, f.serM, f.dim, f.range, f.host, f.limit, f.warn, f.ctr), ctrList);
  const cur = () => typeList.querySelector('input:checked').value;
  const sync = (changedType) => {
    const t = cur();
    if (changedType) { const d = WIDGET_TYPES[t].def; wSel.value = String(d.w); hSel.value = String(d.h); }
    f.statM.hidden = t !== 'stat'; f.serM.hidden = t !== 'series'; f.dim.hidden = t !== 'top'; f.limit.hidden = t !== 'top';
    f.range.hidden = !['stat', 'series', 'scatter', 'top'].includes(t) || (t === 'stat' && NO_RANGE_STATS.has(statM.value));
    f.host.hidden = !['stat', 'series', 'scatter', 'top'].includes(t) || (t === 'stat' && ['csBans', 'healthUp', 'certDays'].includes(statM.value));
    f.warn.hidden = t !== 'stat' || ['csBans', 'healthUp'].includes(statM.value);
    f.ctr.hidden = t !== 'containers';
    const big = (v) => ['6h', '24h', '7d', '30d'].includes(v);
    for (const o of rangeS.options) o.disabled = t === 'scatter' && big(o.value);
    if (t === 'scatter' && big(rangeS.value)) rangeS.value = '1h';
    const m = statM.value;
    f.warn.querySelector('.hint') && (f.warn.querySelector('.hint').textContent = m === 'certDays' ? '이 일수보다 적으면 경고 (비우면 14일)'
      : m === 'p95Ms' || m === 'avgMs' ? '이 값(ms) 이상이면 경고' : m === 'err5xx' || m === 'err4xx' ? '이 비율(%) 이상이면 경고' : '이 값 이상이면 경고 (비우면 없음)');
  };
  if (!f.warn.querySelector('.hint')) f.warn.append(h('p', { class: 'hint' }));
  typeList.addEventListener('change', () => sync(true));
  statM.addEventListener('change', () => sync(false));
  sync(false);

  const save = h('button', { type: 'button', class: 'btn primary' }, isNew ? '추가' : '저장');
  const cancel = h('button', { type: 'button', class: 'btn ghost' }, '취소');
  const del = isNew ? null : h('button', { type: 'button', class: 'btn danger' }, '삭제');
  const dlg = openDialog({ title: isNew ? '위젯 추가' : '위젯 편집', body: form, footer: [del, h('span', { class: 'spacer' }), cancel, save], size: 'wide' });
  setTimeout(() => { const c = typeList.querySelector('input:checked'); if (c) c.focus(); }, 30);
  cancel.addEventListener('click', () => dlg.close());
  if (del) del.addEventListener('click', async () => { dlg.close(); await removeWidget(existing); });
  save.addEventListener('click', () => busy(save, async () => {
    const t = cur();
    const out = {
      id: wd.id, type: t, title: title.value.trim(), w: +wSel.value, h: +hSel.value,
      metric: t === 'stat' ? statM.value : t === 'series' ? serM.value : '', range: rangeS.value, host: hostS.value,
      dim: dimS.value, limit: parseInt(limitI.value, 10) || 8, warn: parseFloat(warnI.value) || 0,
      containers: splitList(ctrI.value),
    };
    if (!out.title) out.title = autoTitle(out);
    const list = DASH.widgets.slice();
    if (isNew) list.push(out); else list[list.findIndex((x) => x.id === wd.id)] = out;
    try {
      await saveLayout(list);
      dlg.close();
      toast(isNew ? '위젯을 추가했습니다' : '위젯을 저장했습니다');
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

async function saveLayout(list) {
  const r = await api('PUT', '/api/dashboard', { widgets: list });
  DASH.widgets = r.widgets;
  buildGrid();
  pollDash(true);
}

async function removeWidget(w) {
  const ok = await confirmDialog({ title: '위젯 삭제', message: `「${w.title}」 위젯을 삭제할까요?`, okText: '삭제', danger: true });
  if (!ok) return;
  await saveLayout(DASH.widgets.filter((x) => x.id !== w.id));
  toast('위젯을 삭제했습니다');
}

async function moveWidget(id, delta) {
  const list = DASH.widgets.slice();
  const i = list.findIndex((x) => x.id === id);
  const j = i + delta;
  if (i < 0 || j < 0 || j >= list.length) return;
  [list[i], list[j]] = [list[j], list[i]];
  await saveLayout(list);
  const btn = document.querySelector(`[data-wid="${id}"] .w-move[data-d="${delta}"]`);
  if (btn) btn.focus();
}

// ======================================================================= page

let dashGrid = null;
let dashHead = null;
let dashEmpty = null; // one notice instead of twelve empty cards while no request has been seen

function widgetMeta(w) {
  const bits = [];
  if (['stat', 'series', 'scatter', 'top'].includes(w.type) && !(w.type === 'stat' && NO_RANGE_STATS.has(w.metric))) bits.push(rangeName(w.range));
  if (w.host) bits.push(w.host.split('.')[0]);
  return bits.join(' · ');
}

function buildGrid() {
  if (!dashGrid) return;
  dashGrid.replaceChildren();
  DASH.cards.clear();
  dashGrid.classList.toggle('editing', DASH.edit);
  if (!DASH.widgets.length) {
    const add = h('button', { type: 'button', class: 'btn primary' }, icon('plus'), '위젯 추가');
    add.addEventListener('click', () => openWidgetEditor(null));
    const reset = h('button', { type: 'button', class: 'btn' }, '기본 구성 불러오기');
    reset.addEventListener('click', () => busy(reset, async () => { const r = await api('PUT', '/api/dashboard', { reset: true }); DASH.widgets = r.widgets; buildGrid(); pollDash(true); }));
    dashGrid.append(h('div', { class: 'empty glass dash-empty' }, h('p', null, '위젯이 없습니다.'), h('div', { class: 'row' }, add, reset)));
    return;
  }
  for (const w of DASH.widgets) {
    const body = h('div', { class: 'w-body' }, spinnerRow(''));
    const tools = DASH.edit ? h('div', { class: 'w-tools' },
      ...[[-1, '앞으로', '◀'], [1, '뒤로', '▶']].map(([dd, l, t]) => {
        const b = h('button', { type: 'button', class: 'icon-btn sm w-move', 'data-d': dd, 'aria-label': `${w.title} ${l} 이동`, title: `${l} 이동` }, t);
        b.addEventListener('click', () => moveWidget(w.id, dd));
        return b;
      }),
      (() => { const b = h('button', { type: 'button', class: 'icon-btn sm', 'aria-label': `${w.title} 편집`, title: '편집' }, '✎'); b.addEventListener('click', () => openWidgetEditor(w)); return b; })(),
      (() => { const b = h('button', { type: 'button', class: 'icon-btn sm danger', 'aria-label': `${w.title} 삭제`, title: '삭제' }, icon('x')); b.addEventListener('click', () => removeWidget(w)); return b; })())
      : null;
    const card = h('section', {
      class: `glass widget w-${w.type}`, 'data-wid': w.id, 'aria-label': w.title, draggable: DASH.edit ? 'true' : null,
      style: { gridColumn: `span ${w.w}`, gridRow: `span ${w.h}` },
    }, h('header', { class: 'w-head' }, h('h2', null, w.title), h('span', { class: 'w-meta' }, widgetMeta(w)), tools), body);
    if (DASH.edit) {
      card.addEventListener('dragstart', (e) => { e.dataTransfer.setData('text/plain', w.id); card.classList.add('dragging'); });
      card.addEventListener('dragend', () => card.classList.remove('dragging'));
      card.addEventListener('dragover', (e) => { e.preventDefault(); card.classList.add('drop'); });
      card.addEventListener('dragleave', () => card.classList.remove('drop'));
      card.addEventListener('drop', (e) => {
        e.preventDefault();
        card.classList.remove('drop');
        const from = e.dataTransfer.getData('text/plain');
        if (!from || from === w.id) return;
        const list = DASH.widgets.filter((x) => x.id !== from);
        list.splice(list.findIndex((x) => x.id === w.id), 0, DASH.widgets.find((x) => x.id === from));
        saveLayout(list);
      });
    }
    dashGrid.append(card);
    DASH.cards.set(w.id, { card, body, w });
  }
  if (DASH.data) paintAll();
}

/** widgets fed by Caddy's access logs / certificates */
const needsCaddy = (w) => ['series', 'scatter', 'top', 'certs'].includes(w.type) || (w.type === 'stat' && !['csBans', 'healthUp'].includes(w.metric));

function paintAll() {
  for (const { body, w } of DASH.cards.values()) {
    const d = DASH.data && DASH.data[w.id];
    if (!d) continue;
    if (d.liveOnly) { fill(body, h('p', { class: 'muted small live-only' }, '실시간 전용 위젯 — 과거 보기에서는 표시하지 않습니다')); continue; }
    if (needsCaddy(w) && !use('caddy')) { fill(body, h('p', { class: 'muted small live-only' }, 'Caddy를 쓰지 않는 구성이라 데이터가 없습니다')); continue; }
    if (w.type === 'stat' && w.metric === 'csBans' && !use('crowdsec')) { fill(body, h('p', { class: 'muted small live-only' }, 'CrowdSec을 쓰지 않는 구성입니다')); continue; }
    if (w.type === 'scatter' && DASH.hold) continue; // don't repaint under an active brush
    try { RENDER[w.type](body, w, d); } catch (ex) { fill(body, errorBox(ex.message)); }
  }
}

function paintStream() {
  if (!dashHead) return;
  const s = DASH.stream || {};
  const chip = dashHead.querySelector('.stream-chip');
  if (!chip) return;
  if (DASH.at) { chip.replaceChildren(statusPill('warn', `과거 보기 · ${new Date(DASH.at).toLocaleString(gmLocale(), { hour12: false })} 기준`)); return; }
  if (dashEmpty) {
    const none = !DASH.at && s.ok && !s.lastTs && settings().dashLogs && use('caddy');
    dashEmpty.replaceChildren(...(none ? [callout('', h('b', null, '아직 수집된 요청이 없습니다'),
      h('span', { class: 'small' }, 'Caddy 로그 수집은 연결되어 있습니다. 사이트에 접속이 생기면 10초 단위로 요청·응답시간 차트가 채워집니다. 서비스 상태·컨테이너·인증서 위젯은 지금도 동작합니다.'))] : []));
  }
  if (!use('caddy') || (settings().caddyMode && settings().caddyMode !== 'docker')) { chip.replaceChildren(h('span', { class: 'muted small' }, '요청 통계 수집 안 함')); return; }
  chip.replaceChildren(s.ok
    ? statusPill('good', `Caddy 로그 수집 중${s.lastTs ? ` · 마지막 요청 ${ago(s.lastTs)}` : ''}`)
    : statusPill('crit', `로그 수집 끊김${s.error ? ` — ${s.error}` : ''}`));
}

async function pollDash(now) {
  const gen = DASH.gen;
  clearTimeout(DASH.timer);
  if (!dashGrid || !dashGrid.isConnected) return;
  if (!document.hidden || now) {
    try {
      const r = await api('POST', '/api/dash/data', { widgets: DASH.widgets, at: DASH.at || 0 });
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

function renderDashboard(panel) {
  DASH.gen++;
  clearTimeout(DASH.timer);
  const st = settings();
  const refresh = h('select', { 'aria-label': '새로고침 주기', class: 'auto-w' },
    [['5', '5초마다'], ['10', '10초마다'], ['30', '30초마다'], ['0', '자동 새로고침 끔']].map(([v, l]) => h('option', { value: v, selected: (localStorage.getItem('gm.dashRefresh') || '5') === v }, l)));
  refresh.addEventListener('change', () => { localStorage.setItem('gm.dashRefresh', refresh.value); pollDash(true); });
  const now = h('button', { type: 'button', class: 'icon-btn', 'aria-label': '지금 새로고침', title: '지금 새로고침' }, icon('refresh'));
  now.addEventListener('click', () => pollDash(true));
  const canEdit = typeof can !== 'function' || can('config');
  if (!canEdit) DASH.edit = false;
  const editBtn = h('button', { type: 'button', class: `btn ${DASH.edit ? 'primary' : ''}`, 'aria-pressed': DASH.edit ? 'true' : 'false', disabled: !canEdit, title: canEdit ? '' : '위젯 편집에는 「구성 변경」 권한이 필요합니다' }, DASH.edit ? '편집 완료' : '위젯 편집');
  const addBtn = h('button', { type: 'button', class: 'btn primary', hidden: !DASH.edit }, icon('plus'), '위젯 추가');
  const resetBtn = h('button', { type: 'button', class: 'btn ghost', hidden: !DASH.edit }, '기본 구성으로');
  editBtn.addEventListener('click', () => { DASH.edit = !DASH.edit; renderPanel(); });
  addBtn.addEventListener('click', () => openWidgetEditor(null));
  resetBtn.addEventListener('click', async () => {
    const ok = await confirmDialog({ title: '기본 구성으로 되돌리기', message: '지금 위젯 배치를 지우고 기본 위젯으로 바꿉니다.', okText: '되돌리기', danger: true });
    if (!ok) return;
    const r = await api('PUT', '/api/dashboard', { reset: true });
    DASH.widgets = r.widgets;
    buildGrid();
    pollDash(true);
  });
  // live ↔ history (any past moment, from the log DB)
  const mode = h('div', { class: 'segmented', role: 'radiogroup', 'aria-label': '보기 시점' },
    [['live', '실시간'], ['past', '과거 보기']].map(([v, l]) => h('label', null, h('input', { type: 'radio', name: 'dash-mode', value: v, checked: (v === 'past') === !!DASH.at }), h('span', null, l))));
  const atInput = h('input', { type: 'datetime-local', class: 'auto-w', 'aria-label': '기준 시각', hidden: !DASH.at, value: DASH.at ? toLocalInput(DASH.at) : toLocalInput(Date.now() - 3600e3), max: toLocalInput(Date.now()) });
  const setAt = () => {
    const v = fromLocalInput(atInput.value);
    if (!v) return;
    DASH.at = Math.min(v, Date.now());
    pollDash(true);
  };
  mode.addEventListener('change', (e) => {
    if (e.target.value === 'live') { DASH.at = 0; atInput.hidden = true; refresh.disabled = false; pollDash(true); } else { atInput.hidden = false; refresh.disabled = true; setAt(); }
  });
  atInput.addEventListener('change', setAt);
  refresh.disabled = !!DASH.at;
  dashHead = h('div', { class: 'dash-head' },
    h('h1', null, '대시보드'), h('span', { class: 'stream-chip', 'aria-live': 'polite' }),
    h('span', { class: 'grow' }), mode, atInput, refresh, now, resetBtn, addBtn, editBtn);
  let banner = null;
  if (!use('caddy') || (st.caddyMode && st.caddyMode !== 'docker')) {
    banner = callout('', h('b', null, '요청 통계 없음'), h('span', { class: 'small' }, use('caddy') ? 'Docker가 아닌 Caddy는 접근 로그를 길목이 읽을 수 없어 요청 관련 위젯이 비어 있습니다. 서비스 상태·컨테이너·이벤트 위젯은 동작합니다.' : 'Caddy를 쓰지 않는 구성이라 요청 관련 위젯은 비어 있습니다. 서비스 상태·컨테이너 위젯은 동작합니다.'));
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
  if (DASH.edit) banner = h('div', { class: 'stack' }, banner, callout('', '편집 중 — 카드를 끌어서 순서를 바꾸거나 ◀ ▶ 로 옮기고, ✎ 로 지표·크기를 바꿉니다.'));
  dashGrid = h('div', { class: 'dash-grid' });
  dashEmpty = h('div');
  append(panel, [dashHead, banner, dashEmpty, dashGrid]);
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
      DASH.roT = setTimeout(() => { if (dashGrid && dashGrid.isConnected) paintAll(); }, 150);
    });
  }
  DASH.ro.disconnect();
  DASH.ro.observe(dashGrid);
}

document.addEventListener('visibilitychange', () => { if (!document.hidden && S.tab === 'dashboard') pollDash(true); });
