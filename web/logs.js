// Gilmok web UI — logs tab: storage & disk guard, view / search / export, settings, delete.
'use strict';

const LOG_CATS = [
  { key: 'audit', name: '감사', desc: '설정·서비스·사용자 변경, 적용, 로그인' },
  { key: 'security', name: '보안·침입탐지', desc: 'WAF 차단, CrowdSec 차단, Authelia·관리자 로그인 실패, 차단된 접근' },
  { key: 'system', name: '시스템', desc: '시작·종료, 서비스 다운/복구, 디스크, 업데이트, 정리 작업' },
  { key: 'requests', name: '요청', desc: 'Caddy가 받은 모든 요청 (대시보드 원본)' },
];
const LVL = { info: ['정보', 'muted'], warn: ['주의', 'warn'], error: ['오류', 'danger'], critical: ['심각', 'danger'] };
const LOGS = { view: 'view', cat: 'audit', filter: {} };

function toLocalInput(ms) {
  if (!ms) return '';
  const d = new Date(ms);
  const p = (n) => String(n).padStart(2, '0');
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())}T${p(d.getHours())}:${p(d.getMinutes())}`;
}
const fromLocalInput = (v) => (v ? new Date(v).getTime() : 0);

function diskBar(disk, th) {
  const used = disk.total ? 100 - disk.freePct : 0;
  const bar = h('div', { class: 'diskbar', role: 'img', 'aria-label': `디스크 사용 ${used.toFixed(1)}%, 여유 ${disk.freePct.toFixed(1)}%` },
    h('i', { class: `fill ${disk.level}`, style: { width: `${Math.min(used, 100)}%` } }));
  for (const [k, pct] of [['warn', th.warn], ['critical', th.critical], ['stop', th.stop]]) {
    bar.append(h('span', { class: `mark ${k}`, style: { left: `${100 - pct}%` }, title: `여유 ${pct}% 이하: ${{ warn: '경고', critical: '강력 경고', stop: '요청 로그 중단' }[k]}` }));
  }
  return bar;
}

function renderLogs(panel) {
  const status = h('div', { class: 'glass card log-status' }, spinnerRow('저장소 상태 확인 중…'));
  const nav = h('div', { class: 'segmented', role: 'radiogroup', 'aria-label': '로그 화면' },
    [['view', '보기'], ['settings', '설정'], ['delete', '정리·삭제']].map(([v, l]) => h('label', null, h('input', { type: 'radio', name: 'logview', value: v, checked: LOGS.view === v }), h('span', null, l))));
  const body = h('div', { class: 'stack' });
  panel.append(h('div', { class: 'tab-head' }, h('h1', null, '로그'),
    h('p', { class: 'muted' }, '모든 기록은 길목 DB(/data/gilmok-logs.db)에 저장됩니다. 디스크 여유가 줄면 단계별로 경고하고, 기준 이하로 떨어지면 요청 로그 기록을 멈춥니다.')),
  status, h('div', { class: 'row' }, nav), body);

  const loadStatus = async () => {
    try {
      const r = await api('GET', '/api/logs/status');
      if (!status.isConnected) return;
      const d = r.disk || {};
      const w = r.writer || {};
      const c = r.counts || {};
      const lvlTxt = { ok: ['정상', 'good'], warn: ['경고', 'warn'], critical: ['강력 경고', 'crit'], stop: ['기록 중단', 'crit'] }[r.level] || ['?', 'warn'];
      fill(status,
        h('div', { class: 'ls-grid' },
          h('div', { class: 'ls-disk' },
            h('div', { class: 'dl-top' }, h('b', null, '디스크 (/data)'), statusPill(lvlTxt[1], lvlTxt[0])),
            d.total ? diskBar(d, r.thresholds) : h('p', { class: 'muted' }, d.err || '확인 중'),
            h('p', { class: 'small muted' }, d.total ? `여유 ${fmtBytes(d.free)} / ${fmtBytes(d.total)} (${d.freePct.toFixed(1)}%) · 경고 ${r.thresholds.warn}% · 강력 경고 ${r.thresholds.critical}% · 중단 ${r.thresholds.stop}%` : '')),
          h('div', null, h('span', { class: 'muted small' }, '로그 DB'), h('b', { class: 'ls-num' }, fmtBytes(r.dbBytes)),
            h('span', { class: 'small muted' }, `최대 ${fmtBytes((st().logMaxDbMb || 0) * 1048576)}`)),
          h('div', null, h('span', { class: 'muted small' }, '기록 상태'),
            h('b', { class: 'ls-num' }, w.lastErr ? '오류' : '정상'),
            h('span', { class: 'small muted', title: w.lastErr || '' }, `기록 ${fmtNum(w.written)} · 버림 ${fmtNum(w.dropped)} · 건너뜀 ${fmtNum(w.skipped)}${w.queued ? ` · 대기 ${w.queued}` : ''}`)),
          r.busy ? h('div', null, h('span', { class: 'muted small' }, '정리 작업'), h('b', { class: 'ls-num' }, r.busy), h('span', { class: 'small muted' }, `${fmtNum(r.busyDone)}건 처리`)) : null),
        h('div', { class: 'ls-cats' }, LOG_CATS.concat([{ key: 'metrics', name: '지표 (분 단위)' }]).map((x) => {
          const v = c[x.key] || {};
          return h('div', { class: 'ls-cat' }, h('b', null, x.name), h('span', null, `${fmtNum(v.rows || 0)}건`), h('span', { class: 'muted small' }, v.oldest ? `${fmtTime(new Date(v.oldest).toISOString())}부터` : '—'));
        })),
        r.level === 'stop' ? callout('danger', h('b', null, '디스크 여유가 중단 기준 아래입니다 — 요청 로그와 지표 기록을 멈췄습니다.'), h('span', null, '「정리·삭제」에서 오래된 로그를 지우거나 디스크를 확보하세요. 감사·보안·시스템 로그는 계속 기록합니다(설정에서 끌 수 있음).')) :
          r.level === 'critical' ? callout('danger', h('b', null, '디스크 여유가 매우 부족합니다'), h('span', null, `여유가 ${r.thresholds.stop}% 아래로 내려가면 요청 로그 기록을 멈춥니다.`)) :
            r.level === 'warn' ? callout('warn', '디스크 여유가 부족해지고 있습니다. 보존 기간을 줄이거나 오래된 로그를 정리하세요.') : null);
      if (r.busy) setTimeout(loadStatus, 2000);
    } catch (ex) { status.replaceChildren(errorBox(ex.message)); }
  };
  const st = () => settings();

  const draw = () => {
    body.replaceChildren();
    if (LOGS.view === 'view') append(body, [logViewer()]);
    else if (LOGS.view === 'settings') append(body, [logSettings()]);
    else append(body, [logDelete(loadStatus)]);
  };
  nav.addEventListener('change', (e) => { LOGS.view = e.target.value; draw(); });
  loadStatus();
  draw();
}

function logViewer() {
  const catNav = h('div', { class: 'segmented', role: 'radiogroup', 'aria-label': '로그 종류' },
    LOG_CATS.map((c) => h('label', { title: c.desc }, h('input', { type: 'radio', name: 'logcat', value: c.key, checked: LOGS.cat === c.key }), h('span', null, c.name))));
  const f = LOGS.filter;
  const from = h('input', { type: 'datetime-local', value: toLocalInput(f.from), 'aria-label': '시작 시각' });
  const to = h('input', { type: 'datetime-local', value: toLocalInput(f.to), 'aria-label': '끝 시각' });
  const q = h('input', { type: 'search', value: f.q || '', placeholder: '검색 (내용·대상·IP·URI)', 'aria-label': '검색어' });
  const level = h('select', { 'aria-label': '수준' }, [['', '모든 수준'], ['info', '정보'], ['warn', '주의'], ['error', '오류'], ['critical', '심각']].map(([v, l]) => h('option', { value: v, selected: f.level === v }, l)));
  const hosts = [...new Set(S.state.services.map((s) => fqdn(s.subdomain)))].sort();
  const host = h('select', { 'aria-label': '사이트' }, [['', '모든 사이트'], ...hosts.map((x) => [x, x])].map(([v, l]) => h('option', { value: v, selected: f.host === v }, l)));
  const status = h('select', { 'aria-label': '상태코드' }, [['', '모든 상태'], ['2xx', '2xx'], ['3xx', '3xx'], ['4xx', '4xx'], ['5xx', '5xx']].map(([v, l]) => h('option', { value: v, selected: f.status === v }, l)));
  const minMs = h('input', { type: 'number', min: '0', value: f.min || '', placeholder: '최소 ms', 'aria-label': '최소 응답시간', class: 'w-num' });
  const go = h('button', { type: 'button', class: 'btn primary' }, icon('search'), '검색');
  const exp = h('a', { class: 'btn', href: '#', download: '' }, icon('download'), 'CSV 내보내기');
  const quick = h('div', { class: 'row' }, [['1h', '1시간'], ['24h', '24시간'], ['7d', '7일'], ['all', '전체']].map(([k, l]) => {
    const b = h('button', { type: 'button', class: 'btn sm ghost' }, l);
    b.addEventListener('click', () => {
      const ms = { '1h': 3600e3, '24h': 864e5, '7d': 6048e5 }[k];
      from.value = ms ? toLocalInput(Date.now() - ms) : '';
      to.value = '';
      run(true);
    });
    return b;
  }));
  const results = h('div', { class: 'stack' });
  const filters = h('div', { class: 'log-filters' }, from, h('span', { class: 'muted' }, '~'), to, q, level, host, status, minMs, go, exp);
  let cursor = 0;
  const params = () => {
    const isReq = LOGS.cat === 'requests';
    Object.assign(LOGS.filter, { from: fromLocalInput(from.value), to: fromLocalInput(to.value), q: q.value.trim(), level: level.value, host: host.value, status: status.value, min: minMs.value });
    const p = new URLSearchParams();
    if (!isReq) p.set('cat', LOGS.cat);
    if (LOGS.filter.from) p.set('from', LOGS.filter.from);
    if (LOGS.filter.to) p.set('to', LOGS.filter.to);
    if (LOGS.filter.q) p.set('q', LOGS.filter.q);
    if (!isReq && LOGS.filter.level) p.set('level', LOGS.filter.level);
    if (isReq) {
      if (LOGS.filter.host) p.set('host', LOGS.filter.host);
      if (LOGS.filter.status) p.set('status', LOGS.filter.status);
      if (LOGS.filter.min) p.set('min', LOGS.filter.min);
    }
    return p;
  };
  const syncFilters = () => {
    const isReq = LOGS.cat === 'requests';
    level.hidden = isReq;
    host.hidden = !isReq; status.hidden = !isReq; minMs.hidden = !isReq;
    const p = params();
    p.set('cat', LOGS.cat);
    exp.href = `/api/logs/export?${p}`;
  };
  const tbody = h('tbody');
  const more = h('button', { type: 'button', class: 'btn', hidden: true }, '더 보기');
  const run = (reset) => busy(go, async () => {
    if (reset) { cursor = 0; tbody.replaceChildren(); }
    syncFilters();
    const p = params();
    p.set('limit', '100');
    if (cursor) p.set('before', cursor);
    const isReq = LOGS.cat === 'requests';
    try {
      const r = await api('GET', `${isReq ? '/api/logs/requests' : '/api/logs/events'}?${p}`);
      const rows = isReq ? r.requests : r.events;
      for (const x of rows) tbody.append(...(isReq ? reqRow(x) : eventRow(x)));
      cursor = rows.length ? rows[rows.length - 1].id : cursor;
      more.hidden = rows.length < 100;
      if (reset && !rows.length) tbody.append(h('tr', null, h('td', { colspan: '7', class: 'muted' }, '조건에 맞는 기록이 없습니다.')));
    } catch (ex) { toast(ex.message, 'err'); }
  });
  const table = h('div', { class: 'table-wrap glass-inner' }, h('table', { class: 'compact logtable' },
    h('thead', null, h('tr', { class: 'lt-head' })), tbody));
  const head = () => {
    table.querySelector('.lt-head').replaceChildren(...(LOGS.cat === 'requests'
      ? ['시각', '사이트', '요청', '상태', '응답시간', '크기', '클라이언트']
      : ['시각', '수준', '작업', '대상', '내용', '행위자', 'IP']).map((t) => h('th', { scope: 'col' }, t)));
  };
  catNav.addEventListener('change', (e) => { LOGS.cat = e.target.value; head(); run(true); });
  go.addEventListener('click', () => run(true));
  q.addEventListener('keydown', (e) => { if (e.key === 'Enter') run(true); });
  more.addEventListener('click', () => run(false));
  head();
  syncFilters();
  run(true);
  return h('section', { class: 'glass card stack' },
    h('div', { class: 'row' }, catNav, h('span', { class: 'hint' }, (LOG_CATS.find((c) => c.key === LOGS.cat) || {}).desc || '')),
    filters, quick, table, h('div', { class: 'row' }, more), results);
}

function eventRow(e) {
  const [lt, lc] = LVL[e.level] || [e.level, 'muted'];
  const tr = h('tr', { class: 'clickable', tabindex: '0', 'aria-expanded': 'false' },
    h('td', { class: 'nowrap' }, fmtTimeSec(e.ts)),
    h('td', null, h('span', { class: `badge ${lc}` }, lt)),
    h('td', null, e.action),
    h('td', { class: 'ellipsis', title: e.target }, e.target || '—'),
    h('td', { class: 'ellipsis wide', title: e.msg }, e.msg),
    h('td', { class: 'ellipsis', title: e.actor }, e.actor || '—'),
    h('td', { class: 'mono' }, e.ip || '—'));
  const det = h('tr', { class: 'detail-row', hidden: true }, h('td', { colspan: '7' }, h('pre', { class: 'log' }, prettyDetail(e))));
  const toggle = () => { det.hidden = !det.hidden; tr.setAttribute('aria-expanded', det.hidden ? 'false' : 'true'); };
  tr.addEventListener('click', toggle);
  tr.addEventListener('keydown', (ev) => { if (ev.key === 'Enter' || ev.key === ' ') { ev.preventDefault(); toggle(); } });
  return [tr, det];
}

function prettyDetail(e) {
  const lines = [`${fmtTimeSec(e.ts)}  [${e.cat}/${e.level}]  ${e.action}`, `행위자: ${e.actor || '—'}   IP: ${e.ip || '—'}`, `대상: ${e.target || '—'}`, `내용: ${e.msg}`];
  if (e.detail) {
    try { lines.push('', JSON.stringify(JSON.parse(e.detail), null, 2)); } catch { lines.push('', e.detail); }
  }
  return lines.join('\n');
}

function reqRow(x) {
  return [h('tr', null,
    h('td', { class: 'nowrap' }, fmtTimeSec(x.t)), h('td', null, x.host),
    h('td', { class: 'mono ellipsis wide', title: `${x.method} ${x.uri}` }, `${x.method} ${x.uri}`),
    h('td', null, h('span', { class: 'sdot', style: { background: statusColor(x.status) } }), String(x.status)),
    h('td', null, fmtMs(x.ms)), h('td', null, fmtBytes(x.size)), h('td', { class: 'mono' }, x.ip || '—'))];
}

const fmtTimeSec = (ms) => new Date(ms).toLocaleString('ko-KR', { month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false });

function logSettings() {
  const form = settingsForm([
    { key: 'logRequests', type: 'switch', label: '요청 로그 기록', hint: '모든 요청 1건 = 1행. 대시보드 과거 조회·요청 검색의 원본' },
    { key: 'logMetrics', type: 'switch', label: '지표 기록 (1분 단위)', hint: '추이 차트의 장기 기록. 용량이 아주 작음' },
    { key: 'logKeepEventsOnStop', type: 'switch', label: '중단 단계에서도 감사·보안·시스템 로그는 계속', hint: '이 기록들은 매우 작습니다. 여유 1% 미만이면 무조건 멈춥니다' },
    { key: 'logMaxDbMb', type: 'number', label: '로그 DB 최대 크기 (MB)', hint: '넘으면 가장 오래된 요청 로그부터 지웁니다', attrs: { min: '50' } },
    { key: 'logRetReqDays', type: 'number', label: '보존 — 요청 (일)', attrs: { min: '1' } },
    { key: 'logRetMetricDays', type: 'number', label: '보존 — 지표 (일)', attrs: { min: '1' } },
    { key: 'logRetAuditDays', type: 'number', label: '보존 — 감사 (일)', attrs: { min: '1' } },
    { key: 'logRetSecurityDays', type: 'number', label: '보존 — 보안 (일)', attrs: { min: '1' } },
    { key: 'logRetSystemDays', type: 'number', label: '보존 — 시스템 (일)', attrs: { min: '1' } },
    { key: 'diskWarnPct', type: 'number', label: '디스크 여유 — 경고 (%)', hint: '이하이면 노란 경고', attrs: { min: '2', max: '90' } },
    { key: 'diskCritPct', type: 'number', label: '디스크 여유 — 강력 경고 (%)', hint: '이하이면 빨간 경고 + 첫 화면 알림', attrs: { min: '1', max: '80' } },
    { key: 'diskStopPct', type: 'number', label: '디스크 여유 — 기록 중단 (%)', hint: '이하이면 요청 로그·지표 기록 중단', attrs: { min: '1', max: '50' } },
  ], {
    validate: (p) => (!(p.diskStopPct < p.diskCritPct && p.diskCritPct < p.diskWarnPct) ? '디스크 기준은 경고 > 강력 경고 > 중단 순서여야 합니다' : ''),
  });
  return h('section', { class: 'glass card stack' }, h('h2', null, '로그 설정'),
    h('p', { class: 'muted small' }, '보안 관련 설정이라 저장할 때 비밀번호를 다시 확인합니다. 보존 기간이 지난 기록은 1시간마다 조금씩(5천 건 단위) 지워 I/O가 몰리지 않게 합니다.'), form);
}

function logDelete(onDone) {
  const boxes = LOG_CATS.concat([{ key: 'metrics', name: '지표 (분 단위)' }]).map((c) => {
    const s = switchCtl(c.name, c.key === 'requests', c.desc);
    s.input.value = c.key;
    return s;
  });
  const modeSeg = segmented(uid('del'), '범위', [{ value: 'older', label: '오래된 것만' }, { value: 'all', label: '전체' }], 'older');
  const days = h('input', { type: 'number', min: '0', value: '30' });
  const daysField = field('며칠보다 오래된 기록', days);
  const canDel = typeof can !== 'function' || can('logs');
  const btn = h('button', { type: 'button', class: 'btn danger', disabled: !canDel, title: canDel ? '' : '로그 삭제에는 「로그 관리」 권한이 필요합니다' }, '삭제…');
  modeSeg.onChange(() => { daysField.hidden = modeSeg.get() === 'all'; });
  btn.addEventListener('click', async () => {
    const cats = boxes.filter((b) => b.input.checked).map((b) => b.input.value);
    if (!cats.length) { toast('지울 로그 종류를 고르세요', 'err'); return; }
    const all = modeSeg.get() === 'all';
    const before = all ? 0 : Date.now() - (parseInt(days.value, 10) || 0) * 864e5;
    const names = cats.map((c) => (LOG_CATS.find((x) => x.key === c) || { name: '지표' }).name).join(', ');
    const ok = await confirmDialog({
      title: '로그 삭제', danger: true, okText: '삭제',
      message: `${names} 로그를 ${all ? '모두' : `${days.value}일보다 오래된 것만`} 지웁니다.\n되돌릴 수 없습니다. 삭제 사실은 감사 로그에 남습니다.`,
    });
    if (!ok) return;
    try {
      await busy(btn, () => api('POST', '/api/logs/delete', { cats, before }));
      toast('삭제를 시작했습니다 — 위의 저장소 상태에서 진행을 볼 수 있습니다');
      setTimeout(onDone, 800);
    } catch (ex) { toast(ex.message, 'err'); }
  });
  return h('section', { class: 'glass card stack' }, h('h2', null, '정리·삭제'),
    h('p', { class: 'muted small' }, '삭제는 5천 건씩 나눠서 진행하고 끝나면 빈 공간을 돌려받습니다(incremental vacuum). 진행 중에도 기록은 계속됩니다.'),
    h('div', { class: 'grid-2' }, boxes), modeSeg, daysField, h('div', { class: 'row' }, btn));
}
