'use strict';
// Caddy 탭 › 리버스 프록시: 사이트(서비스) 등록·수정·삭제 + 엑셀/CSV 일괄 등록.
// 저장은 모두 「적용 대기」 — Caddyfile·DNS는 「적용」 때 바뀐다.

function proxySitesStep() {
  const all = () => S.state.services || [];
  const nSites = all().filter((s) => !s.dnsOnly).length;
  const canEdit = typeof can !== 'function' || can('config');
  const q = h('input', { type: 'search', placeholder: '서브도메인·대상·메모 검색', 'aria-label': '사이트 검색' });
  const addBtn = h('button', { type: 'button', class: 'btn primary', disabled: !canEdit }, icon('plus'), '사이트 추가');
  const bulkBtn = h('button', { type: 'button', class: 'btn', disabled: !canEdit }, icon('upload'), '엑셀 일괄 등록…');
  const exportBtn = h('a', { class: 'btn', href: '/api/services/export.xlsx', download: '', title: '지금 목록을 엑셀로 받습니다. 고쳐서 다시 올리면 일괄 수정됩니다.' }, icon('download'), '엑셀로 내보내기');
  const tbody = h('tbody');
  const picked = new Set();
  let visible = [];
  const allCb = h('input', { type: 'checkbox', 'aria-label': '보이는 사이트 모두 선택' });
  const selInfo = h('b', { class: 'bulk-count' });
  const delSel = h('button', { type: 'button', class: 'btn danger sm' }, '선택 삭제');
  const clearSel = h('button', { type: 'button', class: 'btn ghost sm' }, '선택 해제');
  const selBar = h('div', { class: 'bulk-bar' }, h('div', { class: 'bulk-head' }, selInfo, h('span', { class: 'grow' }), clearSel, delSel));

  const updSel = () => {
    const n = picked.size;
    selInfo.textContent = n ? `${n}개 선택` : '여러 개를 지우려면 표 왼쪽에서 고르세요';
    selBar.classList.toggle('active', n > 0);
    delSel.disabled = clearSel.disabled = !n || !canEdit;
    allCb.checked = visible.length > 0 && visible.every((id) => picked.has(id));
    allCb.indeterminate = n > 0 && !allCb.checked;
  };

  const removeOne = async (s, btn) => {
    const ok = await confirmDialog({
      title: '사이트 삭제',
      message: `${fqdn(s.subdomain)} 를 삭제할까요?\n적용하면 Caddy 사이트${use('cloudflare') && s.manageDns ? '와 길목이 관리하는 DNS 레코드' : ''}가 함께 삭제됩니다.`,
      okText: '삭제', danger: true,
    });
    if (!ok) return;
    try {
      await busy(btn, () => api('DELETE', `/api/services/${encodeURIComponent(s.id)}`));
      picked.delete(s.id);
      toast(`${fqdn(s.subdomain)} 삭제됨 — 적용 대기`);
      await refreshState();
      renderPanel();
    } catch (ex) { toast(ex.message, 'err'); }
  };

  const draw = () => {
    const term = q.value.trim().toLowerCase();
    const list = all().filter((s) => !term || [s.subdomain, s.upstream, s.notes, fqdn(s.subdomain)].some((x) => String(x || '').toLowerCase().includes(term)))
      .sort((a, b) => (a.exposure === b.exposure ? a.subdomain.localeCompare(b.subdomain) : a.exposure === 'public' ? -1 : 1));
    visible = list.map((s) => s.id);
    for (const id of [...picked]) if (!all().some((s) => s.id === id)) picked.delete(id);
    tbody.replaceChildren();
    if (!list.length) {
      tbody.append(h('tr', null, h('td', { colspan: '6', class: 'muted' }, all().length ? '검색 결과가 없습니다.' : '등록된 사이트가 없습니다. 「사이트 추가」로 하나씩 넣거나, 「엑셀 일괄 등록」으로 한 번에 올리세요.')));
      updSel();
      return;
    }
    for (const s of list) {
      const row = h('tr', { class: s.enabled ? '' : 'disabled' });
      const cb = h('input', { type: 'checkbox', checked: picked.has(s.id), disabled: !canEdit, 'aria-label': `${fqdn(s.subdomain)} 선택` });
      cb.addEventListener('change', () => { if (cb.checked) picked.add(s.id); else picked.delete(s.id); row.classList.toggle('picked', cb.checked); updSel(); });
      row.classList.toggle('picked', cb.checked);
      const edit = h('button', { type: 'button', class: 'btn sm', disabled: !canEdit }, '수정');
      edit.addEventListener('click', () => openServiceDrawer(s));
      const del = h('button', { type: 'button', class: 'btn sm danger', disabled: !canEdit, 'aria-label': `${fqdn(s.subdomain)} 삭제` }, '삭제');
      del.addEventListener('click', () => removeOne(s, del));
      const name = h('button', { type: 'button', class: 'link-btn' }, h('b', null, s.subdomain === '@' ? '@ (루트)' : s.subdomain));
      name.addEventListener('click', () => openServiceDrawer(s));
      row.append(
        h('td', { class: 'sel-cell' }, cb),
        h('td', null, name, h('div', { class: 'cell-sub mono' }, fqdn(s.subdomain)), s.notes ? h('div', { class: 'cell-sub', title: s.notes }, s.notes) : null),
        h('td', null, h('div', { class: 'mono' }, s.dnsOnly ? h('span', { class: 'dash' }, 'DNS만') : (s.upstream || h('span', { class: 'dash', title: '추가 지시어로 처리' }, '(사용자 지시어)'))),
          h('div', { class: 'cell-sub' }, s.enabled ? statusCell(s) : h('span', { class: 'badge muted' }, '사용 안 함'))),
        h('td', null, expoBadge(s)),
        h('td', null, h('div', { class: 'chips' }, wafBadge(s) || h('span', { class: 'dash' }, '—'),
          s.authelia && s.authelia.enabled && use('authelia') ? h('span', { class: 'badge accent', title: 'Authelia 로그인 요구' }, icon('lock'), s.authelia.policy === 'one_factor' ? '1단계' : '2단계') : null)),
        h('td', { class: 'row-actions' }, h('div', { class: 'row' }, edit, del)));
      tbody.append(row);
    }
    updSel();
  };

  q.addEventListener('input', draw);
  allCb.addEventListener('change', () => { for (const id of visible) { if (allCb.checked) picked.add(id); else picked.delete(id); } draw(); });
  clearSel.addEventListener('click', () => { picked.clear(); draw(); });
  addBtn.addEventListener('click', () => openServiceDrawer(null));
  bulkBtn.addEventListener('click', () => openBulkImport());
  delSel.addEventListener('click', async () => {
    const targets = all().filter((s) => picked.has(s.id));
    const ok = await confirmDialog({
      title: `사이트 ${targets.length}개 삭제`,
      message: `${targets.map((s) => fqdn(s.subdomain)).join('\n')}\n\n적용하면 Caddy 사이트와 길목이 관리하는 DNS 레코드가 함께 삭제됩니다.`,
      okText: `${targets.length}개 삭제`, danger: true,
    });
    if (!ok) return;
    await busy(delSel, () => deleteServices(targets));
    picked.clear();
    await refreshState();
    renderPanel();
  });
  draw();

  const body = h('div', { class: 'stack' },
    h('div', { class: 'toolbar' }, h('div', { class: 'search' }, icon('search'), q), h('span', { class: 'grow' }), exportBtn, bulkBtn, proxyImportButton(), addBtn),
    selBar,
    h('div', { class: 'table-wrap glass-inner' }, h('table', { class: 'compact proxy-table' },
      h('caption', { class: 'sr-only' }, '리버스 프록시 사이트'),
      h('thead', null, h('tr', null, h('th', { scope: 'col', class: 'sel-cell' }, allCb), ['사이트', '대상 · 상태', '노출', '보호', ''].map((t) => h('th', { scope: 'col' }, t)))),
      tbody)),
    h('p', { class: 'hint' }, `저장하면 「적용 대기」에 쌓이고, 상단 「적용」을 누르면 Caddyfile 생성 → 검증 → 무중단 reload${use('cloudflare') ? ' → DNS 동기화' : ''} 순서로 반영됩니다. 실패하면 이전 파일로 되돌립니다.`));
  return {
    id: 'sites', title: '리버스 프록시', desc: '사이트(서브도메인 → 내부 서비스 host:port)를 추가·수정·삭제합니다. 엑셀로 한 번에 올릴 수도 있습니다.',
    state: nSites ? 'ok' : 'todo', stateText: `사이트 ${nSites}개`, body,
  };
}

/** delete several services (one request each); reports how many went before a failure */
async function deleteServices(targets) {
  let n = 0;
  try {
    for (const s of targets) { await api('DELETE', `/api/services/${encodeURIComponent(s.id)}`); n++; }
  } catch (ex) { toast(`${n}개 삭제 후 실패: ${ex.message}`, 'err'); }
  if (n) toast(`서비스 ${n}개 삭제 — 적용 대기`);
  return n;
}

/** 「엑셀 일괄 등록…」 + 「엑셀로 내보내기」 buttons (Caddy › 리버스 프록시 and the 서비스 tab) */
function bulkButtons() {
  const canEdit = typeof can !== 'function' || can('config');
  const bulkBtn = h('button', { type: 'button', class: 'btn', disabled: !canEdit, title: canEdit ? '엑셀(.xlsx)·CSV로 서비스를 한 번에 추가·수정·삭제합니다' : '「구성 변경」 권한이 필요합니다' }, icon('upload'), '엑셀 일괄 등록…');
  bulkBtn.addEventListener('click', () => openBulkImport());
  const exportBtn = h('a', { class: 'btn', href: '/api/services/export.xlsx', download: '', title: '지금 목록을 엑셀로 받습니다. 고쳐서 다시 올리면 일괄 수정됩니다.' }, icon('download'), '엑셀로 내보내기');
  return [exportBtn, bulkBtn, proxyImportButton()];
}

function proxyImportButton() {
  const canEdit = typeof can !== 'function' || can('config');
  const b = h('button', { type: 'button', class: 'btn', disabled: !canEdit, title: canEdit ? '다른 Caddy·nginx·Traefik 설정에서 사이트를 골라 추가합니다' : '「구성 변경」 권한이 필요합니다' }, icon('download'), '다른 프록시에서 불러오기…');
  b.addEventListener('click', () => openProxyImport());
  return b;
}

const PI_STATUS = { new: ['추가', 'ok'], exists: ['이미 있음', 'accent'], same: ['같음', 'muted'], error: ['건너뜀', 'warn'] };

/**
 * Bring sites over from another reverse proxy (proxyimport.go): pick the format and files, preview,
 * tick the sites to add. Existing subdomains are only changed when 「대상 바꾸기」 is ticked too.
 */
function openProxyImport() {
  let files = [];
  let res = null;
  const fmt = segmented(uid('pif'), '형식', [
    { value: 'auto', label: '자동' },
    { value: 'caddy', label: 'Caddyfile' },
    { value: 'nginx', label: 'nginx · NPM' },
    { value: 'traefik', label: 'Traefik 파일' },
    { value: 'traefik-docker', label: 'Traefik 컨테이너 라벨' },
  ], 'auto');
  const input = h('input', { type: 'file', multiple: true, class: 'sr-only', id: uid('pifile') });
  const pickBtn = h('button', { type: 'button', class: 'btn' }, icon('upload'), '파일 고르기');
  const fname = h('span', { class: 'muted small' }, '여러 개 고를 수 있습니다 (예: nginx sites-enabled/*.conf, NPM proxy_host/*.conf)');
  const drop = h('div', { class: 'drop-zone', tabindex: '-1' }, h('p', null, '여기에 파일을 끌어다 놓거나'), h('div', { class: 'row' }, pickBtn, fname));
  const scanBtn = h('button', { type: 'button', class: 'btn primary' }, icon('search'), '이 Docker의 컨테이너에서 찾기');
  const scanBox = h('div', { class: 'row' }, scanBtn, h('span', { class: 'hint' }, 'traefik.http.routers.* 라벨이 붙은 실행 중인 컨테이너를 읽습니다.'));
  const guide = h('p', { class: 'hint' });
  const result = h('div', { class: 'stack' });
  const applyBtn = h('button', { type: 'button', class: 'btn primary', disabled: true }, '추가');
  const cancel = h('button', { type: 'button', class: 'btn ghost' }, '닫기');
  const GUIDE = {
    auto: '파일 이름과 내용으로 형식을 알아냅니다.',
    caddy: '다른 Caddy의 Caddyfile — 사이트 블록의 reverse_proxy 대상과 Authelia·mTLS·WAF 설정을 가져옵니다. 전역 옵션·스니펫은 가져오지 않습니다.',
    nginx: 'server 블록의 server_name 과 proxy_pass (location / 우선). upstream 블록, Nginx Proxy Manager의 $server·$port 변수도 풉니다.',
    traefik: '동적 설정(YAML·TOML)의 http.routers·services, 또는 docker-compose.yml 의 traefik 라벨.',
    'traefik-docker': '',
  };
  const syncFmt = () => {
    const v = fmt.get();
    guide.textContent = GUIDE[v] || '';
    drop.hidden = v === 'traefik-docker';
    scanBox.hidden = v !== 'traefik-docker';
  };
  fmt.onChange(() => { syncFmt(); if (files.length) preview(); });
  syncFmt();

  const body = h('div', { class: 'stack' },
    h('p', { class: 'small muted' }, '지금 목록은 그대로 두고, 고른 사이트만 추가합니다. 이미 있는 서브도메인은 「대상 바꾸기」를 고른 것만 대상(upstream)을 바꿉니다. 반영해도 「적용」 전까지 Caddy·DNS는 바뀌지 않습니다.'),
    fmt, guide, drop, scanBox, input, result);
  const d = openDialog({ title: '다른 프록시에서 불러오기', size: 'wide', body, footer: [h('span', { class: 'spacer' }), cancel, applyBtn] });
  cancel.addEventListener('click', () => d.close());
  pickBtn.addEventListener('click', () => input.click());

  const picks = new Map(); // sub → { add: checkbox, over: checkbox }
  const countPicked = () => {
    let n = 0;
    for (const [, c] of picks) if (c.add.checked && (!c.over || c.over.checked)) n++;
    applyBtn.disabled = !n;
    applyBtn.textContent = n ? `${n}개 반영` : '추가';
  };
  const show = (r, err) => {
    res = r;
    picks.clear();
    const items = [];
    if (err) items.push(callout('danger', err));
    if (r) {
      for (const w of r.warnings || []) items.push(callout('warn', w));
      const sites = r.sites || [];
      if (!sites.length && !err) items.push(callout('', '불러올 사이트를 찾지 못했습니다.'));
      if (sites.length) {
        const c = {};
        for (const x of sites) c[x.status] = (c[x.status] || 0) + 1;
        items.push(h('div', { class: 'chips' }, ['new', 'exists', 'same', 'error'].filter((k) => c[k]).map((k) => h('span', { class: `badge ${PI_STATUS[k][1]}` }, `${PI_STATUS[k][0]} ${c[k]}`))));
        const allCb = h('input', { type: 'checkbox', checked: true, 'aria-label': '새 사이트 모두 선택' });
        const rows = sites.map((x) => {
          const add = h('input', { type: 'checkbox', checked: x.status === 'new', disabled: x.status === 'error' || x.status === 'same', 'aria-label': `${x.host} 불러오기` });
          let over = null;
          if (x.status === 'exists') {
            over = h('input', { type: 'checkbox', 'aria-label': `${x.sub} 대상 바꾸기` });
            over.addEventListener('change', () => { if (over.checked) add.checked = true; countPicked(); });
          }
          if (x.status !== 'error' && x.status !== 'same') picks.set(x.sub, { add, over });
          add.addEventListener('change', countPicked);
          return h('tr', { class: x.status === 'error' || x.status === 'same' ? 'disabled' : '' },
            h('td', null, add),
            h('td', null, h('b', null, x.sub || '—'), h('div', { class: 'cell-sub mono' }, x.host)),
            h('td', { class: 'mono small' }, x.upstream || '—', x.current && x.current !== x.upstream ? h('div', { class: 'cell-sub' }, `지금: ${x.current}`) : null),
            h('td', null, h('span', { class: `badge ${PI_STATUS[x.status][1]}` }, PI_STATUS[x.status][0]),
              over ? h('label', { class: 'small row' }, over, '대상 바꾸기') : null),
            h('td', { class: 'small' }, x.error ? h('span', { class: 'warn-text' }, x.error) : null,
              (x.notes || []).map((n) => h('div', { class: 'muted' }, n)), h('div', { class: 'cell-sub' }, x.source || '')));
        });
        allCb.addEventListener('change', () => { for (const [, c] of picks) if (!c.over) c.add.checked = allCb.checked; countPicked(); });
        items.push(h('div', { class: 'table-wrap glass-inner', style: { maxHeight: '360px', overflowY: 'auto' } }, h('table', { class: 'compact' },
          h('thead', null, h('tr', null, h('th', { scope: 'col' }, allCb), ['서브도메인', '대상', '상태', '참고'].map((t) => h('th', { scope: 'col' }, t)))),
          h('tbody', null, rows))));
        items.push(h('p', { class: 'hint' }, '불러온 사이트는 공개(:443)·Authelia 없음으로 들어옵니다 (Caddyfile은 원래 설정대로). 노출 방식·Authelia·그룹은 목록에서 고치세요.'));
      }
    }
    result.replaceChildren(...items);
    countPicked();
  };
  const preview = async (btn) => {
    result.replaceChildren(h('p', { class: 'muted' }, '읽는 중…'));
    applyBtn.disabled = true;
    try {
      const run = () => api('POST', '/api/import/sites', { format: fmt.get(), files });
      show(btn ? await busy(btn, run) : await run());
    } catch (ex) { show(null, ex.message); }
  };
  const load = async (list) => {
    const arr = [...(list || [])];
    if (!arr.length) return;
    const total = arr.reduce((n, f) => n + f.size, 0);
    if (total > 10 * 1024 * 1024) { show(null, '파일 합계가 너무 큽니다 (최대 10MB)'); return; }
    files = await Promise.all(arr.map(async (f) => ({ name: f.webkitRelativePath || f.name, content: await f.text() })));
    fname.textContent = arr.length === 1 ? arr[0].name : `${arr.length}개 파일`;
    preview();
  };
  input.addEventListener('change', () => load(input.files));
  drop.addEventListener('dragover', (e) => { e.preventDefault(); drop.classList.add('over'); });
  drop.addEventListener('dragleave', () => drop.classList.remove('over'));
  drop.addEventListener('drop', (e) => { e.preventDefault(); drop.classList.remove('over'); load(e.dataTransfer.files); });
  scanBtn.addEventListener('click', () => { files = []; preview(scanBtn); });

  applyBtn.addEventListener('click', async () => {
    if (!res) return;
    const pick = [];
    const overwrite = [];
    for (const [sub, c] of picks) {
      if (!c.add.checked) continue;
      if (c.over && !c.over.checked) continue;
      pick.push(sub);
      if (c.over) overwrite.push(sub);
    }
    try {
      const r = await busy(applyBtn, () => api('POST', '/api/import/sites/apply', { format: fmt.get(), files, pick, overwrite }));
      d.close();
      toast(`불러오기 — 추가 ${(r.added || []).length} · 대상 변경 ${(r.updated || []).length} — 적용 대기`);
      if ((r.skipped || []).length) toast(`건너뜀: ${r.skipped.join(' / ')}`, 'warn', 9000);
      await refreshState();
      renderPanel();
    } catch (ex) { show(res, ex.message); }
  });
}

function fileToBase64(file) {
  return new Promise((resolve, reject) => {
    const r = new FileReader();
    r.onload = () => resolve(String(r.result).replace(/^data:[^,]*,/, ''));
    r.onerror = () => reject(new Error('파일을 읽지 못했습니다'));
    r.readAsDataURL(file);
  });
}

const BULK_ACT = {
  create: ['추가', 'ok'], update: ['수정', 'accent'], delete: ['삭제', 'danger'], same: ['그대로', 'muted'], error: ['오류', 'warn'],
};

function openBulkImport() {
  let file = null;
  let plan = null;
  const input = h('input', { type: 'file', accept: '.xlsx,.csv,text/csv,application/vnd.openxmlformats-officedocument.spreadsheetml.sheet', class: 'sr-only', id: uid('file') });
  const pickBtn = h('button', { type: 'button', class: 'btn' }, icon('upload'), '파일 고르기');
  const fname = h('span', { class: 'muted small' }, '.xlsx 또는 CSV (UTF-8)');
  const drop = h('div', { class: 'drop-zone', tabindex: '-1' }, h('p', null, '여기에 파일을 끌어다 놓거나'), h('div', { class: 'row' }, pickBtn, fname));
  const result = h('div', { class: 'stack' });
  const applyBtn = h('button', { type: 'button', class: 'btn primary', disabled: true }, '반영');
  const cancel = h('button', { type: 'button', class: 'btn ghost' }, '닫기');

  const body = h('div', { class: 'stack' },
    h('ol', { class: 'flow' },
      h('li', null, h('a', { href: '/api/services/export.xlsx?template=1', download: '' }, '빈 양식 받기'), ' 또는 ', h('a', { href: '/api/services/export.xlsx', download: '' }, '지금 목록 받기'), ' — 「안내」 시트에 열 설명과 예시가 있습니다'),
      h('li', null, '한 줄에 사이트 하나. 서브도메인이 이미 있으면 ', h('b', null, '수정'), ', 없으면 ', h('b', null, '추가'), ', 「삭제」 열에 Y면 ', h('b', null, '삭제')),
      h('li', null, '빈 칸은 지금 값 그대로(새 사이트는 기본값), 글자 칸을 지우려면 ', h('code', null, '-')),
      h('li', null, '올리면 먼저 미리보기 — 반영해도 「적용」 전까지 Caddy·DNS는 바뀌지 않습니다')),
    drop, input, result);

  const d = openDialog({ title: '엑셀 일괄 등록', body, footer: [h('span', { class: 'spacer' }), cancel, applyBtn] });
  cancel.addEventListener('click', () => d.close());
  pickBtn.addEventListener('click', () => input.click());

  const showPlan = (p, err) => {
    plan = p;
    const items = [];
    if (err) items.push(callout('danger', h('b', null, '파일을 처리할 수 없습니다'), h('span', null, err)));
    if (p && p.rows && p.rows.length) {
      const c = p.counts || {};
      items.push(h('div', { class: 'chips' }, ['create', 'update', 'delete', 'same', 'error'].filter((k) => c[k]).map((k) => h('span', { class: `badge ${BULK_ACT[k][1]}` }, `${BULK_ACT[k][0]} ${c[k]}`))));
      if ((p.ignored || []).length) items.push(h('p', { class: 'hint' }, `모르는 열이라 무시: ${p.ignored.join(', ')}`));
      const rows = p.rows.slice().sort((a, b) => (b.action === 'error') - (a.action === 'error') || a.row - b.row); // errors first
      items.push(h('div', { class: 'table-wrap glass-inner', style: { maxHeight: '320px', overflowY: 'auto' } }, h('table', { class: 'compact' },
        h('thead', null, h('tr', null, ['행', '서브도메인', '작업', '내용'].map((t) => h('th', { scope: 'col' }, t)))),
        h('tbody', null, rows.map((r) => h('tr', { class: r.action === 'same' ? 'disabled' : '' },
          h('td', { class: 'mono' }, String(r.row)),
          h('td', null, h('b', null, r.subdomain || '—'), r.subdomain ? h('div', { class: 'cell-sub mono' }, fqdn(r.subdomain)) : null),
          h('td', null, h('span', { class: `badge ${BULK_ACT[r.action][1]}` }, BULK_ACT[r.action][0])),
          h('td', { class: r.action === 'error' ? 'warn-text' : 'small' }, r.error || (r.changes || []).join(', ') || (r.action === 'create' ? '새 사이트' : r.action === 'delete' ? '목록에서 삭제' : '바뀐 것 없음'))))))));
      if (c.error) items.push(callout('warn', `오류 ${c.error}행은 건너뜁니다. 파일을 고쳐 다시 올리거나, 나머지만 반영하세요.`));
    }
    result.replaceChildren(...items);
    const n = p && p.counts ? (p.counts.create || 0) + (p.counts.update || 0) + (p.counts.delete || 0) : 0;
    applyBtn.disabled = !n || !!err;
    applyBtn.textContent = n ? `${n}건 반영${p.counts.error ? ` (오류 ${p.counts.error}건 제외)` : ''}` : '반영';
  };

  const load = async (f) => {
    if (!f) return;
    if (f.size > 1400 * 1024) { showPlan(null, '파일이 너무 큽니다 (최대 약 1.4 MB)'); return; }
    file = f;
    fname.textContent = f.name;
    result.replaceChildren(h('p', { class: 'muted' }, '읽는 중…'));
    applyBtn.disabled = true;
    try {
      const data = await fileToBase64(f);
      file.data = data;
      showPlan(await api('POST', '/api/services/bulk', { name: f.name, data, dry: true }));
    } catch (ex) {
      showPlan(ex.data && ex.data.plan, ex.message);
    }
  };
  input.addEventListener('change', () => load(input.files[0]));
  drop.addEventListener('dragover', (e) => { e.preventDefault(); drop.classList.add('over'); });
  drop.addEventListener('dragleave', () => drop.classList.remove('over'));
  drop.addEventListener('drop', (e) => { e.preventDefault(); drop.classList.remove('over'); load(e.dataTransfer.files[0]); });

  applyBtn.addEventListener('click', async () => {
    if (!file || !plan) return;
    const c = plan.counts || {};
    if (c.delete) {
      const dels = plan.rows.filter((r) => r.action === 'delete').map((r) => fqdn(r.subdomain));
      const ok = await confirmDialog({ title: `사이트 ${dels.length}개 삭제 포함`, message: `${dels.join('\n')}\n\n위 사이트가 목록에서 삭제됩니다. 계속할까요?`, okText: '반영', danger: true });
      if (!ok) return;
    }
    try {
      const res = await busy(applyBtn, () => api('POST', '/api/services/bulk', { name: file.name, data: file.data, dry: false }));
      const r = res.counts || {};
      d.close();
      toast(`일괄 등록 — 추가 ${r.create || 0} · 수정 ${r.update || 0} · 삭제 ${r.delete || 0} — 적용 대기`);
      await refreshState();
      renderPanel();
    } catch (ex) {
      showPlan(ex.data && ex.data.plan, ex.message);
    }
  });
}
