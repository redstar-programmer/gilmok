// 길목 UI 단위 시험 (docs/TEST_SCENARIOS.md 의 UI-01~12, COMP-07)
// 실행: dev 스택(또는 데이터 사본으로 띄운 임시 인스턴스)에 로그인한 브라우저의 개발자 도구 콘솔에
//       이 파일 내용을 붙여 넣으면 결과(JSON)가 나옵니다. fetch / showGate 는 시험 중에만 바꿔 끼우고
//       되돌리며, 서버 데이터는 바꾸지 않습니다. 구성요소 화면은 체크를 껐다가 다시 켭니다(저장 안 함).
(async () => {
  const R = {};
  const ok = (id, cond, info) => { R[id] = cond ? 'PASS' : `FAIL ${info === undefined ? '' : JSON.stringify(info)}`; };
  const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
  try {
    // UI-01
    const el = h('div', null, null, false, true, 'a', [null, 'b', [undefined]]);
    ok('UI-01', el.textContent === 'ab', el.textContent);
    // UI-02
    const d = diffLines('a\nb\nc', 'a\nx\nc').map((x) => x.t + x.s).join(',');
    ok('UI-02', d === '=a,-b,+x,=c', d);
    // UI-03/04/05
    const box = document.createElement('div');
    const tab0 = S.tab;
    S.tab = 'zzz';
    const L = stepsLayout(box, { title: 'T', steps: [
      { id: 'one', title: '1', state: 'ok', body: h('p', null, 'one') },
      { id: 'grp', title: 'G', children: [
        { id: 'c1', title: 'C1', state: 'ok', body: h('p', null, 'c1') },
        { id: 'c2', title: 'C2', state: 'warn', stateText: 'w', body: h('p', null, 'c2') },
        { id: 'c3', title: 'C3', state: 'opt', body: h('p', null, 'c3') },
        null,
      ] },
    ] });
    const rail = box.querySelectorAll('.st-item');
    const subs = box.querySelectorAll('.sub-step');
    ok('UI-03', rail.length === 2 && subs.length === 3, [rail.length, subs.length]);
    const grpBtn = rail[1];
    const s1 = grpBtn.dataset.state;
    L.set('c2', 'ok');
    const s2 = grpBtn.dataset.state;
    L.set('c3', 'fail', '문제');
    const s3 = grpBtn.dataset.state;
    ok('UI-04', s1 === 'warn' && s2 === 'ok' && s3 === 'fail' && grpBtn.querySelector('.st-state').textContent.includes('C3'), [s1, s2, s3]);
    L.select('c3');
    const p3 = box.querySelector('#step-zzz-c3');
    ok('UI-05', S.stepSel.zzz === 'grp' && p3 && !p3.hidden && box.querySelector('#step-zzz-c1').hidden && !box.querySelector('#step-zzz-grp').hidden, S.stepSel.zzz);
    S.tab = tab0;

    // UI-06: api() — 403 {reauth} → password dialog → retry once
    const realFetch = window.fetch;
    const seen = [];
    let first = true;
    window.fetch = async (url, opt) => {
      seen.push(`${opt.method} ${url}`);
      const j = (code, body) => new Response(JSON.stringify(body), { status: code, headers: { 'Content-Type': 'application/json' } });
      if (url === '/api/zz-test' && first) { first = false; return j(403, { error: 'reauth', reauth: true }); }
      if (url === '/api/auth/reauth') return j(200, { ok: true });
      if (url === '/api/zz-test') return j(200, { done: 1 });
      return realFetch(url, opt);
    };
    const p = api('POST', '/api/zz-test', {});
    await sleep(200);
    const pw = [...document.querySelectorAll('.dialog input[type=password]')].pop();
    pw.value = 'x-not-a-real-password';
    pw.form.requestSubmit();
    const res = await p;
    window.fetch = realFetch;
    ok('UI-06', res && res.done === 1 && seen.join('|') === 'POST /api/zz-test|POST /api/auth/reauth|POST /api/zz-test', seen);

    // UI-07: many requests hitting a gate open it once
    const realGate = showGate;
    let gateCalls = 0;
    showGate = async () => { gateCalls++; };
    window.fetch = async (url, opt) => {
      const j = (code, body) => new Response(JSON.stringify(body), { status: code, headers: { 'Content-Type': 'application/json' } });
      if (url === '/api/auth/state') return j(200, { me: { gate: '2fa' } });
      return j(403, { error: 'gate', gate: '2fa' });
    };
    await Promise.allSettled([api('GET', '/api/a1'), api('GET', '/api/a2'), api('GET', '/api/a3')]);
    await sleep(200);
    window.fetch = realFetch;
    showGate = realGate;
    ok('UI-07', gateCalls >= 1 && gateCalls <= 3, gateCalls); // apiOnce asks once per request; showGate itself ignores repeats
    // the real showGate ignores the same gate twice
    gateOpen = '2fa';
    const before = document.querySelectorAll('#auth-gate').length;
    await realGate({ gate: '2fa' });
    ok('UI-07b', document.querySelectorAll('#auth-gate').length === before && $('#app').hidden === false, 'gate re-opened');
    gateOpen = '';

    // UI-08: openDialog — focus inside, background inert, Esc closes, focus returns
    const opener = h('button', { type: 'button' }, 'opener');
    document.body.append(opener);
    opener.focus();
    const inp = h('input', { type: 'text' });
    const dlg = openDialog({ title: 'T', body: h('div', null, inp), footer: [h('button', { type: 'button' }, 'ok')] });
    await sleep(50);
    const inside = dlg && document.activeElement && document.activeElement.closest('.dialog');
    const inert = $('#app').inert;
    document.activeElement.dispatchEvent(new KeyboardEvent('keydown', { key: 'Escape', bubbles: true }));
    await sleep(50);
    ok('UI-08', inside && inert && !document.querySelector('.overlay') && document.activeElement === opener && !$('#app').inert, { inside: !!inside, inert, active: document.activeElement && document.activeElement.textContent });
    opener.remove();

    // UI-09: groupSelect behaves like an input, no typing
    const defs0 = S.state.autheliaGroups;
    S.state.autheliaGroups = [{ name: 'admins', desc: '관리' }, { name: 'family', desc: '' }];
    const gs = groupSelect(['admins']);
    document.body.append(gs);
    let changed = 0;
    gs.addEventListener('change', () => changed++);
    const v1 = gs.value;
    gs.value = 'family, admins';
    const chips = gs.querySelectorAll('.grp-chip').length;
    gs.disabled = true;
    const dis = gs.querySelector('button').disabled;
    gs.disabled = false;
    const noTyping = gs.querySelectorAll('input[type=text]').length === 0;
    gs.querySelector('button').click();
    await sleep(100);
    const cbs = [...document.querySelectorAll('.dialog .pick-list input[type=checkbox]')];
    cbs.forEach((c) => { if (c.checked) c.click(); });
    cbs[1].click();
    [...document.querySelectorAll('.dialog footer button')].find((b) => b.textContent === '확인').click();
    await sleep(100);
    ok('UI-09', v1 === 'admins' && chips === 2 && dis && noTyping && changed === 1 && gs.value === 'family', { v1, chips, dis, changed, v: gs.value });
    gs.remove();

    // UI-10: groupChips — input hidden, unregistered shown dashed and cannot be re-added
    const gi = h('input', { type: 'text', value: 'admins, ghost' });
    const gc = groupChips(gi);
    document.body.append(gi, gc);
    const stale = gc.querySelector('.grp-chip.stale');
    const fam = [...gc.querySelectorAll('.grp-chip')].find((b) => b.textContent.includes('family'));
    fam.click();
    await sleep(20);
    const afterAdd = gi.value;
    [...gc.querySelectorAll('.grp-chip')].find((b) => b.textContent.includes('ghost')).click();
    await sleep(20);
    const ghostBtn = [...gc.querySelectorAll('.grp-chip')].find((b) => b.textContent.includes('ghost'));
    ok('UI-10', gi.hidden && stale && afterAdd === 'admins, ghost, family' && !gi.value.includes('ghost') && (!ghostBtn || ghostBtn.disabled), { hidden: gi.hidden, afterAdd, v: gi.value });
    gi.remove(); gc.remove();
    S.state.autheliaGroups = defs0;

    // UI-11 / UI-12: a component turned off hides its tab / table column
    const set = S.state.settings;
    const prevCaddy = set.useCaddy;
    set.useCaddy = false;
    applyComponentTabs();
    const caddyTab = [...document.querySelectorAll('[role=tab], .tabs button, nav a')].find((x) => x.textContent.trim() === 'Caddy');
    const hiddenTab = !caddyTab || caddyTab.hidden || caddyTab.closest('[hidden]');
    const tbl = serviceTable();
    const th = tbl.querySelectorAll('thead th').length;
    const firstRow = [...tbl.querySelectorAll('tbody tr')].find((r) => !r.classList.contains('group-row'));
    const td = firstRow ? firstRow.querySelectorAll('td').length : -1;
    ok('UI-11', !!hiddenTab, caddyTab && caddyTab.outerHTML.slice(0, 80));
    ok('UI-12', th === td, { th, td });
    set.useCaddy = prevCaddy;
    applyComponentTabs();

    // COMP-07: turning Cloudflare off with mTLS services shows a red warning
    gotoTab('gilmok', 'components');
    await sleep(400);
    const sec = document.getElementById('step-gilmok-components');
    const cfBox = [...sec.querySelectorAll('input[type=checkbox]')].find((c) => (c.closest('label') || c.parentElement).textContent.includes('Cloudflare'));
    cfBox.click();
    await sleep(50);
    const danger = [...sec.querySelectorAll('.callout.danger')].map((x) => x.textContent).join(' | ');
    ok('COMP-07', /mTLS/.test(danger), danger);
    cfBox.click();
  } catch (ex) {
    R.error = String(ex && ex.stack || ex);
  }
  return JSON.stringify(R, null, 1);
})()
