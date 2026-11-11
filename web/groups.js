'use strict';
// Authelia 허용 그룹 — 미리 정의(이름·설명)하고, 서비스·사용자 편집에서 골라 쓴다 (groups.go).

const groupDefs = () => (S.state && S.state.autheliaGroups) || [];
const groupDesc = (name) => (groupDefs().find((g) => g.name === name) || {}).desc || '';

/** Edit (or create when g is null) one group. Resolves true when something changed. */
function openGroupEdit(g, usage) {
  return new Promise((resolve) => {
    const isNew = !g;
    const name = h('input', { type: 'text', value: g ? g.name : '', autocomplete: 'off', spellcheck: 'false', placeholder: 'family', class: 'mono', required: true });
    const desc = h('input', { type: 'text', value: g ? g.desc || '' : '', autocomplete: 'off', placeholder: '예: 가족 — 사진·영상 서비스' });
    const err = h('p', { class: 'form-error', role: 'alert', hidden: true });
    const u = usage || { users: [], services: [] };
    const impact = h('div');
    const showImpact = () => {
      const renamed = !isNew && name.value.trim() && name.value.trim() !== g.name;
      impact.replaceChildren();
      if (renamed && (u.users.length || u.services.length)) {
        impact.append(callout('warn', h('b', null, `이름을 바꾸면 쓰는 곳도 함께 바뀝니다`),
          h('ul', null,
            u.services.length ? h('li', null, `서비스 ${u.services.length}개 (${u.services.join(', ')}) — 「적용 대기」, 적용할 때 Authelia 규칙에 반영`) : null,
            u.users.length ? h('li', null, `사용자 ${u.users.length}명 (${u.users.join(', ')}) — users_database.yml 을 바로 고치고 Authelia가 재시작됩니다`) : null)));
      }
    };
    name.addEventListener('input', () => {
      showImpact();
      // renaming a group that users have rewrites users_database.yml right away
      const now = !isNew && name.value.trim() && name.value.trim() !== g.name && u.users.length;
      ok.textContent = now ? '저장 · 사용자 바로 반영' : (isNew ? '추가' : '저장');
    });
    const form = h('form', { class: 'stack', novalidate: true }, err,
      field('그룹 이름', name, '영문·숫자·-_. — Authelia 사용자와 접근 규칙에 그대로 쓰입니다'),
      field('설명', desc, '길목에만 저장됩니다 (선택)'), impact);
    const ok = h('button', { type: 'submit', class: 'btn primary' }, isNew ? '추가' : '저장');
    const cancel = h('button', { type: 'button', class: 'btn ghost' }, '취소');
    ok.setAttribute('form', form.id = uid('form'));
    let done = false;
    const d = openDialog({ title: isNew ? '그룹 추가' : `그룹 ${g.name}`, body: form, footer: [h('span', { class: 'spacer' }), cancel, ok], onClose: () => { if (!done) resolve(false); } });
    cancel.addEventListener('click', () => d.close());
    form.addEventListener('submit', async (e) => {
      e.preventDefault();
      err.hidden = true;
      const body = { name: name.value.trim(), desc: desc.value.trim() };
      if (!/^[A-Za-z0-9._-]{1,64}$/.test(body.name)) { err.textContent = '그룹 이름은 영문·숫자·-_. 만 쓸 수 있습니다'; err.hidden = false; name.focus(); return; }
      try {
        const res = await busy(ok, () => (isNew ? api('POST', '/api/groups', body) : api('PUT', `/api/groups/${encodeURIComponent(g.name)}`, body)));
        done = true;
        d.close();
        // remember renames so open editors can follow the new name instead of dropping the group
        if (!isNew && body.name !== g.name) { S.groupRenames = S.groupRenames || {}; S.groupRenames[g.name] = body.name; }
        if (res && (res.users || res.services)) {
          toast(`그룹 이름 변경 — 서비스 ${res.services || 0}개${res.services ? '(적용 대기)' : ''} · 사용자 ${res.users || 0}명${res.users ? '(Authelia 재시작)' : ''}`);
          if (res.users) S.users = null;
        } else toast(isNew ? `그룹 ${body.name} 추가됨` : `그룹 ${body.name} 저장됨`);
        resolve(true);
      } catch (ex) {
        err.textContent = ex.message;
        err.hidden = false;
      }
    });
  });
}

async function removeGroup(g, btn) {
  const inUse = (g.users || []).length || (g.services || []).length;
  const ok = await confirmDialog({
    title: `그룹 ${g.name} 삭제`,
    message: inUse
      ? `이 그룹을 쓰는 곳에서도 뺍니다.\n${g.services.length ? `· 서비스 ${g.services.length}개: ${g.services.join(', ')} (적용 대기)\n` : ''}${g.users.length ? `· 사용자 ${g.users.length}명: ${g.users.join(', ')} (Authelia 바로 재시작)\n` : ''}\n허용 그룹이 비게 되는 서비스는 「로그인한 모든 사용자」 허용이 됩니다.`
      : '아무 데서도 쓰지 않는 그룹입니다. 목록에서 지웁니다.',
    okText: '삭제', danger: true,
  });
  if (!ok) return false;
  try {
    const res = await busy(btn, () => api('DELETE', `/api/groups/${encodeURIComponent(g.name)}${inUse ? '?purge=1' : ''}`));
    if (res.users) S.users = null;
    toast(`그룹 ${g.name} 삭제${res.services ? ` — 서비스 ${res.services}개 적용 대기` : ''}${res.users ? ` · 사용자 ${res.users}명 변경` : ''}`);
    return true;
  } catch (ex) { toast(ex.message, 'err'); return false; }
}

/** Groups table with add / edit / delete. onChanged runs after every change (state refreshed). */
function groupsPanel(onChanged, onCount) {
  const canEdit = typeof can !== 'function' || can('config');
  const box = h('div', { class: 'stack' });
  const addBtn = h('button', { type: 'button', class: 'btn primary sm', disabled: !canEdit }, icon('plus'), '그룹 추가');
  const after = async () => { await refreshState(); await draw(); onChanged && onChanged(); };
  addBtn.addEventListener('click', async () => { if (await openGroupEdit(null)) after(); });
  const tableBox = h('div', { class: 'table-wrap glass-inner' }, h('p', { class: 'muted', style: { padding: '8px 12px' } }, '불러오는 중…'));
  let count = 0;
  async function draw() {
    let res;
    try { res = await api('GET', '/api/groups'); } catch (ex) { tableBox.replaceChildren(errorBox(ex.message)); return; }
    const list = res.groups || [];
    count = list.length;
    if (onCount) onCount(count, list.filter((g) => !g.defined).length);
    const rows = list.map((g) => {
      const edit = h('button', { type: 'button', class: 'btn sm', disabled: !canEdit }, '수정');
      edit.addEventListener('click', async () => { if (await openGroupEdit(g, g)) after(); });
      const del = h('button', { type: 'button', class: 'btn sm danger', disabled: !canEdit }, '삭제');
      del.addEventListener('click', async () => { if (await removeGroup(g, del)) after(); });
      const adopt = !g.defined ? h('button', { type: 'button', class: 'btn sm', disabled: !canEdit, title: '쓰이고 있지만 목록에 없는 그룹 — 목록에 등록합니다' }, '등록') : null;
      if (adopt) adopt.addEventListener('click', () => busy(adopt, async () => { try { await api('POST', '/api/groups', { name: g.name, desc: '' }); after(); } catch (ex) { toast(ex.message, 'err'); } }));
      const names = (arr, fmt) => (arr.length ? h('span', { title: arr.map(fmt || ((x) => x)).join('\n') }, `${arr.length} · ${arr.slice(0, 3).join(', ')}${arr.length > 3 ? ' …' : ''}`) : h('span', { class: 'dash' }, '—'));
      return h('tr', null,
        h('td', null, h('b', { class: 'mono' }, g.name), g.defined ? null : h('span', { class: 'badge warn', style: { marginLeft: '6px' }, title: '사용자나 서비스에 있지만 길목 목록에는 없습니다' }, '목록에 없음')),
        h('td', { class: 'small' }, g.desc || h('span', { class: 'dash' }, '—')),
        h('td', { class: 'small' }, names(g.users)),
        h('td', { class: 'small' }, names(g.services, fqdn)),
        h('td', { class: 'row-actions' }, h('div', { class: 'row' }, adopt, edit, del)));
    });
    tableBox.replaceChildren(...[h('table', { class: 'compact proxy-table' },
      h('caption', { class: 'sr-only' }, 'Authelia 그룹'),
      h('thead', null, h('tr', null, ['그룹', '설명', '사용자', '서비스', ''].map((t) => h('th', { scope: 'col' }, t)))),
      h('tbody', null, rows.length ? rows : h('tr', null, h('td', { colspan: '5', class: 'muted' }, '그룹이 없습니다. 「그룹 추가」로 만들어 두면 서비스·사용자 편집에서 골라 쓸 수 있습니다.')))),
    res.usersError ? h('p', { class: 'hint warn-text', style: { padding: '6px 12px' } }, res.usersError) : null].filter(Boolean));
  }
  box.append(h('div', { class: 'toolbar' }, h('p', { class: 'hint grow', style: { margin: 0 } }, '서비스의 「허용 그룹」과 사용자의 「그룹」에서 고르는 목록입니다. 이름을 바꾸거나 지우면 쓰는 곳에도 함께 반영됩니다.'), addBtn), tableBox);
  draw();
  return { el: box, reload: draw, count: () => count };
}

function openGroupManager(onChanged) {
  const close = h('button', { type: 'button', class: 'btn primary' }, '닫기');
  const p = groupsPanel(onChanged);
  const d = openDialog({ title: 'Authelia 그룹 관리', size: 'wide', body: p.el, footer: [h('span', { class: 'spacer' }), close] });
  close.addEventListener('click', () => d.close());
}

/**
 * Toggle chips for picking groups into a comma-separated input, plus 「+ 새 그룹」 and 「그룹 관리…」.
 * Returns the element to append under the input's field.
 */
function groupChips(input) {
  // selection only: the comma list lives in a hidden input, the chips are the control
  input.hidden = true;
  input.readOnly = true;
  input.tabIndex = -1;
  const wrap = h('div', { class: 'grp-chips', role: 'group', 'aria-label': '그룹 선택' });
  const draw = () => {
    const cur = splitList(input.value);
    const reg = groupDefs().map((g) => g.name);
    const names = [...new Set([...reg, ...cur])].sort();
    const chips = names.map((g) => {
      const on = cur.includes(g);
      const d = groupDesc(g);
      const stale = !reg.includes(g);
      const b = h('button', { type: 'button', class: `badge chip-btn grp-chip ${on ? 'on' : ''} ${stale ? 'stale' : ''}`, 'aria-pressed': on ? 'true' : 'false',
        title: `${g}${d ? ` — ${d}` : ''}${stale ? '\n등록되지 않은 그룹 — 빼면 다시 넣을 수 없습니다' : ''}\n${on ? '눌러서 빼기' : '눌러서 넣기'}` }, on ? '✓ ' : '+ ', g);
      if (stale && !on) b.disabled = true;
      b.addEventListener('click', () => {
        const now = splitList(input.value);
        input.value = (now.includes(g) ? now.filter((x) => x !== g) : [...now, g]).join(', ');
        input.dispatchEvent(new Event('input', { bubbles: true }));
        input.dispatchEvent(new Event('change', { bubbles: true }));
      });
      return b;
    });
    const add = h('button', { type: 'button', class: 'badge chip-btn grp-add', title: '새 그룹을 만들고 바로 넣습니다' }, '+ 새 그룹…');
    add.addEventListener('click', async () => {
      const before = new Set(groupDefs().map((x) => x.name));
      if (!(await openGroupEdit(null))) return;
      await refreshState();
      const made = groupDefs().map((x) => x.name).filter((n) => !before.has(n));
      if (made.length) {
        input.value = [...splitList(input.value), ...made].join(', ');
        input.dispatchEvent(new Event('input', { bubbles: true }));
      }
      draw();
    });
    const manage = h('button', { type: 'button', class: 'link-btn small' }, '그룹 관리…');
    manage.addEventListener('click', () => openGroupManager(async () => {
      // a rename / delete may have changed this input's names
      const known = new Set(knownGroups());
      const follow = (g) => { const seen = new Set(); while (S.groupRenames && S.groupRenames[g] && !seen.has(g)) { seen.add(g); g = S.groupRenames[g]; } return g; };
      const before = splitList(input.value);
      const kept = [...new Set(before.map(follow))].filter((g) => known.has(g));
      if (kept.join(',') !== before.join(',')) { input.value = kept.join(', '); input.dispatchEvent(new Event('input', { bubbles: true })); }
      draw();
    }));
    const none = cur.length ? null : h('span', { class: 'small muted' }, '선택 없음 — 로그인한 모든 사용자');
    wrap.replaceChildren(...[h('div', { class: 'chips' }, chips, add), names.length ? none : h('span', { class: 'hint' }, '아직 등록된 그룹이 없습니다 — 「+ 새 그룹…」으로 만드세요'), manage].filter(Boolean));
  };
  input.addEventListener('input', () => queueMicrotask(draw));
  draw();
  return wrap;
}

/** Checkbox dialog over the registered groups. Resolves the new list, or null when cancelled. */
function pickGroups(current, title = '그룹 선택') {
  return new Promise((resolve) => {
    let sel = new Set(current || []);
    const list = h('div', { class: 'pick-list', role: 'group', 'aria-label': '그룹' });
    const draw = () => {
      const reg = groupDefs();
      const stale = [...sel].filter((g) => !reg.some((x) => x.name === g));
      list.replaceChildren(...[...reg.map((g) => ({ name: g.name, desc: g.desc })), ...stale.map((g) => ({ name: g, stale: true }))].map((g) => {
        const cb = h('input', { type: 'checkbox', checked: sel.has(g.name) });
        cb.addEventListener('change', () => { if (cb.checked) sel.add(g.name); else sel.delete(g.name); });
        return h('label', { class: 'pick-item' }, cb,
          h('span', { class: 'grow' }, h('b', { class: 'mono' }, g.name), g.desc ? h('small', null, g.desc) : null,
            g.stale ? h('small', { class: 'pick-why' }, '등록되지 않은 그룹 — 빼면 다시 넣을 수 없습니다') : null));
      }));
      if (!reg.length && !stale.length) list.append(h('p', { class: 'muted' }, '등록된 그룹이 없습니다. 「+ 새 그룹…」으로 만드세요.'));
    };
    const add = h('button', { type: 'button', class: 'btn sm' }, icon('plus'), '새 그룹…');
    add.addEventListener('click', async () => {
      const before = new Set(groupDefs().map((x) => x.name));
      if (!(await openGroupEdit(null))) return;
      await refreshState();
      for (const n of groupDefs().map((x) => x.name)) if (!before.has(n)) sel.add(n);
      draw();
    });
    const manage = h('button', { type: 'button', class: 'link-btn small' }, '그룹 관리…');
    manage.addEventListener('click', () => openGroupManager(() => {
      const reg = new Set(groupDefs().map((x) => x.name));
      sel = new Set([...sel].filter((g) => reg.has(g)));
      draw();
    }));
    const none = h('button', { type: 'button', class: 'btn sm ghost' }, '모두 해제');
    none.addEventListener('click', () => { sel.clear(); draw(); });
    const ok = h('button', { type: 'button', class: 'btn primary' }, '확인');
    const cancel = h('button', { type: 'button', class: 'btn ghost' }, '취소');
    let done = false;
    const d = openDialog({
      title, body: h('div', { class: 'stack' }, h('p', { class: 'hint' }, '아무것도 고르지 않으면 로그인한 모든 사용자를 허용합니다.'), list, h('div', { class: 'row' }, add, none, h('span', { class: 'grow' }), manage)),
      footer: [h('span', { class: 'spacer' }), cancel, ok], onClose: () => { if (!done) resolve(null); },
    });
    cancel.addEventListener('click', () => d.close());
    ok.addEventListener('click', () => { done = true; d.close(); resolve([...sel].sort()); });
    draw();
  });
}

/**
 * groupSelect(initial, {label}) — a button showing the chosen groups; click → pickGroups.
 * Behaves like an input for existing code: .value (comma list, get/set), .disabled, 'change' event, .focus().
 */
function groupSelect(initial = [], { label = '허용 그룹', empty = '로그인한 모든 사용자' } = {}) {
  let cur = Array.isArray(initial) ? [...initial] : splitList(initial);
  const btn = h('button', { type: 'button', class: 'grp-select' });
  const wrap = h('div', { class: 'grp-select-wrap' }, btn);
  const paint = () => {
    btn.replaceChildren(...(cur.length
      ? cur.map((g) => h('span', { class: 'badge grp-chip on', title: groupDesc(g) || g }, g))
      : [h('span', { class: 'muted small' }, empty)]), h('span', { class: 'grp-caret', 'aria-hidden': 'true' }, '▾'));
    btn.setAttribute('aria-label', `${label}: ${cur.length ? cur.join(', ') : empty} — 눌러서 고르기`);
  };
  btn.addEventListener('click', async () => {
    const r = await pickGroups(cur, label);
    if (!r) return;
    cur = r;
    paint();
    wrap.dispatchEvent(new Event('change'));
  });
  Object.defineProperty(wrap, 'value', { get: () => cur.join(', '), set: (v) => { cur = splitList(v); paint(); } });
  Object.defineProperty(wrap, 'disabled', { get: () => btn.disabled, set: (v) => { btn.disabled = !!v; } });
  wrap.focus = () => btn.focus();
  paint();
  return wrap;
}
