'use strict';
// 가벼운 코드 편집기: <textarea>는 그대로 두고, 같은 글꼴·크기로 색을 입힌 <pre>를 그 아래에 겹쳐 그린다.
// 입력·선택·되돌리기·IME(한글 입력)는 브라우저의 textarea가 그대로 처리한다. innerHTML은 쓰지 않는다.
// 지원: yaml (compose.yml 등)

const YAML_LIT = /^(true|false|yes|no|on|off|null|~)$/i;

/** one YAML line → [[text, class]] (class '' = plain) */
function yamlTokens(line) {
  const out = [];
  const push = (t, c = '') => { if (t) out.push([t, c]); };
  // leading indentation (a tab there is an error in YAML)
  const ind = /^[ \t]*/.exec(line)[0];
  if (ind.includes('\t')) push(ind, 'tk-err'); else push(ind);
  let rest = line.slice(ind.length);
  if (rest.startsWith('#')) { push(rest, 'tk-com'); return out; }
  if (/^-(\s|$)/.test(rest)) { push('-', 'tk-punct'); rest = rest.slice(1); const sp = /^\s*/.exec(rest)[0]; push(sp); rest = rest.slice(sp.length); }
  // key:
  const km = /^("(?:[^"\\]|\\.)*"|'(?:[^']|'')*'|[^\s:#'"][^:#]*?)(\s*:)(?=\s|$)/.exec(rest);
  if (km) { push(km[1], 'tk-key'); push(km[2], 'tk-punct'); rest = rest.slice(km[0].length); }
  // value: strings, ${vars}, comments, literals, numbers
  const re = /("(?:[^"\\]|\\.)*"?|'(?:[^']|'')*'?)|(\$\{[^}]*\}?)|((?:^|\s)#.*$)|([&*][\w-]+)|(\|[-+]?|>[-+]?)(?=\s*$)/g;
  let last = 0;
  let m;
  const plain = (t) => {
    // literals / numbers only when they are the whole scalar
    const v = t.trim();
    if (v && (YAML_LIT.test(v) || /^[-+]?\d+(\.\d+)?$/.test(v))) {
      const i = t.indexOf(v);
      push(t.slice(0, i)); push(v, 'tk-lit'); push(t.slice(i + v.length));
    } else push(t);
  };
  while ((m = re.exec(rest))) {
    plain(rest.slice(last, m.index));
    if (m[1]) push(m[1], (m[1].length < 2 || m[1].at(-1) !== m[1][0]) ? 'tk-err' : 'tk-str'); // an unclosed quote shows red
    else if (m[2]) push(m[2], 'tk-env');
    else if (m[3]) push(m[3], 'tk-com');
    else if (m[4]) push(m[4], 'tk-anchor');
    else if (m[5]) push(m[5], 'tk-punct');
    last = m.index + m[0].length;
    if (m[0].length === 0) re.lastIndex++;
  }
  plain(rest.slice(last));
  return out;
}

/**
 * codeEditor(textarea, {lang}) → wrapper element (put it where the textarea was).
 * The textarea keeps its value / events; wrapper.refresh() repaints after a programmatic change.
 */
function codeEditor(ta, { lang = 'yaml' } = {}) {
  const code = h('code');
  const pre = h('pre', { class: 'ce-hl', 'aria-hidden': 'true' }, code);
  const wrap = h('div', { class: 'code-editor' }, pre);
  ta.classList.add('ce-input');
  ta.setAttribute('spellcheck', 'false');
  ta.setAttribute('autocapitalize', 'off');
  ta.setAttribute('autocomplete', 'off');
  wrap.append(ta);
  const paint = () => {
    const frag = document.createDocumentFragment();
    const lines = ta.value.split('\n');
    lines.forEach((line, i) => {
      for (const [t, c] of lang === 'yaml' ? yamlTokens(line) : [[line, '']]) {
        frag.append(c ? h('span', { class: c }, t) : document.createTextNode(t));
      }
      if (i < lines.length - 1) frag.append('\n');
    });
    frag.append('\n'); // keeps the last line's height when the text ends with a newline
    code.replaceChildren(frag);
    sync();
  };
  const sync = () => { pre.scrollTop = ta.scrollTop; pre.scrollLeft = ta.scrollLeft; };
  ta.addEventListener('input', paint);
  ta.addEventListener('scroll', sync);
  // Tab keeps moving focus out of the editor (no keyboard trap); YAML does not allow tabs anyway
  wrap.refresh = paint;
  paint();
  return wrap;
}
