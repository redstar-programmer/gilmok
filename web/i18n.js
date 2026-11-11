'use strict';
// 화면 언어: 한국어(기본, 원문) / English.
// 언어는 설치 단위 설정(Settings.lang)이다 — 첫 접속에서 고르고(언어 선택 화면), 이후 설정 탭에서 바꾼다.
// localStorage gm.lang은 그 값을 기억해 첫 화면부터 맞는 언어로 그리기 위한 캐시일 뿐이다.
// 원문(한국어)이 곧 메시지 ID다(gettext 방식) — web/i18n/<lang>.json = { "원문": "번역" }.
// 원문 목록은 `go run ./tools/i18n`이 소스에서 뽑아 web/i18n/ko.json으로 만든다(새 언어는 이 파일을 복사해 번역).
// 한국어일 때는 아무것도 하지 않는다. 다른 언어면 화면에 그려진 글자(텍스트·title·placeholder·aria-label)를
// 그리기 직전(MutationObserver)에 바꾼다. 서버가 보낸 오류 문구도 같은 목록으로 바뀐다.
// 보간된 문구("적용 대기 변경 {0}건")는 패턴으로 맞추고, 찾지 못한 글자는 원문 그대로 둔다.
// 코드·로그 원문(pre, code, textarea, translate="no")은 바꾸지 않는다.
(function () {
  const KEY = 'gm.lang';
  const LANGS = { ko: '한국어', en: 'English' };
  let lang = 'ko';
  try { const v = localStorage.getItem(KEY); if (v && LANGS[v]) lang = v; } catch { /* private mode */ }
  document.documentElement.lang = lang;

  const HANGUL = /[가-힣]/;
  const exact = new Map(); // 원문 → 번역
  const patterns = []; // { lazy, greedy, out, lits, weight }
  const cache = new Map();
  const misses = new Set();
  const debug = (() => { try { return localStorage.getItem('gm.i18nDebug') === '1'; } catch { return false; } })();

  const escRe = (s) => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

  const hangulCount = (x) => (x.match(/[\uac00-\ud7a3]/g) || []).length;

  // A pattern: "적용 대기 변경 {0}건" → regex with one capture per slot. Placeholders written next to
  // each other ("{1}{2}") cannot be split reliably, so they share one slot when the translation keeps
  // them together in the same order (the slot's text is then translated as a whole).
  function load(dict) {
    for (const [k, v] of Object.entries(dict)) {
      if (v == null || k === v) continue;
      if (!/\{\d+\}/.test(k)) {
        exact.set(k, v);
        // "· 2단계 켜짐" is often shown without its leading dot too
        const m = /^· (.+)$/.exec(k);
        if (m && /^· /.test(v) && !dict[m[1]]) exact.set(m[1], v.slice(2));
        continue;
      }
      const parts = k.split(/(\{\d+\})/).filter((x) => x !== '');
      const slots = []; // [[ids…]]
      const lits = [];
      const seq = []; // {lit} | {slot}
      for (const x of parts) {
        const m = /^\{(\d+)\}$/.exec(x);
        if (m) {
          const last = seq[seq.length - 1];
          if (last && last.slot !== undefined) slots[last.slot].push(Number(m[1]));
          else { slots.push([Number(m[1])]); seq.push({ slot: slots.length - 1 }); }
        } else { seq.push({ lit: x }); lits.push(x); }
      }
      // a pattern needs Korean outside its placeholders, or it would match anything
      const weight = hangulCount(lits.join(''));
      if (!weight) continue;
      let out = v;
      let ok = true;
      slots.forEach((ids, i) => {
        const run = ids.map((n) => `{${n}}`).join('');
        if (ids.length > 1) {
          if (out.includes(run)) out = out.replace(run, `\u0000${i}\u0000`); else ok = false;
        } else out = out.replace(run, `\u0000${i}\u0000`);
      });
      if (!ok) continue;
      const build = (cap) => new RegExp('^' + seq.map((x) => (x.lit !== undefined ? escRe(x.lit) : cap)).join('') + '$');
      patterns.push({ lazy: build('([\\s\\S]*?)'), greedy: build('([\\s\\S]*)'), out, lits, weight });
    }
    patterns.sort((a, b) => b.weight - a.weight); // the most specific first
  }

  // composed text: line breaks first, then the usual joiners
  const SEPS = ['\n', ' — ', ': ', ' · ', ' / ', '. ', ', '];
  const MAXD = 5;

  function fill(p, m, depth) {
    const vals = m.slice(1);
    // short patterns are easy to hit by accident — "공통인 부분" is not "{0}분":
    // 1 Korean letter: values without Korean only; 2 letters: Korean values must be known words
    if (p.weight === 1 && vals.some((x) => HANGUL.test(x))) return null;
    // a value must not swallow a line break or " — " the message itself does not have
    // ("Caddy 연결 — 확인 중…" is a title and a state, not "{0} 확인 중…")
    if (!p.lits.some((l) => l.includes('\n')) && vals.some((x) => x.includes('\n'))) return null;
    if (vals.some((x) => /^\s*—|—\s*$/.test(x))) return null;
    if (p.weight === 2 && vals.some((x) => HANGUL.test(x) && !exact.has(x.trim()))) return null;
    const tv = vals.map((x) => (x && depth < MAXD ? tr(x, depth + 1) : x));
    return p.out.replace(/\u0000(\d+)\u0000/g, (_, i) => tv[Number(i)] ?? '');
  }

  function viaPattern(core, depth) {
    let best = null;
    let bestLeft = Infinity;
    for (const p of patterns) {
      if (bestLeft === 0) break;
      if (!p.lits.every((l) => core.includes(l))) continue;
      for (const re of [p.lazy, p.greedy]) {
        const m = re.exec(core);
        if (!m) continue;
        const out = fill(p, m, depth);
        if (out == null) continue;
        const left = hangulCount(out);
        if (left < bestLeft) { best = out; bestLeft = left; }
        if (!left) break;
      }
    }
    return best;
  }

  /** known message only (no splitting): exact or pattern */
  function known(core, depth) {
    const e = exact.get(core);
    if (e !== undefined) return e;
    return viaPattern(core, depth);
  }

  /** translate one string (trimmed match, keeps surrounding white space) */
  function tr(s, depth = 0) {
    if (lang === 'ko' || !s || !HANGUL.test(s)) return s;
    const hit = cache.get(s);
    if (hit !== undefined) return hit;
    const lead = /^\s*/.exec(s)[0];
    const trail = /\s*$/.exec(s)[0];
    const core = s.slice(lead.length, s.length - trail.length);
    let r = exact.get(core);
    // "서비스 추가: <이름>" — a known heading with its colon beats any pattern
    const ci = core.indexOf(': ');
    if (r === undefined && ci > 0 && depth < MAXD) {
      const hk = exact.get(core.slice(0, ci + 1));
      if (hk !== undefined) r = hk + ' ' + tr(core.slice(ci + 2), depth + 1);
    }
    if (r === undefined || HANGUL.test(r)) {
      const pr = viaPattern(core, depth);
      if (pr != null && (r === undefined || hangulCount(pr) < hangulCount(r))) r = pr;
    }
    let bestLeft = r == null ? hangulCount(core) : hangulCount(r);
    const consider = (out) => { const left = hangulCount(out); if (left < bestLeft) { r = out; bestLeft = left; } };
    if (bestLeft && depth < MAXD) {
      const d = depth + 1;
      // numbers / codes around the words: "942 SQL 인젝션", "통과:", ":443 공개"
      const pm = /^([^\uac00-\ud7a3]*?)([\uac00-\ud7a3][\s\S]*?[\uac00-\ud7a3]|[\uac00-\ud7a3])([^\uac00-\ud7a3]*)$/.exec(core);
      if (pm && (pm[1] || pm[3])) {
        const mid = known(pm[2], d);
        if (mid != null) consider(pm[1] + mid + pm[3]);
      }
      // "이름 (설명)"
      const par = /^([\s\S]+?) \(([^()]+)\)$/.exec(core);
      if (par) {
        const inner = known('(' + par[2] + ')', d); // some messages carry their own parentheses
        consider(tr(par[1], d) + ' ' + (inner != null ? inner : '(' + tr(par[2], d) + ')'));
      }
      // composed text ("검증 실패: <서버 오류>", "A — B\n설명"): pieces, or head + rest
      for (const sep of SEPS) {
        if (!bestLeft) break;
        const at = core.indexOf(sep);
        if (at < 0) continue;
        const head = core.slice(0, at);
        const rest = core.slice(at + sep.length);
        consider(core.split(sep).map((x) => tr(x, d)).join(sep));
        consider(tr(head, d) + sep + tr(rest, d));
        const glued = sep.trimEnd(); // a message that ends with its own ":" / "."
        if (glued && glued !== sep) {
          const h2 = known(head + glued, d);
          if (h2 != null) consider(h2 + sep.slice(glued.length) + tr(rest, d));
        }
      }
      // the longest known beginning, then the rest ("<알려진 문장> <이어 붙인 문장>")
      if (bestLeft) {
        for (let i = core.lastIndexOf(' '); i > 0; i = core.lastIndexOf(' ', i - 1)) {
          const head = known(core.slice(0, i), d);
          if (head != null) { consider(head + ' ' + tr(core.slice(i + 1), d)); break; }
        }
      }
      // …or the longest known ending ("942 SQL 인젝션", "<이름> 2단계 인증 초기화")
      if (bestLeft) {
        for (let i = core.indexOf(' '); i > 0; i = core.indexOf(' ', i + 1)) {
          const tail = known(core.slice(i + 1), d);
          if (tail != null) { consider(tr(core.slice(0, i), d) + ' ' + tail); break; }
        }
      }
    }
    if (debug && depth === 0 && (r == null || HANGUL.test(r))) misses.add(core);
    if (r == null) r = core;
    const full = lead + r + trail;
    if (cache.size > 20000) cache.clear();
    cache.set(s, full);
    return full;
  }

  /** t('원문 {0}', x) for code that paints text itself (canvas, document.title) */
  function t(s, ...args) {
    const out = tr(s);
    return args.length ? out.replace(/\{(\d+)\}/g, (_, i) => String(args[Number(i)] ?? '')) : out;
  }

  const SKIP = 'pre,code,textarea,script,style,[translate="no"],[contenteditable="true"]';
  const ATTRS = ['title', 'placeholder', 'aria-label', 'alt'];

  function fixText(n) {
    const v = n.nodeValue;
    if (!v || !HANGUL.test(v)) return;
    const p = n.parentElement;
    if (p && p.closest(SKIP)) return;
    const r = tr(v);
    if (r !== v) n.nodeValue = r;
  }
  function fixAttrs(el) {
    if (el.closest(SKIP) && el.tagName !== 'TEXTAREA') return;
    for (const a of ATTRS) {
      const v = el.getAttribute(a);
      if (v && HANGUL.test(v)) { const r = tr(v); if (r !== v) el.setAttribute(a, r); }
    }
    if (el.tagName === 'INPUT' && (el.type === 'button' || el.type === 'submit') && HANGUL.test(el.value)) el.value = tr(el.value);
  }
  function walk(root) {
    if (root.nodeType === 3) { fixText(root); return; }
    if (root.nodeType !== 1 && root.nodeType !== 11) return;
    if (root.nodeType === 1) fixAttrs(root);
    const w = document.createTreeWalker(root, NodeFilter.SHOW_TEXT | NodeFilter.SHOW_ELEMENT);
    for (let n = w.nextNode(); n; n = w.nextNode()) {
      if (n.nodeType === 3) fixText(n); else fixAttrs(n);
    }
  }

  function start() {
    walk(document.documentElement);
    document.title = tr(document.title);
    new MutationObserver((list) => {
      for (const m of list) {
        if (m.type === 'characterData') fixText(m.target);
        else if (m.type === 'attributes') fixAttrs(m.target);
        else for (const n of m.addedNodes) walk(n);
      }
    }).observe(document.documentElement, { subtree: true, childList: true, characterData: true, attributes: true, attributeFilter: ATTRS });
  }

  const ready = lang === 'ko'
    ? Promise.resolve()
    : fetch(`i18n/${lang}.json`, { cache: 'no-cache' })
      .then((r) => (r.ok ? r.json() : {}))
      .then((d) => { load(d); })
      .catch(() => { /* fall back to Korean */ })
      .then(() => {
        if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', start, { once: true });
        else start();
      });

  window.gmI18n = {
    lang: () => lang,
    langs: LANGS,
    locale: () => (lang === 'ko' ? 'ko-KR' : lang === 'en' ? 'en-US' : lang),
    ready,
    set(v) {
      if (!LANGS[v] || v === lang) return;
      try { localStorage.setItem(KEY, v); } catch { /* ignore */ }
      location.reload(); // simplest way back to the source text
    },
    /** the install's language from the server (/api/auth/state); true = reloading into it */
    sync(v) {
      if (!LANGS[v]) return false;
      try { localStorage.setItem(KEY, v); } catch { /* ignore */ }
      if (v === lang) return false;
      location.reload();
      return true;
    },
    tr,
    t,
    /** untranslated text seen on screen (localStorage gm.i18nDebug = '1') */
    misses: () => [...misses],
  };
  window.t = t;
  window.gmLocale = () => window.gmI18n.locale();
}());
