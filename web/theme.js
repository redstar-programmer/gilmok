'use strict';
// 테마: 시스템 / 다크 / 화이트 — <head>에서 바로 실행해 첫 화면부터 맞는 색으로 그린다.
// 선택은 이 브라우저에만 저장(localStorage gm.theme). 「시스템」은 OS의 라이트/다크 설정을 따른다.
(function () {
  const KEY = 'gm.theme';
  const valid = (t) => (t === 'dark' || t === 'light' || t === 'system' ? t : 'system');
  let pref = 'system';
  try { pref = valid(localStorage.getItem(KEY)); } catch { /* private mode */ }
  const mq = window.matchMedia ? window.matchMedia('(prefers-color-scheme: light)') : null;
  const effective = () => (pref === 'system' ? (mq && mq.matches ? 'light' : 'dark') : pref);
  const apply = () => {
    document.documentElement.setAttribute('data-theme', pref);
    const meta = document.querySelector('meta[name="color-scheme"]');
    if (meta) meta.setAttribute('content', effective());
  };
  apply();
  // redraw what JS painted with theme colors (topology SVG, dashboard charts)
  const changed = () => {
    apply();
    document.dispatchEvent(new CustomEvent('gm:theme', { detail: { pref, effective: effective() } }));
  };
  if (mq) mq.addEventListener('change', () => { if (pref === 'system') changed(); });
  window.gmTheme = {
    get: () => pref,
    effective,
    set(t) {
      pref = valid(t);
      try { localStorage.setItem(KEY, pref); } catch { /* ignore */ }
      changed();
    },
  };
}());

/** CSS custom property value (theme-aware colors for SVG/canvas). */
function cssVar(name) {
  return getComputedStyle(document.documentElement).getPropertyValue(name).trim();
}
