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
function clientCell(x) {
  if (!x || !x.ip) return h('span', { class: 'muted' }, '—');
  if (x.via === 'hidden') return h('span', { class: 'muted', title: `${x.ip} — ${VIA_TEXT.hidden}` }, '알 수 없음');
  const tag = x.via === 'tailnet' ? 'Tailscale' : x.via === 'lan' ? '내부망' : '';
  return h('span', { class: 'client-cell', title: VIA_TEXT[x.via] || '' },
    h('span', { class: 'mono' }, x.ip),
    x.cc ? h('span', { class: 'cc-badge', title: geoName(x.cc) }, x.cc) : null,
    x.cc ? h('span', { class: 'small muted' }, geoName(x.cc)) : null,
    tag ? h('span', { class: 'small muted' }, tag) : null);
}
/** one line for tooltips: "1.2.3.4 · 대한민국" */
function clientText(x) {
  if (!x || !x.ip) return '';
  if (x.via === 'hidden') return '접속자 알 수 없음 (Docker Desktop)';
  return [x.ip, x.cc ? `${geoName(x.cc)} (${x.cc})` : x.via === 'tailnet' ? 'Tailscale' : x.via === 'lan' ? '내부망' : ''].filter(Boolean).join(' · ');
}

// ======================================================================= Caddy tab: country block

function geoBlockStep() {
  const st = settings();
  const body = h('div', { class: 'stack' }, spinnerRow('GeoIP 상태를 확인하는 중…'));
  const direct = S.state.services.filter((s) => s.enabled && !s.dnsOnly && s.exposure === 'public' && !(s.proxied && use('cloudflare')));
  const proxied = S.state.services.filter((s) => s.enabled && !s.dnsOnly && s.exposure === 'public' && s.proxied && use('cloudflare'));

  const draw = async () => {
    let g = {};
    let topo = null;
    try { g = await api('GET', '/api/geoip'); } catch (ex) { fill(body, errorBox(ex.message)); return; }
    try { topo = S.topoInfo || await api('GET', '/api/topology'); } catch { /* optional */ }
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
    if (topo && topo.dockerDesktop && cur.caddyMode !== 'api' && cur.caddyMode !== 'native') {
      notes.push(callout('warn', h('b', null, '이 서버(Docker Desktop)에서는 Caddy가 실제 접속자 주소를 보지 못합니다.'),
        h('span', { class: 'small' }, '외부 접속이 모두 Docker 내부 주소로 들어와 국가를 알 수 없고, 내부 주소는 차단하지 않으므로 이 기능은 아무것도 막지 않습니다. Proxied로 바꾸고 Cloudflare 국가 규칙을 쓰거나, 공유기의 국가 차단을 쓰세요.')));
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
