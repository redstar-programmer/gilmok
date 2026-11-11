'use strict';
// 관리형 스택 (stacks.go): 길목이 Caddy·Authelia·CrowdSec을 옆 컨테이너로 설치·관리한다.
// 구성요소 탭 › 연결 단계 맨 위에 붙는다. 이미 있는 컨테이너에 연결하는 방식은 그대로 아래에 있다.

const STACK_STATE = { running: ['실행 중', 'ok'], exited: ['멈춤', 'warn'], created: ['만들어짐', 'muted'], restarting: ['재시작 반복', 'danger'], paused: ['일시 정지', 'warn'] };

async function loadStacks() { return api('GET', '/api/stacks'); }

/** m:ss (or h:mm:ss) — language-neutral so the translated sentence around it still matches */
function clockText(ms) {
  const t = Math.max(0, Math.floor(ms / 1000));
  const h2 = Math.floor(t / 3600);
  const m = Math.floor((t % 3600) / 60);
  const sec = String(t % 60).padStart(2, '0');
  return h2 ? `${h2}:${String(m).padStart(2, '0')}:${sec}` : `${m}:${sec}`;
}

/**
 * Live line under a job log: elapsed time and time since the last output, ticking every second,
 * so a long quiet step (image pull, build, waiting for start) still looks alive.
 * update(job, serverNow) after each poll; lost(msg) when a poll fails (the job keeps going on the server).
 */
function jobPulse() {
  const el = h('p', { class: 'job-pulse', 'aria-live': 'off' });
  let job = null;
  let skew = 0;
  let timer = 0;
  let lostMsg = '';
  const stopTimer = () => { clearInterval(timer); timer = 0; };
  const render = () => {
    if (!job) { el.replaceChildren(); return; }
    if (timer && el.dataset.shown && !el.isConnected) { stopTimer(); return; }
    if (el.isConnected) el.dataset.shown = '1';
    const started = Date.parse(job.started);
    if (job.state !== 'running') {
      stopTimer();
      const took = job.ended && started ? Date.parse(job.ended) - started : 0;
      el.replaceChildren(took > 0 ? h('span', null, '걸린 시간 ', h('span', { class: 'mono' }, clockText(took))) : h('span'));
      return;
    }
    const now = Date.now() + skew;
    const quiet = now - Date.parse(job.updated || job.started);
    const parts = [h('span', { class: 'spinner', 'aria-hidden': 'true' }),
      h('span', null, '경과 ', h('span', { class: 'mono' }, clockText(now - started)))];
    if (lostMsg) parts.push(h('span', { class: 'quiet long' }, `서버 응답을 기다리는 중 — 작업은 서버에서 계속됩니다 (${lostMsg})`));
    else if (quiet >= 300000) parts.push(h('span', { class: 'quiet long' }, `${clockText(quiet)} 동안 새 출력이 없습니다 — 네트워크가 느리거나 Docker가 응답하지 않을 수 있습니다. 서버에서 docker ps로 확인해 보세요.`));
    else if (quiet >= 15000) parts.push(h('span', { class: 'quiet' }, `마지막 출력 ${clockText(quiet)} 전 — 이미지 받기·빌드·시작 확인 중에는 한동안 출력이 없을 수 있습니다.`));
    el.replaceChildren(...parts);
  };
  el.update = (j, serverNow) => {
    job = j;
    lostMsg = '';
    if (serverNow) skew = Date.parse(serverNow) - Date.now();
    render();
    if (j && j.state === 'running' && !timer) timer = setInterval(render, 1000);
  };
  el.lost = (msg) => { lostMsg = msg || '연결 끊김'; render(); };
  return el;
}

/** job log viewer that follows a running job until it ends */
function stackJobLog(name, onEnd) {
  const pre = h('pre', { class: 'log-view stack-log', 'aria-live': 'polite' });
  const head = h('div', { class: 'row' });
  const pulse = jobPulse();
  const box = h('div', { class: 'stack tight' }, head, pre, pulse);
  let stop = false;
  let lastLen = -1;
  const paint = (j, serverNow) => {
    if (!j) return;
    const log = j.log || [];
    // repaint only when the text changed, and follow the end only if the reader is already there
    if (log.length !== lastLen) {
      const atEnd = pre.scrollHeight - pre.scrollTop - pre.clientHeight < 24;
      pre.textContent = log.join('\n');
      if (atEnd || lastLen < 0) pre.scrollTop = pre.scrollHeight;
      lastLen = log.length;
    }
    const [t, c] = j.state === 'running' ? ['진행 중…', 'warn'] : j.state === 'ok' ? ['완료', 'ok'] : ['실패', 'danger'];
    head.replaceChildren(h('b', null, `${stackActionLabel(j.action)}`), h('span', { class: `badge ${c}` }, t), j.error ? h('span', { class: 'small danger-text' }, j.error) : h('span'));
    pulse.update(j, serverNow);
  };
  let fails = 0;
  const tick = async () => {
    if (stop || !box.isConnected && box.dataset.started) return;
    box.dataset.started = '1';
    let r;
    try { r = await loadStacks(); } catch (ex) {
      // a dropped poll does not mean the job failed: keep asking (the server runs it regardless)
      fails++;
      pulse.lost(ex.message);
      setTimeout(tick, Math.min(10000, 1500 * fails));
      return;
    }
    fails = 0;
    const j = r.stacks[name] && r.stacks[name].job;
    paint(j, r.now);
    if (j && j.state === 'running') { setTimeout(tick, 1500); return; }
    onEnd && onEnd(j);
  };
  box.start = () => { stop = false; tick(); };
  box.stop = () => { stop = true; };
  box.paint = paint;
  return box;
}

/** tell other views (the setup wizard's connection fields) that a stack job started or ended */
const stackEvent = (name) => document.dispatchEvent(new CustomEvent('gm:stack', { detail: { name } }));

const stackActionLabel = (a) => ({ install: '설치', start: '시작', stop: '정지', restart: '재시작', remove: '제거', compose: 'compose 적용' }[a] || a);

/** the managed-stack card for one component */
function stackCard(name, onChanged) {
  const box = h('div', { class: 'stack-card' }, spinnerRow('길목이 설치한 구성요소 확인 중…'));
  const canSys = typeof can !== 'function' || can('system');
  const draw = async () => {
    let r;
    try { r = await loadStacks(); } catch (ex) { box.replaceChildren(h('p', { class: 'hint' }, `관리형 정보를 읽지 못했습니다: ${ex.message}`)); return; }
    const v = r.stacks[name];
    if (!v) { box.replaceChildren(); return; }
    const rec = v.record;
    const job = v.job;
    const log = stackJobLog(name, async (j) => { if (j && j.state !== 'running') { await refreshState(); stackEvent(name); onChanged && onChanged(); draw(); } });
    if (job) log.paint(job);
    const running = job && job.state === 'running';
    if (!rec) {
      const inst = h('button', { type: 'button', class: 'btn primary', disabled: !canSys || running, title: canSys ? '' : '「연결·시스템」 권한이 필요합니다' }, icon('plus'), `길목이 ${v.label} 설치…`);
      inst.addEventListener('click', () => openStackInstall(name, v, () => { stackEvent(name); draw(); }, () => { stackEvent(name); draw(); }));
      fill(box, h('div', { class: 'stack-intro' },
        h('div', { class: 'grow' }, h('b', null, `${v.label}가 아직 없나요?`),
          h('p', { class: 'small muted' }, `길목이 ${v.label}를 옆 컨테이너로 설치하고 아래 연결 정보까지 맞춥니다. 이미 실행 중인 ${v.label}가 있으면 아래에서 그 컨테이너에 연결하세요.`)),
        inst),
      job && (running || job.state === 'fail') ? log : null);
      if (running) log.start();
      return;
    }
    const [st, cls] = STACK_STATE[v.state] || [v.state || '없음', 'danger'];
    const btn = (label, action, cls2 = '', confirmMsg) => {
      const b = h('button', { type: 'button', class: `btn sm ${cls2}`, disabled: !canSys || running }, label);
      b.addEventListener('click', async () => {
        let body = {};
        if (action === 'remove') {
          const ok = await confirmDialog({ title: `${v.label} 제거`, danger: true, okText: '제거',
            message: `${rec.container} 컨테이너를 지웁니다.\n폴더(${rec.hostDir})는 기본으로 남깁니다 — 인증서·설정을 다시 쓸 수 있게.\n\n폴더까지 지우려면 다음 창에서 고르세요.` });
          if (!ok) return;
          const wipeOk = await confirmDialog({ title: '폴더도 지울까요?', okText: '폴더도 삭제', cancelText: '폴더는 남김', danger: true,
            message: `${rec.hostDir}\n\n지우면 인증서·설정·데이터가 사라집니다. 되돌릴 수 없습니다.` });
          body = { keepData: wipeOk ? '0' : '1' };
        } else if (confirmMsg && !(await confirmDialog({ title: `${v.label} ${label}`, message: confirmMsg, okText: label }))) return;
        try { await busy(b, () => api('POST', `/api/stacks/${name}/${action}`, body)); stackEvent(name); draw(); } catch (ex) { toast(ex.message, 'err', 8000); }
      });
      return b;
    };
    fill(box,
      !v.state ? callout('danger', h('b', null, `${rec.container} 컨테이너가 없습니다`), h('span', { class: 'small' }, '길목 기록과 폴더는 남아 있습니다. 「다시 설치」를 누르면 그 설정·데이터로 컨테이너를 다시 만듭니다.')) : null,
      h('div', { class: 'stack-intro managed' },
        h('div', { class: 'grow' },
          h('div', { class: 'row' }, h('b', null, `길목이 설치한 ${v.label}`), h('span', { class: `badge ${cls}` }, st)),
          h('dl', { class: 'kv small' },
            h('dt', null, '컨테이너'), h('dd', { class: 'mono' }, rec.container),
            h('dt', null, '네트워크'), h('dd', { class: 'mono' }, rec.network),
            h('dt', null, '폴더'), h('dd', { class: 'mono' }, rec.hostDir),
            h('dt', null, '설치'), h('dd', null, fmtTime(rec.installed) || '—'))),
        h('div', { class: 'row' },
          !v.state ? btn('다시 설치', 'install', 'primary', `${rec.container} 컨테이너가 없습니다 (누군가 지웠거나 Docker가 정리함). 폴더의 설정·데이터를 그대로 써서 다시 만듭니다.`)
            : v.state !== 'running' ? btn('시작', 'start', 'primary') : btn('재시작', 'restart', '', '컨테이너를 다시 시작합니다. 잠깐 사이트가 끊깁니다.'),
          v.state === 'running' ? btn('정지', 'stop', '', '정지하면 이 구성요소를 쓰는 모든 사이트가 멈춥니다.') : null,
          (() => {
            const b = h('button', { type: 'button', class: 'btn sm', disabled: !canSys || running, title: '네트워크·포트·볼륨 등을 이 환경에 맞게 고칩니다' }, 'compose 편집…');
            b.addEventListener('click', () => openComposeEditor(name, v.label, () => draw()));
            return b;
          })(),
          btn('제거…', 'remove', 'danger'))),
      job ? h('details', { class: 'stack-last', open: running || job.state === 'fail' }, h('summary', null, `마지막 작업: ${stackActionLabel(job.action)} (${job.state === 'ok' ? '완료' : job.state === 'fail' ? '실패' : '진행 중'})`), log) : null);
    if (running) log.start();
  };
  draw();
  return box;
}

/**
 * The install options of one component: { fields (elements), opts() → request body, pwOk() }.
 * o.followCaddy: CrowdSec reads whatever Caddy Gilmok ends up with (quick setup installs it first).
 * o.domain: getter for a domain that is not saved yet (quick setup).
 */
function stackInstallFields(name, defaultContainer, o = {}) {
  const st = settings();
  const ctr = h('input', { type: 'text', class: 'mono', value: defaultContainer, autocomplete: 'off', spellcheck: 'false' });
  const net = h('input', { type: 'text', class: 'mono', autocomplete: 'off', spellcheck: 'false', placeholder: '비우면 자동' });
  const netList = h('datalist', { id: uid('nets') });
  net.setAttribute('list', netList.id);
  const netField = field('Docker 네트워크', net, 'Caddy와 서비스 컨테이너는 같은 네트워크에 있어야 컨테이너 이름으로 서로 찾아갑니다. 없는 이름이면 새로 만들고, 길목도 이 네트워크에 연결합니다 (bridge·host는 이름으로 찾을 수 없어 안 됨).');
  const netAdvice = h('div', { class: 'net-advice', 'aria-live': 'polite' });
  netField.append(netList, netAdvice);
  // recommend the network that makes this work, and warn when the choice would split Caddy from it
  let nets = null; // { networks, counts, caddy: {container, networks}, self }
  const useBtn = (v) => {
    const b = h('button', { type: 'button', class: 'btn sm' }, `${v} 로 바꾸기`);
    b.addEventListener('click', () => { net.value = v; syncNet(); });
    return b;
  };
  const syncNet = () => {
    if (!nets) return;
    const v = net.value.trim();
    const counts = nets.counts || {};
    if (name === 'caddy') {
      // Caddy goes where the service containers already are
      const best = (nets.networks || []).slice().sort((a, b) => (counts[b] || 0) - (counts[a] || 0))[0];
      if (!best || !(counts[best] > 0)) { fill(netAdvice, h('p', { class: 'hint' }, '아직 서비스 컨테이너가 있는 네트워크가 없습니다 — 비워 두면 길목이 쓰는 네트워크에 설치합니다.')); return; }
      if (!v) {
        fill(netAdvice, callout('', h('b', null, `추천: ${best}`), h('span', { class: 'small' }, `컨테이너 ${counts[best]}개가 있는 네트워크입니다. 서비스 컨테이너들과 같은 네트워크여야 Caddy가 이름(예: 컨테이너:포트)으로 찾아갑니다.`), useBtn(best)));
      } else if (v !== best && (counts[v] || 0) < counts[best]) {
        fill(netAdvice, callout('warn', h('b', null, `${v} 에는 컨테이너가 ${counts[v] || 0}개뿐입니다`), h('span', { class: 'small' }, `서비스 컨테이너가 ${best} 에 있다면 Caddy가 그 컨테이너들을 찾지 못합니다 — 대상을 host.docker.internal:포트로 바꾸거나 컨테이너를 이 네트워크에 연결해야 합니다.`), useBtn(best)));
      } else {
        fill(netAdvice, h('p', { class: 'hint ok-text' }, `✓ 컨테이너 ${counts[v] || 0}개가 있는 네트워크입니다.`));
      }
      return;
    }
    // Authelia / CrowdSec: Caddy must reach them by name → Caddy's network
    const planned = o.caddyNet ? o.caddyNet() : undefined; // quick setup: the network typed for the Caddy being installed
    const caddyNets = planned !== undefined ? (planned ? [planned] : []) : ((nets.caddy && nets.caddy.networks) || []);
    const who = planned !== undefined ? '함께 설치하는 Caddy' : `Caddy(${(nets.caddy && nets.caddy.container) || 'caddy'})`;
    if (!caddyNets.length) {
      fill(netAdvice, h('p', { class: 'hint' }, planned !== undefined
        ? '비워 두면 함께 설치하는 Caddy와 같은 네트워크에 설치합니다 (권장).'
        : '아직 Caddy 컨테이너가 없습니다 — 나중에 Caddy를 설치할 때 같은 네트워크를 고르세요.'));
      return;
    }
    const rec = caddyNets.find((x) => (nets.self || []).includes(x)) || caddyNets[0];
    if (!v) {
      fill(netAdvice, h('p', { class: 'hint ok-text' }, `비워 두면 ${who}와 같은 네트워크 ${rec} 에 설치합니다 (권장).`));
    } else if (caddyNets.includes(v)) {
      fill(netAdvice, h('p', { class: 'hint ok-text' }, `✓ ${who}와 같은 네트워크입니다.`));
    } else {
      fill(netAdvice, callout('warn', h('b', null, `${who}는 ${v} 에 없습니다`),
        h('span', { class: 'small' }, name === 'authelia'
          ? 'Caddy가 Authelia를 이름으로 찾지 못해, 로그인 포털과 Authelia로 보호한 모든 사이트가 502가 됩니다.'
          : '길목·Caddy와 다른 네트워크면 CrowdSec LAPI 연결이 안 될 수 있습니다.'),
        useBtn(rec)));
    }
  };
  net.addEventListener('input', syncNet);
  api('GET', '/api/docker/networks').then((r) => {
    nets = r;
    netList.replaceChildren(...(r.networks || []).map((n) => h('option', { value: n }, r.counts && r.counts[n] != null ? `컨테이너 ${r.counts[n]}개` : '')));
    syncNet();
  }).catch(() => {});
  if (o.onCaddyNet) o.onCaddyNet(syncNet); // quick setup: re-check when the Caddy network field changes
  const fields = [h('div', { class: 'grid-2' }, field('컨테이너 이름', ctr, '영문·숫자·_.- (이미 같은 이름이 있으면 설치하지 않습니다)'), netField)];
  const read = { container: () => ctr.value.trim(), network: () => net.value.trim() };
  if (name === 'caddy') {
    const port = h('input', { type: 'number', min: 1, max: 65535, value: '443', class: 'w-num' });
    const open80 = switchCtl('포트 80도 열기', false, 'HTTP→HTTPS 리다이렉트나 HTTP-01 인증서 발급이 필요할 때만. Cloudflare DNS로 인증서를 받으면 필요 없습니다.');
    const tls = segmented(uid('tls'), '인증서', [
      { value: 'acme', label: '자동 발급 (Let\'s Encrypt)' },
      { value: 'internal', label: '내부 인증서 (사설·테스트)' },
    ], 'acme');
    const tlsHint = h('p', { class: 'hint' });
    const syncTls = () => {
      tlsHint.textContent = tls.get() === 'internal'
        ? 'Caddy 자체 CA로 발급합니다 — 브라우저 경고가 나오므로 Tailscale 전용·시험용입니다.'
        : (st.cfConfigured || (S.state || {}).cfConfigured)
          ? 'Cloudflare DNS로 발급합니다 (길목의 Cloudflare 토큰을 스택 폴더 .env에 넣음, 0600).'
          : 'Cloudflare 토큰이 없어 HTTP/TLS 방식으로 발급합니다 — 인터넷에서 이 서버의 443(또는 80)이 열려 있어야 합니다.';
    };
    tls.onChange(syncTls);
    syncTls();
    fields.push(field('HTTPS 포트 (호스트)', port, '인터넷에서 들어오는 포트 — 앞단 장비가 다른 포트로 넘기면 그 포트'), open80, h('div', { class: 'stack tight' }, tls, tlsHint));
    read.httpsPort = () => port.value;
    read.open80 = () => (open80.input.checked ? '1' : '');
    read.tls = () => tls.get();
    if (use('cloudflare')) {
      const ca = h('textarea', { class: 'code', rows: '4', spellcheck: 'false', placeholder: '-----BEGIN CERTIFICATE-----\n…\n-----END CERTIFICATE-----' });
      fields.push(field('인증된 원본 풀 CA (mTLS, 선택)', ca, 'Proxied·mTLS 사이트를 쓸 때 Cloudflare가 보여 주는 클라이언트 인증서의 CA (PEM). 나중에 넣어도 됩니다 — 없으면 mTLS 사이트는 적용 때 검증에서 걸립니다.'));
      read.fileCaPem = () => ca.value.trim();
    }
    const priv = caddyPrivOnUI() ? h('p', { class: 'hint' }, `사설 포트 :${st.tailscalePort || 8443} 은 구성도의 사설 경로에 맞춰 게시합니다 — ${privBindText(st)}.`) : null;
    if (priv) fields.push(priv);
  }
  if (name === 'crowdsec' && !o.followCaddy) {
    const cad = h('input', { type: 'text', class: 'mono', value: st.caddyContainer || '', autocomplete: 'off', spellcheck: 'false' });
    fields.push(field('로그를 읽을 Caddy 컨테이너', cad, '이 컨테이너의 로그(길목이 mTLS 사이트에만 남기는 실제 IP 접근 로그)를 분석합니다. Caddy 컨테이너가 바뀌면 길목이 자동으로 따라 바꿉니다.'),
      callout('', h('b', null, 'CrowdSec에 Docker 소켓을 읽기 전용으로 넘깁니다'), h('span', { class: 'small' }, 'Caddy 컨테이너의 로그를 읽는 데 필요합니다. 바운서 키는 길목이 만들어 양쪽에 넣으므로 따로 할 일이 없습니다. 첫 시작 때 허브에서 규칙 묶음을 받느라 1분쯤 걸립니다(인터넷 필요).')),
      use('cloudflare') ? null : callout('warn', 'Cloudflare를 쓰지 않으면 공격 IP를 판정만 하고 차단은 하지 않습니다 (차단은 Cloudflare 엣지에서).'));
    read.caddyCtr = () => cad.value.trim();
  }
  if (name === 'authelia') {
    const dom = (o.domain ? o.domain() : st.domain) || '';
    const user = h('input', { type: 'text', class: 'mono', value: 'admin', autocomplete: 'off', spellcheck: 'false' });
    const pw = h('input', { type: 'password', autocomplete: 'new-password' });
    const pw2 = h('input', { type: 'password', autocomplete: 'new-password' });
    const portal = h('input', { type: 'text', class: 'mono', value: 'auth', autocomplete: 'off', spellcheck: 'false' });
    const portalField = field('로그인 포털 서브도메인', portal, `${'auth'}.${dom || '(도메인)'} — 로그인 화면 주소. 세션 쿠키는 ${dom || '(도메인)'} 전체에 걸립니다.`);
    const syncPortal = () => { portalField.querySelector('.hint').textContent = `${portal.value.trim() || 'auth'}.${dom || '(도메인)'} — 로그인 화면 주소. 세션 쿠키는 ${dom || '(도메인)'} 전체에 걸립니다.`; };
    portal.addEventListener('input', syncPortal);
    const addPortal = switchCtl('포털을 서비스로 추가', true, `${'공개'}${use('cloudflare') ? '·Proxied' : ''} 사이트로 추가하고 Authelia 관문은 걸지 않습니다(자기 자신을 막으면 무한 리다이렉트). 「적용」하면 Caddy에 반영됩니다.`);
    if (!dom && !o.domain) fields.push(callout('danger', h('b', null, '도메인이 없습니다'), h('span', { class: 'small' }, '설정 탭 › 도메인에서 먼저 정하세요 — 로그인 쿠키와 포털 주소의 기준입니다.')));
    fields.push(
      h('div', { class: 'grid-2' }, field('Authelia 관리자 아이디', user, '그룹 admins 로 만듭니다'), portalField),
      h('div', { class: 'grid-2' }, field('관리자 비밀번호', pw, '10자 이상 — argon2id로 해시해 저장, 길목에는 남지 않습니다'), field('비밀번호 확인', pw2)),
      addPortal,
      h('p', { class: 'hint' }, '비밀값(jwt·session·storage)은 길목이 무작위로 만들어 stacks/authelia/secrets 에 둡니다(0600). 알림은 파일(notifier: filesystem)로 남습니다 — 메일은 나중에 configuration.yml에서.'));
    read.adminUser = () => user.value.trim();
    read.secretPassword = () => pw.value;
    read.portal = () => portal.value.trim();
    read.addPortal = () => (addPortal.input.checked ? '1' : '0');
    read._pwCheck = () => (pw.value === pw2.value ? '' : 'mismatch');
  }
  const opts = () => {
    const out = Object.fromEntries(Object.entries(read).map(([k, f]) => [k, f()]));
    delete out._pwCheck;
    return out;
  };
  return { fields, opts, pwOk: () => !(read._pwCheck && read._pwCheck()), network: () => net.value.trim(), netInput: net };
}

/** install dialog: options → preflight → install (background job with a live log) */
function openStackInstall(name, v, onDone, onStart) {
  const f = stackInstallFields(name, v.defaultContainer);
  const fields = f.fields;
  const opts = f.opts;
  const read = { _pwCheck: () => (f.pwOk() ? '' : 'mismatch') };
  const checks = h('div');
  const logBox = h('div');
  const pre = h('button', { type: 'button', class: 'btn' }, '사전 점검');
  const go = h('button', { type: 'button', class: 'btn primary' }, '설치');
  const close = h('button', { type: 'button', class: 'btn ghost' }, '닫기');
  const form = h('div', { class: 'stack' },
    callout('', h('b', null, `길목이 ${v.label}를 옆 컨테이너로 설치합니다`),
      h('span', { class: 'small' }, `파일은 길목 데이터 폴더 아래 stacks/${name} 에 만들고, 설치가 끝나면 길목의 연결 정보를 자동으로 맞춥니다.${name === 'caddy' ? ' 처음엔 Caddy 이미지를 빌드하느라 2~5분 걸립니다.' : ''}`)),
    h('div', { class: 'stack' }, fields), checks, logBox);
  const d = openDialog({ title: `${v.label} 설치`, size: 'wide', body: form, footer: [close, h('span', { class: 'grow' }), pre, go] });
  close.addEventListener('click', () => d.tryClose());
  const runChecks = async () => {
    const r = await api('POST', `/api/stacks/${name}/preflight`, opts());
    const list = r.checks || [];
    checks.replaceChildren(h('h3', null, '사전 점검'), checkList({ checks: list }));
    return !list.some((c) => c.status === 'fail');
  };
  // phase: idle → running → done | idle (failed: fix and retry). busy() restores a button's
  // disabled state when its handler returns, so the state is re-applied after every handler.
  let phase = 'idle';
  const lockForm = () => {
    const off = phase !== 'idle';
    for (const el of form.querySelectorAll('input,textarea,select,button')) if (!logBox.contains(el)) el.disabled = off;
    pre.disabled = go.disabled = off;
    if (phase === 'running') go.textContent = '설치 중…';
    else if (phase === 'done') { go.textContent = '설치됨'; pre.hidden = true; close.className = 'btn primary'; }
    else go.textContent = '다시 설치';
  };
  pre.addEventListener('click', () => busy(pre, async () => { try { await runChecks(); } catch (ex) { toast(ex.message, 'err'); } }).then(() => phase !== 'idle' && lockForm()));
  go.addEventListener('click', () => busy(go, async () => {
    try {
      if (read._pwCheck && read._pwCheck()) { toast('비밀번호 확인이 다릅니다', 'err'); return; }
      if (!(await runChecks())) { toast('사전 점검에서 막힌 항목을 먼저 고치세요', 'err'); return; }
      await api('POST', `/api/stacks/${name}/install`, opts());
      phase = 'running';
      onStart && onStart();
      const log = stackJobLog(name, async (j) => {
        await refreshState();
        if (j && j.state === 'ok') {
          phase = 'done';
          toast(`${v.label}를 설치했습니다`);
          logBox.append(callout('ok', h('b', null, '설치 완료'), h('span', { class: 'small' }, '길목이 연결 정보(컨테이너 이름·설정 파일 경로)를 이미 맞췄습니다 — 컨테이너를 따로 고를 필요가 없습니다. 서비스를 추가하고 「적용」하면 반영됩니다.')));
        } else {
          phase = 'idle';
        }
        lockForm();
        onDone && onDone(j);
      });
      logBox.replaceChildren(h('h3', null, '진행'), log);
      log.start();
    } catch (ex) { toast(ex.message, 'err', 8000); }
  }).then(() => phase !== 'idle' && lockForm()));
}

function caddyPrivOnUI() { return use('tailscale') || ((S.state && S.state.services) || []).some((s) => s.exposure !== 'public'); }
function privBindText(st) {
  if (st.topoPrivKind === 'ts_direct') return st.tailscaleIp ? `Tailscale IP ${st.tailscaleIp} 에만` : '모든 주소 (Tailscale IP를 정하면 그 주소에만)';
  if (st.topoPrivKind === 'vpn') return '모든 주소 (VPN)';
  return '127.0.0.1 에만 (tailscale serve가 넘겨줌)';
}

/** start an install and wait for it; onLog(job) gets every poll. Resolves the finished job. */
async function runStackInstall(name, opts, onLog, onLost) {
  await api('POST', `/api/stacks/${name}/install`, opts);
  let fails = 0;
  for (;;) {
    await new Promise((r) => setTimeout(r, Math.min(10000, 1500 * (fails + 1))));
    let r;
    try { r = await loadStacks(); } catch (ex) {
      // the install keeps running on the server; give up only after ~5 minutes without an answer
      if (++fails > 40) throw ex;
      if (onLost) onLost(ex.message);
      continue;
    }
    fails = 0;
    const j = r.stacks[name] && r.stacks[name].job;
    if (onLog) onLog(j, r.now);
    if (j && j.state !== 'running') return j;
  }
}

/** edit a managed stack's compose.yml: validate → back up → apply → wait until ready (rolls back on failure) */
async function openComposeEditor(name, label, onDone) {
  let cur;
  try { cur = await api('GET', `/api/stacks/${name}/compose`); } catch (ex) { toast(ex.message, 'err'); return; }
  const ta = h('textarea', { rows: '22', 'aria-label': 'compose.yml', 'aria-describedby': uid('ces') });
  ta.value = cur.content;
  const editor = codeEditor(ta, { lang: 'yaml' });
  // live check as you type: our rules + compose itself, nothing is written
  const status = h('div', { class: 'ce-status', id: ta.getAttribute('aria-describedby'), 'aria-live': 'polite' });
  let checkT = 0;
  let checkGen = 0;
  const check = () => {
    clearTimeout(checkT);
    status.className = 'ce-status busy';
    status.textContent = '검사 중…';
    checkT = setTimeout(async () => {
      const gen = ++checkGen;
      let r;
      try { r = await api('POST', `/api/stacks/${name}/compose-check`, { content: ta.value }); } catch (ex) { r = { ok: false, error: ex.message }; }
      if (gen !== checkGen) return;
      status.className = `ce-status ${r.ok ? 'ok' : 'err'}`;
      status.textContent = r.ok ? `✓ 문법 정상 — compose가 받아들이는 파일입니다${(r.networks || []).length ? ` (네트워크: ${r.networks.join(', ')})` : ''}` : `✗ ${r.error}`;
    }, 700);
  };
  ta.addEventListener('input', check);
  check();
  const err = h('p', { class: 'form-error', role: 'alert', hidden: true });
  const logBox = h('div');
  const save = h('button', { type: 'button', class: 'btn primary' }, '검증 후 적용');
  const reset = h('button', { type: 'button', class: 'btn ghost', disabled: !cur.custom, title: cur.custom ? '길목이 만드는 기본 파일로 되돌리고 다시 시작합니다' : '아직 고친 적이 없습니다' }, '기본값으로');
  const close = h('button', { type: 'button', class: 'btn ghost' }, '닫기');
  const body = h('div', { class: 'stack' },
    callout('', h('b', null, `${label} compose.yml`),
      h('ul', { class: 'tight small' },
        h('li', null, '네트워크(networks), 포트(ports), 볼륨, 환경변수 등을 이 환경에 맞게 고칠 수 있습니다.'),
        h('li', null, h('b', null, '그대로 둘 것: '), h('code', null, `container_name: ${cur.container}`), ' 과 라벨 ', h('code', null, `gilmok.managed: ${name}`), ' — 길목이 이 컨테이너를 찾는 기준입니다.'),
        h('li', null, '적용하면 compose가 먼저 검사하고, 이전 파일을 백업한 뒤 컨테이너를 다시 만듭니다. 시작하지 못하면 이전 파일로 되돌립니다.'),
        h('li', null, '고친 파일은 다시 설치해도 유지됩니다. 비밀값은 이 파일이 아니라 같은 폴더의 .env·secrets 에 있습니다.'))),
    cur.custom ? callout('warn', '직접 고친 파일입니다.') : null,
    editor, status, err, logBox);
  const d = openDialog({ title: `${label} compose 편집`, size: 'wide', body, footer: [reset, h('span', { class: 'grow' }), close, save],
    beforeClose: async () => ta.value === cur.content || confirmDialog({ title: '닫기', message: '저장하지 않은 수정이 있습니다. 닫을까요?', okText: '닫기' }) });
  close.addEventListener('click', () => d.tryClose());
  const follow = () => {
    const log = stackJobLog(name, async (j) => {
      save.disabled = reset.disabled = false;
      if (j && j.state === 'ok') {
        toast(`${label} compose를 적용했습니다`);
        cur = await api('GET', `/api/stacks/${name}/compose`);
        ta.value = cur.content;
        editor.refresh();
        check();
        reset.disabled = !cur.custom;
        await refreshState();
        onDone && onDone();
      }
    });
    logBox.replaceChildren(h('h3', null, '진행'), log);
    log.start();
  };
  save.addEventListener('click', () => busy(save, async () => {
    err.hidden = true;
    try {
      await api('PUT', `/api/stacks/${name}/compose`, { content: ta.value });
      save.disabled = reset.disabled = true;
      follow();
    } catch (ex) { err.textContent = ex.message; err.hidden = false; }
  }));
  reset.addEventListener('click', async () => {
    if (!(await confirmDialog({ title: '기본값으로 되돌리기', danger: true, okText: '되돌리기', message: '직접 고친 내용을 버리고 길목이 만드는 compose.yml 로 바꾼 뒤 컨테이너를 다시 만듭니다. (이전 파일은 .bak 으로 남습니다)' }))) return;
    busy(reset, async () => {
      try { await api('POST', `/api/stacks/${name}/compose-reset`, {}); save.disabled = reset.disabled = true; follow(); } catch (ex) { toast(ex.message, 'err'); }
    });
  });
}
