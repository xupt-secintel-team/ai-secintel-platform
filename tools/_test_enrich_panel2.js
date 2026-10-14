/* _test_enrich_panel2.js —— 富化台第二轮三个区块的 DOM 桩测试（不开浏览器）
 *
 * 覆盖 ASURF（测绘实查）/ ASUB（预警订阅）/ REMED（修复方案）：
 *   ① 契约：detailSections 含修复方案区块（漏洞条目才有）
 *   ② 渲染：实查结果（总量/分布条/样本表/演示横幅）、订阅列表、告警流、方案结构
 *   ③ 脏数据：null / 缺字段 / 数组含 null 不崩
 *   ④ XSS：severity 进 class 前必须白名单化，用户文本全部转义
 *
 * 用法： node tools/_test_enrich_panel2.js
 */
const fs = require('fs');
const path = require('path');
const vm = require('vm');

const ROOT = path.dirname(__dirname);
const CODE = fs.readFileSync(path.join(ROOT, 'modules', 'm2_enrich', 'web', 'panel.js'), 'utf8');

let PASS = 0, FAIL = 0;
function check(cond, label, extra) {
  if (cond) { PASS++; console.log('  [PASS] ' + label); }
  else { FAIL++; console.log('  [FAIL] ' + label + (extra !== undefined ? '  → ' + extra : '')); }
}

/* ---------------- 最小 DOM 桩（与 _test_enrich_panel.js 同款） ---------------- */
function fakeEl(id) {
  const e = {
    id, innerHTML: '', textContent: '', value: '', checked: false, disabled: false,
    dataset: {}, style: {}, files: null,
    classList: { add() {}, remove() {}, toggle() {}, contains: () => false },
    addEventListener() {}, appendChild() {}, removeChild() {}, remove() {}, click() {},
    querySelector(sel) { return fakeEl(id + sel); },
    querySelectorAll() { return []; },
  };
  return e;
}
function sectionRoot(name) {
  const memo = {};
  const e = {
    id: name,
    querySelector(sel) { return memo[sel] || (memo[sel] = fakeEl(name + sel)); },
    querySelectorAll() { return []; },
    addEventListener() {},
  };
  return e;
}

const SURF = sectionRoot('enSurvey');
const SUB = sectionRoot('enSubscribe');
const els = {};
for (const id of ['remBtn', 'remOut', 'remRe']) els[id] = fakeEl(id);

global.$ = (id) => els[id] || null;
global.esc = (s) => String(s == null ? '' : s)
  .replace(/[&<>"]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));
global.link = (u) => `<a href="${esc(u)}" target="_blank" rel="noopener">${esc(u)}</a>`;
global.document = {
  getElementById: (id) => els[id] || null,
  querySelector: () => null,
  querySelectorAll: () => [],
  createElement: () => fakeEl('_tmp'),
  body: { appendChild() {}, removeChild() {} },
};
global.window = { scrollTo() {}, addEventListener() {} };
global.navigator = {};
global.location = { href: '' };
global.toast = (msg) => { global.__lastToast = msg; };
global.openDetail = (id) => { global.__opened = id; };
global.AISEC = { register(m) { global.__mod = m; } };

/* fetch 桩：按路径前缀路由（最长前缀优先，避免 /api/subscribe 抢走 /api/subscribe/alerts） */
const RESP = {};
global.fetch = (url) => {
  const u = String(url);
  const key = Object.keys(RESP).sort((a, b) => b.length - a.length).find((k) => u.includes(k));
  const payload = key ? RESP[key] : {};
  return Promise.resolve({ json: () => Promise.resolve(payload), blob: () => Promise.resolve({}) });
};

vm.runInThisContext(CODE, { filename: 'panel.js' });

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

(async () => {
  console.log('=== ① 契约 ===');
  check(!!global.__mod, '模块已注册到 AISEC');
  const secs = global.__mod.enrichSections();
  // ★ 按 id 查区块，不写死下标：2026-10-06 之前这里是 secs.length === 4 / secs[1]，
  //   后来前面插入了 ACMDB 区块（下标全部右移一位），契约断言与 mount 全部错位，
  //   表现为「ASURF 已绑事件」FAIL + querySelector(...).onclick is not a function 崩掉。
  //   下标断言在区块增删时必然失效，改成 id 查找后与顺序解耦。
  const secById = (id) => secs.find((s) => s.id === id) || null;
  check(!!secById('enSurvey') && !!secById('enSubscribe') && !!secById('enCmdb'),
        'enrichSections 含实查 / 订阅 / CMDB 区块');
  check(secById('enSurvey').html.includes('asPlat') && secById('enSurvey').html.includes('asGo'),
        '实查区块含平台选择与按钮');
  check(secById('enSubscribe').html.includes('asubAdd') && secById('enSubscribe').html.includes('asubAlerts'),
        '订阅区块含表单与告警流');
  const ds = global.__mod.detailSections('CVE-2024-37032', { id: 'x' }, true) || [];
  check(ds.some((s) => typeof s.html === 'string' && s.html.includes('remBtn')),
        '漏洞详情含「修复方案生成」区块');
  check((global.__mod.detailSections('CVE-x', {}, false) || null) === null,
        '非漏洞条目不注入任何详情区块');

  console.log('\n=== ② ASURF 实查渲染 ===');
  RESP['/api/asset_search/status'] = { ok: true, platforms: {
    fofa: { label: 'FOFA', configured: false, env: 'AISEC_FOFA_KEY' },
    shodan: { label: 'Shodan', configured: true, env: 'AISEC_SHODAN_KEY' } } };
  RESP['/api/asset_search'] = {
    ok: true, mode: 'demo', demo: true, platform: 'fofa', query: 'body="Ollama is running"',
    total: 2341, took_ms: 3,
    demo_note: '演示数据（未配置 AISEC_FOFA_KEY）',
    compliance: '合规文案',
    countries: [{ value: 'CN', count: 487 }, { value: 'US', count: 301 }],
    asns: [{ value: 'AS4134', count: 198 }], orgs: [], ports: [{ value: '443', count: 500 }],
    samples: [{ host: 'a.example.com', ip: '1.2.3.4', port: '443', country: 'CN',
                org: 'orgA', product: 'Ollama', title: 't' }],
    alternatives: [{ q: 'app="Ollama"', why: '平台指纹', product: 'ollama' }],
  };
  secById('enSurvey').mount(SURF);
  await sleep(30);
  check(typeof SURF.querySelector('#asGo').onclick === 'function', '「实查」已绑事件');
  check(SURF.querySelector('#asStatus').innerHTML.includes('Shodan'),
        '平台状态角标渲染（含 Shodan）');
  SURF.querySelector('#asQ').value = 'CVE-2024-37032';
  SURF.querySelector('#asGo').onclick();
  await sleep(40);
  let html = SURF.querySelector('#asOut').innerHTML;
  check(html.includes('as-total-n') && html.includes('2341'), '渲染全网暴露总量大数字');
  check(html.includes('as-demo') && html.includes('演示数据'), '演示模式显式标注横幅');
  check(html.includes('as-bar-row') && html.includes('CN') && html.includes('487'),
        '渲染国家/地区分布条');
  check(html.includes('as-samples') && html.includes('a.example.com'), '渲染暴露样本表');
  check(html.includes('app=&quot;Ollama&quot;') || html.includes('app="Ollama"'),
        '备选语法随行展示');

  console.log('\n=== ③ ASURF 脏数据与 XSS ===');
  const ev = '<img src=x onerror="alert(2)">';
  RESP['/api/asset_search'] = {
    ok: true, mode: 'real', demo: false, platform: 'fofa', query: ev, total: 5, took_ms: 1,
    demo_note: null, compliance: null,
    countries: [null, { value: ev, count: NaN }, { value: 'US' }],
    asns: null, orgs: null, ports: null, samples: [null, { host: ev, country: null }],
    alternatives: [null, { q: ev }],
  };
  SURF.querySelector('#asQ').value = 'body="x"';
  let threw = null;
  try { SURF.querySelector('#asGo').onclick(); await sleep(40); } catch (e) { threw = e; }
  html = SURF.querySelector('#asOut').innerHTML;
  check(threw === null && typeof html === 'string', '实查脏数据不崩', threw && threw.message);
  check(!/onerror="/i.test(html) && !/<img\s/i.test(html), '实查 XSS 载荷被转义');
  RESP['/api/asset_search'] = { ok: false, error: ev, hint: ev + ' 提示' };
  SURF.querySelector('#asGo').onclick();
  await sleep(40);
  html = SURF.querySelector('#asOut').innerHTML;
  check(!/onerror="/i.test(html), '失败信息同样转义（不把错误当可信）');

  console.log('\n=== ④ ASUB 订阅渲染 ===');
  RESP['/api/subscribe'] = { ok: true, subs: [
    { id: 'S1', kind: 'product', value: 'ollama', name: 'Ollama 相关漏洞', min_severity: 'HIGH',
      kev_only: false, ai_min: 0, webhook: '', enabled: true },
    null,
    { id: 'S2', kind: 'kev', value: '', name: '仅 KEV', enabled: false },
  ], status: { subs: 2, enabled: 1, alerts: 3, unread: 2, last_check: '2026-10-03 20:00:00',
               webhook: true, daemon: true, interval: 120 } };
  RESP['/api/subscribe/alerts'] = { ok: true, count: 2, alerts: [
    { id: 'AL1', ts: '2026-10-03 20:00', sub_name: 'Ollama 相关漏洞', doc_id: 'CVE-2026-1',
      title: ev, severity: ev, score: 9.8, kev: true, read: false, pushed: true },
    { id: 'AL2', ts: '', sub_name: null, doc_id: null, title: null, severity: null,
      score: null, kev: false, read: false, pushed: false },
  ] };
  secById('enSubscribe').mount(SUB);
  await sleep(40);
  check(typeof SUB.querySelector('#asubAdd').onclick === 'function', '「订阅」按钮已绑事件');
  html = SUB.querySelector('#asubSubs').innerHTML;
  check(html.includes('Ollama 相关漏洞') && html.includes('HIGH+'), '订阅列表渲染（含严重度门槛）');
  check(html.includes('仅 KEV'), 'KEV 订阅渲染');
  html = SUB.querySelector('#asubStatus').innerHTML;
  check(html.includes('2') && html.includes('上次巡检'), '状态区渲染（未读数/巡检时间）');
  html = SUB.querySelector('#asubAlerts').innerHTML;
  check(html.includes('CVE-2026-1') && html.includes('badge UNKNOWN'), 'severity 脏值白名单化为 UNKNOWN');
  check(!/onerror="/i.test(html) && !/<img\s/i.test(html), '告警流 XSS 转义（severity 曾直接进 class）');
  check(html.includes('已推 Webhook'), '推送状态随行');

  console.log('\n=== ⑤ REMED 修复方案渲染 ===');
  RESP['/api/remediation'] = { ok: true, plan: {
    cve: 'CVE-2026-1', generated_by: 'template', generated_at: '2026-10-03 20:00:00',
    summary: ev + ' 概要', risk: { cvss_score: 9.8, severity: ev, vector: 'AV:N', kev: true, kev_due: '2026-10-21' },
    upgrade: [{ component: 'demoerp < 3.2.2', target: '≥ 3.2.2', note: ev }],
    config: [{ item: ev, detail: '怎么做', code: 'location / { deny all; }' }],
    mitigations: [ev], verify: ['复测'], references: ['https://nvd.nist.gov/vuln/detail/x'],
    disclaimer: '仅供处置参考' } };
  const remSec = ds.find((s) => typeof s.html === 'string' && s.html.includes('remBtn'));
  remSec.mount('CVE-2026-1');                      // 先挂载（bind 把 onclick 绑到全局 $ 元素上）
  els.remBtn.onclick();
  await sleep(40);
  html = els.remOut.innerHTML;
  check(html.includes('rem-sum') && html.includes('rem-cfg'), '方案结构渲染（概要 + 加固卡）');
  check(html.includes('模板模式'), '生成方式显式标注');
  check(html.includes('KEV 在野 · 截止 2026-10-21'), 'KEV 处置时限随行');
  check(html.includes('deny all'), '代码块保留');
  check(!/onerror="/i.test(html) && !/<img\s/i.test(html), '方案 XSS 转义');
  els.remRe.onclick();
  await sleep(30);
  check(els.remOut.innerHTML.includes('rem-sum'), '「重新生成」可复用同一渲染');

  console.log('\n===== 结果：' + PASS + ' 项通过 / ' + FAIL + ' 项失败 =====');
  if (FAIL) process.exit(1);
  console.log('ENRICH PANEL2 TEST OK');
})();
