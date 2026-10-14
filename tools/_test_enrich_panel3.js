/* _test_enrich_panel3.js —— 富化台第三轮区块的 DOM 桩测试（不开浏览器）
 *
 * 覆盖 ASTIX（STIX/TAXII 导出）/ TBOX（详情处置工具箱 · 复现环境生成）：
 *   ① 契约：enrichSections 返回 4 个区块；详情含处置工具箱
 *   ② ASTIX：Bundle 导出触发下载、结果回显
 *   ③ TBOX：复现环境 zip 下载、镜像/警告回显
 *
 * 用法： node tools/_test_enrich_panel3.js
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

function fakeEl(id) {
  const e = {
    id, innerHTML: '', textContent: '', value: '', checked: false, disabled: false,
    dataset: {}, style: {}, files: null, _clicked: 0,
    classList: { add() {}, remove() {}, toggle() {}, contains: () => false },
    addEventListener() {}, appendChild() {}, removeChild() {}, remove() {},
    click() { e._clicked++; },
    querySelector(sel) { return e._memo(sel); },
    _memoMap: null,
    _memo(sel) { e._memoMap = e._memoMap || {}; return e._memoMap[sel] || (e._memoMap[sel] = fakeEl(id + sel)); },
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

const STIX = sectionRoot('enStix');
const els = {};
for (const id of ['tbox', 'tbEnv', 'tbOut']) els[id] = fakeEl(id);

global.$ = (id) => els[id] || null;
global.esc = (s) => String(s == null ? '' : s)
  .replace(/[&<>"]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));
global.document = {
  getElementById: (id) => els[id] || null,
  querySelector: () => null,
  querySelectorAll: () => [],
  createElement: () => fakeEl('_tmp'),
  documentElement: {},
  body: { appendChild() {}, removeChild() {} },
};
global.window = { __lastPocUrls: ['https://poc.example/one'], scrollTo() {}, addEventListener() {} };
/* Node 21+ 的 globalThis.navigator 是只读 getter，赋值会被静默忽略 —— 必须 defineProperty */
Object.defineProperty(globalThis, 'navigator', {
  value: { clipboard: { writeText: async () => {} } }, configurable: true,
});
global.location = { href: '', origin: 'http://127.0.0.1:8848' };
global.toast = (msg) => { global.__lastToast = msg; };
global.openDetail = (id) => { global.__opened = id; };
global.AISEC = { register(m) { global.__mod = m; } };
/* 不覆盖原生 URL 的 instanceof 语义（node fs shim 依赖），只挂静态方法 */
global.URL = class extends URL {
  static createObjectURL() { global.__dl = (global.__dl || 0) + 1; return 'blob:x'; }
  static revokeObjectURL() {}
};

const RESP = {};
global.fetch = (url, opts) => {
  const u = String(url);
  global.__lastFetch = u;
  global.__lastBody = opts && opts.body ? String(opts.body) : '';
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
  // ★ 按 id 查，不写死下标/个数（理由同 _test_enrich_panel2.js：插入 ACMDB 后下标右移）
  const stixSec = secs.find((s) => s.id === 'enStix') || null;
  check(!!stixSec, 'enrichSections 含 STIX 区块', secs.map((s) => s.id).join(','));
  check(stixSec.html.includes('stixGo') && stixSec.html.includes('/taxii2/'), 'STIX 区块含导出按钮与 TAXII 端点');
  const ds = global.__mod.detailSections('CVE-2024-37032', { id: 'x' }, true) || [];
  check(ds.some((s) => typeof s.html === 'string' && s.html.includes('tbox')), '漏洞详情含「处置工具箱」区块');
  check((global.__mod.detailSections('CVE-x', {}, false) || null) === null, '非漏洞条目不注入详情区块');

  console.log('\n=== ② ASTIX 导出 ===');
  RESP['/api/stix'] = { ok: true, filename: 'a.json', count: 2,
    bundle: { id: 'bundle--x', objects: [{ labels: ['critical', 'kev'] }, { labels: ['high'] }] } };
  stixSec.mount(STIX);
  await sleep(20);
  check(typeof STIX.querySelector('#stixGo').onclick === 'function', '「导出 Bundle」已绑事件');
  STIX.querySelector('#stixGo').onclick();
  await sleep(40);
  check(global.__dl === 1, '触发一次 Blob 下载', global.__dl);
  check(STIX.querySelector('#stixOut').innerHTML.includes('<b>2</b>'), '结果回显条数');
  check(STIX.querySelector('#stixOut').innerHTML.includes('KEV 1'), '回显含 KEV 计数');

  console.log('\n=== ③ TBOX 复现环境生成 ===');
  RESP['/api/vuln_env'] = { ok: true, filename: 'CVE-2024-37032-env.zip',
    b64: Buffer.from('hellozip').toString('base64'), bytes: 8,
    plan: { image: 'ollama/ollama:0.1.29', port: 11434, warnings: ['版本取自语料'] } };
  const dsTbox = ds.find((s) => typeof s.html === 'string' && s.html.includes('tbox'));
  dsTbox.mount('CVE-2024-37032');
  await sleep(40);
  const tb = (sel) => els.tbox.querySelector(sel);
  check(typeof tb('#tbEnv').onclick === 'function', '「生成复现环境」已绑事件');
  const dlBefore = global.__dl;
  tb('#tbEnv').onclick();
  await sleep(40);
  check(global.__dl === dlBefore + 1, '复现环境触发 zip 下载');
  check(tb('#tbOut').innerHTML.includes('ollama/ollama:0.1.29'), '生成结果回显镜像');
  check(tb('#tbOut').innerHTML.includes('⚠ 版本取自语料'), '警告回显');
  check(global.__lastBody.includes('CVE-2024-37032'), '请求体带 CVE id', global.__lastBody);

  console.log('\n========================================');
  console.log('ENRICH PANEL3: %d pass, %d fail', PASS, FAIL);
  process.exit(FAIL ? 1 : 0);
})().catch((e) => { console.error('TEST CRASH:', e); process.exit(1); });
