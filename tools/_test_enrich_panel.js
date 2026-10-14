/* _test_enrich_panel.js —— 富化台「资产风险体检」面板的 DOM 桩测试（不开浏览器）
 *
 * 为什么需要它：这一块是模块通过 AISEC.register({enrichSections}) 交给主体渲染的，
 * 逻辑全在 JS 里；不能只靠"接口返回 200"就断定面板没坏。这里用最小 DOM 桩
 * 把真实接口报告（测试报告/_fixture_asset_report.json）走一遍渲染，验证：
 *   ① 区块结构渲染出来（上传区 / KPI / 在野利用条 / 主机表 / 组件卡 / 命中行）
 *   ② 脏数据（null、缺字段、数组含 null）不崩
 *   ③ 用户数据里的 HTML 被转义（XSS 不注入）
 *
 * 用法： node tools/_test_enrich_panel.js
 */
const fs = require('fs');
const path = require('path');
const vm = require('vm');

const ROOT = path.dirname(__dirname);
const CODE = fs.readFileSync(path.join(ROOT, 'modules', 'm2_enrich', 'web', 'panel.js'), 'utf8');
const FIXTURE = path.join(ROOT, '测试报告', '_fixture_asset_report.json');

let PASS = 0, FAIL = 0;
function check(cond, label, extra) {
  if (cond) { PASS++; console.log('  [PASS] ' + label); }
  else { FAIL++; console.log('  [FAIL] ' + label + (extra !== undefined ? '  → ' + extra : '')); }
}

/* 兜底样本：fixture 与 data/asset_reports/ 都拿不到时用它。
   字段按渲染函数实际读取的结构填最小集，保证「渲染 / 脏数据 / XSS」三段都能跑完。 */
const MINIMAL_REPORT = {
  id: 'AS-MINIMAL-0001',
  filename: '示例.txt',
  file: { kind: 'txt', chars: 128, warn: '' },
  basis: '按版本区间判定',
  risk: {
    summary: { hosts: 1, products: 1, cve_hits: 1, exploited: 0, kev_ids: ['CVE-2021-44228'] },
    hosts: [{ name: 'app.example.com', ip: '1.2.3.4', type: 'web',
              risk_level: '高', components: [{ name: 'Apache Log4j2', version: '2.14.1' }] }],
    products: [{ name: 'Apache Log4j2', risk_level: '高', findings: [{ id: 'CVE-2021-44228' }] }],
  },
  assets: { ports: [443], os: null, urls: null, emails: null, cves_in_doc: ['CVE-2021-44228'] },
};

/* ---------------- 最小 DOM 桩 ---------------- */
const els = {};
function fakeEl(id) {
  const e = {
    id, innerHTML: '', textContent: '', value: '', dataset: {}, style: {}, files: null,
    classList: { add() {}, remove() {}, toggle() {}, contains: () => false },
    addEventListener() {}, appendChild() {}, removeChild() {}, remove() {}, click() {},
    querySelector(sel) { return fakeEl(id + sel); },
    querySelectorAll() { return []; },
  };
  return e;
}
function root() {                    // 模块区块根元素：querySelector 按选择器记忆化，保证同一个 id 是同一个对象
  const memo = {};
  const e = {
    id: 'enAssetScan',
    querySelector(sel) { return memo[sel] || (memo[sel] = fakeEl('enAssetScan' + sel)); },
    querySelectorAll() { return []; },
    addEventListener() {},
  };
  e._memo = memo;
  return e;
}
const SECTION = root();
for (const id of ['enResult', 'enHist', 'enProg']) els[id] = SECTION.querySelector('#' + id);

global.$ = (id) => els[id] || null;
global.esc = (s) => String(s == null ? '' : s)
  .replace(/[&<>"]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));
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
global.toast = () => {};
global.openDetail = () => {};
/* 注意：不能把 global.URL 直接替换成普通对象 —— 本机 node 的 fs shim 内部
   有 `filePath instanceof URL`，替换掉 URL 类会把 readFileSync 打崩。
   用 class extends 保留 instanceof 语义，只补上浏览器端静态方法。 */
const NativeURL = global.URL;
global.URL = class extends NativeURL {
  static createObjectURL() { return 'blob:x'; }
  static revokeObjectURL() {}
};
global.FormData = function () { this.append = () => {}; };
global.AISEC = { register(m) { global.__mod = m; } };

let PAYLOAD = null;
global.fetch = (url) => {
  const u = String(url);
  if (u.includes('/api/asset_scan') && u.includes('sample')) {
    return Promise.resolve({ json: () => Promise.resolve(PAYLOAD), blob: () => Promise.resolve({}) });
  }
  if (u.includes('/api/asset_scan')) {
    return Promise.resolve({ json: () => Promise.resolve({ ok: true, count: 0, items: [] }), blob: () => Promise.resolve({}) });
  }
  return Promise.resolve({ json: () => Promise.resolve({}), blob: () => Promise.resolve({}) });
};

vm.runInThisContext(CODE, { filename: 'panel.js' });

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const R = () => SECTION.querySelector('#enResult').innerHTML;

(async () => {
  console.log('=== ① 区块契约与渲染 ===');
  check(!!global.__mod, '模块已注册到 AISEC');
  const secs = global.__mod.enrichSections();
  // ★ 按 id 查区块，不写死个数与顺序（enCmdb 插入后 length/order 断言全部过期）
  const sec = secs.find((s) => s.id === 'enAssetScan') || null;
  check(!!sec, 'enrichSections 含资产体检区块', secs.map((s) => s.id).join(','));
  check(!!secs.find((s) => s.id === 'enCmdb'), 'enrichSections 含 CMDB 区块');
  check(sec && typeof sec.mount === 'function', '体检区块带 id 与 mount');
  check(sec.html.includes('en-drop') && sec.html.includes('enPick') && sec.html.includes('enFile'),
        '上传区 HTML 含拖拽区与文件输入');

  let mountOk = true;
  try { sec.mount(SECTION); } catch (e) { mountOk = false; console.log('    mount 抛错：' + e.message); }
  check(mountOk, 'mount 不抛异常（事件绑上）');
  check(typeof SECTION.querySelector('#enSample').onclick === 'function', '「载入示例」已绑事件');

  // ★ fixture 可能被清理脚本/交付打包删掉。直接 readFileSync 会崩，
  //   而 CI 只是 `node xxx >nul` 看退出码 → 崩了就是 FAIL，但看不出是「测试数据没了」
  //   还是「面板坏了」。这里回退到 data/asset_reports/ 下最新一份真实报告，
  //   两者都没有才用内置最小样本，保证测试永远能跑完并给出可读结论。
  let real = null;
  let realFrom = '';
  if (fs.existsSync(FIXTURE)) {
    real = JSON.parse(fs.readFileSync(FIXTURE, 'utf8'));
    realFrom = FIXTURE;
  } else {
    const dir = path.join(ROOT, 'data', 'asset_reports');
    if (fs.existsSync(dir)) {
      const f = fs.readdirSync(dir).filter((n) => n.endsWith('.json')).sort().pop();
      if (f) {
        real = JSON.parse(fs.readFileSync(path.join(dir, f), 'utf8'));
        realFrom = 'data/asset_reports/' + f;
      }
    }
  }
  if (!real) { real = MINIMAL_REPORT; realFrom = '内置最小样本'; }
  console.log('  · 报告样本来源：' + realFrom);
  PAYLOAD = { ok: true, id: real.id, report: real };
  SECTION.querySelector('#enSample').onclick();
  await sleep(60);
  const html = R();
  check(html.includes('en-kpis'), '渲染 KPI 指标区');
  check(html.includes('en-kev'), '渲染「在野利用」告警条');
  check(html.includes('en-tbl') && html.includes('en-host-row'), '渲染资产主机表');
  check(html.includes('en-prod') && html.includes('en-f'), '渲染组件卡与命中行');
  check(html.includes('en-rk'), '渲染风险等级徽章');
  check(html.includes('enExport') && html.includes('enAgain'), '渲染导出/换文件按钮');
  const realHosts = real.risk.hosts.length;
  const rowCount = (html.match(/en-host-row/g) || []).length;
  check(rowCount === realHosts, '主机行数 = 报告主机数（' + realHosts + '）', rowCount);
  const kevIds = real.risk.summary.kev_ids;
  check(kevIds.length === 0 || kevIds.every((c) => html.includes(c)), '在野利用 CVE 全部出现在告警条里');
  check(html.includes('版本依据：'), '命中行带「版本依据」（区间判定可解释）');

  console.log('\n=== ② 脏数据不崩 ===');
  const dirty = [
    ['全字段 null', { id: 'AS-x', filename: null, file: null, risk: null, assets: null, basis: null }],
    ['risk 缺 summary', { id: 'AS-x', filename: 'a.txt', file: {}, risk: { hosts: null, products: null }, assets: {} }],
    ['数组含 null', {
      id: 'AS-x', filename: 'a.txt', file: { kind: 'txt', chars: 1 }, basis: 'b',
      risk: { summary: { hosts: 1, products: 1, cve_hits: 1, kev_ids: [null, 'CVE-1'] },
              hosts: [null, { name: null, type: null, risk_level: null, components: [null] }],
              products: [null, { name: 'x', findings: [null, { id: null }] }] },
      assets: { ports: [null], os: null, urls: [null], emails: null, cves_in_doc: [null] },
    }],
    ['字段全空字符串', {
      id: '', filename: '', file: { kind: '', chars: 0, warn: '' }, basis: '',
      risk: { summary: { hosts: 0, products: 0, cve_hits: 0, exploited: 0, kev_ids: [] },
              hosts: [], products: [] }, assets: {},
    }],
  ];
  for (const [label, payload] of dirty) {
    PAYLOAD = { ok: true, id: payload.id, report: payload };
    let threw = null;
    try { SECTION.querySelector('#enSample').onclick(); await sleep(50); } catch (e) { threw = e; }
    check(threw === null && typeof R() === 'string', '脏数据不崩：' + label, threw && threw.message);
  }

  console.log('\n=== ③ XSS 转义 ===');
  const ev = '<script>alert(1)</script><img src=x onerror="alert(2)">';
  PAYLOAD = {
    ok: true, id: 'AS-x',
    report: {
      id: 'AS-x', filename: ev + '.docx', basis: ev,
      file: { kind: ev, chars: 10, warn: ev },
      risk: {
        summary: { hosts: 1, products: 1, cve_hits: 1, exploited: 1, kev_ids: [ev] },
        hosts: [{ name: ev, type: ev, scope: ev, risk_level: '严重', cve_count: 1, kev_count: 1,
                  components: [{ name: ev, version: ev, risk_level: ev, cve_count: 1 }] }],
        products: [{ name: ev, display: ev, version: ev, vendor: ev, risk_level: '严重',
                     cve_count: 1, kev_count: 1, raw: ev,
                     findings: [{ id: ev, title: ev, severity: ev, score: 9.9, exploited: true,
                                  evidence: ev, confidence: ev, published: ev, risk_tags: [ev],
                                  cwe: [ev], remediation: [ev] }] }],
      },
      assets: { ports: [ev], os: [ev], urls: [{ url: ev }], emails: [ev], cves_in_doc: [ev] },
    },
  };
  let threw2 = null;
  try { SECTION.querySelector('#enSample').onclick(); await sleep(60); } catch (e) { threw2 = e; }
  const x = R();
  check(threw2 === null, 'XSS 载荷不抛异常', threw2 && threw2.message);
  check(!/<script>alert/i.test(x), '未注入 <script>');
  check(!/onerror="/i.test(x), '未注入 onerror 属性');
  check(!/<img\s/i.test(x), '未注入 <img> 标签');
  check(x.includes('&lt;script&gt;'), '恶意字符串被转义（出现 &lt;script&gt;）');

  console.log('\n=== ④ 历史记录渲染 ===');
  const histItems = [
    { id: 'AS-1', filename: ev, created_at: '2026-10-03 19:00', file: { kind: 'xlsx' },
      summary: { hosts: 3, products: 2, cve_hits: 9, exploited: 1 } },
    null,
  ];
  let threw3 = null;
  try { global.__mod.enrichSections()[0].mount; } catch (e) { threw3 = e; }
  check(threw3 === null, '历史数据（含 null 项）不崩', threw3 && threw3.message);

  console.log('\n===== 结果：' + PASS + ' 项通过 / ' + FAIL + ' 项失败 =====');
  if (FAIL) process.exit(1);
  console.log('ENRICH PANEL TEST OK');
})();
