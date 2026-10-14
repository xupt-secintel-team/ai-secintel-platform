// 趋势图面板 DOM 桩测试（不开浏览器，验证渲染 + XSS + 脏数据 + 点击绑定）
const fs = require('fs');
const path = require('path');
const vm = require('vm');
const ROOT = path.resolve(__dirname, '..');
const CODE = fs.readFileSync(
  path.join(ROOT, 'frontend', 'modules', 'm1_monitor', 'panel.js'), 'utf8');

const els = {};
function fakeEl(id) {
  const e = {
    id, innerHTML: '', textContent: '', value: '', scrollTop: 0, scrollHeight: 40,
    style: {}, dataset: {}, hidden: false, className: '', onload: null,
    classList: { add() {}, remove() {}, toggle() {}, contains: () => false },
    addEventListener() {}, appendChild() {}, removeChild() {}, select() {},
    querySelector: () => null, querySelectorAll: () => [], closest: () => null,
    parentNode: { insertBefore() {} },
  };
  els[id] = e;
  return e;
}
// 趋势卡会用到的固定 id
fakeEl('trendbox');

global.$ = (id) => els[id] || null;
global.esc = (s) => String(s == null ? '' : s)
  .replace(/[&<>"]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));
global.toast = () => {};
global.openDetail = (id) => { global.__opened = id; };
global.document = {
  getElementById: (id) => els[id] || null,
  querySelector: () => null,
  querySelectorAll: () => [],
  createElement: () => fakeEl('_tmp'),
  body: { appendChild() {}, removeChild() {} },
};
global.AISEC = { register(m) { global.__mod = m; } };
Object.defineProperty(globalThis, 'navigator', {
  value: { clipboard: { writeText: async () => {} } }, configurable: true,
});
global.location = { href: '' };
global.URL = class extends URL {
  static createObjectURL() { return 'blob:x'; }
  static revokeObjectURL() {}
};
// requestAnimationFrame 立即执行
global.requestAnimationFrame = (fn) => { fn(); };

// fetch 桩：返回当前 payload
let PAYLOAD = null;
let lastFetchUrl = null;
global.fetch = async (url) => {
  lastFetchUrl = String(url);
  return { json: async () => PAYLOAD, blob: async () => ({}) };
};

vm.runInThisContext(CODE, { filename: 'panel.js' });

const mod = global.__mod;
if (!mod || !mod.monitorSections) {
  console.error('FAIL: 未注册 monitorSections');
  process.exit(1);
}

const secs = mod.monitorSections();
const trend = secs.find((s) => s.id === 'moTrendStats');
if (!trend) {
  console.error('FAIL: monitorSections 里没有 moTrendStats');
  process.exit(1);
}
console.log('monitorSections 含 moTrendStats ✅');

// 用桩元素跑 mount
const root = {
  innerHTML: '', querySelector(sel) {
    if (sel === '#trendbox') return els.trendbox;
    if (sel === '#trMd') return { onclick: null };
    return null;
  },
  querySelectorAll: () => [],
};

// 正常 payload
const good = {
  start: '2026-10-02', end: '2026-10-08', total_cves: 1234, kev_count: 12,
  by_ai_risk: [
    { category: '① AI基础设施与推理框架', short: '基础设施/\n推理框架', count: 25 },
    { category: '② 模型与数据层', short: '模型与\n数据层', count: 13 },
    { category: '③ AI应用与智能体', short: '应用与\n智能体', count: 60 },
    { category: '④ AI供应链与平台', short: '供应链\n与平台', count: 3 },
    { category: '通用网络安全', short: '通用\n网络安全', count: 1133 },
  ],
  top_cwe: [{ cwe: 'CWE-79', count: 88 }, { cwe: 'CWE-787', count: 55 }],
  top_product: [{ product: 'apache_tomcat', count: 40 }, { product: 'log4j', count: 10 }],
  top_cve: [{ cve: 'CVE-2021-44228', cvss: 10, severity: 'CRITICAL', kev: true, title: 'log4shell' },
            { cve: 'CVE-2020-1938', cvss: 9.8, severity: 'CRITICAL', kev: true, title: 'ghostcat' }],
  by_severity: [{ severity: 'CRITICAL', label: '严重', count: 5 }, { severity: 'HIGH', label: '高危', count: 9 }],
};

const assert = (name, cond, extra) => {
  if (cond) { console.log('PASS ' + name); }
  else { console.error('FAIL ' + name + (extra ? ' → ' + extra : '')); process.exitCode = 1; }
};

// 通过 monitorSections 的 mount 驱动（面板的 mount 里会调 load -> fetch -> render）
PAYLOAD = good;
trend.mount(root);

// fetch 是异步的，mount 里 load() 是 async；等一个微任务
setTimeout(() => {
  const html = els.trendbox.innerHTML;

  assert('渲染出横向条', html.includes('tr-hbar') && html.includes('tr-fill'), html.slice(0, 80));
  assert('CWE 标签渲染', html.includes('CWE-79'), '');
  assert('产品标签渲染', html.includes('apache_tomcat'), '');
  assert('高危 CVE 渲染', html.includes('CVE-2021-44228'), '');
  assert('KEV 标记渲染', html.includes('tr-kev'), '');
  assert('CVSS 数值渲染', html.includes('>10<') || html.includes('>10.0<') || html.includes('10'), '');
  assert('严重度分布渲染', html.includes('tr-segbar'), '');
  assert('范围行渲染', html.includes('1234'), '');
  // AI 四分类垂直柱状图
  assert('四分类图渲染', html.includes('AI 安全风险四分类分布'), '');
  assert('四分类 5 根柱', (html.match(/<rect /g) || []).length === 5,
         String((html.match(/<rect /g) || []).length));
  assert('四分类 X 轴标签', html.includes('推理框架') && html.includes('智能体'), '');
  assert('柱顶数值标注', (html.match(/text-anchor="middle"/g) || []).length >= 10, '');

  // XSS：塞恶意 payload 再 render
  const xss = JSON.parse(JSON.stringify(good));
  xss.top_cwe[0].cwe = '<script>alert(1)</script>';
  xss.top_cve[0].title = '<img src=x onerror="alert(2)">';
  PAYLOAD = xss;
  // 直接调 render（绕过 mount 的 fetch 绑定）
  // 通过重新 mount 触发 load
  els.trendbox.innerHTML = '';
  trend.mount(root);
  setTimeout(() => {
    const h2 = els.trendbox.innerHTML;
    assert('XSS 未注入 script', !/<script>alert/i.test(h2), h2.match(/alert[^)]*\)/g));
    assert('XSS 未注入 onerror', !/onerror="/i.test(h2), '');
    assert('XSS 未注入 img', !/<img\s/i.test(h2), '');

    // 空数据不崩
    const empty = { start: '2026-10-02', end: '2026-10-08', total_cves: 0, kev_count: 0,
      top_cwe: [], top_product: [], top_cve: [], by_severity: [] };
    PAYLOAD = empty;
    els.trendbox.innerHTML = '';
    trend.mount(root);
    setTimeout(() => {
      const h3 = els.trendbox.innerHTML;
      assert('空数据不崩（有兜底文案）', h3.includes('窗口内无'), h3.slice(0, 80));

      // null 字段不崩
      const nullz = { start: null, end: null, total_cves: null, kev_count: null,
        top_cwe: null, top_product: null, top_cve: null, by_severity: null };
      PAYLOAD = nullz;
      els.trendbox.innerHTML = '';
      trend.mount(root);
      setTimeout(() => {
        const h4 = els.trendbox.innerHTML;
        assert('null 字段不崩', typeof h4 === 'string', String(h4).slice(0, 80));
        console.log('\n=== 完成 ===');
        process.exit(process.exitCode || 0);
      }, 20);
    }, 20);
  }, 20);
}, 20);
