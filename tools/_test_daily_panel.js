/* _test_daily_panel.js —— m1_monitor「每日按类报告」面板 DOM 桩测试（不开浏览器）
 *
 * 为什么需要它：日报面板是**唯一**把"今天查出了什么、按哪类风险分"直接
 * 呈现给评审的地方。渲染错了不会报错 —— 用户只会以为"系统就是这么分的"。
 * 2026-10-06 实测/预判的真问题：
 *   ① severity 直接拼 class → 语料里塞 <img onerror> 就是 XSS
 *      （m2_enrich 已踩过同一个坑，日报又拼一次，必须钉死）
 *   ② 标题/来源/链接全是外部数据 → 不转义就破版 + XSS
 *   ③ 日期缺失 / 报告为空 / 已过期 三种状态不能都渲染成"没有数据"
 *   ④ 下载必须带对 date 与 fmt，且不能拿 fetch+blob（会占内存、丢文件名）
 *   ⑤ 改了 modules/ 下的源必须同步到 frontend/，否则浏览器跑旧代码
 *
 * 用法： node tools/_test_daily_panel.js
 */
const fs = require('fs');
const path = require('path');
const vm = require('vm');

const ROOT = path.dirname(__dirname);
const SRC = path.join(ROOT, 'modules', 'm1_monitor', 'web', 'daily.js');
const CSS = path.join(ROOT, 'modules', 'm1_monitor', 'web', 'daily.css');
const BUILT_JS = path.join(ROOT, 'frontend', 'modules', 'm1_monitor', 'daily.js');
const BUILT_CSS = path.join(ROOT, 'frontend', 'modules', 'm1_monitor', 'daily.css');
const APP = path.join(ROOT, 'frontend', 'app.js');
const MANIFEST = path.join(ROOT, 'modules', 'm1_monitor', 'module.json');
const CODE = fs.readFileSync(SRC, 'utf8');

let PASS = 0, FAIL = 0;
function check(cond, label, extra) {
  if (cond) { PASS++; console.log('  [PASS] ' + label); }
  else { FAIL++; console.log('  [FAIL] ' + label + (extra !== undefined ? '  → ' + extra : '')); }
}
function section(t) { console.log('\n=== ' + t + ' ==='); }

/* ---------------- DOM / 全局桩 ---------------- */
function fakeEl(tag) {
  return {
    tagName: (tag || 'div').toUpperCase(),
    innerHTML: '', textContent: '', value: '', href: '', download: '',
    style: {}, dataset: {}, children: [], attrs: {},
    classList: {
      _s: new Set(),
      add(c) { this._s.add(c); }, remove(c) { this._s.delete(c); },
      toggle(c) { this._s.has(c) ? this._s.delete(c) : this._s.add(c); },
      contains(c) { return this._s.has(c); },
    },
    addEventListener() {}, appendChild(c) { this.children.push(c); },
    removeChild() {}, remove() {}, insertBefore() {}, click() { this._clicked = true; },
    querySelector() { return null; }, querySelectorAll() { return []; },
    closest() { return null; }, focus() {}, scrollIntoView() {},
  };
}
global.$ = () => null;
global.esc = (s) => String(s == null ? '' : s)
  .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
global.document = {
  getElementById: () => null, querySelector: () => null, querySelectorAll: () => [],
  createElement: () => fakeEl(), body: fakeEl('body'), addEventListener() {},
};
global.window = { addEventListener() {} };
global.fetch = () => Promise.reject(new Error('no net in test'));
const TOASTS = [];
global.toast = (m) => TOASTS.push(String(m));
global.__mod = null;
global.AISEC = { register(m) { global.__mod = m; } };

vm.runInThisContext(CODE, { filename: 'm1_daily.js' });

const M = global.window.M1Daily;
const mod = global.__mod;

section('① 契约：模块通过 monitorSections 贡献，不改主体契约');
check(!!mod && mod.id === 'm1_daily', 'register 了 m1_daily 模块', mod && mod.id);
check(typeof mod.monitorSections === 'function', '实现了 monitorSections 钩子');
const secs = mod.monitorSections ? mod.monitorSections() : [];
check(Array.isArray(secs) && secs.length === 1, '贡献 1 个区块', JSON.stringify(secs.length));
check(secs[0] && secs[0].id === 'moDailyReport', '区块 id 固定', secs[0] && secs[0].id);
check(secs[0] && typeof secs[0].html === 'string' && secs[0].html.length > 200,
  '区块带骨架 HTML', secs[0] && secs[0].html.length);
check(secs[0] && typeof secs[0].mount === 'function', '区块带 mount 回调');

const appSrc = fs.readFileSync(APP, 'utf8');
check(/AISEC\.collect\('monitorSections'\)/.test(appSrc), '主体 app.js 消费 monitorSections');
check(/enrichSections|sideSections/.test(appSrc), '主体既有契约未被破坏（仍在）');
check(!/id,\s*init,\s*sideSections[^}]*monitorSections/.test(appSrc),
  '文件头声明的契约清单未被改动（只做扩展）');

section('② 骨架：下载/生成/日期控件齐全');
const H = M.HTML;
['moDayPick', 'moDayGen', 'moDayDl', 'moDayXl', 'moDayJs', 'moDayBody'].forEach((id) => {
  check(H.indexOf(id) >= 0, '骨架含 #' + id);
});
check(/保留一个月/.test(H), '界面明示保留期');
check(/MD/.test(H) && /XLSX/.test(H) && /JSON/.test(H), '三种下载格式都有按钮');

section('③ XSS / 转义（外部数据一律不可信）');
const XSS = '<img src=x onerror=alert(1)>';
const days = {
  today: '2026-10-06', retention_days: 30, expired_days: [],
  stats: { files: 3, total_mb: 0.08 },
  days: [{ date: '2026-10-06', total: 2, category_count: 1, kev: 1,
    by_sev: { critical: 1, high: 0, info: 1 },
    categories: [{ key: '③ AI应用与智能体', label: '应用智能体', count: 2, critical: 1, high: 0, info: 1 }] }],
};
let listHtml = M.renderDays(days);
check(listHtml.indexOf('<img src=x') < 0, '日期列表转义了 HTML');
check(!/<\/?(img|svg|script|iframe)/i.test(listHtml), '日期列表里没有注入的标签');

const detail = {
  date: '2026-10-06', generated_at: '2026-10-06T21:24:01', total: 2,
  category_count: 1, kev: 1, poc: 0, by_sev: { critical: 1, high: 0, medium: 0, low: 0, info: 1 },
  categories: [{
    key: '③ AI应用与智能体', full: '③ AI应用与智能体', label: '应用智能体',
    desc: '<b>desc</b>', color: '#36b37e', count: 1, truncated: 0,
    by_sev: { critical: 1, high: 0, medium: 0, low: 0, info: 0 },
    items: [{
      title: XSS, severity: XSS, severity_label: '', cvss: 9.8, has_cvss: true,
      kev: true, poc: true, source: XSS, published: '2026-10-06',
      link: 'javascript:alert(1)', risk_tags: [XSS],
    }],
  }],
};
let dHtml = M.renderDetail(detail);
check(dHtml.indexOf('<img src=x') < 0, '标题里的 HTML 被转义');
/* 判据：输出里出现的**所有标签名**必须都来自面板自己的模板白名单。
   外部数据经 esc 后 '<' 全变成 '&lt;'，所以这个检查能真实抓到"转义失效"。
   （不要把转义还原再找标签 —— 还原后必然又匹配上，等于自证失败。） */
const TAGS = (dHtml.match(/<\/?([a-zA-Z][a-zA-Z0-9]*)/g) || [])
  .map((t) => t.replace(/^<\/?/, '').toLowerCase());
const ALLOWED = new Set(['div', 'span', 'a', 'b', 'i', 'em', 'strong', 'br']);
const BAD_TAGS = TAGS.filter((t) => !ALLOWED.has(t));
check(BAD_TAGS.length === 0, '输出里只有面板自己的标签', JSON.stringify([...new Set(BAD_TAGS)]));
/* 注意：不能笼统查 "on*=" —— 面板自己的模板就有 onclick（分类折叠靠它）。
   主判据是上面的 TAGS 白名单：外部数据经 esc 后 '<' 全成 '&lt;'，
   根本无法形成标签，所以不存在可执行属性。 */
check((dHtml.match(/&lt;img/g) || []).length > 0,
  '恶意标题确实以转义文本形式落在页面里（说明检查的是真实渲染结果）');
check((TAGS.filter((t) => t === 'img' || t === 'svg')).length === 0,
  '恶意标题没有变成任何真实元素');
check(dHtml.indexOf('&lt;img') >= 0, '原始 HTML 以转义形态存在（说明确实渲染了这段文本）');
check(dHtml.indexOf('javascript:alert') < 0, 'javascript: 链接被白名单拦下');
check(!/href="javascript:/i.test(dHtml), 'href 里没有 javascript: 伪协议');
check(dHtml.indexOf('原文') < 0, '危险链接那条不渲染"原文"入口（而不是渲染一个点了就中招的链接）');
check(dHtml.indexOf('<b>desc</b>') < 0, '分类说明被转义');
check(dHtml.indexOf('&lt;b&gt;desc') >= 0, '分类说明以转义形态渲染');

/* 正向：正常 https 链接必须还能用（别为堵 XSS 把功能也堵了） */
const goodLink = JSON.parse(JSON.stringify(detail));
goodLink.categories[0].items[0].link = 'https://nvd.nist.gov/vuln/detail/CVE-2026-1';
const gHtml = M.renderDetail(goodLink);
check(/href="https:\/\/nvd\.nist\.gov/.test(gHtml), '正常 https 链接照常渲染');
check(/rel="noopener noreferrer"/.test(gHtml), '外链带 noopener（防 tabnabbing）');
check(/sev-/.test(dHtml), '严重度进了样式类（经白名单映射）');
check(dHtml.indexOf('"crit"') >= 0 || dHtml.indexOf('crit"') >= 0,
  '未知 severity 落到安全的 crit/info 类', dHtml.slice(0, 0));

const weird = Object.assign({}, detail, {
  categories: [{ key: null, full: null, label: null, desc: null, color: null, count: 1,
    by_sev: null, truncated: null, items: [{}] }],
});
let wHtml = '';
try { wHtml = M.renderDetail(weird); } catch (e) { wHtml = 'THROW:' + e.message; }
check(wHtml.indexOf('THROW') < 0, '分类/条目字段全为 null 不崩', wHtml.slice(0, 60));

section('④ 三种空状态要分得开（不能都显示"没有数据"）');
check(M.renderDetail(null).indexOf('THROW') < 0, 'renderDetail(null) 不崩');
const expired = Object.assign({}, detail, { empty_reason: 'expired', total: 0, categories: [] });
check(/保留期/.test(M.renderDetail(expired)), '已过期 → 提示超出保留期');
check(M.renderDetail(expired).indexOf('没有采到') < 0, '已过期不被误报成"没采到数据"');
const noData = Object.assign({}, detail, { total: 0, categories: [] });
check(/没有采到/.test(M.renderDetail(noData)), '当天无数据 → 明确说无数据');
const truncated = JSON.parse(JSON.stringify(detail));
truncated.categories[0].truncated = 12;
check(/另 12 条未展开/.test(M.renderDetail(truncated)), '截断条数有提示（不会让人以为只有这些）');

section('⑤ 分类口径：AI 四分类必须都在前端可见');
const AI4 = ['① AI基础设施与推理框架', '② 模型与数据层', '③ AI应用与智能体', '④ AI供应链与平台'];
const allCats = {
  date: '2026-10-06', total: 4, category_count: 4, by_sev: {}, kev: 0, poc: 0,
  categories: AI4.map((k, i) => ({
    key: k, full: k, label: k.slice(2), desc: '', color: '#4d7cfe', count: 1,
    by_sev: { critical: 0, high: 0, medium: 0, low: 0, info: 1 },
    items: [{ title: 'x' + i, severity: 'info', has_cvss: false, risk_tags: [] }],
  })),
};
const aHtml = M.renderDetail(allCats);
AI4.forEach((k) => check(aHtml.indexOf(k) >= 0, '前端能显示分类「' + k + '」'));
check((aHtml.match(/mo-cat/g) || []).length >= 4, '四个分类各自成块');

section('⑥ 下载：用 a[download]，带对 date 与 fmt');
const clicks = [];
const origCreate = global.document.createElement;
global.document.createElement = (t) => {
  const el = fakeEl(t);
  el.click = function () { clicks.push({ href: this.href, download: this.download }); };
  return el;
};
M.state.day = '2026-09-22';
M.state.canDownload = true;          // 后端说这天有报告
M.state.emptyReason = '';
M.download('md');
M.download('xlsx');
M.download('json');
global.document.createElement = origCreate;
check(clicks.length === 3, '点了 3 次就建 3 个下载链接', clicks.length);
check(clicks[0].href.indexOf('date=2026-09-22') >= 0, '下载带上了日期', clicks[0].href);
check(clicks[0].href.indexOf('fmt=md') >= 0, 'MD 下载带 fmt=md', clicks[0].href);
check(clicks[1].href.indexOf('fmt=xlsx') >= 0, 'XLSX 下载带 fmt=xlsx', clicks[1].href);
check(clicks[2].href.indexOf('fmt=json') >= 0, 'JSON 下载带 fmt=json', clicks[2].href);
check(clicks.every((c) => c.href.indexOf('/api/daily_report?') === 0), '都指向日报接口');
TOASTS.length = 0;
M.state.day = null;
M.download('md');
check(TOASTS.length === 1 && /先选一个日期/.test(TOASTS[0]), '没选日期时拒绝下载并提示');

/* 后端对"没有报告的日期"返回 404。而 <a href> 是导航不是 fetch，
   404 时浏览器会跳过去显示那段 JSON —— 用户既离了页也看不懂。
   所以前端必须先判断 canDownload，不能把 404 交给浏览器。 */
section('⑥b 无报告日期：不发请求，直接提示（否则会导航到 404 JSON）');
const before = clicks.length;
TOASTS.length = 0;
M.state.day = '1999-01-01';
M.state.canDownload = false;
M.state.emptyReason = 'no_data';
M.download('md');
check(clicks.length === before, '没有报告的日期不发起下载（一个链接都没建）', clicks.length - before);
check(TOASTS.length === 1 && /没有可下载的报告/.test(TOASTS[0]), '提示"没有可下载的报告"', TOASTS[0]);
TOASTS.length = 0;
M.state.emptyReason = 'expired';
M.download('xlsx');
check(clicks.length === before, '过期日期同样不发起下载');
check(TOASTS.length === 1 && /保留期/.test(TOASTS[0]), '过期时明确说"已超保留期"', TOASTS[0]);

M.state.day = '2026-09-22';
M.state.canDownload = true;
M.state.emptyReason = '';

section('⑦ 严重度白名单（severity 直接进 class，必须映射过）');
[['critical', 'crit'], ['high', 'high'], ['medium', 'med'], ['low', 'low'],
 ['info', 'info'], ['CRITICAL', 'crit'], ['High', 'high'], ['  medium  ', 'med'],
 ['', 'info'], [null, 'info'], [undefined, 'info'],
 ['<svg onload=1>', 'info'], ['__proto__', 'info'], ['constructor', 'info'],
 ['toString', 'info'], ['hasOwnProperty', 'info']].forEach(([inp, want]) => {
  const t = JSON.parse(JSON.stringify(detail));
  t.categories[0].items[0].severity = inp;
  const h = M.renderDetail(t);
  const m = h.match(/badge (\w+)"/);
  check(m && m[1] === want, 'severity ' + JSON.stringify(inp) + ' → ' + want,
    m && m[1]);
});

section('⑦b 分类颜色白名单（color 会进 style 属性）');
['red;background:url(//evil)', 'expression(1)', 'javascript:1', '', null, '#36b37e']
  .forEach((c) => {
    const t = JSON.parse(JSON.stringify(detail));
    t.categories[0].color = c;
    let h = '';
    try { h = M.renderDetail(t); } catch (e) { h = 'THROW'; }
    check(h.indexOf('THROW') < 0 && !/style="background:[^"]*url\(/.test(h)
      && !/style="background:[^"]*expression/.test(h),
      'color ' + JSON.stringify(c) + ' 被拦或安全渲染');
  });

section('⑧ 产物同步 + manifest 声明');
const man = JSON.parse(fs.readFileSync(MANIFEST, 'utf8'));
check(man.web.indexOf('web/daily.js') >= 0, 'module.json 声明了 web/daily.js');
check(man.web.indexOf('web/daily.css') >= 0, 'module.json 声明了 web/daily.css');
check(fs.existsSync(BUILT_JS), 'frontend/modules/m1_monitor/daily.js 存在');
check(fs.existsSync(BUILT_CSS), 'frontend/modules/m1_monitor/daily.css 存在');
if (fs.existsSync(BUILT_JS)) {
  // 产物比源多 banner 注释，不能比字节相等 → 查关键标记都在
  const b = fs.readFileSync(BUILT_JS, 'utf8');
  check(b.indexOf('monitorSections') >= 0, '产物含 monitorSections');
  check(b.indexOf('自动生成') >= 0, '产物带自动生成 banner（确认是同步来的）');
  check(b.length >= CODE.length, '产物不短于源');
}
if (fs.existsSync(BUILT_CSS)) {
  const bc = fs.readFileSync(BUILT_CSS, 'utf8');
  check(bc.indexOf('--accent') >= 0 || bc.indexOf('var(--') >= 0, '样式走 CSS 变量（亮/暗主题自适应）');
  /* 判据必须剥注释：注释里常写 #fff / #0a0b0c 做举例说明，
     不剥会把注释当违规（第一版踩过，白排查一轮）。 */
  const bcCode = bc.replace(/\/\*[\s\S]*?\*\//g, '');
  const hard = ['#0a0b0c', '#fff', '#000'].filter((h) =>
    new RegExp('(^|[^\\w-])' + h + '(?![\\w-])', 'i').test(bcCode));
  check(hard.length === 0, '样式里没写死颜色', JSON.stringify(hard));
}

section('⑨ 样式覆盖了实际用到的类名（防止改了 JS 忘了改 CSS）');
const css = fs.readFileSync(CSS, 'utf8');
['mo-sec', 'mo-daily', 'mo-daybtn', 'mo-sum', 'mo-cat', 'mo-item',
 'mo-daylist', 'mo-split', 'mo-tog', 'mo-dot', 'mo-daychips'].forEach((c) => {
  check(css.indexOf('.' + c) >= 0, 'CSS 定义了 .' + c);
});

console.log('\n结果：通过 ' + PASS + ' / 失败 ' + FAIL);
process.exit(FAIL === 0 ? 0 : 1);