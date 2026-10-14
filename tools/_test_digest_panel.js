/* _test_digest_panel.js —— 四模块每日报告区块（core/daily_digest → /api/daily_digest）
 *
 * 为什么单独一个文件：这个区块和上面的 m1 按类日报是**两套不同的引擎**
 * （daily_digest.py vs daily_report.py），数据源、下载语义、失败模式全不同。
 * 混在一个文件里会让"哪个接口对应哪段代码"变得不清楚。
 *
 * 重点验的真实风险：
 *   ① headline / metrics 全部来自外部落盘数据 → 必须转义（同日报面板的 XSS 坑）
 *   ② 没有 md 文件时 MD 按钮必须 disabled —— 否则点了就是 404 导航
 *   ③ 「立即生成」在"该日无产出"时**不能**谎报成功（后端刻意不造空报告）
 *   ④ 通知已读要带 ids，不能把全部标了
 *   ⑤ 改了 modules/ 下的源必须同步到 frontend/，否则浏览器跑旧代码
 *
 * 用法： node tools/_test_digest_panel.js
 */
const fs = require('fs');
const path = require('path');
const vm = require('vm');

const ROOT = path.dirname(__dirname);
const SRC = path.join(ROOT, 'modules', 'm1_monitor', 'web', 'daily.js');
const CSS = path.join(ROOT, 'modules', 'm1_monitor', 'web', 'daily.css');
const BUILT_JS = path.join(ROOT, 'frontend', 'modules', 'm1_monitor', 'daily.js');
const BUILT_CSS = path.join(ROOT, 'frontend', 'modules', 'm1_monitor', 'daily.css');
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

/* fetch 桩：按 URL 返回预设响应，并记录所有请求 */
const CALLS = [];
let ROUTES = {};
global.fetch = (url, opt) => {
  const u = String(url);
  CALLS.push({ url: u, opt: opt || null });
  const key = Object.keys(ROUTES).find((k) => u.indexOf(k) >= 0);
  if (!key) return Promise.reject(new Error('no route: ' + u));
  const v = ROUTES[key];
  const val = (typeof v === 'function') ? v(u, opt) : v;
  return Promise.resolve({ json: () => Promise.resolve(val) });
};
const TOASTS = [];
global.toast = (m) => TOASTS.push(String(m));
global.openDetail = () => {};
global.__mod = null;
global.AISEC = { register(m) { global.__mod = m; } };
/* TR 桩：验证「译」开着时会调 applyView，但不能用 window.TR（恒 undefined） */
let TR_CALLS = 0;
global.TR = { on: true, applyView: (v) => { TR_CALLS++; } };

vm.runInThisContext(CODE, { filename: 'm1_daily.js' });
const M = global.window.M1Daily;

/* ---------------- 构造数据 ---------------- */
/* 2026-10-07 起 list_all 只返回方向（模块台账已去掉）——
   mock 与后端契约保持一致：没有 modules 元信息，grid 里只有方向格。 */
const XSS = '<img src=x onerror=alert(1)>';
const LIST = {
  days: ['2026-10-07', '2026-10-06'],
  retention_days: 30,
  daily_at: '23:30',
  directions: [
    { id: 'dir_infra', name: '① AI基础设施/推理框架风险', desc: 'Ollama、vLLM、Triton 等框架漏洞', color: '#7c5cff' },
    { id: 'dir_model', name: '② 模型与数据层风险', desc: '提示词注入、数据投毒等', color: '#00b8d9' },
    { id: 'dir_appagent', name: '③ AI应用与智能体风险', desc: 'Agent 与应用风险', color: '#36b37e' },
    { id: 'dir_supply', name: '④ 供应链风险', desc: '模型仓库与依赖链', color: '#ffab00' },
  ],
  missing: ['2026-10-03', '2026-10-02'],
  grid: [
    {
      date: '2026-10-07',
      modules: {
        dir_infra: {
          module: 'dir_infra', kind: 'direction',
          module_name: '① AI基础设施/推理框架风险', color: '#7c5cff',
          headline: '当日该方向新增 37 条：严重 0、高危 0。',
          has_md: true, empty_reason: '',
          metrics: [{ k: '当日条目', v: '37 条' }, { k: '严重 / 高危', v: '0 / 0' },
            { k: 'K', v: XSS }],
        },
        dir_model: {
          module: 'dir_model', kind: 'direction',
          module_name: '② 模型与数据层风险', color: '#00b8d9',
          headline: '当日该方向新增 96 条。', has_md: true, empty_reason: '',
          metrics: [{ k: '当日条目', v: '96 条' }],
        },
        dir_appagent: {
          module: 'dir_appagent', kind: 'direction',
          module_name: '③ AI应用与智能体风险', color: '#36b37e',
          headline: '当日该方向新增 289 条。', has_md: true, empty_reason: '',
          metrics: [{ k: '当日条目', v: '289 条' }],
        },
        dir_supply: {
          module: 'dir_supply', kind: 'direction',
          module_name: '④ 供应链风险',
          color: 'not-a-color',                       // ★ 故意坏色值：进 style 前必须被拦
          headline: '当日该方向无新增情报。', has_md: false, empty_reason: 'no_data',
          metrics: [{ k: '当日条目', v: '0 条' }],
        },
      },
    },
    { date: '2026-10-06', modules: {} },              // 老日期没有方向报告
  ],
};
const NOTES = {
  unread: 2,
  items: [
    { id: 'n1', read: false, ts: '2026-10-07T23:31:02',
      title: '2026-10-07 每日报告已生成（4 份）',
      modules: [{ module: 'dir_infra', module_name: '① AI基础设施/推理框架风险' }] },
    { id: 'n2', read: true, ts: '2026-10-06T23:31:00', title: '已读的老通知', modules: [] },
  ],
};

/* ================= ① 契约 ================= */
section('① 契约：仍走 monitorSections，不改主体契约');
check(!!global.__mod && global.__mod.id === 'm1_daily', '模块 id 不变');
const secs = global.__mod.monitorSections();
check(secs.length === 1 && secs[0].id === 'moDailyReport', '区块 id 不变');
check(secs[0].html.indexOf('moDigest') >= 0, '骨架里有四模块日报容器 #moDigest');
check(M.dst && typeof M.dst === 'object', '四模块状态独立挂在 dst 上（不污染 state）');
check(M.state && !M.state.modules, '没往 m1 日报状态里塞四模块字段');

/* ================= ② 渲染 ================= */
section('② 渲染：四张方向卡 + 头部信息（模块台账已去掉）');
M.dst.list = LIST;
M.dst.day = '2026-10-07';
M.dst.notes = NOTES;
M.dst.unread = 2;
const H = M.renderDigest();
check(H.indexOf('每日报告 · AI 安全四方向') >= 0, '有区块标题（四方向主视图）');
['m1_monitor', 'm0_ops', 'm2_enrich', 'm3_qa'].forEach((id) => {
  check(H.indexOf('data-mod="' + id + '"') < 0, '模块卡 ' + id + ' 已从页面移除（用户要求）');
});
check(H.indexOf('moDgCatch') < 0, '「补齐缺失」按钮已去掉（方向报告不进自动补全清单）');
check(H.indexOf('23:30') >= 0, '显示每天自动生成时刻');
check(H.indexOf('30') >= 0, '显示保留天数');
check(H.indexOf('moDgDay') >= 0, '有日期下拉');
check(H.indexOf('moDgGen') >= 0, '有「立即生成」');
check(H.indexOf('moDgNote') >= 0, '有通知按钮');
check(H.indexOf('通知 2') >= 0, '通知按钮显示未读数');
check(H.indexOf('mo-dg-notes') >= 0, '渲染了未读通知条');
check(H.indexOf('2026-10-07 每日报告已生成') >= 0, '通知标题正确');
check(H.indexOf('已读的老通知') < 0, '已读通知不显示在未读条里');
check(H.indexOf('还缺 2 天') < 0, '缺失提示条已去掉（补齐按钮不存在了）');

/* ================= ②b 四方向主卡 ================= */
section('②b 四方向主卡：唯一内容，带分类色条');
['dir_infra', 'dir_model', 'dir_appagent', 'dir_supply'].forEach((id) => {
  check(H.indexOf('data-mod="' + id + '"') >= 0, '方向卡 ' + id + ' 渲染了');
});
check(H.indexOf('① AI基础设施/推理框架风险') >= 0, '方向卡用用户指定的四方向命名');
check(H.indexOf('border-left:3px solid #7c5cff') >= 0, '方向卡带分类色条（合法色值才进 style）');
check(H.indexOf('border-left:3px solid not-a-color') < 0,
  '坏色值进不了 style（#rrggbb 白名单拦下，不会注入任意样式）');
check(H.indexOf('moDgModsTgl') < 0 && H.indexOf('mo-dg-mods-tgl') < 0,
  '模块台账折叠按钮已彻底移除');
check(H.indexOf('共 4 / 4 个方向有报告') >= 0, '日期行报方向数');
/* 方向卡下载按钮也要常驻 */
['dir_infra', 'dir_supply'].forEach((id) => {
  const seg = (H.split('data-mod="' + id + '"')[1] || '').split('data-mod="')[0];
  check(seg.indexOf('data-dl=') >= 0, id + ' 方向卡常驻下载按钮');
});

/* ================= ③ XSS ================= */
section('③ XSS：headline / metrics 全部来自落盘数据，必须转义');
check(H.indexOf('<img src=x') < 0, '注入的标签被转义');
const TAGS = (H.match(/<\/?([a-zA-Z][a-zA-Z0-9]*)/g) || [])
  .map((t) => t.replace(/^<\/?/, '').toLowerCase());
const ALLOWED = new Set(['div', 'span', 'b', 'em', 'p', 'h4', 'button',
  'select', 'option', 'i', 'strong']);
const bad = [...new Set(TAGS)].filter((t) => !ALLOWED.has(t));
check(bad.length === 0, '输出里只出现白名单标签', JSON.stringify(bad));
check(H.indexOf('onerror=alert') >= 0 && H.indexOf('&lt;img') >= 0,
  '原始文本仍在（只是被转义，不是被吞掉）');

/* ================= ④ 下载按钮必须常驻（回归：曾藏在展开区里） ================= */
section('④ 下载：无 md 时按钮禁用，且**折叠态也要看得见**');
M.dst.open = {};                                // 全部折叠
const Hc = M.renderDigest();
check(Hc.indexOf('data-dl="md"') >= 0, '折叠状态下 MD 按钮就存在（不是展开才有）');
check(Hc.indexOf('data-dl="json"') >= 0, '折叠状态下 JSON 按钮就存在');
/* 逐张卡片验证：data-mod 段内必须有下载按钮 */
['dir_infra', 'dir_model', 'dir_appagent', 'dir_supply'].forEach((id) => {
  const seg = (Hc.split('data-mod="' + id + '"')[1] || '').split('data-mod="')[0];
  check(seg.indexOf('data-dl=') >= 0, id + ' 折叠态卡片里就有下载按钮');
});
check(Hc.indexOf('mo-dg-hint') >= 0, '卡片上标了「点此展开」提示');
/* 关键回归：下载按钮不能被包在 open 才渲染的容器里 */
const cardTpl = CODE.slice(CODE.indexOf('function dgCard'));
check(/const dls = `[\s\S]*?data-dl="md"/.test(cardTpl),
  '下载区是独立变量（不嵌在 open 条件里）');
check(!/const body = open \? `[\s\S]*?data-dl=/.test(cardTpl),
  '展开区里不含下载按钮（否则又藏回去了）');

M.dst.open['dir_supply'] = true;                // 展开无 md 的那张
const H2 = M.renderDigest();
const seg2 = (H2.split('data-mod="dir_supply"')[1] || '').split('data-mod="')[0];
const seg1 = (H2.split('data-mod="dir_infra"')[1] || '').split('data-mod="')[0];
check(/data-dl="md"[^>]*disabled/.test(seg2), 'dir_supply（has_md=false）的 MD 按钮 disabled');
check(seg2.indexOf('没有落盘的 md 文件') >= 0, '禁用原因写进了 title');
check(!/data-dl="md"[^>]*disabled/.test(seg1), 'dir_infra（has_md=true）的 MD 可用');

section('④b 打包下载（ZIP）');
check(Hc.indexOf('moDgZip') >= 0, '有打包下载按钮');
check(Hc.indexOf('打包下载当天全部 4 份') >= 0, '按钮写明了份数（四方向）');
/* ★ grid.modules 是**字典**不是数组。踩过：用 `(grid.modules||{}).length`
   永远是 undefined → `dirGot > 1` 恒 false → ZIP 条永远不渲染。
   现按方向元信息数组逐个取格，且只数值真存在的格子。 */
check(/[^.\w]grid\.modules\s*\|\|\s*\{\}\s*\)\.length/.test(CODE) === false,
  '没用 grid.modules.length（字典没有 length，会导致 ZIP 条永不出现）');
check(CODE.indexOf('.filter((d) => cells[d.id]).length') >= 0,
  '方向计数只数真实存在的格子（跳过后端异常留下的 null 格）');
check(Hc.indexOf('mo-dg-daytag') >= 0 && Hc.indexOf('2026-10-07') >= 0,
  '有日期行，看得出在看哪天');
check(Hc.indexOf('共 4 / 4 个方向有报告') >= 0, '日期行说明当天有几份');
section('④c 只有一份时不显示打包按钮（与后端 404 判据一致）');
M.dst.day = '2026-10-06';
const H1only = M.renderDigest();
check(H1only.indexOf('moDgZip') < 0, '没有方向报告时不显示打包按钮');
check(H1only.indexOf('该日无报告') >= 0, '缺报告的方向明说"该日无报告"');
check(H1only.indexOf('共 0 / 4 个方向有报告') >= 0, '计数相应变成 0');
M.dst.day = '2026-10-07';

section('④d 方向当天无产出：如实显示，但不假装能下载');
M.dst.list = JSON.parse(JSON.stringify(LIST));
M.dst.list.grid[0].modules.dir_supply.empty_reason = 'no_data';
M.dst.list.grid[0].modules.dir_supply.headline = '当日该方向无新增情报。';
const Hz = M.renderDigest();
check(Hz.indexOf('该方向无新增情报') >= 0, '无产出方向的结论照实显示');
const segz = (Hz.split('data-mod="dir_supply"')[1] || '').split('data-mod="')[0];
check(segz.indexOf('data-dl="json"') >= 0, '无产出方向仍可下 JSON（记录本身存在）');
check(Hz.indexOf('共 4 / 4 个方向有报告') >= 0,
  '计数按"有报告文件"算，不按"有数据"算（无产出也是一份报告）');
/* 完全没有报告的方向：必须明说"该日无报告"，且不能摆一个能点的下载按钮 */
M.dst.list.grid[0].modules.dir_supply = undefined;
const Hnone = M.renderDigest();
check(Hnone.indexOf('该日无报告') >= 0, '缺报告的方向明说"该日无报告"');
check(Hnone.indexOf('无可下载文件') >= 0, '并明确标注无可下载文件');
check(Hnone.indexOf('共 3 / 4 个方向有报告') >= 0, '计数相应变成 3');
M.dst.list = LIST;

/* ================= ⑤ 无产出不谎报 ================= */
section('⑤ 生成：后端不造空报告，前端也不能谎报成功');
ROUTES['/api/daily_digest/generate'] = {
  date: '2026-10-07', generated: [], reports: [],
};
ROUTES['/api/daily_digest?'] = LIST;
ROUTES['/api/daily_digest/notifications'] = NOTES;
CALLS.length = 0;
(async () => {
  await M.dgGenerate({ querySelector: () => null });
  check(CALLS.some((c) => c.url.indexOf('/generate') >= 0), '确实发了 generate 请求');
  check(TOASTS.some((t) => t.indexOf('未生成报告') >= 0),
    'generated 为空时如实说"未生成报告"', JSON.stringify(TOASTS));
  check(!TOASTS.some((t) => t.indexOf('已生成 0 份') >= 0), '不会谎报"已生成 0 份"');

  /* 生成成功时提示份数与日期（生成范围 = 四方向） */
  TOASTS.length = 0;
  ROUTES['/api/daily_digest/generate'] = {
    date: '2026-10-07',
    generated: ['dir_infra', 'dir_model', 'dir_appagent', 'dir_supply'],
    reports: [],
  };
  M.dst.list = LIST;
  await M.dgGenerate({ querySelector: () => null });
  check(TOASTS.some((t) => t.indexOf('已生成 4 份方向报告') >= 0
    && t.indexOf('2026-10-07') >= 0),
    '成功提示份数与日期（四方向报告）', JSON.stringify(TOASTS));
  TOASTS.length = 0;
  ROUTES['/api/daily_digest/generate'] = {
    date: '2026-10-07', generated: ['dir_infra'], reports: [],
  };
  M.dst.list = LIST;
  await M.dgGenerate({ querySelector: () => null });
  check(TOASTS.some((t) => t.indexOf('已生成 1 份方向报告') >= 0),
    '部分方向生成时也如实报份数', JSON.stringify(TOASTS));

  /* ================= ⑦ 翻译钩子 ================= */
  section('⑦ 「译」开着时本区块也被翻（TR 是顶层 const，不能用 window.TR）');
  TR_CALLS = 0;
  const root = {
    querySelector(sel) {
      if (sel === '#moDigest') {
        const el = fakeEl();
        el.innerHTML = H2;
        return el;
      }
      return null;
    },
    querySelectorAll() { return []; },
  };
  M.dst.list = LIST; M.dst.day = '2026-10-07';
  // 直接调 paintDigest 不可导出时用 renderDigest 兜底验证：这里验证源码里的钩子
  check(CODE.indexOf("TR.applyView('每日报告')") >= 0, '源码里有每日报告的翻译钩子');
  check(CODE.indexOf("typeof TR !== 'undefined'") >= 0, '用 typeof 判 TR（window.TR 恒 undefined）');
  /* 判据：剥掉注释与字符串字面量后再查。源码注释里**故意**写了
     "window.TR 永远是 undefined" 这句话来说明这个坑，正则会误报。 */
  const codeNoComment = CODE
    .replace(/\/\*[\s\S]*?\*\//g, '')
    .replace(/(^|[^:])\/\/.*$/gm, '$1');
  check(!/window\s*\.\s*TR\b/.test(codeNoComment), '代码里没用 window.TR（只看代码，不看注释）');

  /* ================= ⑧ 同步 ================= */
  section('⑧ 组装：frontend/ 里的产物是最新的');
  if (fs.existsSync(BUILT_JS)) {
    const b = fs.readFileSync(BUILT_JS, 'utf8');
    check(b.indexOf('moDigest') >= 0, '产物含 #moDigest');
    check(b.indexOf('每日报告 · AI 安全四方向') >= 0, '产物含四方向主视图文案');
    check(b.indexOf('moDgModsTgl') < 0 && b.indexOf('dgCatchUp') < 0,
      '产物里模块台账折叠与补齐按钮已彻底移除');
    check(b.indexOf('/api/daily_digest') >= 0, '产物含新接口');
    check(b.indexOf('renderDigest') >= 0, '产物含渲染函数');
  } else { check(false, '产物 daily.js 存在'); }
  if (fs.existsSync(BUILT_CSS)) {
    const bc = fs.readFileSync(BUILT_CSS, 'utf8');
    ['mo-digest', 'mo-dg-head', 'mo-dg-grid', 'mo-dg-card', 'mo-dg-notes']
      .forEach((c) => check(bc.indexOf('.' + c) >= 0, '产物 CSS 定义了 .' + c));
    const bcCode = bc.replace(/\/\*[\s\S]*?\*\//g, '');
    const hard = ['#0a0b0c', '#fff', '#000'].filter((h) =>
      new RegExp('(^|[^\\w-])' + h + '(?![\\w-])', 'i').test(bcCode));
    check(hard.length === 0, '没写死颜色（亮/暗自适应）', JSON.stringify(hard));
  } else { check(false, '产物 daily.css 存在'); }

  const css = fs.readFileSync(CSS, 'utf8');
  ['mo-digest', 'mo-dg-head', 'mo-dg-acts', 'mo-dg-grid', 'mo-dg-card',
   'mo-dg-metrics', 'mo-dg-detail', 'mo-dg-notes'].forEach((c) => {
    check(css.indexOf('.' + c) >= 0, '源 CSS 定义了 .' + c);
  });

  section('⑪ 可读性：对比度与变量存在性（用户报"有些部件看不清"）');
  /* ① 变量必须真实存在。项目里是 --txt / --txt-2/3/4，**没有 --txt-1** ——
        凭空写 var(--txt-1) 会让浏览器回落到继承色/透明，表现为"看不清"，
        而且**不会报任何错**。这个坑踩过 4 处（daily.css 4 + ops.css 2）。 */
  const mainCss = fs.readFileSync(path.join(ROOT, 'frontend', 'styles.css'), 'utf8');
  const declared = new Set();
  (mainCss.match(/(--[\w-]+)\s*:/g) || []).forEach((m) => {
    declared.add(m.replace(/\s*:$/, '').trim());
  });
  check(declared.has('--txt'), '主样式确实声明了 --txt');
  check(!declared.has('--txt-1'), '项目里不存在 --txt-1（别再凭想象用）');
  const used = [...new Set((css.match(/var\((--[\w-]+)\)/g) || [])
    .map((m) => m.replace(/var\(|\)/g, '')))];
  const missing = used.filter((v) => !declared.has(v));
  check(missing.length === 0, 'daily.css 用的变量全部已声明', JSON.stringify(missing));
  check(!/var\(--txt-1\)/.test(css), 'daily.css 不再引用不存在的 --txt-1');

  /* ② accent-3 是**文字色**不是底色。它两主题明度差 3 倍
        （暗色 #93b1ff / 亮色 #2b52bf），白字压上去亮色只有 2.11。
        按钮底色必须用 --accent 族 + --accent-ink 文字。 */
  check(!/background\s*:[^;]*var\(--accent-3\)/.test(css),
    '没有拿 --accent-3 当按钮底色（亮色下白字会看不见）');
  check(css.indexOf('color:var(--accent-ink)') >= 0,
    '强调色底上的文字用 --accent-ink');
  check(css.indexOf('color:var(--surface-1)') < 0,
    '没有把半透明 --surface-1 当文字色（它是底色层，叠任何强调色都糊）');

  /* ③ 小字号不用 --txt-4（ratio 只有 2.4~2.9）。 */
  const smallWeak = /font-size:1[01](?:\.\d)?px[^}]*color\s*:\s*var\(--txt-4\)/.test(css);
  check(!smallWeak, '≤11px 文字不用 --txt-4（ratio 2.4~2.9 看不清）');
  const tiny = (css.match(/font-size:9(?:\.\d)?px/g) || []);
  check(tiny.length === 0, '没有 9px 这种过小字号', JSON.stringify(tiny));

  /* ④ 下载按钮的 title 必须解释禁用原因（用户看不到就是问题）。 */
  check(css.indexOf('.mo-dg-acts2') >= 0, '下载按钮区有独立样式');
  check(!/opacity:\s*0\.[1-6]/.test(css.split('.mo-dg-acts2 button:disabled')[1] ?
      '.mo-dg-acts2 button:disabled' + css.split('.mo-dg-acts2 button:disabled')[1].split('}')[0] : ''),
    '禁用按钮不透明度不低于 0.4（否则看不出是禁用态还是坏了）');

  /* ================= ⑨ 后端接口名对得上 ================= */
  section('⑨ 前后端接口名一致（改了一边忘了另一边 = 404）');
  const srv = fs.readFileSync(path.join(ROOT, 'core', 'server.py'), 'utf8');
  check(srv.indexOf('/api/daily_digest"') >= 0
    || srv.indexOf('path.startswith("/api/daily_digest")') >= 0,
    'server.py 注册了 /api/daily_digest');
  check(srv.indexOf('"notifications"') >= 0, 'server.py 处理 notifications 子路径');
  check(srv.indexOf('"generate"') >= 0 && srv.indexOf('"catch_up"') >= 0
    && srv.indexOf('"cleanup"') >= 0, 'server.py 处理 generate/catch_up/cleanup');
  const dg = fs.readFileSync(path.join(ROOT, 'core', 'daily_digest.py'), 'utf8');
  check(/^def list_all\(/m.test(dg), '后端有 list_all');
  check(/^def MIME|^MIME = /m.test(dg), '后端有 MIME 映射');
  check(dg.indexOf('def push_notification') >= 0, '后端有 push_notification');
  check(/^def build_zip\(/m.test(dg), '后端有 build_zip');
  check(dg.indexOf('import zipfile') >= 0, 'zipfile 是标准库依赖（没新增第三方依赖）');
  /* —— AI 安全四方向：前后端契约（2026-10-07）—— */
  check(dg.indexOf('DIRECTIONS = [') >= 0, '后端有 DIRECTIONS 方向注册表');
  for (const d of ['dir_infra', 'dir_model', 'dir_appagent', 'dir_supply']) {
    check(new RegExp('["\'' + d + '"\'::]').test(dg), '后端注册了方向 ' + d);
  }
  check(dg.indexOf('DIR_CATEGORY') >= 0 && dg.indexOf('① AI基础设施与推理框架') >= 0,
    '方向映射到日报 AI 四分类（分类口径同源）');
  check(dg.indexOf('def _build_direction') >= 0, '后端有方向报告 builder');
  check(dg.indexOf('ENTRY_NAME = dict(MODULE_NAME)') >= 0,
    'ENTRY_NAME = 模块 + 方向 合并名称表（模块 id 历史兼容）');
  check(srv.indexOf('DG.ENTRY_NAME') >= 0 && srv.indexOf('DG.MODULE_NAME') < 0,
    'server 校验改用 ENTRY_NAME（方向 id 也能走详情/下载链路）');
  /* 生成/打包只产方向（模块台账已去掉） */
  check(dg.indexOf('for did in DIR_IDS:') >= 0, 'generate_all 只遍历四方向');
  /* ★ JS 的 split(sep, limit) 是"截断结果数组"，不是 Python 的 maxsplit ——
     取函数源码段要用 indexOf+slice，不能用 split(...,1)[1]（恒 undefined）。 */
  const _fnSrc = (src, marker) => {
    const i = src.indexOf(marker);
    if (i < 0) return '';
    const j = src.indexOf('\ndef ', i + 1);
    return src.slice(i, j === -1 ? undefined : j);
  };
  const bzSrc = _fnSrc(dg, 'def build_zip');
  check(bzSrc.length > 0, 'build_zip 源码段取到了');
  check(bzSrc.indexOf('for did, name, _desc in DIRECTIONS') >= 0,
    'build_zip 只打四方向（历史模块文件不进包）');
  check(bzSrc.indexOf('AI 安全四方向每日报告') >= 0, 'zip README 标题是四方向口径');
  check(dg.indexOf('days or 3') >= 0, 'catch_up 补全窗口收窄为 3 天（方向源老日期会滚动掉）');
  /* zip 分支必须跨模块可用：不能挂在「必须给 module 参数」的校验之后，
     否则用户只能四份点四次。 */
  const iZip = srv.indexOf('if fmt == "zip":');
  const iMid = srv.indexOf('if not mid:');
  check(iZip >= 0, 'server.py 有 zip 分支');
  check(iZip >= 0 && iZip < iMid, 'zip 分支在 module 必填校验之前（跨模块打包）');
  check(srv.indexOf('application/zip') >= 0, 'zip 用对的 Content-Type');
  check(srv.indexOf('"fmt 只支持 md / json / zip"') >= 0, 'fmt 白名单含 zip');

  section('⑩ 通知去重（曾经同一天堆 5 条）');
  check(dg.indexOf('def _dedup_notifications') >= 0, '有通知去重函数');
  check(dg.indexOf('r.get("date") == day') >= 0, '按 (kind, date) 合并同一天的通知');
  check(dg.indexOf('_dedup_notifications(rows)') >= 0,
    '读取时也去重（历史文件里可能已堆着重复）');
  check(dg.indexOf('_sig') >= 0, '用内容签名判断"内容是否变了"（变了才重新提醒）');
  check(CODE.indexOf('dgDownloadZip') >= 0, '前端有打包下载函数');

  console.log('\n结果：通过 ' + PASS + ' / 失败 ' + FAIL);
  process.exit(FAIL === 0 ? 0 : 1);
})();
