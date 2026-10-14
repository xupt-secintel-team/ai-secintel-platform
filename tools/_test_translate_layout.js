/* _test_translate_layout.js —— 译文块（.trl）插入后**不得破坏宿主布局**
 *
 * 背景（真实用户截图反馈）：
 *   左栏「实时监测 · 最新情报」标题被挤成竖排一条、右侧大片空白、底部长出横向滚动条。
 *   根因不是 slice 长度，而是**布局被译文块抢了横向空间**：
 *     · .lat 是 `display:flex`（不换行）的行，TR 用 el.after() 把 .trl 插成**兄弟节点**
 *     · 兄弟节点在 flex 行里 = 并列 flex item，与日期/徽章/标题抢同一条横向空间
 *     · .trl 的 padding-left:42px 是**最小内容宽度底线**，撑不扁
 *     · 两者一起被压到极窄 → 中文按字竖排；容器 overflow-y:auto 使 x 轴隐式变 auto
 *       → 长出横向滚动条
 *
 * 这个坑的恶劣之处：**加翻译功能时是好的**（译文落在标题下方，纵向），
 * 去掉翻译功能也是好的，只有"翻译开着 + 容器是 flex 行"才炸 ——
 * 纯靠肉眼看代码很难在提交前发现，所以在这里钉死。
 *
 * 用法： node tools/_test_translate_layout.js
 */
const fs = require('fs');
const path = require('path');

const ROOT = path.dirname(__dirname);
const STYLES = fs.readFileSync(path.join(ROOT, 'frontend', 'styles.css'), 'utf8');
const APP = fs.readFileSync(path.join(ROOT, 'frontend', 'app.js'), 'utf8');
const PANEL = fs.readFileSync(path.join(ROOT, 'modules', 'm1_monitor', 'web', 'panel.js'), 'utf8');
const DAILY_CSS = fs.readFileSync(path.join(ROOT, 'modules', 'm1_monitor', 'web', 'daily.css'), 'utf8');

let PASS = 0, FAIL = 0;
function check(cond, label, extra) {
  if (cond) { PASS++; console.log('  [PASS] ' + label); }
  else { FAIL++; console.log('  [FAIL] ' + label + (extra !== undefined ? '  →  ' + extra : '')); }
}
function section(t) { console.log('\n=== ' + t + ' ==='); }

/* 从 CSS 里抽出某选择器的声明体。
 * **合并同名规则的所有声明块**（不是只取第一个）——
 * 同一选择器在文件里出现多次很常见（基础样式 + 补丁），
 * 只取第一个会漏掉后面的补丁，让测试对真实代码失明。
 * 嵌套 @media 里的同名规则也会被并进来 —— 对本文件这些断言是宽松方向，安全。 */
function mergeRules(src, sel) {
  const esc = sel.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  const re = new RegExp('(?:^|[,{}])\\s*' + esc + '\\s*\\{([^}]*)\\}', 'gm');
  let m, out = '';
  while ((m = re.exec(src)) !== null) out += ';' + m[1];
  return out;
}
function rule(sel) { return mergeRules(STYLES, sel); }
/* decl 传**完整声明**（含冒号），如 'display:flex'、'min-width:0'。
 * 允许 ';'/换行/首尾空白分隔，避免 'color' 误命中 'color-scheme'。 */
function has(sel, decl) {
  const r = rule(sel);
  if (!r) return false;
  const d = decl.replace(/[.*+?^${}()|[\]\\]/g, '\\$&').replace(/:\s*/, ':\\s*');
  return new RegExp('(^|;)\\s*' + d + '\\s*(?=[;}]|$)', 'm').test(r);
}
function dailyRule(sel) { return mergeRules(DAILY_CSS, sel); }
function dailyHas(sel, decl) {
  const r = dailyRule(sel);
  if (!r) return false;
  const d = decl.replace(/[.*+?^${}()|[\]\\]/g, '\\$&').replace(/:\s*/, ':\\s*');
  return new RegExp('(^|;)\\s*' + d + '\\s*(?=[;}]|$)', 'm').test(r);
}

console.log('_test_translate_layout.js —— 译文块不得破坏宿主布局');

/* ------------------------------------------------------------------ */
section('① 复现前提：.lat 是 flex 行，译文块被插成兄弟节点');
check(has('.lat', 'display:flex'), '.lat 是 flex 行（所以译文块会成为并列 item）');
check(!has('.lat', 'flex-wrap:wrap'), '.lat 故意**不**换行（一行一条情报，节奏紧凑）');
check(APP.indexOf('t.el.after(ph)') >= 0,
  'TR 用 el.after() 把译文块插成兄弟节点 —— 这就是抢位的成因');
/* 2026-10-07 起左侧栏**不再翻**（用户要求）：侧栏太窄，译文块会把每条
   撑成两行、9 条就占满整屏。改为从白名单移除，但 .latmain 那层壳保留 ——
   万一将来有人加回来，译文块会落进纵向容器，挤不坏布局。 */
check(!/'#latestbody \.latt'/.test(APP),
  '左栏标题已从 TR.SEL 移除（侧栏太窄，不适合翻译）');

section('② 修法：标题独占纵向容器 .latmain');
check(PANEL.indexOf('class="latmain"') >= 0,
  'panel.js 用 .latmain 包住 .latt（译文块落在容器内，不再与日期/徽章并列）');
check(has('.latmain', 'flex-direction:column'), '.latmain 是纵向容器');
check(has('.latmain', 'min-width:0'), '.latmain 有 min-width:0（flex 子项不给这个值，长内容会撑破容器）');
check(has('.latmain', 'flex:1 1 auto'), '.latmain flex:1 1 auto（吃掉日期/徽章之外的剩余宽度）');
check(has('.latmain .latt', 'text-overflow:ellipsis'),
  '.latt 仍单行省略（译文在下方另起一行，不影响标题省略）');
check(has('.latmain .latt', 'white-space:nowrap'), '.latt 不换行（保持一行一条的节奏）');
/* 关键回归：这层壳一旦被"简化"掉，bug 立刻回来 */
check(PANEL.indexOf('别把这层壳删掉') >= 0,
  '代码里有注释钉住"别删这层壳"（否则后人重构会顺手删掉）');

section('③ .trl 自身防溢出（通用保护，不只救 .lat）');
check(has('.trl', 'min-width:0'), '.trl 有 min-width:0');
check(has('.trl', 'max-width:100%'), '.trl 有 max-width:100%（译文再长也不越界）');
check(has('.trl', 'overflow-wrap:anywhere'),
  '.trl 有 overflow-wrap:anywhere（译文里的长 URL/标识符不得撑宽容器）');

section('④ 其余 flex 宿主同样处理（同一个坑，多处中招）');
check(has('.card>h3', 'flex-wrap:wrap'), '.card>h3 允许换行（TR.SEL 里的 `#db h3` 会往里插译文）');
check(has('.card>h3>.trl', 'flex:0 0 100%'),
  '.card>h3 里的译文块独占整行（不挤掉 margin-left:auto 的右侧按钮）');
check(dailyHas('.mo-sum>.trl', 'flex:0 0 100%'), '.mo-sum 里的译文块独占整行（不挤 6 个计数指标）');
check(dailyHas('.mo-sum', 'flex-wrap:wrap'), '.mo-sum 本身可换行');

section('⑤ 白名单没被掏空（全页翻译能力保留）');
const selBlock = (APP.match(/SEL:\s*\[([\s\S]*?)\],\n/) || [, ''])[1];
const selCount = (selBlock.match(/'[^']+'/g) || []).length;
check(selCount >= 9, 'TR.SEL 仍有 ' + selCount + ' 组选择器（没被掏空，全页自动翻译能力保留）');
/* 其它内容型文本仍要翻 —— 侧栏不翻不等于把功能整体关了 */
for (const keep of ['#results .ttl', '#db .desc-p', '#qaans .ans']) {
  check(selBlock.indexOf(keep) >= 0, '仍翻译 ' + keep + '（只去掉侧栏，不是关掉功能）');
}
/* 只看可执行代码：注释里会解释"为什么去掉 applyView"，那里出现它是应该的 */
const panelCode = PANEL.split('\n')
  .filter((l) => !l.trim().startsWith('*') && !l.trim().startsWith('/*') && !l.trim().startsWith('//'))
  .join('\n');
check(panelCode.indexOf('applyView') < 0,
  'panel.js 的可执行代码里没有 applyView（侧栏已不翻，调了也只是空跑）');
check(PANEL.indexOf('别删') >= 0,
  'panel.js 留了注释说明 .latmain 为何仍要保留（防将来加回来时布局又炸）');

section('⑥ 加载模式（body.zl）字号同步');
check(/body\.zl \.latmain \.trl\{[^}]*font-size/.test(STYLES),
  'body.zl 下译文块字号有单独规则（否则中文比英文标题还小，看着像没翻）');
check(/body\.zl \.latd,\s*body\.zl \.latt/.test(STYLES), 'body.zl 下日期/标题有放大规则');

section('⑦ 同步一致性（改了 modules/ 必须同步 frontend/）');
const built = fs.readFileSync(path.join(ROOT, 'frontend', 'modules', 'm1_monitor', 'panel.js'), 'utf8');
check(built.indexOf('class="latmain"') >= 0, 'frontend/ 里的 panel.js 已含 .latmain（组装已同步）');
const builtCss = fs.readFileSync(path.join(ROOT, 'frontend', 'modules', 'm1_monitor', 'daily.css'), 'utf8');
check(/mo-sum>\.trl/.test(builtCss), 'frontend/ 里的 daily.css 已含 .mo-sum>.trl 规则');

console.log('\n结果：通过 ' + PASS + ' / 失败 ' + FAIL);
process.exit(FAIL === 0 ? 0 : 1);
