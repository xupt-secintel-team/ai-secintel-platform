/* _test_translate_cache.js —— 译文缓存的**版本盐 + 坏译文拦截**
 *
 * 背景（真实用户截图反馈 2026-10-07）：
 *   同一屏里「左边不正常、右边正常」——
 *     · 左侧检索卡片的 .snip 译文：仍是 "…很容易被存储 跨线脚本, a, a, a, a, e, e, e, e…"
 *     · 右侧检查器的 .desc-p 译文：完整正确、无循环
 *   两块译文来自**同一后端接口**，同一个页面、同一次操作。
 *   根因不是模型：是 **localStorage 里的译文缓存**。
 *     · 缓存 key 之前只有 hash(原文)，不含"由哪个版本的翻译管线产出"
 *     · 左侧那条是**旧代码时期**翻好并缓存的，后端修好退化后依旧命中缓存原样显示
 *     · 右侧那条是刚翻的（新代码），所以正常
 *   → 光修后端永远修不掉用户看到的"一半好一半坏"。
 *
 * 修法（本测试钉死这三条）：
 *   ① 缓存 key 加**版本盐** TRV；改翻译行为就 +1 → 整库自动作废重翻；
 *   ② 加载缓存时**逐条过滤**退化译文（isBadDst，后端 is_degenerate 的前端镜像）；
 *   ③ 写入缓存前也过滤 —— 坏结果宁可不显示、下轮再试，也不许进缓存。
 *
 * 用法： node tools/_test_translate_cache.js
 */
const fs = require('fs');
const path = require('path');

const ROOT = path.dirname(__dirname);
const APP = fs.readFileSync(path.join(ROOT, 'frontend', 'app.js'), 'utf8');

let PASS = 0, FAIL = 0;
function check(cond, label, extra) {
  if (cond) { PASS++; console.log('  [PASS] ' + label); }
  else { FAIL++; console.log('  [FAIL] ' + label + (extra !== undefined ? '  →  ' + extra : '')); }
}
function section(t) { console.log('\n=== ' + t + ' ==='); }

/* 从 app.js 里切出一个方法的源码段。
 * ★ 不能用 split(sep, 1)[1] —— JS 的 split limit 是**截断结果数组**，
 *   不是 Python 的 maxsplit。这里用 indexOf + 括号配平。 */
function methodSrc(name) {
  const i = APP.indexOf('\n  ' + name + '(');
  if (i < 0) return '';
  const j = APP.indexOf('{', i);
  if (j < 0) return '';
  let d = 0;
  for (let k = j; k < APP.length; k++) {
    const c = APP[k];
    if (c === '{') d++;
    else if (c === '}') { d--; if (d === 0) return APP.slice(i, k + 1); }
  }
  return '';
}

section('① 缓存 key 带版本盐（改翻译行为可一键作废旧译文）');
check(/\bTRV:\s*'v\d+'/.test(APP), "app.js 定义了 TRV 版本号（形如 TRV: 'v2'）");
const hashSrc = methodSrc('hash');
check(hashSrc.length > 0, '找到 hash() 方法');
check(/this\.TRV/.test(hashSrc), 'hash() 把 TRV 掺进 key（否则老 key 会被新代码命中）');
check(/TRV: 'v2'/.test(APP), 'TRV 已升到 v2（本轮修了退化，必须 +1）');
check(APP.indexOf("localStorage.setItem('asi-trv'") >= 0,
  '版本号落到 localStorage（下次启动才能知道版本变了）');
check(/localStorage\.getItem\('asi-trv'\)\s*!==\s*this\.TRV/.test(APP),
  '启动时比对版本号，不一致就整库作废（避免"半新半旧"混在一屏）');

section('② isBadDst：后端 is_degenerate 的前端镜像');
const badSrc = methodSrc('isBadDst');
check(badSrc.length > 0, '找到 isBadDst() 方法');
check(/shortRun\(segs,\s*3\)\s*>=\s*5/.test(badSrc),
  '判据①：短 token（≤3）用逗号/空白串成 ≥5 连');
check(/shortRun\(segs2,\s*4\)\s*>=\s*5/.test(badSrc),
  '判据②：短 token（≤4）用连接符串成 ≥5 连（"成本-成本-成本…"）');
check(/short\s*\/\s*segs\.length\s*>\s*0\.5/.test(badSrc),
  '判据③：≥20 个 token 且 ≤2 字符占比 >50%');
check(/\(\.\)\\1\{14,\}/.test(badSrc), '判据④：同一非空白字符连续 ≥15 次');
check(/split\(\/\[\\-·・—\]\+\//.test(badSrc),
  '判据②只按连接符切、**不含空白**（"very very very" 强调式重复不被误伤）');

section('③ 加载缓存时过滤坏译文');
check(/isBadDst\(this\.cache\[k\]\)/.test(APP), '遍历缓存逐条用 isBadDst 判定');
check(/delete this\.cache\[k\]/.test(APP), '命中的条目被删除（不是只跳过）');
check(APP.indexOf('purged') >= 0, '有清理计数/标记（用于决定是否回写 localStorage）');

section('④ 写入缓存前拦截（坏结果不许污染缓存）');
check(/if \(this\.isBadDst\(it\.dst\)\) return;/.test(APP),
  'translate() 里命中 isBadDst 的结果直接丢弃、不入缓存');
check(APP.indexOf('退化译文**不入缓存**') >= 0,
  '代码里有注释钉住"退化译文不入缓存"这条规矩');

section('⑤ 真实形态自测（含用户截图里的两条原文）');
/* 把 app.js 里的 isBadDst 抠出来真跑一遍 —— 静态断言只能证明"代码写了什么"，
   证明不了"判据算出来对不对"。 */
const fnBody = badSrc.slice(badSrc.indexOf('{') + 1, badSrc.lastIndexOf('}'));
const isBadDst = new Function('return function isBadDst(dst) {' + fnBody + '}')();

const BAD = [
  ['用户截图·左侧（.snip 译文，a/e 循环）',
   '柯基 - 自由页面构建器, WordPress网站构建器和自定义插件,通过所有版本的注册元数据, 很容易被存储 跨线脚本, ' +
   Array(40).fill('a').join(', ') + ', ' + Array(50).fill('e').join(', ')],
  ['用户截图·上一轮（成本-成本-成本 连字符循环）',
   '成本-成本-软件 成本-成本-成本-成本-成本-成本-成本-成本-成本-成本 等级-多代理高级随机器器检测和家庭归属分析预算'],
  ['单字符超长重复', '这是一个测试' + '。'.repeat(20) + '结尾'],
];
for (const [label, txt] of BAD) {
  check(isBadDst(txt) === true, '判为退化：' + label);
}

const GOOD = [
  ['用户截图·右侧（.desc-p 译文，完整正确）',
   '柯基- 自由页面构建器、WordPress网站构建器和自定义插件,在直到和包括6.3.1的所有版本中,都很容易通过注册元数据进行存储跨线脚本的存储,因为 " 例外元素:image_ementle () " 中没有足够地逃脱,而该元素将用户-元值直接连接到属性中。这样,未经认证的攻击者就有可能随意输入网络脚本,只要用户进入页面,将Kirki用户收集的图像内容与九个注册元字段之一捆绑在一起,即可任意执行。'],
  ['正常强调式重复（空格连接）', '这是一段非常重要的说明，请务必务必务必务必务必务必认真看完，它关系到整个流程能否跑通。'],
  ['正常中文长句', 'Ollama 允许远程攻击者通过编造的 GGUF 文件任意执行代码，导致远程代码执行。'],
  ['短文本（不判定）', '成本-成本-成本'],
];
for (const [label, txt] of GOOD) {
  check(isBadDst(txt) === false, '保留：' + label);
}

console.log('\n结果：通过 ' + PASS + ' / 失败 ' + FAIL);
process.exit(FAIL === 0 ? 0 : 1);
