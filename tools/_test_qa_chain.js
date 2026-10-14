/* _test_qa_chain.js —— m3_qa「推理链」渲染 DOM 桩测试（不开浏览器）
 *
 * 为什么需要它：推理链是"跨文档推理"唯一可视的证据，但它渲染错了也
 * 不报错——用户只会以为"系统就是这么查的"。2026-10-06 实测真问题：
 *   ① 第 1 跳是多路并行检索式（原问题/跨来源召回/条件算子），后端每路
 *      各记一条 → hops 里出现多个 hop:1，而前端用 hops.length 当"步数"，
 *      把 2 跳说成"3 步"（后端 hop_count 才是真实跳数）。
 *   ② 检索式与派生实体直接拼进 innerHTML，源站标题里带尖括号就会破版 / XSS。
 *   ③ 没有 chain / hops 为空时不能渲染出空的 <details> 壳子。
 *
 * 覆盖：步数口径、多路标识、转义、空/脏数据兜底。
 *
 * 用法： node tools/_test_qa_chain.js
 */
const fs = require('fs');
const path = require('path');
const vm = require('vm');

const ROOT = path.dirname(__dirname);
const SRC = path.join(ROOT, 'modules', 'm3_qa', 'web', 'panel.js');
const BUILT = path.join(ROOT, 'frontend', 'modules', 'm3_qa', 'panel.js');
const CODE = fs.readFileSync(SRC, 'utf8');

let PASS = 0, FAIL = 0;
function check(cond, label, extra) {
  if (cond) { PASS++; console.log('  [PASS] ' + label); }
  else { FAIL++; console.log('  [FAIL] ' + label + (extra !== undefined ? '  → ' + extra : '')); }
}

/* ---------------- DOM / 全局桩 ---------------- */
function fakeEl() {
  return {
    innerHTML: '', textContent: '', value: '', style: {}, dataset: {},
    classList: { _s: new Set(), add(c) { this._s.add(c); }, remove(c) { this._s.delete(c); },
      toggle(c) { this._s.has(c) ? this._s.delete(c) : this._s.add(c); },
      contains(c) { return this._s.has(c); } },
    addEventListener() {}, appendChild() {}, removeChild() {}, remove() {},
    insertBefore() {}, querySelector() { return null; }, querySelectorAll() { return []; },
    closest() { return null; }, focus() {}, scrollIntoView() {},
  };
}
global.$ = () => null;
global.esc = (s) => String(s == null ? '' : s)
  .replace(/[&<>"]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));
global.document = {
  getElementById: () => null, querySelector: () => null,
  querySelectorAll: () => [], createElement: () => fakeEl(),
  body: { appendChild() {}, removeChild() {} }, addEventListener() {},
};
global.window = { addEventListener() {} };
global.fetch = () => Promise.reject(new Error('no net in test'));
global.__state = {};
global.AISEC = { register(m) { global.__mod = m; } };

vm.runInThisContext(CODE, { filename: 'm3_qa-panel.js' });

const chainHtml = global.__mod && global.__mod.chainHtml;
const wrap = (m) => ({ reasoning_chain: m, elapsed_ms: m && m.total_ms });

console.log('=== ① 契约 ===');
check(!!global.__mod, '模块已注册');
check(!!chainHtml, 'chainHtml 已导出（可被回归测试驱动）');
if (!chainHtml) { console.log('\nQA CHAIN: ' + PASS + ' pass, ' + FAIL + ' fail'); process.exit(1); }

console.log('\n=== ② 步数口径（本次修的真 bug）===');
const multi = {
  strategy: 'rule+iterative', generation: 'template(未配置Key或调用失败)',
  hop_count: 2, pool_size: 12, returned: 8, total_ms: 1830,
  hops: [
    { hop: 1, sub: 1, routes: 3, query: 'Ollama 的漏洞', basis: '用户原问题', hits: 12, new_docs: 12, ms: 814 },
    { hop: 1, sub: 2, routes: 3, query: 'Ollama kev', basis: '跨来源补充召回', hits: 12, new_docs: 0, ms: 900 },
    { hop: 1, sub: 3, routes: 3, query: 'Ollama 高危 cvss>=7', basis: '结构化条件算子', hits: 12, new_docs: 0, ms: 1023 },
    { hop: 2, query: 'ollama 在野利用 高危', basis: '由第1跳命中【题面主实体】的条目的受影响产品/厂商派生',
      hits: 8, new_docs: 0, derived_entities: ['ollama', 'vllm'], ms: 613 },
  ],
};
let h = chainHtml(wrap(multi));
check(h.includes('2 跳'), '步数用后端 hop_count（不是记录条数）', h.slice(0, 190));
check(h.includes('4 次检索'), '同时如实给出"几次检索"', h.slice(0, 190));
check(!h.includes('3 跳'), '不会把 2 跳说成 3 步');
check(h.includes('跳1·1/3') && h.includes('跳1·2/3') && h.includes('跳1·3/3'),
    '第 1 跳三路分别标为 跳1·n/3', h.slice(0, 260));
check(h.includes('跳2'), '第 2 跳正常显示为 跳2');
check(h.includes('派生实体：ollama、vllm'), '派生实体透出');
check(h.includes('由第1跳命中'), '派生依据透出（可核对为什么这么查）');
check(h.includes('命中 <b>12</b>') && h.includes('新增 <b>0</b>'), '命中/新增数渲染');
check(h.includes('814ms'), '每跳耗时渲染');
check(h.includes('rule+iterative'), '检索策略透出');
check(h.includes('生成 template(未配置Key或调用失败)'), '生成模式如实透出（不谎称用了 LLM）');
check(h.includes('总耗时 1830ms'), '总耗时透出');

console.log('\n=== ③ 停止深化也要显示 ===');
const stopped = {
  hop_count: 2, hops: [
    { hop: 1, sub: 1, routes: 1, query: 'x', basis: '用户原问题', hits: 3, new_docs: 3, ms: 5 },
    { hop: 2, skipped: 'no_entity', basis: '第2跳未派生出新实体，停止深化（避免跑偏到无关产品）' },
  ],
};
h = chainHtml(wrap(stopped));
check(h.includes('qa-hop stop'), '停止态有独立样式类', h.slice(0, 200));
check(h.includes('停止深化'), '停止原因透出（而不是凭空消失一跳）');

console.log('\n=== ④ 脏数据 / 空数据兜底 ===');
check(chainHtml({ reasoning_chain: null }) === '', '无 chain → 返回空串（不渲染空壳）');
check(chainHtml({ reasoning_chain: {} }) === '', '空对象 → 返回空串');
check(chainHtml({ reasoning_chain: { hops: [] } }) === '', 'hops 为空 → 返回空串');
check(chainHtml({ reasoning_chain: 'oops' }) === '', 'chain 类型错（字符串）→ 返回空串，不崩');
check(chainHtml({ reasoning_chain: { hops: [null, undefined, 1] } }) === '', 'hops 里混入脏项 → 不崩');
check(chainHtml({ reasoning_chain: { hops: [{ hop: 1 }] } }).includes('—'), '字段全缺 → 用 — 占位');
h = chainHtml(wrap({ hops: [{ hop: 1, query: 'a', derived_entities: '不是数组' }] }));
check(typeof h === 'string' && h.length > 0, 'derived_entities 类型错 → 不崩', h.slice(0, 120));
h = chainHtml(wrap({ hops: [{ hop: 1, query: 'a', derived_entities: [] }] }));
check(!h.includes('派生实体'), '派生实体为空数组 → 不渲染空标签');

console.log('\n=== ⑤ XSS 转义 ===');
h = chainHtml(wrap({
  hop_count: 2,
  hops: [
    { hop: 1, sub: 1, routes: 1, query: '<img src=x onerror=alert(1)>',
      basis: '<script>bad()</script>', hits: '<b>1</b>', new_docs: 0, ms: '<i>5</i>',
      derived_entities: ['<svg onload=alert(2)>'] },
    { hop: 2, skipped: 'no_entity', basis: '"><script>x()</script>' },
  ],
}));
check(!h.includes('<img src=x') && h.includes('&lt;img'), '检索式里的 HTML 已转义');
check(!h.includes('<script>bad()') && h.includes('&lt;script&gt;'), '派生依据里的 script 已转义');
check(!h.includes('<svg onload') && h.includes('&lt;svg'), '派生实体里的 svg 已转义');
check(!h.includes('<i>5</i>') && h.includes('&lt;i&gt;'), '耗时字段里的 HTML 已转义');
check(h.includes('&lt;b&gt;1&lt;/b&gt;') || !h.includes('<b>1</b>'), '命中数字段未被注入');
check(!h.includes('"><script>'), '停止原因里的属性逃逸已转义');

console.log('\n=== ⑥ 产物同步 ===');
check(fs.existsSync(BUILT), 'frontend 产物存在');
const b = fs.readFileSync(BUILT, 'utf8');
check(b.includes('跳1·') || (b.includes('跳') && b.includes('routes')), 'frontend 产物含新的跳次渲染（源改了就组装过）');
check(b.includes('2 跳') || b.includes('hop_count'), 'frontend 产物含 hop_count 步数口径');
// 产物比源多一段「自动生成」banner，所以不能比字节相等，
// 要比"源内容是否完整落在产物里" —— 这才是"有没有漏组装"的真判据。
const srcTxt = CODE.trim();
check(b.includes(srcTxt), 'frontend/modules/m3_qa/panel.js 完整包含模块源内容（banner 之外无差异）');
check(b.startsWith('// web/panel.js'), '产物带「自动生成，改源请跑组装脚本」提示头');

console.log('\n========================================');
console.log('QA CHAIN: %d pass, %d fail', PASS, FAIL);
process.exit(FAIL ? 1 : 0);