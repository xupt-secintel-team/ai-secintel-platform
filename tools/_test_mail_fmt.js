/* _test_mail_fmt.js —— CMDB「发到邮箱」参数的 DOM 桩测试（不开浏览器）
 *
 * 为什么需要它：2026-10-06 的邮件功能里藏过一个静默 bug ——
 * 前端 buildSubmitQuery 把 `fmt === 'both'` 降级成 'md'，指望一个
 * 并不存在的 afterSubmitMail() 去补发 xlsx。结果是：用户在下拉里选
 * 「两份都发」，实际只收到一份七章制 md，而且后端的 both 分支永远不可达，
 * 表面看一切正常（响应 200、有回执），只有收件人自己知道少了一份。
 *
 * 光看代码很容易再犯，所以这里真点「开始分析」，抓请求 URL 做断言：
 *   ① 用户选什么 fmt，URL 里就是什么（不再有任何降级）
 *   ② 「另一份发给不同的人」时 mail2 正确带上，且 fmt 不被篡改
 *   ③ 未勾选 / 没填 / 格式错 三种情况不能把 mail 参数发出去
 *   ④ 中文/加号地址做 URL 编码
 *   ⑤ frontend/ 产物与模块源一致（改了源忘了组装 = 浏览器跑旧代码）
 *
 * 用法： node tools/_test_mail_fmt.js
 */
const fs = require('fs');
const path = require('path');
const vm = require('vm');

const ROOT = path.dirname(__dirname);
const SRC_PATH = path.join(ROOT, 'modules', 'm2_enrich', 'web', 'panel.js');
const BUILT_PATH = path.join(ROOT, 'frontend', 'modules', 'm2_enrich', 'panel.js');
const CODE = fs.readFileSync(SRC_PATH, 'utf8');
const BUILT = fs.readFileSync(BUILT_PATH, 'utf8');

let PASS = 0, FAIL = 0;
function check(cond, label, extra) {
  if (cond) { PASS++; console.log('  [PASS] ' + label); }
  else { FAIL++; console.log('  [FAIL] ' + label + (extra !== undefined ? '  → ' + extra : '')); }
}

/* ---------------- DOM 桩 ---------------- */
function makeEl(tag, id) {
  const listeners = {};
  return {
    tagName: (tag || 'div').toUpperCase(),
    id: id || '',
    innerHTML: '', textContent: '', value: '', checked: false, disabled: false,
    dataset: {}, style: {}, files: null, children: [],
    classList: {
      _s: new Set(),
      add(c) { this._s.add(c); }, remove(c) { this._s.delete(c); },
      toggle(c, on) { on ? this._s.add(c) : this._s.delete(c); },
      contains(c) { return this._s.has(c); },
    },
    addEventListener(ev, fn) { (listeners[ev] = listeners[ev] || []).push(fn); },
    removeEventListener() {},
    appendChild(c) { this.children.push(c); return c; },
    removeChild() {}, remove() {},
    click() { if (this.onclick) this.onclick({ target: this, preventDefault() {}, stopPropagation() {} }); },
    closest() { return null; },
    contains() { return false; },
    querySelector() { return null; },
    querySelectorAll() { return []; },
    fire(ev, evt) { (listeners[ev] || []).forEach((fn) => fn(evt || { preventDefault() {}, stopPropagation() {} })); },
    hasListener(ev) { return !!(listeners[ev] && listeners[ev].length); },
  };
}

let TAB = 'file';
function sectionRoot(tab) {
  if (tab) TAB = tab;
  const memo = {};
  return {
    id: 'enCmdb',
    querySelector(sel) {
      const k = String(sel);
      if (k.startsWith('#')) return memo[k] || (memo[k] = makeEl('div', k.slice(1)));
      return null;
    },
    querySelectorAll(sel) {
      if (sel === '.cm-tab') {
        return ['rest', 'sqlite', 'inline', 'file'].map((m) => {
          const t = makeEl('button', 'tab-' + m);
          t.dataset.mode = m;
          t.classList.toggle('on', m === TAB);
          return t;
        });
      }
      return [];
    },
    addEventListener() {},
    _memo: memo,
  };
}

global.$ = () => null;
global.esc = (s) => String(s == null ? '' : s)
  .replace(/[&<>"]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));
global.link = (u) => `<a href="${esc(u)}">${esc(u)}</a>`;
const NativeURL = global.URL;
global.URL = class extends NativeURL {
  static createObjectURL() { return 'blob:x'; }
  static revokeObjectURL() {}
};
global.document = {
  getElementById: () => null,
  querySelector: () => null,
  querySelectorAll: () => [],
  createElement: () => makeEl('a'),
  body: { appendChild() {}, removeChild() {} },
};
global.window = { scrollTo() {}, addEventListener() {}, prompt: () => '' };
global.navigator = {};
global.location = { href: '' };
global.toast = (msg) => { global.__toasts = global.__toasts || []; global.__toasts.push(String(msg)); };
global.openDetail = () => {};
global.AISEC = { register(m) { global.__mod = m; } };

/* fetch 桩：只抓提交分析那一次 POST（成功后 show() 还会 GET 历史，别被冲掉） */
let LAST = null;
let MAIL_STATE = { ok: true, configured: true, host: 'smtp.qq.com', port: 465,
                   user: 'me@qq.com', ssl: true, from: 'me@qq.com' };
global.fetch = (url, opt) => {
  const o = opt || {};
  const u = String(url);
  if (u.indexOf('/api/cmdb_scan/mail') === 0) {
    return Promise.resolve({ ok: true, json: () => Promise.resolve(MAIL_STATE) });
  }
  if (o.method === 'POST') LAST = { url: u, opt: o };
  return Promise.resolve({
    ok: true,
    json: () => Promise.resolve({
      ok: true, id: 'CMDB-T', report: { id: 'CMDB-T' },
      mail: { ok: true, queued: true, to: ['x@qq.com'], mask: 'basic', fmt: 'both' },
    }),
    blob: () => Promise.resolve({}),
  });
};
global.Blob = class { constructor(parts) { this.parts = parts; this.size = (parts || []).length; } };

vm.runInThisContext(CODE, { filename: 'panel.js' });

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const mkFile = (name, size) => ({ name, size: size === undefined ? 512 : size });
/* 从提交 URL 里取 query 参数 */
function qv(u, k) {
  const m = String(u).match(new RegExp('[?&]' + k + '=([^&]*)'));
  return m ? decodeURIComponent(m[1]) : null;
}

(async () => {
  const sec = global.__mod.enrichSections().find((s) => s.id === 'enCmdb');
  check(!!sec, 'enrichSections 含 enCmdb 区块');

  const R = sectionRoot('file');
  sec.mount(R);
  const el = (id) => R.querySelector('#' + id);

  /* 邮件 UI 必须在 HTML 里（否则用户根本找不到入口） */
  console.log('=== ① 邮件 UI 契约 ===');
  const H = sec.html;
  check(H.includes('id="cmMailOn"'), 'HTML 含「发到邮箱」勾选框');
  check(H.includes('id="cmMailTo"'), 'HTML 含收件邮箱输入框');
  check(H.includes('id="cmMailFmt"'), 'HTML 含「发哪一份」下拉');
  check(/value="both"/.test(H), '下拉里有「两份都发」选项');
  check(H.includes('id="cmMailSplit"') && H.includes('id="cmMailTo2"'),
        'HTML 含「另一份发给不同的人」+ 第二收件人输入框');
  check(H.includes('id="cmMailMask"'), 'HTML 含脱敏级别选择');

  /* 每次提交：清空文件清单外的现场，塞一个文件让 file 模式通过前置校验 */
  function arm(fmt, to, to2, split) {
    el('cmFile').onchange({ target: { files: [mkFile('assets.csv', 512)] } });
    el('cmMailOn').checked = true;
    el('cmMailTo').value = to === undefined ? 'x@qq.com' : to;
    el('cmMailFmt').value = fmt || 'md';
    el('cmMailMask').value = 'basic';
    el('cmMailSplit').checked = !!split;
    el('cmMailTo2').value = to2 || '';
    LAST = null;
    global.__toasts = [];
  }

  console.log('\n=== ② fmt 原样直传（核心回归护栏）===');
  for (const f of ['md', 'xlsx', 'both']) {
    arm(f, 'x@qq.com');
    el('cmGo').onclick();
    await sleep(60);
    check(!!LAST, `fmt=${f}：发起了提交请求`);
    check(qv(LAST && LAST.url, 'fmt') === f,
          `fmt=${f}：URL 里 fmt 就是 ${f}（没有被降级）`,
          LAST && LAST.url);
    check(qv(LAST && LAST.url, 'mail') === 'x@qq.com', `fmt=${f}：mail 参数带上`);
  }

  console.log('\n=== ③ 「另一份发给不同的人」 ===');
  arm('md', 'boss@qq.com', 'ops@qq.com', true);
  el('cmGo').onclick();
  await sleep(60);
  check(qv(LAST && LAST.url, 'mail') === 'boss@qq.com', '第一收件人正确', LAST && LAST.url);
  check(qv(LAST && LAST.url, 'mail2') === 'ops@qq.com', 'mail2 正确带上第二收件人', LAST && LAST.url);
  check(qv(LAST && LAST.url, 'fmt') === 'md',
        '选了 md + 分别发 → fmt 仍是 md（后端据此把另一份取反成 xlsx）', LAST && LAST.url);

  arm('xlsx', 'boss@qq.com', 'ops@qq.com', true);
  el('cmGo').onclick();
  await sleep(60);
  check(qv(LAST && LAST.url, 'fmt') === 'xlsx',
        '选了 xlsx + 分别发 → fmt 仍是 xlsx（另一份取反成 md）', LAST && LAST.url);

  console.log('\n=== ④ 不该发的时候不发 ===');
  arm('md', 'x@qq.com');
  el('cmMailOn').checked = false;
  LAST = null;
  el('cmGo').onclick();
  await sleep(60);
  check(qv(LAST && LAST.url, 'mail') === null, '未勾选「发到邮箱」→ URL 不含 mail 参数', LAST && LAST.url);

  arm('md', '');
  el('cmGo').onclick();
  await sleep(60);
  check(qv(LAST && LAST.url, 'mail') === null, '勾了但没填邮箱 → 不带 mail 参数', LAST && LAST.url);
  check((global.__toasts || []).some((t) => t.includes('收件邮箱') || t.includes('没填')),
        '并且给出可读提示', (global.__toasts || []).join(' | '));

  arm('md', 'not-an-email');
  el('cmGo').onclick();
  await sleep(60);
  check(qv(LAST && LAST.url, 'mail') === null, '邮箱格式错 → 不带 mail 参数', LAST && LAST.url);
  check((global.__toasts || []).some((t) => t.includes('格式不正确')),
        '并提示格式不正确', (global.__toasts || []).join(' | '));

  arm('md', 'a@qq.com', 'bad-addr', true);
  el('cmGo').onclick();
  await sleep(60);
  const u5 = LAST && LAST.url;
  const sent5 = qv(u5, 'mail') !== null && qv(u5, 'mail2') !== null;
  check(!sent5, '第二收件人格式错 → 整单不发（避免只发一半）', u5);
  check((global.__toasts || []).some((t) => t.includes('第二个邮箱') || t.includes('格式不正确')),
        '并说明是第二个邮箱的问题', (global.__toasts || []).join(' | '));

  console.log('\n=== ⑤ 地址编码与多收件人 ===');
  arm('md', 'a+b@qq.com');
  el('cmGo').onclick();
  await sleep(60);
  check(qv(LAST && LAST.url, 'mail') === 'a+b@qq.com',
        '含 + 的地址能正确编解码', LAST && LAST.url);
  check(/mail=a%2Bb%40qq\.com/.test(String(LAST && LAST.url)),
        'URL 里确实做了 percent-encoding（不是裸 + ，裸 + 会被当空格）', LAST && LAST.url);

  arm('md', 'a@qq.com,b@qq.com');
  el('cmGo').onclick();
  await sleep(60);
  check(qv(LAST && LAST.url, 'mail') === 'a@qq.com,b@qq.com',
        '多个收件人逗号拼接后整体传输', LAST && LAST.url);

  arm('md', 'a@qq.com;b@qq.com');
  el('cmGo').onclick();
  await sleep(60);
  check(qv(LAST && LAST.url, 'mail') === 'a@qq.com,b@qq.com',
        '分号分隔会被规整成逗号（从 Excel 粘贴常见）', LAST && LAST.url);

  console.log('\n=== ⑥ 前端产物必须同步 ===');
  check(BUILT.includes("qy.push('fmt=' + p.fmt)"),
        'frontend/ 产物里也已直传 fmt');
  check(!/p\.fmt === 'both' \? 'md'/.test(BUILT),
        'frontend/ 产物里没有残留的 both→md 降级');

  console.log('\n========================================');
  console.log(`MAIL FMT: ${PASS} pass, ${FAIL} fail`);
  console.log(PASS > 0 && FAIL === 0 ? 'MAIL FMT TEST OK' : 'MAIL FMT TEST FAILED');
  process.exit(FAIL === 0 ? 0 : 1);
})();
