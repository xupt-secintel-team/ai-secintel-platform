/* _test_cmdb_db_upload.js —— CMDB「数据库文件」拖拽上传的 DOM 桩测试（不开浏览器）
 *
 * 为什么单独一个：2026-10-06 把数据库 tab 从「只填服务器本地路径」改成
 * 「可拖可点、可多选」的上传区。这块交互全在 JS 里，光看代码不够——
 * 必须验四件事：
 *   ① 契约：拖拽区 / 文件输入 / 清单容器都在 HTML 里，且 accept 限了数据库扩展名
 *   ② 交互：点选择、拖拽、多选累积去重、**逐个移除**、扩展名拦截
 *   ③ 提交：走二进制直传（octet-stream + X-Cmdb-Manifest，mode=sqlite），
 *      而不是把 .db 当 CSV 塞进 JSON —— 后者会让服务端 sqlite3 打不开
 *   ④ 回归：CSV 上传区没被改坏（manifest.mode 仍是 file）
 *
 * 桩的两个关键能力（_test_enrich_panel*.js 那套 fakeEl 没有）：
 *   ① addEventListener 记回调 → 拖拽事件可手动 fire
 *   ② querySelectorAll('.cm-file-i .x') 从 innerHTML 解析出「×」按钮，
 *      且按 innerHTML 记忆化 —— 这样 renderFileList 绑在按钮上的 onclick
 *      才不会被下一次 querySelectorAll 冲掉，「逐个移除」才是真测而非假测。
 *
 * 用法： node tools/_test_cmdb_db_upload.js
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

/* ---------------- DOM 桩 ---------------- */
function makeEl(tag, id) {
  const listeners = {};
  let xCache = { html: null, btns: [] };
  const e = {
    tagName: (tag || 'div').toUpperCase(),
    id: id || '',
    innerHTML: '', textContent: '', value: '', checked: false, disabled: false,
    dataset: {}, style: {},
    classList: {
      _s: new Set(),
      add(c) { this._s.add(c); }, remove(c) { this._s.delete(c); },
      toggle(c, on) { on ? this._s.add(c) : this._s.delete(c); },
      contains(c) { return this._s.has(c); },
    },
    children: [], files: null,
    addEventListener(ev, fn) { (listeners[ev] = listeners[ev] || []).push(fn); },
    removeEventListener() {},
    appendChild(c) { this.children.push(c); return c; },
    removeChild() {}, remove() {},
    click() { if (this.onclick) this.onclick({ target: this, preventDefault() {}, stopPropagation() {} }); },
    /* 真实 DOM 有 closest；面板用它判断「点的是不是按钮」。默认 null = 点在普通区域。 */
    closest() { return null; },
    contains() { return false; },
    querySelector() { return null; },
    querySelectorAll(sel) {
      // 从已渲染的 innerHTML 里解析「×」移除按钮，并按 innerHTML 记忆化，
      // 保证 renderFileList 绑上去的 onclick 能被测试原样取到并调用。
      if (sel === '.cm-file-i .x') {
        if (xCache.html !== this.innerHTML) {
          xCache = {
            html: this.innerHTML,
            btns: Array.from(this.innerHTML.matchAll(/data-i="(\d+)"[^>]*title="移除"/g))
              .map((m) => ({ dataset: { i: m[1] }, onclick: null })),
          };
        }
        return xCache.btns;
      }
      return [];
    },
    fire(ev, evt) {
      (listeners[ev] || []).forEach((fn) => fn(evt || { preventDefault() {}, stopPropagation() {} }));
    },
    hasListener(ev) { return !!(listeners[ev] && listeners[ev].length); },
    _listeners: listeners,
  };
  return e;
}

/* 当前激活的 tab（真实 DOM 里由点击切换；桩里用变量模拟） */
let TAB = 'sqlite';
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
global.window = { scrollTo() {}, addEventListener() {} };
global.navigator = {};
global.location = { href: '' };
global.toast = (msg) => { global.__toasts = global.__toasts || []; global.__toasts.push(msg); };
global.openDetail = () => {};
global.AISEC = { register(m) { global.__mod = m; } };

/* fetch 桩：只抓「提交分析」那一次 POST。
   不能盲抓最后一个 —— submit() 成功后 show() 会再调 loadHist()，也是
   /api/cmdb_scan（GET、无 opt），会把真正的提交记录冲掉。 */
let LAST = null;
global.fetch = (url, opt) => {
  const o = opt || {};
  if (o.method === 'POST' && o.headers) LAST = { url: String(url), opt: o };
  return Promise.resolve({
    ok: true,
    json: () => Promise.resolve({ ok: true, id: 'CMDB-X', report: { id: 'CMDB-X' } }),
    blob: () => Promise.resolve({}),
  });
};
global.Blob = class { constructor(parts) { this.parts = parts; this.size = (parts || []).length; } };

vm.runInThisContext(CODE, { filename: 'panel.js' });

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const mkFile = (name, size) => ({ name, size: size === undefined ? 1024 : size });
/* 清单里当前列出的文件名（按 data-i 顺序） */
const listedNames = (box) => Array.from(box.innerHTML.matchAll(/title="([^"]*)"/g))
  .filter((m) => m[1] && m[1] !== '移除')
  .map((m) => m[1]);
const countIn = (box) => {
  const m = box.innerHTML.match(/共\s*(\d+)\s/);
  return m ? Number(m[1]) : -1;
};

(async () => {
  const sec = global.__mod.enrichSections().find((s) => s.id === 'enCmdb');

  console.log('=== ① 区块契约与上传区 HTML ===');
  check(!!sec, 'enrichSections 含 enCmdb 区块');
  const H = sec.html;
  check(H.includes('id="cmDbDrop"'), 'HTML 含数据库拖拽区 cmDbDrop');
  check(H.includes('id="cmDbFile"') && H.includes('type="file"'), 'HTML 含隐藏的文件输入 cmDbFile');
  check(/id="cmDbFile"[^>]*multiple/.test(H), '文件输入带 multiple（可多选）');
  check(/id="cmDbFile"[^>]*accept="[^"]*\.db/.test(H), 'accept 限定数据库扩展名');
  check(H.includes('id="cmDbList"'), 'HTML 含已选文件清单容器');
  check(H.includes('id="cmDbClear"'), 'HTML 含「清空」按钮（选错文件能一键重置）');
  check(H.includes('id="cmDbPath"'), '保留服务器本地路径输入（降级入口）');
  check(H.includes('id="cmDbTables"'), '保留表名可选输入');
  check(H.includes('id="cmPick') && H.includes('id="cmFileList"'),
        'CSV 上传区未被误删（仍在同一面板组里）');
  check(H.includes('把 CMDB 的 SQLite 库拖到这里'), '拖拽区有明确操作提示文案');

  console.log('\n=== ② mount 与事件绑定 ===');
  const R1 = sectionRoot('sqlite');
  let mountOk = true, mountErr = '';
  try { sec.mount(R1); } catch (e) { mountOk = false; mountErr = e.message; }
  check(mountOk, 'mount 不抛异常', mountErr);
  const el1 = (id) => R1.querySelector('#' + id);
  check(typeof el1('cmGo').onclick === 'function', '「开始分析」已绑事件');
  const drop = el1('cmDbDrop');
  check(drop.hasListener('dragover') && drop.hasListener('drop'), '拖拽区绑了 dragover / drop');
  check(drop.hasListener('dragleave'), '拖拽区绑了 dragleave（拖出后高亮消失）');

  // 拖拽路径：fire drop，把文件塞进去
  drop.fire('dragover');
  check(drop.classList.contains('drag'), 'dragover 时高亮');
  drop.fire('drop', { preventDefault() {}, stopPropagation() {}, dataTransfer: { files: [mkFile('drag.db', 4096)] } });
  check(!drop.classList.contains('drag'), 'drop 后高亮消失');
  check(listedNames(el1('cmDbList')).includes('drag.db'), '拖拽进来的库进了清单');

  console.log('\n=== ③ 点选与多选累积去重 ===');
  const input = el1('cmDbFile');
  let clicked = 0;
  input.click = () => { clicked++; };
  drop.onclick({ target: makeEl('div') });
  check(clicked === 1, '点击拖拽区打开文件选择界面');
  // 面板用 e.target.closest('button') 判断是否点在按钮上，命中就不该再弹文件框
  const onButton = makeEl('div');
  onButton.closest = () => makeEl('button');
  drop.onclick({ target: onButton });
  check(clicked === 1, '点在按钮上不重复触发文件选择（closest 判别生效）', clicked);

  const box1 = el1('cmDbList');
  const n0 = countIn(box1);
  input.onchange({ target: { files: [mkFile('cmdb_asset.db', 2048), mkFile('cmdb_vuln.db', 4096)] } });
  check(countIn(box1) === n0 + 2, '一次选中两个库都进清单', countIn(box1));
  check(listedNames(box1).includes('cmdb_asset.db') && listedNames(box1).includes('cmdb_vuln.db'),
        '两个库名都列出');
  check(/2 KB/.test(box1.innerHTML) && /4 KB/.test(box1.innerHTML),
        '清单显示可读体积', box1.innerHTML.replace(/<[^>]+>/g, '|').slice(0, 200));
  check(!/个个/.test(box1.innerHTML), '合计文案无「个个」这类叠字', box1.innerHTML.slice(-60));

  const n1 = countIn(box1);
  input.onchange({ target: { files: [mkFile('cmdb_asset.db', 2048), mkFile('cmdb_idc.db', 1024)] } });
  check(countIn(box1) === n1 + 1, '同名同大小去重，只新增 1 个', countIn(box1));

  console.log('\n=== ④ 扩展名拦截（拖入 CSV/Excel 要指路）===');
  global.__toasts = [];
  const n2 = countIn(box1);
  input.onchange({ target: { files: [mkFile('资产清单.xlsx'), mkFile('notes.txt')] } });
  check((global.__toasts || []).some((t) => t.includes('非数据库文件')),
        '拖入非数据库文件时明确提示', (global.__toasts || []).join(' | '));
  check((global.__toasts || []).some((t) => t.includes('上传文件')),
        '提示里指路到正确模式（CSV/Excel 走「上传文件」）');
  check(countIn(box1) === n2, '非数据库文件未进清单');
  check(!box1.innerHTML.includes('xlsx'), '清单里没有 xlsx');

  console.log('\n=== ⑤ 逐个移除（真点 × 按钮）===');
  const before5 = listedNames(box1);
  check(before5.length === countIn(box1), '清单项数与合计一致', before5.length + '/' + countIn(box1));
  const victim = before5[1];
  const xBtns = box1.querySelectorAll('.cm-file-i .x');
  check(xBtns.length === before5.length, '每个库都有 × 按钮', xBtns.length);
  check(xBtns[1] && typeof xBtns[1].onclick === 'function', '× 按钮绑了移除事件');
  if (xBtns[1]) {
    xBtns[1].onclick();
    const after = listedNames(box1);
    check(after.length === before5.length - 1, '点 × 后少一项', after.length);
    check(!after.includes(victim), `被移除的是 ${victim}`, after.join(','));
    check(after.includes(before5[0]) && after.includes(before5[2]), '其余项仍在', after.join(','));
  }

  console.log('\n=== ⑥ 提交协议：必须走二进制直传 ===');
  el1('cmDbTables').value = 'middleware_instance';
  LAST = null;
  el1('cmGo').onclick();
  await sleep(50);
  check(!!LAST, '发起了提交请求');
  const hdr = LAST && LAST.opt.headers;
  check(hdr && hdr['Content-Type'] === 'application/octet-stream',
        'Content-Type 为 octet-stream（.db 塞 JSON 会被服务端解析失败）',
        hdr && hdr['Content-Type']);
  check(!!(hdr && hdr['X-Cmdb-Manifest']), '带 X-Cmdb-Manifest 清单头');
  let man = null;
  try { man = JSON.parse(decodeURIComponent(hdr['X-Cmdb-Manifest'])); } catch (e) { man = null; }
  check(!!man, '清单头是合法的 URI 编码 JSON');
  check(man && man.mode === 'sqlite', "manifest.mode = 'sqlite'（后端据此落盘 .db）", man && man.mode);
  check(man && man.tables === 'middleware_instance', '表名过滤条件随清单一起上传');
  check(man && Array.isArray(man.files) && man.files.length === countIn(box1),
        '清单列出全部已选库（多库合并）', man && man.files && man.files.length);
  check(man && man.files.every((f) => typeof f.size === 'number' && f.size > 0),
        '每个库都带字节数（服务端据此切分请求体）');
  const listed = listedNames(box1);
  const expectSum = listed.reduce((s, n) => {
    const known = { 'drag.db': 4096, 'cmdb_asset.db': 2048, 'cmdb_vuln.db': 4096, 'cmdb_idc.db': 1024 };
    return s + (known[n] || 0);
  }, 0);
  check(man && man.files.reduce((s, f) => s + f.size, 0) === expectSum,
        '清单字节数之和与实际体积一致（服务端会逐项校验）',
        man && man.files.reduce((s, f) => s + f.size, 0) + ' vs ' + expectSum);
  check(LAST && LAST.opt.body instanceof global.Blob, '请求体是 Blob 拼接（惰性，不占内存）');

  console.log('\n=== ⑦ 清空按钮可重置已选库 ===');
  const R2 = sectionRoot('sqlite');
  sec.mount(R2);
  const el2 = (id) => R2.querySelector('#' + id);
  // mountedAt 之后的状态是模块级的（pickedDbs 不随 mount 重置），
  // 所以这里先点「清空」拿到干净起点，再验证「只填路径」这条老路没被改坏。
  check(typeof el2('cmDbClear').onclick === 'function', '「清空」按钮已绑事件');
  el2('cmDbClear').onclick();
  check(countIn(el2('cmDbList')) === -1 || el2('cmDbList').innerHTML === '',
        '点清空后清单为空');
  check(el2('cmDbList').style.display === 'none', '清单容器隐藏');
  check(el2('cmDbClear').style.display === 'none', '清空按钮自身隐藏');

  console.log('\n=== ⑧ 只填路径（不上传）仍可走通 ===');
  el2('cmDbPath').value = 'E:\\cmdb\\sqlite\\cmdb.db';
  LAST = null;
  el2('cmGo').onclick();
  await sleep(50);
  check(!!LAST && LAST.opt.headers['Content-Type'] === 'application/json',
        '无库 + 填路径 → 走 JSON（服务端直读本地文件）',
        LAST && LAST.opt.headers['Content-Type']);
  check(LAST && String(LAST.opt.body).includes('cmdb.db'), '路径随 JSON 体上传');
  check(LAST && JSON.parse(String(LAST.opt.body)).mode === 'sqlite', 'mode 仍是 sqlite');

  console.log('\n=== ⑨ 前置校验：既无库也无路径要拦下 ===');
  el2('cmDbPath').value = '';
  global.__toasts = [];
  LAST = null;
  el2('cmGo').onclick();
  await sleep(50);
  check((global.__toasts || []).some((t) => t.includes('数据库文件') || t.includes('SQLite')),
        '无输入时提示该选文件或填路径', (global.__toasts || []).join(' | '));
  check(!LAST, '无输入时不发请求（不空转）');

  console.log('\n=== ⑩ 回归：CSV 上传区未被改坏 ===');
  const R4 = sectionRoot('file');
  sec.mount(R4);
  const el4 = (id) => R4.querySelector('#' + id);
  el4('cmFile').onchange({ target: { files: [mkFile('assets.csv', 111), mkFile('台账.xlsx', 222)] } });
  const fBox = el4('cmFileList');
  check(listedNames(fBox).includes('assets.csv') && listedNames(fBox).includes('台账.xlsx'),
        'CSV 区仍能多选（中文名也进清单）', listedNames(fBox).join(','));
  check(!/共\s*\d+\s*个个/.test(fBox.innerHTML), 'CSV 合计文案无叠字', fBox.innerHTML.slice(-60));
  LAST = null;
  el4('cmGo').onclick();
  await sleep(50);
  check(!!LAST && LAST.opt.headers['Content-Type'] === 'application/octet-stream',
        'CSV 模式仍走二进制直传');
  const cman = LAST && JSON.parse(decodeURIComponent(LAST.opt.headers['X-Cmdb-Manifest'] || '""') || '""');
  check(cman && cman.mode === 'file', 'CSV 模式 manifest.mode 仍是 file（未串味成 sqlite）', cman && cman.mode);

  console.log('\n========================================');
  console.log(`CMDB DB UPLOAD: ${PASS} pass, ${FAIL} fail`);
  console.log(PASS > 0 && FAIL === 0 ? 'CMDB DB UPLOAD TEST OK' : 'CMDB DB UPLOAD TEST FAILED');
  process.exit(FAIL === 0 ? 0 : 1);
})();
