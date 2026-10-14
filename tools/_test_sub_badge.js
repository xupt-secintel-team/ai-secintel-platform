/* 预警订阅未读角标（app.js initSubBadge）+ 模块删除订阅确认（m2_enrich panel.js）回归测试
 *
 * 为什么要有这个测试：角标逻辑之前完全没覆盖，而它有两类容易悄悄坏掉的点——
 *   ① 判据写错（比如"有未读就画"→ 删光订阅后红点永久挂着，用户以为是 bug）
 *   ② 时序（用户点了「全部已读」，红点要等 45 秒才消失 → 用户以为功能没生效）
 * 这两类都不会抛异常，只会让界面"看起来不对"，靠人工点击很难稳定复现。
 */
const fs = require('fs');
const path = require('path');

const ROOT = path.dirname(__dirname);
const APP = path.join(ROOT, 'frontend', 'app.js');
const PANEL = path.join(ROOT, 'modules', 'm2_enrich', 'web', 'panel.js');

let PASS = 0, FAIL = 0;
function check(cond, label, extra) {
  if (cond) { PASS++; console.log('  [PASS] ' + label); }
  else { FAIL++; console.log('  [FAIL] ' + label + (extra !== undefined ? '  → ' + extra : '')); }
}

/* ---------- 最小 DOM 桩 ---------- */
function mkEl(tag, id) {
  const L = {};
  return {
    tagName: (tag || 'div').toUpperCase(), id: id || '', innerHTML: '', textContent: '',
    value: '', checked: false, disabled: false, dataset: {}, style: {},
    classList: { _s: new Set(), add(c) { this._s.add(c); }, remove(c) { this._s.delete(c); },
      toggle(c, on) { on ? this._s.add(c) : this._s.delete(c); }, contains(c) { return this._s.has(c); } },
    children: [], files: null,
    addEventListener(e, f) { (L[e] = L[e] || []).push(f); },
    removeEventListener() {}, appendChild(c) { this.children.push(c); return c; },
    removeChild(c) { const i = this.children.indexOf(c); if (i >= 0) this.children.splice(i, 1); },
    remove() { if (this.parent) this.parent.removeChild(this); },
    click() {}, closest() { return null; }, contains() { return false; },
    querySelector() { return null; }, querySelectorAll() { return []; },
    _l: L,
  };
}

/* rail-item 的桩：能按 class 找到 badge 子元素，模拟 appendChild/remove */
function mkRailItem() {
  const el = mkEl('button');
  el.className = 'rail-item';
  el.querySelector = (s) => el.children.find((c) => c.className === s.replace('.', '')) || null;
  el.querySelectorAll = (s) => el.children.filter((c) => c.className === s.replace('.', ''));
  el.appendChild = (c) => { c.parent = el; el.children.push(c); return c; };
  el.removeChild = (c) => { const i = el.children.indexOf(c); if (i >= 0) el.children.splice(i, 1); };
  return el;
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

/* 从 app.js 里抠出 initSubBadge 的源码（它是模块私有的，不导出） */
function extractInitSubBadge() {
  const src = fs.readFileSync(APP, 'utf8');
  const start = src.indexOf('function initSubBadge()');
  if (start < 0) throw new Error('app.js 里找不到 initSubBadge');
  /* 从函数声明起 brace-match 到函数结束 */
  let i = src.indexOf('{', start), depth = 0;
  for (; i < src.length; i++) {
    if (src[i] === '{') depth++;
    else if (src[i] === '}') { depth--; if (!depth) { i++; break; } }
  }
  return src.slice(start, i);
}

async function runBadge(fnSrc, subscribeResponses) {
  const rail = mkRailItem();
  let idx = 0;
  const AISEC = {};
  const doc = { querySelector: (s) => (s === '.rail-item[data-view="enrich"]' ? rail : null) };
  const fakeDoc = {
    querySelector: (s) => (s === '.rail-item[data-view="enrich"]' ? rail : null),
    querySelectorAll: () => [],
    createElement: (t) => mkEl(t),
    getElementById: () => null,
  };
  const api = {
    document: fakeDoc,
    window: {},
    setInterval: () => 0,          /* 别真起定时器 */
    clearInterval: () => {},
    fetch: () => {
      const body = subscribeResponses[Math.min(idx++, subscribeResponses.length - 1)];
      return Promise.resolve({ ok: true, json: () => Promise.resolve(body) });
    },
    console,
  };
  api.window.document = fakeDoc;
  api.AISEC = AISEC;
  const vm = require('vm');
  const ctx = vm.createContext(api);
  vm.runInContext(fnSrc + '\n;initSubBadge();', ctx);
  await sleep(30);
  return { rail, AISEC };
}

(async () => {
  console.log('\n=== ① 正常场景：有订阅 + 有未读 → 画角标 ===');
  {
    const { rail, AISEC } = await runBadge(extractInitSubBadge(), [
      { ok: true, status: { subs: 1, enabled: 1, alerts: 32, unread: 3 } },
    ]);
    const b = rail.children[0];
    check(!!b && b.className === 'rail-badge', 'subs=1 & unread=3 时创建了角标', JSON.stringify(rail.children.map(c => c.className)));
    check(b && b.textContent === '3', '角标数字 = 未读条数', b && b.textContent);
    check(typeof AISEC.refreshSubBadge === 'function', '暴露了 refreshSubBadge 供模块调用');
  }

  console.log('\n=== ② 用户要求：订阅数为 0 时不显示角标 ===');
  {
    const { rail } = await runBadge(extractInitSubBadge(), [
      { ok: true, status: { subs: 0, enabled: 0, alerts: 29, unread: 1 } },
    ]);
    check(rail.children.length === 0,
          'subs=0（哪怕还有 1 条历史未读）→ 不画角标',
          JSON.stringify(rail.children.map(c => c.className + ':' + c.textContent)));
  }

  console.log('\n=== ③ 反向：先有角标，订阅被删光后要移除 ===');
  {
    /* 第一次 tick 有订阅有未读 → 角标出现；再手动触发一次（订阅已删光）→ 角标消失 */
    const rail = mkRailItem();
    const seq = [
      { ok: true, status: { subs: 1, enabled: 1, alerts: 32, unread: 3 } },
      { ok: true, status: { subs: 0, enabled: 0, alerts: 32, unread: 3 } },
    ];
    let idx = 0;
    const fakeDoc = {
      querySelector: (s) => (s === '.rail-item[data-view="enrich"]' ? rail : null),
      querySelectorAll: () => [], createElement: (t) => mkEl(t), getElementById: () => null,
    };
    const AISEC = {};
    const vm = require('vm');
    const ctx = vm.createContext({
      document: fakeDoc, window: { document: fakeDoc }, setInterval: () => 0, clearInterval: () => {},
      console, AISEC,
      fetch: () => Promise.resolve({ ok: true, json: () => Promise.resolve(seq[Math.min(idx++, seq.length - 1)]) }),
    });
    vm.runInContext(extractInitSubBadge() + '\n;initSubBadge();', ctx);
    await sleep(30);
    check(rail.children.length === 1, '初始（subs=1）有角标', rail.children.length);
    await AISEC.refreshSubBadge();          /* 模拟用户删掉最后一个订阅后模块触发刷新 */
    await sleep(30);
    check(rail.children.length === 0, '删光订阅后再刷新 → 角标已移除（不永久挂着）', rail.children.length);
  }

  console.log('\n=== ④ 边界：unread 为 0 / 接口挂掉 / 字段缺失 ===');
  {
    const cases = [
      [{ ok: true, status: { subs: 1, enabled: 1, alerts: 5, unread: 0 } }, 'unread=0 → 不画'],
      [{ ok: false }, 'ok=false → 不画且不崩'],
      [{}, '空对象 → 不画且不崩'],
      [{ ok: true, status: {} }, 'status 缺字段 → 不画且不崩'],
    ];
    for (const [resp, label] of cases) {
      const { rail } = await runBadge(extractInitSubBadge(), [resp]);
      check(rail.children.length === 0, label, JSON.stringify(rail.children.map((c) => c.className)));
    }
  }

  console.log('\n=== ⑤ 接口抛异常（网络断）→ 移除角标而非永久残留 ===');
  {
    const rail = mkRailItem();
    const AISEC = {};
    const fakeDoc = {
      querySelector: (s) => (s === '.rail-item[data-view="enrich"]' ? rail : null),
      querySelectorAll: () => [], createElement: (t) => mkEl(t), getElementById: () => null,
    };
    const vm = require('vm');
    const ctx = vm.createContext({
      document: fakeDoc, window: { document: fakeDoc }, setInterval: () => 0, clearInterval: () => {},
      console, AISEC,
      fetch: () => Promise.reject(new Error('network down')),
    });
    vm.runInContext(extractInitSubBadge() + '\n;initSubBadge();', ctx);
    await sleep(30);
    check(rail.children.length === 0, 'fetch reject → 无角标且未抛异常', rail.children.length);
  }

  console.log('\n=== ⑥ 超过 99 显示 99+ ===');
  {
    const { rail } = await runBadge(extractInitSubBadge(), [
      { ok: true, status: { subs: 1, enabled: 1, alerts: 300, unread: 1234 } },
    ]);
    check(rail.children[0] && rail.children[0].textContent === '99+',
          'unread=1234 → 显示 99+', rail.children[0] && rail.children[0].textContent);
  }

  console.log('\n=== ⑦ 模块侧：删除订阅前的确认文案 ===');
  {
    const src = fs.readFileSync(PANEL, 'utf8');
    /* 提取删除按钮的处理块 */
    const i = src.indexOf(".asub-del').onclick");
    check(i > 0, 'panel.js 里有删除按钮的 onclick 处理');
    const blk = src.slice(i, i + 1400);
    check(/confirm\(/.test(blk), '删除前有 confirm 二次确认');
    check(/历史告警/.test(blk), '确认文案里说明了「历史告警」会被保留');
    check(/条历史告警/.test(blk) || /un\s*\?/.test(blk), '文案里带未读条数');
    check(/r\s*&&\s*r\.ok/.test(blk) || /\.ok\b/.test(blk), '检查了接口返回 ok，不再无条件 toast 成功');
    check(/refreshSubBadge/.test(src), '模块在 refresh() 里调用了 AISEC.refreshSubBadge');
    /* 未读数要按 sub_id 聚合，不能只算全局总数 */
    check(/unreadBy/.test(blk), '按 sub_id 统计该订阅自己的未读条数（不是用全局 unread）');
  }

  console.log('\n' + '='.repeat(58));
  console.log(`合计 ${PASS + FAIL} 项，通过 ${PASS}，失败 ${FAIL}`);
  process.exit(FAIL ? 1 : 0);
})();