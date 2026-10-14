# -*- coding: utf-8 -*-
"""app.js v11 补丁：toast 堆叠 / 视图方向 / 幽灵字数字 / 搜索清空与最近检索 /
   检查器拖拽调宽 / theme-color 对齐。单次读写。"""
import io, sys, os
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
P = r'C:\Users\丁\Desktop\aisec-D_2.0\frontend\app.js'
s = open(P, encoding='utf-8').read()
orig = s
ok = []

def rep(a, b, label):
    global s
    n = s.count(a)
    if n != 1:
        print(f'!! {label}: 命中 {n} 次（期望 1）')
        return
    s = s.replace(a, b)
    ok.append(label)

# ---- 1. theme-color 与 --bg 对齐 ----
rep("""real === 'light' ? '#f6f3eb' : '#0b0906'""",
    """real === 'light' ? '#f6f3eb' : '#0b0a08'""", 'theme-color')

# ---- 2. toast 堆叠（M5） ----
rep("""/* ============================ 14. 提示条 ============================ */
let tt = null;
function toast(msg, ms) {
  const el = $('toast');
  el.textContent = msg;
  el.classList.add('on');
  clearTimeout(tt);
  tt = setTimeout(() => el.classList.remove('on'), ms || 2600);
}""",
    """/* ============================ 14. 提示条 ============================ */
/* ★ v11（M5）：toast 由「单条覆盖」改为「最多 3 条向上堆叠」。
   原先连点两个按钮时，后一条会直接盖掉前一条 —— 用户永远看不到第一条的结果。 */
const TOAST_MAX = 3;
function toast(msg, ms) {
  const wrap = $('toastwrap') || $('toast');
  if (!wrap) return;
  const el = document.createElement('div');
  el.className = 'toast';
  el.textContent = msg;
  wrap.appendChild(el);
  while (wrap.children.length > TOAST_MAX) wrap.removeChild(wrap.firstElementChild);
  requestAnimationFrame(() => el.classList.add('on'));
  setTimeout(() => {
    el.classList.remove('on');
    setTimeout(() => { if (el.parentNode) el.parentNode.removeChild(el); }, 340);
  }, ms || 2600);
}""", 'toast 堆叠')

# ---- 3. 视图方向（A6） + 幽灵字（O3） ----
rep("""function switchView(id, opts) {
  const item = document.querySelector('.rail-item[data-view="' + id + '"]');
  if (!item) return;
  S.view = id;""",
    """/* ★ v11（A6）：按导航顺序给视图切换一个**方向** —— 往右切从 +22px 推入、
   往左切从 -22px 推入（与 crossfade 叠加），"翻页"因此有了连续感。 */
const VIEW_ORDER = ['search', 'monitor', 'enrich', 'ask'];
function switchView(id, opts) {
  const item = document.querySelector('.rail-item[data-view="' + id + '"]');
  if (!item) return;
  const sgn = (VIEW_ORDER.indexOf(id) - VIEW_ORDER.indexOf(S.view)) < 0 ? -1 : 1;
  document.querySelectorAll('.view').forEach((v) => {
    v.style.setProperty('--vx', (v.dataset.view === id ? sgn : -sgn) * 22 + 'px');
  });
  S.view = id;""", 'switchView 方向')

rep("""  if (typeof TR !== 'undefined' && TR.on) {
    TR.applyView('当前页');
    setTimeout(() => TR.applyView('当前页'), 420);
    setTimeout(() => TR.applyView('当前页'), 1200);
  }
}""",
    """  if (typeof TR !== 'undefined' && TR.on) {
    TR.applyView('当前页');
    setTimeout(() => TR.applyView('当前页'), 420);
    setTimeout(() => TR.applyView('当前页'), 1200);
  }
  updateGhost(id);
}""", 'switchView 幽灵字')

# ---- 4. doSearch 记录最近检索（M3b） ----
rep("""async function doSearch(scroll) {
  S.q = $('q').value.trim();
  S.sel = -1;""",
    """async function doSearch(scroll) {
  S.q = $('q').value.trim();
  S.sel = -1;
  if (S.q) pushRecent(S.q);         /* ★ v11（M3b）：最近检索 */""", 'doSearch pushRecent')

# ---- 5. 搜索清空 + 最近检索渲染（M3） ----
rep("""  $('spcollapse').onclick = () => setSidePanel(false);""",
    """  /* ★ v11（M3）：搜索框清空（×）与「最近检索」快捷词 */
  const sb = document.querySelector('.searchbar');
  const syncQ = () => { if (sb) sb.classList.toggle('has-q', !!$('q').value); };
  if ($('sbclear')) $('sbclear').onclick = () => {
    $('q').value = ''; hideSug(); syncQ(); $('q').focus();
  };
  $('q').addEventListener('input', syncQ);
  syncQ();
  renderRecent();
  $('spcollapse').onclick = () => setSidePanel(false);""", '搜索清空')

# ---- 6. 首屏初始化：检查器拖宽 ----
rep("""  repositionSegs();
  initRail();
  initSubBadge();""",
    """  repositionSegs();
  initRail();
  initInspGrip();          /* ★ v11（M4）：检查器拖拽调宽 */
  initSubBadge();""", 'init 调用 initInspGrip')

# ---- 7. renderTop 末尾刷新幽灵字 ----
rep("""  $('topstat').querySelectorAll('b[data-n]').forEach((b) => tweenNum(b, +b.dataset.n));
}""",
    """  $('topstat').querySelectorAll('b[data-n]').forEach((b) => tweenNum(b, +b.dataset.n));
  updateGhost('search');
}""", 'renderTop 幽灵字')

# ---- 8. renderMonitor 末尾写入实时条目数 ----
rep("""  requestAnimationFrame(() => repositionSegs());
}

/* ============================ 12. 情报富化台（视图三） ============================ */""",
    """  updateGhost('monitor', live ? (live.live_docs != null ? live.live_docs : live.added_total) : null);
  requestAnimationFrame(() => repositionSegs());
}

/* ============================ 12. 情报富化台（视图三） ============================ */""", 'renderMonitor 幽灵字')

# ---- 9. 新增函数块 ----
NEW = """/* ============================ 14c. v11 纪律层（前端） ============================
   O3 幽灵字承载数字 · M3 最近检索 · M4 检查器拖拽调宽。纯前端，不动任何数据流。 */

/* ★ O3：幽灵字从「装饰词」升级为「本视图第一关键数字」的载体。
   原先 SEARCH / MONITOR / ENRICH / ASK 只是描边大字，不承载任何信息；
   现在下行显示本视图的第一关键数字（检索=语料总量、监测=实时条目、
   富化=在野利用、问答=知识条目），随数据与视图切换实时更新。 */
const GHOST_KEY = { search: 'total', monitor: 'live', enrich: 'exploited', ask: 'knowledge' };
function updateGhost(view, override) {
  const id = view || S.view || 'search';
  const el = document.querySelector('.view[data-view="' + id + '"] .vh-ghost b');
  if (!el) return;
  let v = override;
  if (v == null) {
    const s = S.stats || {};
    const map = { total: s.total, live: s.total, exploited: s.exploited, knowledge: s.knowledge };
    v = map[GHOST_KEY[id]];
  }
  if (v == null || isNaN(+v)) { el.textContent = ''; delete el.dataset.v; return; }
  el.textContent = num(+v);
  el.dataset.v = String(+v);
}

/* ★ M3b：最近 5 条检索词（本地持久化，不涉及后端） */
const RECENT_KEY = 'asi-recent';
function getRecent() { try { return JSON.parse(localStorage.getItem(RECENT_KEY) || '[]') || []; } catch (e) { return []; } }
function pushRecent(q) {
  q = String(q || '').trim();
  if (!q) return;
  let a = getRecent().filter((x) => x !== q);
  a.unshift(q);
  a = a.slice(0, 5);
  try { localStorage.setItem(RECENT_KEY, JSON.stringify(a)); } catch (e) {}
  renderRecent();
}
function renderRecent() {
  const box = $('sbrecent');
  if (!box) return;
  const a = getRecent();
  if (!a.length) { box.innerHTML = ''; return; }
  box.innerHTML = '<span class="lbl">最近</span>'
    + a.map((q) => `<span class="rq" data-q="${esc(q)}" title="${esc(q)}">${esc(q)}</span>`).join('');
  box.querySelectorAll('.rq').forEach((el) => {
    el.onclick = () => { $('q').value = el.dataset.q; S.page = 1; doSearch(true); };
  });
}

/* ★ M4：情报检查器拖拽调宽（桌面端内联模式才有）+ 双击复位。
   宽度写在内联 --inspw 上；窄屏（≤1200px，检查器是浮层）一律忽略。 */
function initInspGrip() {
  const grip = $('inspgrip'), stage = $('stage'), insp = $('inspector');
  if (!grip || !stage || !insp) return;
  const KEY = 'asi-inspw', MIN = 360, MAX = 960, NARROW = 1200;
  const setW = (w) => {
    if (w && window.innerWidth > NARROW) stage.style.setProperty('--inspw', w + 'px');
    else stage.style.removeProperty('--inspw');
  };
  try {
    const w = parseInt(localStorage.getItem(KEY) || '', 10);
    if (w >= MIN && w <= MAX) setW(w);
  } catch (e) {}
  /* 窗口跨越断点时清掉内联宽度，交回 CSS 接管 */
  window.addEventListener('resize', () => setW(parseInt(stage.style.getPropertyValue('--inspw'), 10) || 0), { passive: true });
  grip.addEventListener('dblclick', () => {
    stage.style.removeProperty('--inspw');
    try { localStorage.removeItem(KEY); } catch (e) {}
    toast('检查器宽度已复位');
  });
  grip.addEventListener('pointerdown', (ev) => {
    if (window.innerWidth <= NARROW) return;
    ev.preventDefault();
    grip.classList.add('on');
    try { grip.setPointerCapture(ev.pointerId); } catch (e) {}
    const move = (e2) => {
      const w = Math.min(MAX, Math.max(MIN, Math.round(insp.getBoundingClientRect().right - e2.clientX)));
      stage.style.setProperty('--inspw', w + 'px');
    };
    const up = () => {
      grip.classList.remove('on');
      grip.removeEventListener('pointermove', move);
      grip.removeEventListener('pointerup', up);
      grip.removeEventListener('pointercancel', up);
      try {
        const w = parseInt(stage.style.getPropertyValue('--inspw'), 10);
        if (w) localStorage.setItem(KEY, String(w));
      } catch (e) {}
      requestAnimationFrame(() => repositionSegs());
    };
    grip.addEventListener('pointermove', move);
    grip.addEventListener('pointerup', up);
    grip.addEventListener('pointercancel', up);
  });
}

"""
rep("""/* ============================ 15. 启动 ============================ */""",
    NEW + """/* ============================ 15. 启动 ============================ */""", 'v11 函数块')

if s != orig:
    open(P, 'w', encoding='utf-8', newline='').write(s)
print('完成：', ', '.join(ok), f'| Δ{len(s)-len(orig):+d}B')
