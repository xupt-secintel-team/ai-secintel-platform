/* ============================================================================
   AI-SecIntel 控制台 · 外壳逻辑 v4 —— frontend/app.js
   ----------------------------------------------------------------------------
   与 v3 的差别不是"改了几处"，而是骨架重写：
     · 左侧图标导航栏 + 顶部命令栏(⌘K) + 三视图工作区 + 右侧情报检查器
     · 视图切换、指示块滑移、卡片阶梯入场、数字滚动、图谱描线等动效全部新增
     · 新增「实时监测台」「情报富化台」两个由主体渲染的视图（数据来自模块接口）
     · 详情从"整屏抽屉"改为"就地检查器"（窄屏自动退回浮层）

   ⚠ 模块契约一个都没动（这是三个模块能整包替换的前提，别改）：
     AISEC.register({id, init, sideSections, sideMounted, detailSections, detailMounted})
     全局可用：$ · esc · toast · S · TYPE_META · openDetail · doSearch · renderTop · renderSide · link
     固定 id：livewrap/livestat · refbtn/refstat · side · dh/db · mask · toast · q/expcbx/go/hints/qparse/sug
   ============================================================================ */

/* ============================ 1. 基础工具 ============================ */
const $ = (id) => document.getElementById(id);
const esc = (s) => String(s == null ? '' : s)
  .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
  .replace(/"/g, '&quot;');
/* ★ cvss 规范化（实测坑）：后端 cvss 字段有**两种形态** ——
   · 检索/详情接口（/api/search、/api/detail、/api/hybrid_search）：dict
     {score, severity, vector, version, exploitability, impact}
   · 问答证据（/api/chat 的 evidence[]、related[]、sources[]）：裸 float（如 9.8）
   直接 `esc(x)` 遇到 dict 会渲染出 "[object Object]"（String({}) 的结果）。
   前端所有展示 CVSS 的地方统一走这里 —— 取分值，取不到给空串。 */
const cvssNum = (v) => {
  if (v == null) return '';
  if (typeof v === 'object') {
    const s = v.score != null ? v.score : v.cvss;
    return s == null ? '' : String(s);
  }
  return String(v);
};
/* 严重度也一并规范化：dict 形态从 cvss.severity 取，float 形态请调用方另传 */
const cvssSev = (v, fallback) => {
  if (v && typeof v === 'object' && v.severity) return String(v.severity);
  return fallback == null ? '' : String(fallback);
};
const fmt = (n) => (n == null ? '—' : n);
const pct = (v) => esc(v);
const RM = !!(window.matchMedia && matchMedia('(prefers-reduced-motion: reduce)').matches);
/* 严重度白名单：severity 会被拼进 class="badge ${sev}"，未白名单化等于把
   属性逃逸开在徽章上（m2_enrich/panel.js:190 已记录过这个坑）。 */
const SEV_OK = new Set(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN', 'NONE', '']);
/* severity 会进 class 属性，统一走这个函数白名单化后再用 */
const sevBadge = (v) => {
  const s = String(v == null ? '' : v).toUpperCase();
  return SEV_OK.has(s) ? (s || 'UNKNOWN') : 'UNKNOWN';
};
const debounce = (fn, ms) => { let t; return (...a) => { clearTimeout(t); t = setTimeout(() => fn(...a), ms); }; };
/* 千分位（统计数字用，避免 8 万多条写成 81234） */
const num = (n) => (n == null || isNaN(n)) ? '—' : (+n).toLocaleString();

/* 数字滚动：rAF 补间，只改 textContent；不做 MutationObserver，避免与 30s 刷新互相触发 */
const EASE_OUT_EXPO = (t) => (t >= 1 ? 1 : 1 - Math.pow(2, -10 * t));
function tweenNum(el, to) {
  if (!el) return;
  const target = Number(to);
  if (!isFinite(target)) { el.textContent = fmt(to); return; }
  const from = Number(el.dataset.v || 0);
  el.dataset.v = String(target);
  if (RM || from === target) { el.textContent = num(target); return; }
  if (el._raf) cancelAnimationFrame(el._raf);
  const t0 = performance.now(), dur = 620;
  const step = (now) => {
    const k = Math.min(1, (now - t0) / dur);
    el.textContent = num(Math.round(from + (target - from) * EASE_OUT_EXPO(k)));
    if (k < 1) el._raf = requestAnimationFrame(step); else { el.textContent = num(target); el._raf = null; }
  };
  el._raf = requestAnimationFrame(step);
}

/* 条形图入场：先 0 宽渲染，下一帧写入目标宽度，让 CSS 的 width 过渡真正播出来 */
function animateBars(root) {
  const bars = (root || document).querySelectorAll('[data-w]');
  if (!bars.length) return;
  requestAnimationFrame(() => bars.forEach((b) => {
    b.style.width = b.dataset.w + '%';
    delete b.dataset.w;
  }));
}

/* 复制到剪贴板（带一个「✓」回执，不弹窗不打断） */
async function copyText(text, el) {
  try {
    await navigator.clipboard.writeText(text);
    toast('已复制：' + text);
    if (el) {
      el.classList.add('copied');
      setTimeout(() => el.classList.remove('copied'), 900);
    }
  } catch (e) { toast('复制失败，请手动选中：' + text); }
}

/* 视口宽度断点（检查器是否内联、遮罩是否出现） */
const isNarrow = () => window.innerWidth <= 1280;

/* ============================ 2. 状态与常量 ============================ */
const S = {
  q: '', page: 1, size: 12, sort: 'relevance',
  expand: (localStorage.getItem('asi_expand') ?? '1') === '1',
  f: { severity: [], category: [], source: [], scope: [], exploited: false, poc: false, paper: false,
       cvss_min: '', year_from: '', year_to: '' },
  last: null, stats: null,
  view: 'search', sel: -1, monLoaded: false, enLoaded: false, enf: 'exploited',
};

/* 知识类条目的类型徽章（m1 的实时列表直接用 TYPE_META，字段名不能改） */
const TYPE_META = {
  knowledge: { label: 'ATLAS 知识', tag: '威胁技术', fg: '#93b1ff', bd: 'rgba(77,124,254,.48)', bg: 'rgba(77,124,254,.13)', idc: '#6b93ff' },
  advisory: { label: 'GitHub 供应链公告', tag: '供应链', fg: '#e0bd6a', bd: 'rgba(212,167,44,.5)', bg: 'rgba(212,167,44,.13)', idc: '#d4a72c' },
  repo: { label: 'GitHub 工具仓库', tag: '安全工具', fg: '#7fd894', bd: 'rgba(63,185,80,.45)', bg: 'rgba(63,185,80,.13)', idc: '#3fb950' },
  article: { label: 'CSDN 社区文章', tag: '社区文章', fg: '#b9c2cd', bd: 'rgba(255,255,255,.16)', bg: 'rgba(255,255,255,.05)', idc: '#8a929c' },
  paper: { label: '学术论文', tag: '论文', fg: '#ff9b9f', bd: 'rgba(240,85,93,.42)', bg: 'rgba(240,85,93,.13)', idc: '#f0555d' },
};
const typeBadge = (t) => {
  const m = TYPE_META[t];
  return m ? `<span class="badge" style="color:${m.fg};border-color:${m.bd};background:${m.bg}">${m.label}</span>` : '';
};
/* 快车道实时情报（id 形如 LIVE:BLOG:…）：列表里显示「来源 + 实时情报」，原标识只放进 title */
const isLive = (x) => String((x && x.id) || '').startsWith('LIVE:');
const LIVE_META = { fg: '#7fd894', bd: 'rgba(63,185,80,.45)', bg: 'rgba(63,185,80,.13)', idc: '#3fb950' };
const liveBadge = () => `<span class="badge" style="color:${LIVE_META.fg};border-color:${LIVE_META.bd};background:${LIVE_META.bg}">⚡ 实时情报</span>`;
const liveName = (x) => (x.sources || [])[0] || x.kind || '实时情报';

/* 关系图谱配色：只在图里出现的数据色 */
const GCAT = ['#4d7cfe', '#38bdf8', '#3fb950', '#d4a72c', '#f0883e', '#f0555d', '#a78bfa', '#8a929c', '#22c55e'];

/* 模块前端注册中心 —— 主体提供，模块只往里注册（见 modules/<id>/web/panel.js） */
const AISEC = {
  modules: {}, order: [],
  register(mod) {
    if (!mod || !mod.id) return;
    if (!this.modules[mod.id]) this.order.push(mod.id);
    this.modules[mod.id] = mod;
    console.log('[module] 已注册前端：' + mod.id + (mod.name ? '（' + mod.name + '）' : ''));
  },
  list() { return this.order.map((id) => this.modules[id]).filter(Boolean); },
  collect(fn, ...args) {
    const out = [];
    for (const id of this.order) {
      const m = this.modules[id];
      if (m && typeof m[fn] === 'function') {
        try { const v = m[fn](...args); if (v != null) out.push({ mod: m, value: v }); }
        catch (e) { console.error('[module] ' + id + '.' + fn + ' 出错', e); }
      }
    }
    return out;
  },
  call(fn, ...args) { this.collect(fn, ...args); },
};
window.AISEC = AISEC;

/* ============================ 3. 主题 / 字号 ============================ */
const THEME_KEY = 'asi-theme-mode';
const THEME_LABEL = { dark: '深色', light: '浅色', auto: '跟随系统' };

function resolvedTheme(mode) {
  if (mode === 'auto') return (window.matchMedia && matchMedia('(prefers-color-scheme: light)').matches) ? 'light' : 'dark';
  return mode === 'light' ? 'light' : 'dark';
}
function applyTheme(mode) {
  const real = resolvedTheme(mode);
  document.documentElement.setAttribute('data-theme', real);
  document.querySelector('meta[name=theme-color]')?.setAttribute('content', real === 'light' ? '#f5f6f8' : '#0a0b0c');
  try { localStorage.setItem(THEME_KEY, mode); localStorage.setItem('asi-theme', real); } catch (e) {}
  S.themeMode = mode;
  const b = $('themebtn');
  if (b) { b.classList.toggle('on', real === 'light'); b.title = '主题：' + THEME_LABEL[mode] + '（点击切换）'; }
}
/* 明暗切换用 View Transitions 做整页交叉淡入（Edge/Chrome 原生支持，退化就是瞬间切换） */
function setTheme(mode, animate) {
  const run = () => applyTheme(mode);
  if (animate !== false && !RM && document.startViewTransition) document.startViewTransition(run);
  else run();
}
function cycleTheme() {
  const order = ['dark', 'light', 'auto'];
  const i = order.indexOf(S.themeMode || 'dark');
  const next = order[(i + 1) % order.length];
  setTheme(next);
  toast('主题：' + THEME_LABEL[next]);
}
function initTheme() {
  let mode = 'dark';
  try { mode = localStorage.getItem(THEME_KEY) || localStorage.getItem('asi-theme') || 'dark'; } catch (e) {}
  applyTheme(mode);
  $('themebtn').onclick = () => cycleTheme();
  /* 「字号 A / A」与「译」：v3 就有这两个按钮的绑定，v4 重写时漏了 —— 补回来 */
  if ($('z1')) $('z1').onclick = () => setZoom(false);
  if ($('z2')) $('z2').onclick = () => setZoom(true);
  if ($('trtgl')) $('trtgl').onclick = () => TR.toggle();
  /* 启动时恢复上次的字号选择（静默，不弹 toast） */
  try { if (localStorage.getItem('asi-zoom') === '1') setZoom(true, true); } catch (e) {}
  if (window.matchMedia) {
    matchMedia('(prefers-color-scheme: light)').addEventListener?.('change', () => {
      if (S.themeMode === 'auto') applyTheme('auto');
    });
  }
}
/* 阅读字号（沿用旧版行为与键名）；quiet=true 用于启动时静默恢复 */
function setZoom(big, quiet) {
  document.body.classList.toggle('zl', big);
  $('z1').classList.toggle('on', !big);
  $('z2').classList.toggle('on', big);
  try { localStorage.setItem('asi-zoom', big ? '1' : '0'); } catch (e) {}
  requestAnimationFrame(() => repositionSegs());
  if (!quiet) toast(big ? '浏览方式：精读（大字距 · 摘要全文 · 正文栏限宽）' : '浏览方式：速览（条目紧凑 · 摘要两行）', 3600);
}

/* ============================ 4. 视图切换 / 导航栏指示块 ============================ */
function moveRailPill(el) {
  const pill = $('railpill'), nav = $('railnav');
  if (!pill || !nav || !el) return;
  const nb = nav.getBoundingClientRect(), b = el.getBoundingClientRect();
  if (!b.height) return;                       /* 窄屏 rail 变成横排，指示块隐藏 */
  pill.style.height = b.height + 'px';
  pill.style.transform = 'translateY(' + Math.round(b.top - nb.top) + 'px)';
}
function switchView(id, opts) {
  const item = document.querySelector('.rail-item[data-view="' + id + '"]');
  if (!item) return;
  S.view = id;
  document.querySelectorAll('.view').forEach((v) => v.classList.toggle('on', v.dataset.view === id));
  document.querySelectorAll('.rail-item').forEach((b) => b.classList.toggle('on', b === item));
  $('crumb').textContent = item.dataset.label || '';
  $('crumbsub').textContent = item.dataset.sub || '';
  moveRailPill(item);
  try { localStorage.setItem('asi-view', id); } catch (e) {}
  if (id === 'monitor' && (!S.monLoaded || (opts && opts.force))) { S.monLoaded = true; renderMonitor(); }
  if (id === 'enrich' && !S.enLoaded) { S.enLoaded = true; renderEnrich(); }
  /* 富化台的筛选分段在隐藏视图里量不到宽度：切进来后补量一次指示块 */
  if (id === 'enrich') requestAnimationFrame(() => repositionSegs());
  if (id === 'search') requestAnimationFrame(() => repositionSegs());
  if (id === 'ask' && !RM) {
    const q = $('qa-q'); if (q) setTimeout(() => q.focus({ preventScroll: true }), 220);
  }
  /* 切视图时收起浮层，避免"新页面还挂着旧弹层" */
  closePalette(); closeHelp();
  /* 「译」开着就自动翻这一屏（2026-10-07：原来只在出检索结果和开详情时翻，
     切到监测台/日报/富化台一律不翻 —— 用户看到的正是"日报整页还是英文"）。
     各视图的 render* 是异步取数后重绘的，所以补一次延时扫描。 */
  if (typeof TR !== 'undefined' && TR.on) {
    TR.applyView('当前页');
    setTimeout(() => TR.applyView('当前页'), 420);
    setTimeout(() => TR.applyView('当前页'), 1200);
  }
}
function initRail() {
  document.querySelectorAll('.rail-item').forEach((b) => {
    b.onclick = () => switchView(b.dataset.view);
  });
  let v = 'search';
  try {
    /* 深链优先：?view=enrich 可直接打开某个视图（演示 / 交付时省去手点，
       也让"新功能在哪个页面"这件事变成一条可分享的链接）。 */
    const pv = new URLSearchParams(location.search).get('view');
    v = pv || localStorage.getItem('asi-view') || 'search';
  } catch (e) { v = 'search'; }
  if (!document.querySelector('.view[data-view="' + v + '"]')) v = 'search';
  switchView(v);
  window.addEventListener('resize', debounce(() => {
    moveRailPill(document.querySelector('.rail-item.on'));
    repositionSegs();
  }, 140));
}

/* ============================ 5. 分段控件（指示块滑移） ============================ */
function moveSegThumb(seg) {
  if (!seg) return;
  const on = seg.querySelector('button.on');
  const thumb = seg.querySelector('.seg-thumb');
  if (!on || !thumb) return;
  /* 先用 0 尺寸量一次，避免首帧从 0 宽"拉长"过去 */
  const w = on.offsetWidth;
  thumb.style.width = w + 'px';
  thumb.style.transform = 'translateX(' + (on.offsetLeft - 2) + 'px)';
}
function repositionSegs() {
  document.querySelectorAll('.seg').forEach(moveSegThumb);
}
function bindSeg(seg, onPick) {
  if (!seg) return;
  seg.querySelectorAll('button').forEach((b) => {
    b.onclick = () => {
      seg.querySelectorAll('button').forEach((x) => x.classList.toggle('on', x === b));
      moveSegThumb(seg);
      onPick(b);
    };
  });
}

/* ============================ 6. 命令面板 ⌘K ============================ */
const PAL = { open: false, rows: [], idx: 0, seq: 0 };
const PAL_VIEWS = [
  ['search', '检索工作区', '自然语言检索 / 意图解析 / 结果分面'],
  ['monitor', '实时监测台', '快车道增量同步 · 八源情报流'],
  ['enrich', '情报富化台', '资产风险体检 / 受影响资产 / 测绘语法 / POC'],
  ['ask', '情报问答', 'RAG 多跳 · 引用可回溯'],
];
function palRow(o) { return o; }
function buildPaletteRows(q) {
  const rows = [];
  const ql = q.trim().toLowerCase();
  const hit = (t) => !ql || String(t).toLowerCase().includes(ql);
  PAL_VIEWS.filter(([, t, d]) => hit(t) || hit(d)).forEach(([id, t, d]) => rows.push({
    kind: 'view', ic: '⇥', t, d, run: () => switchView(id),
  }));
  const ops = [
    ['深度增量同步', '/api/refresh POST', () => { const b = $('refbtn'); b ? b.click() : toast('监测模块未加载'); }],
    ['切换明暗主题', THEME_LABEL[S.themeMode || 'dark'], () => cycleTheme()],
    ['切换结果密度', S.dense ? '紧凑' : '舒适', () => {
      const b = document.querySelector('#density button:not(.on)'); b ? b.click() : null;
    }],
    ['导出当前检索报告', 'Markdown', () => $('expbtn').click()],
    ['清除全部筛选条件', '重置', () => $('clr') ? $('clr').click() : null],
    ['收起 / 展开筛选栏', '左栏', () => toggleSide()],
    ['收起 / 展开情报检查器', '右栏', () => { $('stage').classList.contains('insp') ? closeDrawer() : openInspector(); }],
    ['键盘快捷键', '帮助', () => { closePalette(); openHelp(); }],
  ].filter(([t, d]) => hit(t) || hit(d)).map(([t, d, run]) => ({ kind: 'op', ic: '⌘', t, d, run }));
  rows.push(...ops);
  HINTS.slice(0, 10).filter(hit).forEach((t) => rows.push({
    kind: 'q', ic: '⌕', t, d: '示例查询', run: () => { $('q').value = t; switchView('search'); S.page = 1; doSearch(true); },
  }));
  if (q.trim().length >= 1) {
    rows.unshift({
      kind: 'q', ic: '↵', t: '在情报库中检索「' + q.trim() + '」', d: '全文 + 同义词扩展',
      run: () => { $('q').value = q.trim(); switchView('search'); S.page = 1; doSearch(true); },
    });
    (S._sug || []).forEach(([type, x]) => rows.push({
      kind: 'jump', ic: type === 'CVE 编号' ? '＃' : '◦', t: x, d: type,
      run: () => {
        if (/^CVE-/i.test(x)) { switchView('search'); openDetail(x); }
        else { $('q').value = x; switchView('search'); S.page = 1; doSearch(true); }
      },
    }));
  }
  const max = 40;
  return rows.slice(0, max);
}
const palHi = (t, q) => {
  const s = esc(t);
  const qq = q.trim();
  if (!qq) return s;
  const re = new RegExp('(' + qq.replace(/[.*+?^${}()|[\]\\]/g, '\\$&') + ')', 'ig');
  return s.replace(re, '<mark>$1</mark>');
};
function renderPalette() {
  const q = $('palinput').value;
  PAL.rows = buildPaletteRows(q);
  if (PAL.idx >= PAL.rows.length) PAL.idx = 0;
  const groups = { view: '视图', op: '操作', q: '查询', jump: '情报直达' };
  let html = '', cur = '';
  PAL.rows.forEach((r, i) => {
    if (r.kind !== cur) { cur = r.kind; html += `<div class="pal-grp">${groups[cur] || cur}</div>`; }
    html += `<div class="pal-row${i === PAL.idx ? ' on' : ''}" data-i="${i}">
      <span class="pr-ic">${r.ic}</span><span class="pr-t">${palHi(r.t, q)}</span><span class="pr-d">${esc(r.d || '')}</span></div>`;
  });
  if (!PAL.rows.length) html = '<div class="empty" style="padding:30px 10px">没有匹配的命令，直接回车即按此关键词检索</div>';
  $('palbody').innerHTML = html;
  $('palbody').querySelectorAll('.pal-row').forEach((el) => {
    el.onmouseenter = () => { PAL.idx = +el.dataset.i; paintPalActive(); };
    el.onclick = () => runPal(+el.dataset.i);
  });
}
function paintPalActive() {
  const rows = $('palbody').querySelectorAll('.pal-row');
  rows.forEach((el) => el.classList.toggle('on', +el.dataset.i === PAL.idx));
  const on = $('palbody').querySelector('.pal-row.on');
  if (on) on.scrollIntoView({ block: 'nearest' });
}
function runPal(i) {
  const r = PAL.rows[i];
  if (!r) return;
  closePalette();
  setTimeout(() => { try { r.run(); } catch (e) { toast('执行失败：' + e.message); } }, 60);
}
/* 面板里输入时顺便问一次服务端建议（防抖，不阻塞输入） */
const palSuggest = debounce(async (v) => {
  if (!v || v.length < 2) { S._sug = null; return; }
  try {
    const r = await (await fetch('/api/suggest?q=' + encodeURIComponent(v))).json();
    S._sug = [...(r.cves || []).slice(0, 4).map((x) => ['CVE 编号', x]),
              ...(r.products || []).slice(0, 4).map((x) => ['组件', x]),
              ...(r.terms || []).slice(0, 4).map((x) => ['术语', x])];
  } catch (e) { S._sug = null; }
  if (PAL.open) renderPalette();
}, 220);

function openPalette(seed) {
  PAL.open = true;
  $('palettewrap').classList.add('on');
  const inp = $('palinput');
  if (seed != null) inp.value = seed;
  PAL.idx = 0;
  renderPalette();
  setTimeout(() => { inp.focus(); inp.select(); }, 30);
}
function closePalette() {
  if (!PAL.open) return;
  PAL.open = false;
  $('palettewrap').classList.remove('on');
}
function initPalette() {
  $('palettebtn').onclick = () => openPalette('');
  $('palettebtn2').onclick = () => openPalette('');
  $('palettewrap').onclick = (e) => { if (e.target === $('palettewrap')) closePalette(); };
  const inp = $('palinput');
  inp.addEventListener('input', () => { PAL.idx = 0; renderPalette(); palSuggest(inp.value); });
  inp.addEventListener('keydown', (e) => {
    if (e.key === 'ArrowDown') { e.preventDefault(); PAL.idx = Math.min(PAL.idx + 1, PAL.rows.length - 1); paintPalActive(); }
    else if (e.key === 'ArrowUp') { e.preventDefault(); PAL.idx = Math.max(PAL.idx - 1, 0); paintPalActive(); }
    else if (e.key === 'Enter') {
      e.preventDefault();
      const q = inp.value.trim();
      if (PAL.rows.length && !(PAL.rows[0].kind === 'q' && PAL.rows[0].t.indexOf(q) < 0)) runPal(PAL.idx);
      else if (q) { $('q').value = q; switchView('search'); S.page = 1; doSearch(true); closePalette(); }
    }
  });
}
/* 全局快捷键 */
function openHelp() {
  $('helpgrid').innerHTML = HELP_ROWS.map(([k, d]) => `<span>${esc(d)}</span><kbd>${esc(k)}</kbd>`).join('');
  $('helpwrap').classList.add('on');
}
function closeHelp() { $('helpwrap').classList.remove('on'); }
function initHelp() {
  $('helpbtn').onclick = () => openHelp();
  $('helpclose').onclick = () => closeHelp();
  $('helpwrap').onclick = (e) => { if (e.target === $('helpwrap')) closeHelp(); };
}
const HELP_ROWS = [
  ['⌘K / Ctrl+K', '打开命令面板（检索、跳视图、执行操作）'],
  ['/', '聚焦检索输入框'],
  ['↑ ↓ / k j', '在结果列表中上下移动'],
  ['↵', '打开选中情报的检查器'],
  ['Esc', '收起命令面板 / 检查器'],
  ['[', '收起或展开左侧筛选栏'],
  [']', '收起或展开右侧情报检查器'],
  ['t', '切换明暗主题'],
];

/* ============================ 7. 检索 ============================ */
const HINTS = [
  'Ollama 有哪些远程代码执行漏洞',
  '提示词注入的修复建议',
  'SQL注入漏洞与防御',
  'XSS 跨站脚本攻击原理',
  'log4j 漏洞影响哪些版本',
  'vLLM 高危漏洞影响哪些版本',
  '已被在野利用的漏洞',
  '缓冲区溢出与提权',
  '渗透测试开源工具有哪些',
  '内网渗透的中文教程文章',
  '容器逃逸技术',
  '勒索软件最新情报',
  'product:ollama cvss>=9',
  'severity:critical year:>=2025 kev:yes',
  '提示词注入 -rejected year:2024-2026',
  'cwe:CWE-502 type:漏洞',
];

function initSearchUI() {
  $('go').onclick = () => { S.page = 1; doSearch(true); };
  $('expcbx').checked = S.expand;
  $('expcbx').onchange = () => {
    S.expand = $('expcbx').checked;
    try { localStorage.setItem('asi_expand', S.expand ? '1' : '0'); } catch (e) {}
    S.page = 1; doSearch(true);
    toast(S.expand ? '已开启同义词扩展（缩写 / 中英双向）' : '已关闭扩展，按字面精确匹配');
  };
  $('q').addEventListener('keydown', (e) => {
    if (e.key === 'Enter') { S.page = 1; hideSug(); doSearch(true); }
    if (e.key === 'Escape') hideSug();
  });
  const doSug = debounce((v) => suggest(v), 220);
  $('q').addEventListener('input', () => {
    const v = $('q').value.trim();
    if (v.length < 2) return hideSug();
    doSug(v);
  });
  if ($('expbtn')) {
    $('expbtn').onclick = () => {
      const q = $('q').value.trim();
      if (!q) { toast('请先输入检索词，再导出报告'); return; }
      toast('正在生成检索报告…');
      location.href = '/api/export?q=' + encodeURIComponent(q) + '&size=30';
    };
  }
  bindSeg($('sortseg'), (b) => { S.sort = b.dataset.sort; S.page = 1; doSearch(false); });
  bindSeg($('density'), (b) => {
    S.dense = b.dataset.d === 'list';
    document.body.classList.toggle('dense', S.dense);
    try { localStorage.setItem('asi-dense', S.dense ? '1' : '0'); } catch (e) {}
  });
  $('spcollapse').onclick = () => setSidePanel(false);
  $('spopen').onclick = () => setSidePanel(true);
  $('mask').onclick = closeDrawer;
  /* 监测台「刷新视图」/ 富化台筛选分段 / 左下角「检查器」—— v4 重写时漏绑，点击无响应（2026-09-28 修复） */
  if ($('monrefresh')) $('monrefresh').onclick = () => { S.monLoaded = true; renderMonitor(); };
  if ($('enfilt')) bindSeg($('enfilt'), (b) => { S.enf = b.dataset.f || 'exploited'; renderEnrich(); });
  if ($('inspbtn')) $('inspbtn').onclick = () => { $('stage').classList.contains('insp') ? closeDrawer() : openInspector(); };
  const rb = $('resbar'), mn = document.querySelector('.view[data-view="search"] .main');
  if (mn) mn.addEventListener('scroll', () => rb.classList.toggle('stuck', mn.scrollTop > 10), { passive: true });
  document.addEventListener('click', (e) => {
    if (!e.target.closest('#sug') && !e.target.closest('.searchbar')) hideSug();
  });
}
function setSidePanel(open) {
  const v = document.querySelector('.view[data-view="search"]');
  v.classList.toggle('nopanel', !open);
  try { localStorage.setItem('asi-sidepanel', open ? '1' : '0'); } catch (e) {}
  requestAnimationFrame(() => repositionSegs());
}
function toggleSide() {
  const v = document.querySelector('.view[data-view="search"]');
  if (S.view !== 'search') { switchView('search'); setSidePanel(true); return; }
  setSidePanel(v.classList.contains('nopanel'));
}

function renderHints() {
  $('hints').innerHTML = HINTS.slice(0, 8).map((q) => `<span class="hint" data-q="${esc(q)}">${esc(q)}</span>`).join('');
  $('hints').querySelectorAll('.hint').forEach((h) => {
    h.onclick = () => { $('q').value = h.dataset.q; S.page = 1; doSearch(true); };
  });
}

async function suggest(v) {
  try {
    const r = await (await fetch('/api/suggest?q=' + encodeURIComponent(v))).json();
    const items = [...r.cves.map((x) => ['CVE', x]), ...r.products.map((x) => ['组件', x]),
                   ...r.terms.map((x) => ['术语', x]),
                   ...(r.cn_terms || []).map((x) => ['中文', x])].slice(0, 8);
    if (!items.length) return hideSug();
    $('sug').style.display = 'block';
    $('sug').innerHTML = '<div class="body">' + items.map(([t, x]) =>
      `<div class="fchk sugitem" data-x="${esc(x)}"><i class="chip" style="font-size:10px">${t}</i>
       <span style="font-family:var(--mono);font-size:12px">${esc(x)}</span></div>`).join('') + '</div>';
    $('sug').querySelectorAll('.sugitem').forEach((i) => {
      i.onclick = () => { $('q').value = i.dataset.x; hideSug(); S.page = 1; doSearch(true); };
    });
  } catch (e) { /* 建议失败不影响检索 */ }
}
const hideSug = () => { const s = $('sug'); if (s) s.style.display = 'none'; };

function params() {
  const p = new URLSearchParams();
  p.set('q', S.q); p.set('page', S.page); p.set('size', S.size); p.set('sort', S.sort);
  if (!S.expand) p.set('expand', '0');
  S.f.severity.forEach((v) => p.append('severity', v));
  S.f.category.forEach((v) => p.append('category', v));
  S.f.source.forEach((v) => p.append('source', v));
  S.f.scope.forEach((v) => p.append('scope', v));
  if (S.f.exploited) p.set('exploited', '1');
  if (S.f.poc) p.set('poc', '1');
  if (S.f.paper) p.set('paper', '1');
  if (S.f.cvss_min) p.set('cvss_min', S.f.cvss_min);
  if (S.f.year_from) p.set('year_from', S.f.year_from);
  if (S.f.year_to) p.set('year_to', S.f.year_to);
  return p;
}

async function doSearch(scroll) {
  S.q = $('q').value.trim();
  S.sel = -1;
  /* 体验：二次检索不再"清空→骨架→结果"闪一下 —— 有旧结果就把它压暗保留，
     顶部走一条 2px 进度条，新结果到位后整块替换（2026-09-28） */
  const box = $('results');
  const had = box && box.querySelector('.res');
  if (had) { box.classList.add('ld'); $('resbar').classList.add('busy'); }
  else {
    box.innerHTML = Array(4).fill(0).map((_, i) =>
      `<div class="sk" style="animation-delay:${i * 60}ms;height:${118 - i * 6}px"></div>`).join('');
    $('resbar').classList.add('busy');
  }
  $('answer').innerHTML = '';
  $('qparse').innerHTML = '';
  try {
    const r = await (await fetch('/api/search?' + params())).json();
    S.last = r;
    box.classList.remove('ld');
    $('resbar').classList.remove('busy');
    renderParse(r);
    renderAnswer(r);
    renderResults(r);
    renderSide();
    const c = $('count');
    c.innerHTML = `命中 <b>${num(r.total)}</b> 条 &nbsp;·&nbsp; 第 ${r.page}/${r.pages} 页 &nbsp;·&nbsp; <b>${r.elapsed_ms || '—'}</b> ms`
      + (r.cached ? ' &nbsp;·&nbsp; <span class="hitcache" title="命中服务端结果缓存，未重算">缓存</span>' : '');
    renderPager(r);
    const sp = new URLSearchParams();
    if (S.q) sp.set('q', S.q);
    if (S.sort !== 'relevance') sp.set('sort', S.sort);
    if (S.f.severity.length) sp.set('severity', S.f.severity.join(','));
    if (S.f.category.length) sp.set('category', S.f.category.join(','));
    if (S.f.exploited) sp.set('exploited', '1');
    if (S.f.poc) sp.set('poc', '1');
    if (S.f.cvss_min) sp.set('cvss_min', S.f.cvss_min);
    if (S.f.year_from) sp.set('year_from', S.f.year_from);
    if (S.f.year_to) sp.set('year_to', S.f.year_to);
    history.replaceState(null, '', sp.toString() ? '?' + sp.toString() : location.pathname);
    const mn = document.querySelector('.view[data-view="search"] .main');
    if (scroll && mn) mn.scrollTo({ top: 0, behavior: RM ? 'auto' : 'smooth' });
  } catch (e) {
    box.classList.remove('ld');
    $('resbar').classList.remove('busy');
    $('results').innerHTML = `<div class="empty"><div class="big">检索失败</div>${esc(e.message)}</div>`;
  }
}

/* ---------------- 查询解析展示 ---------------- */
function renderParse(r) {
  const a = r.answer, q = r.query;
  const out = [];
  out.push(`<span class="tagx intent">查询意图 <b>${esc(a.intent)}</b></span>`);
  if (q.cn_terms && q.cn_terms.length)
    out.push(`<span class="tagx">识别中文术语 <b>${esc(q.cn_terms.slice(0, 5).join('、'))}</b></span>`);
  if (a.ops && a.ops.length)
    out.push(`<span class="tagx">结构化算子 <b>${esc(a.ops.join(' '))}</b></span>`);
  if (a.must_not && a.must_not.length)
    out.push(`<span class="tagx">排除 <b>${esc(a.must_not.map((x) => '-' + x).join(' '))}</b></span>`);
  if (a.did_you_mean && a.did_you_mean.length) {
    const dm = a.did_you_mean[0];
    out.push(`<span class="tagx dym" title="点击替换为纠错后的查询"
      data-from="${esc(dm.from)}" data-to="${esc(dm.to)}">你是不是想找 <b>${esc(dm.from)} → ${esc(dm.to)}</b></span>`);
  }
  const rows = [];
  (a.expansion || []).forEach((e) => {
    rows.push(`<div class="qpd-row"><span>${esc(e.from)}</span><i>→</i><em>${esc(e.to.join(' / '))}</em></div>`);
  });
  if (q.phrases && q.phrases.length)
    rows.push(`<div class="qpd-row"><span>短语命中</span><i>·</i><em>${esc(q.phrases.join(' / '))}</em></div>`);
  if (a.concepts && a.concepts.length)
    rows.push(`<div class="qpd-row"><span>概念空间</span><i>·</i><em class="cn">${esc(a.concepts.join('、'))}</em></div>`);
  if (rows.length)
    out.push(`<details class="qpd"><summary>语义扩展明细（${rows.length} 组）</summary>
      <div class="qpd-body">${rows.join('')}</div></details>`);

  const rel = [];
  const lowq = (S.q || '').toLowerCase();
  (a.expansion || []).forEach((e) => {
    const from = e.from.replace(/^≈/, '');
    if (from && !lowq.includes(from.toLowerCase())) rel.push(from);
    (e.to || []).slice(0, 2).forEach((t) => {
      if (t && t.length <= 24 && !lowq.includes(t.toLowerCase())) rel.push(t);
    });
  });
  const relUniq = [...new Set(rel)].slice(0, 8);
  if (relUniq.length) {
    out.push(`<span class="tagx relwrap">相关搜索 ${relUniq.map((t) =>
      `<button class="relq" data-q="${esc(t)}">${esc(t)}</button>`).join('')}</span>`);
  }
  $('qparse').innerHTML = out.join('');
  $('qparse').querySelectorAll('.relq').forEach((b) => {
    b.onclick = () => { $('q').value = b.dataset.q; S.page = 1; doSearch(true); };
  });
  const dym = $('qparse').querySelector('.tagx.dym');
  if (dym) dym.onclick = () => {
    const re = new RegExp(dym.dataset.from.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), 'i');
    $('q').value = $('q').value.replace(re, dym.dataset.to);
    S.page = 1; doSearch(true);
  };
}

/* ---------------- 答复卡 ---------------- */
function renderAnswer(r) {
  const a = r.answer, st = a.stats;
  if (!r.total) { $('answer').innerHTML = ''; return; }
  $('answer').innerHTML = `
  <div class="answer">
    <div class="hd">
      <div class="ic">✓</div>
      <b>情报答复 · ${esc(a.intent)}</b>
      <span class="sub">意图驱动 · 证据可回溯 · ${esc(r.query.raw || '全量浏览')}</span>
    </div>
    <div class="body">
      <div class="metrics">
        <span class="metric"><b data-n="${st.total}">0</b>命中</span>
        <span class="metric"><b data-n="${st.critical_high}">0</b>高危/严重</span>
        <span class="metric"><b data-n="${st.exploited}">0</b>在野利用</span>
        <span class="metric"><b data-n="${st.poc}">0</b>含 POC</span>
        <span class="metric"><b data-n="${st.papers}">0</b>关联论文</span>
      </div>
      <ul>${a.summary.map((x) => `<li>${esc(x)}</li>`).join('')}</ul>
    </div>
    <div class="plan">
      <h4>建议处置路径</h4>
      <ol>${a.plan.map((x) => `<li>${esc(x)}</li>`).join('')}</ol>
    </div>
  </div>`;
  $('answer').querySelectorAll('.metric b').forEach((b) => tweenNum(b, +b.dataset.n));
}

/* ---------------- 结果列表 ---------------- */
function hlTitle(title, r) {
  let out = esc(title);
  const q = (r && r.query) || {};
  const terms = new Set();
  Object.keys(q.terms || {}).forEach((t) => {
    if (t.length > 2 || (t.length === 2 && /[^\x00-\x7f]/.test(t))) terms.add(t);
  });
  (q.phrases || []).forEach((p) => terms.add(p));
  const arr = [...terms].filter((t) => t.length >= 2).sort((a, b) => b.length - a.length).slice(0, 40);
  arr.forEach((t) => {
    const re = new RegExp('(' + t.replace(/[.*+?^${}()|[\]\\]/g, '\\$&') + ')', 'gi');
    out = out.replace(re, '<mark>$1</mark>');
  });
  return out;
}

function renderResults(r) {
  if (!r.results.length) {
    $('results').innerHTML = `<div class="empty"><div class="big">没有匹配的情报</div>
      试试更换关键词，或放宽左侧筛选条件</div>`;
    return;
  }
  const maxW = Math.max(1, ...r.results.map((x) =>
    Math.max(1, ...((x.evidence || []).map((e) => e.weight || 0)))));
  $('results').innerHTML = r.results.map((x, i) => {
    const isVuln = x.type === 'vulnerability';
    const tm = TYPE_META[x.type];
    const sev = isVuln ? sevBadge(x.cvss.severity) : '';
    const catColor = x.category_color || '#8a929c';
    const head = isVuln
      ? `<span class="cve" data-copy="${esc(x.id)}" title="点击复制 ${esc(x.id)}">${esc(x.id)}</span>
         <span class="badge ${sev}">${sev}${x.cvss.score != null ? ' ' + x.cvss.score : ''}</span>`
      : isLive(x)
        ? `<span class="cve" style="color:${LIVE_META.idc}" title="实时情报条目 · 原始标识 ${esc(x.id)}">${esc(liveName(x))}</span>${liveBadge()}`
        : `<span class="cve" data-copy="${esc(x.id)}" style="color:${tm ? tm.idc : '#6b93ff'}" title="点击复制标识">${esc(x.id)}</span>${typeBadge(x.type)}`;
    const extra = [];
    if (x.type === 'repo' && x.stars != null) extra.push(`<span class="chip ok">★ ${(+x.stars).toLocaleString()}</span>`);
    if (x.type === 'article' && x.views != null) extra.push(`<span class="chip">阅读 ${(+x.views).toLocaleString()}</span>`);
    if (x.type === 'repo' && x.language) extra.push(`<span class="chip">${esc(x.language)}</span>`);
    return `<div class="res" data-id="${esc(x.id)}" style="--i:${Math.min(i, 14)};--accent:${catColor}">
      <div class="r1">
        ${head}
        <span class="chip cat" style="--c:${catColor}">${esc(x.category)}</span>
        ${x.exploited ? '<span class="chip alert">● 在野利用</span>' : ''}
        ${x.trust_label ? `<span class="chip trust" title="可信度 ${fmt(x.trust_score)}/100 · ${esc(x.cross_label || '')} · 综合置信度 ${fmt(x.confidence)}">◆ ${esc(x.trust_label)}</span>` : ''}
        ${x.cross_verified ? '<span class="chip ok" title="至少两个独立来源交叉确认">✔ 多源交叉</span>' : ''}
        ${x.exploit_score >= 6 ? '<span class="chip alert" title="存在公开可利用代码或已在野利用">高可利用性</span>' : ''}
        ${x.poc_count ? `<span class="chip alert">POC×${x.poc_count}</span>` : ''}
        ${x.paper_count ? `<span class="chip ok">论文×${x.paper_count}</span>` : ''}
        ${extra.join('')}
        ${isVuln ? `<span class="chip">${esc(x.published)}</span>` : (x.risk_tags || []).slice(0, 2).map((t) => `<span class="chip">${esc(t)}</span>`).join('')}
      </div>
      <div class="ttl">${hlTitle(x.title, r)}</div>
      <div class="snip">${x.snippet}</div>
      <div class="r3">
        ${x.products.slice(0, 4).map((p) => `<span class="chip">${esc(p)}</span>`).join('')}
        ${x.cwe.slice(0, 2).map((w) => `<span class="chip">${esc(w.id)}</span>`).join('')}
        <span class="date">${esc(x.sources.join(' · '))}</span>
      </div>
      <div class="why"><span class="whytxt"><b>匹配依据：</b>${esc(x.why)}</span>
        ${x.evidence.map((e) => `<span class="ev"><i style="width:${Math.max(4, Math.round(e.weight / maxW * 34))}px;animation-delay:${Math.min(i, 10) * 30}ms"></i>${esc(e.term)}</span>`).join('')}
      </div>
    </div>`;
  }).join('');
  $('results').querySelectorAll('.res').forEach((el) => {
    el.onclick = (ev) => {
      const cp = ev.target.closest('[data-copy]');
      if (cp) { ev.stopPropagation(); copyText(cp.dataset.copy, cp); return; }
      openDetail(el.dataset.id);
    };
    /* 指针跟随柔光：只写 CSS 变量，rAF 节流，不触发重排 */
    el.addEventListener('pointermove', (ev) => {
      if (el._q) return;
      el._q = true;
      requestAnimationFrame(() => {
        el._q = false;
        const b = el.getBoundingClientRect();
        el.style.setProperty('--mx', Math.round(ev.clientX - b.left) + 'px');
        el.style.setProperty('--my', Math.round(ev.clientY - b.top) + 'px');
      });
    }, { passive: true });
  });
  TR.applyList();
}

/* ---------------- 分页 ---------------- */
function renderPager(r) {
  if (r.pages <= 1) { $('pager').innerHTML = ''; return; }
  const cur = r.page, nums = [];
  for (let i = 1; i <= r.pages; i++) {
    if (i <= 2 || i > r.pages - 2 || Math.abs(i - cur) <= 1) nums.push(i);
  }
  const uniq = [...new Set(nums)].sort((a, b) => a - b);
  let html = `<button class="btn ghost sm" ${cur <= 1 ? 'disabled' : ''} data-p="${cur - 1}">上一页</button>`;
  let prev = 0;
  uniq.forEach((i) => {
    if (prev && i - prev > 1) html += `<span class="pg">…</span>`;
    html += `<button class="btn ${i === cur ? '' : 'ghost'} sm" data-p="${i}">${i}</button>`;
    prev = i;
  });
  html += `<button class="btn ghost sm" ${cur >= r.pages ? 'disabled' : ''} data-p="${cur + 1}">下一页</button>`;
  $('pager').innerHTML = html;
  $('pager').querySelectorAll('button[data-p]').forEach((b) => {
    b.onclick = () => { S.page = +b.dataset.p; doSearch(true); };
  });
}

/* ---------------- 键盘导航（j/k 在结果间移动） ---------------- */
function moveSel(d) {
  const els = [...document.querySelectorAll('#results .res')];
  if (!els.length) return;
  S.sel = Math.max(0, Math.min(els.length - 1, (S.sel < 0 ? (d > 0 ? -1 : 0) : S.sel) + d));
  els.forEach((el, i) => el.classList.toggle('sel', i === S.sel));
  els[S.sel].scrollIntoView({ block: 'nearest', behavior: RM ? 'auto' : 'smooth' });
}
function openSel() {
  const els = [...document.querySelectorAll('#results .res')];
  if (S.sel >= 0 && els[S.sel]) openDetail(els[S.sel].dataset.id);
}

/* ============================ 8. 侧栏筛选 ============================ */
function renderSide() {
  const s = S.stats;
  if (!s) return;
  const f = (S.last && S.last.facets) || null;
  const catCount = mapOf(f ? f.category : s.category.map((c) => [c.name, c.count]));
  const sevCount = mapOf(f ? f.severity : s.severity);
  const srcCount = mapOf(f ? f.source : s.source);

  const sevAll = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN'];
  const cats = s.category.map((c) => c.name);
  const srcAll = (s.source || []).map((x) => x[0]);

  const sideMods = AISEC.collect('sideSections');
  const sideAt = (a) => sideMods.flatMap(({ value }) => (Array.isArray(value) ? value : [value]))
    .filter((x) => x && x.html && (x.anchor || 'top') === a)
    .map((x) => x.html).join('');

  $('side').innerHTML = `
  ${sideAt('top')}

  <div class="card">
    <h3>筛选条件 <button id="clr">清除</button></h3>
    <div class="body" style="padding-top:4px">
      ${(s.scope || []).length > 1 ? `<details class="fgroup" open>
        <summary>情报范围 <span class="fcount">${(s.scope || []).length}</span></summary>
        <div class="fbody">
        ${(s.scope || []).map(([v, c]) => chk('scope', v, v, v === 'AI安全' ? '#4d7cfe' : '#3fb950', (f && f.scope ? mapOf(f.scope)[v] : c), c)).join('')}
        </div></details>` : ''}
      <details class="fgroup" open>
        <summary>风险分类 <span class="fcount">${cats.length}</span></summary>
        <div class="fbody">
        ${cats.map((c) => {
          const col = (s.category.find((x) => x.name === c) || {}).color || '#8a929c';
          const back = (s.category.find((x) => x.name === c) || {}).count || 0;
          return chk('category', c, shortCat(c), col, catCount[c], back);
        }).join('')}
        </div></details>
      <details class="fgroup" open>
        <summary>CVSS 严重度 <span class="fcount">${sevAll.length}</span></summary>
        <div class="fbody">
        ${sevAll.map((v) => chk('severity', v, v, null, sevCount[v], 0)).join('')}
        </div></details>
      <details class="fgroup">
        <summary>数据来源 <span class="fcount">${srcAll.length}</span></summary>
        <div class="fbody tall">
        ${srcAll.map((v) => chk('source', v, v, null, srcCount[v], 0)).join('')}
        </div></details>
      <details class="fgroup" open>
        <summary>可利用性</summary>
        <div class="fbody">
        <label class="switch ${S.f.exploited ? 'on' : ''}" data-sw="exploited"><span>仅看已在野利用</span><i class="tgl"></i></label>
        <label class="switch ${S.f.poc ? 'on' : ''}" data-sw="poc"><span>仅看含 POC/EXP</span><i class="tgl"></i></label>
        <label class="switch ${S.f.paper ? 'on' : ''}" data-sw="paper"><span>仅看有关联论文</span><i class="tgl"></i></label>
        </div></details>
      <details class="fgroup">
        <summary>CVSS 最低分</summary>
        <div class="fbody">
        <div class="flabel"><span>门槛</span><span id="cvlb" style="font-family:var(--mono)">${S.f.cvss_min || '不限'}</span></div>
        <input type="range" min="0" max="10" step="0.5" value="${S.f.cvss_min || 0}" id="cv">
        </div></details>
      <details class="fgroup">
        <summary>发布年份</summary>
        <div class="fbody">
        <div class="rowsel">
          <input id="yf" placeholder="起" value="${esc(S.f.year_from)}">
          <input id="yt" placeholder="止" value="${esc(S.f.year_to)}">
          <button class="btn ghost sm" id="ygo" style="flex:none">应用</button>
        </div>
        </div></details>
    </div>
  </div>

  <div class="card">
    <h3>语料构成 <span style="margin-left:auto;font-family:var(--mono);font-size:10px;color:var(--txt-4)">${num(s.total)} 条</span></h3>
    <div class="body">
      ${(() => {
        const srcs = s.source || [];
        const srow = ([n, c]) => `
        <div style="margin-bottom:9px">
          <div class="mini"><span>${esc(n)}</span><span>${num(c)}</span></div>
          <div class="bar"><i data-w="${Math.round(c / s.total * 100)}"></i></div>
        </div>`;
        const rest = srcs.slice(8);
        return srcs.slice(0, 8).map(srow).join('') + (rest.length ? `<details class="foldmore">
          <summary><span class="fm-closed">展开其余 ${rest.length} 个来源</span><span class="fm-open">收起列表</span></summary>
          <div>${rest.map(srow).join('')}</div>
        </details>` : '');
      })()}
      <div class="mini" style="margin-top:11px"><span>覆盖 AI 相关漏洞</span><span>${num(s.total)}</span></div>
      <div class="mini"><span>自动关联论文</span><span>${num(s.paper_linked)} / ${num(s.papers)}</span></div>
      <div class="mini"><span>情报词项</span><span id="nt">—</span></div>
    </div>
  </div>

  ${sideAt('after-corpus')}

  <div class="card">
    <h3>高发组件 TOP</h3>
    <div class="body">
      ${(() => {
        const ps = s.products || [];
        const mx = ps[0] ? ps[0][1] : 1;
        const prow = ([p, c]) => `
        <div class="prodrow prod" data-p="${esc(p)}" style="margin-bottom:8px">
          <div class="mini"><span>${esc(p)}</span><span>${num(c)}</span></div>
          <div class="bar"><i data-w="${Math.round(c / (mx || 1) * 100)}"></i></div>
        </div>`;
        const rest = ps.slice(6, 30);
        return ps.slice(0, 6).map(prow).join('') + (rest.length ? `<details class="foldmore">
          <summary><span class="fm-closed">展开其余 ${rest.length} 个组件</span><span class="fm-open">收起列表</span></summary>
          <div>${rest.map(prow).join('')}</div>
        </details>` : '');
      })()}
    </div>
  </div>`;

  if ($('nt')) $('nt').textContent = (s.terms || 0).toLocaleString();
  animateBars($('side'));
  /* 模块侧栏卡片渲染完成 → 交给模块自己去拉数据、绑事件（契约） */
  AISEC.call('sideMounted', $('side'));
  if ($('latgo')) $('latgo').onclick = () => {
    document.querySelectorAll('#sortseg button').forEach((x) => x.classList.remove('on'));
    document.querySelector('#sortseg [data-sort=recent]').classList.add('on');
    moveSegThumb($('sortseg'));
    S.sort = 'recent'; S.page = 1; $('q').value = ''; switchView('search'); doSearch(true);
  };
  $('side').querySelectorAll('input[type=checkbox]').forEach((cb) => {
    cb.onchange = () => {
      const k = cb.dataset.k, v = cb.dataset.v;
      const arr = S.f[k];
      const i = arr.indexOf(v);
      if (cb.checked && i < 0) arr.push(v); else if (!cb.checked && i >= 0) arr.splice(i, 1);
      cb.closest('.fchk').classList.toggle('on', cb.checked);
      S.page = 1; doSearch(false);
    };
  });
  $('side').querySelectorAll('.switch').forEach((sw) => {
    sw.onclick = () => {
      const k = sw.dataset.sw; S.f[k] = !S.f[k];
      sw.classList.toggle('on', S.f[k]); S.page = 1; doSearch(false);
    };
  });
  if ($('cv')) {
    $('cv').oninput = (e) => { $('cvlb').textContent = e.target.value == 0 ? '不限' : e.target.value; };
    $('cv').onchange = (e) => { S.f.cvss_min = e.target.value == 0 ? '' : e.target.value; S.page = 1; doSearch(false); };
  }
  if ($('ygo')) $('ygo').onclick = () => { S.f.year_from = $('yf').value.trim(); S.f.year_to = $('yt').value.trim(); S.page = 1; doSearch(false); };
  if ($('clr')) $('clr').onclick = () => {
    S.f = { severity: [], category: [], source: [], scope: [], exploited: false, poc: false, paper: false,
            cvss_min: '', year_from: '', year_to: '' };
    S.page = 1; renderSide(); doSearch(false);
    toast('已清除全部筛选条件');
  };
  $('side').querySelectorAll('.prod').forEach((p) => {
    p.onclick = () => { switchView('search'); $('q').value = p.dataset.p + ' 漏洞'; S.page = 1; doSearch(true); };
  });
}
const mapOf = (arr) => Object.fromEntries(arr || []);
const shortCat = (c) => c.replace(/^[①②③④⑤⑥⑦⑧⑨⑩⑪]\s*/, '');
function chk(k, v, label, color, cnt, back) {
  const on = S.f[k].includes(v);
  const n = cnt == null ? (back || 0) : cnt;
  return `<label class="fchk ${on ? 'on' : ''}">
    <input type="checkbox" data-k="${k}" data-v="${esc(v)}" ${on ? 'checked' : ''}>
    ${color ? `<i class="dot" style="background:${color}"></i>` : ''}
    <span>${esc(label)}</span><span class="n">${num(n)}</span></label>`;
}

/* ============================ 9. 顶栏统计 ============================ */
function renderTop() {
  const s = S.stats; if (!s) return;
  const m = s.meta || {};
  const kpi = (v, l, cls) => `<div class="kv${cls ? ' ' + cls : ''}"><b data-n="${v}">0</b><span>${esc(l)}</span></div>`;
  $('topstat').innerHTML = [
    kpi(s.vulnerabilities, '情报条目'),
    kpi(s.knowledge, '知识条目'),
    kpi(s.total, '语料总量'),
    kpi(s.exploited, '在野利用'),
    kpi(s.poc, '含 POC'),
  ].join('') + `<div class="kv" style="display:flex;align-items:center;gap:7px;justify-content:flex-end">
      <span class="pulse"></span>
      <span style="font-size:10.5px;color:var(--txt-4);font-family:var(--mono)">${esc((m.generated_at || '').replace('T', ' ').slice(0, 16))} 采集</span>
    </div>`;
  $('topstat').querySelectorAll('b[data-n]').forEach((b) => tweenNum(b, +b.dataset.n));
}

/* ============================ 10. 情报检查器（详情） ============================ */
function openInspector() {
  $('stage').classList.add('insp');
  if (isNarrow()) $('mask').classList.add('on');
}
function closeDrawer() {
  $('stage').classList.remove('insp');
  $('mask').classList.remove('on');
}
/* 详情请求序号：连续点两条情报时，后一条可能先返回。
   没有守卫的话，先点的那条**后到**的响应会覆盖当前面板 —— 用户看到的是
   A 的标题配 B 的正文（实测复现）。每次 openDetail 自增，谁的序号过期谁就不渲染。*/
let detailSeq = 0;
async function openDetail(id) {
  const my = ++detailSeq;
  openInspector();
  $('dh').innerHTML = `<h2 title="${esc(id)}">${esc(id)}</h2><span class="chip">加载中…</span>`;
  $('db').innerHTML = '<div class="loading">正在读取富化情报…</div>';
  try {
    const d = await (await fetch('/api/detail?id=' + encodeURIComponent(id))).json();
    if (my !== detailSeq) return;              // 已被更新的请求取代，丢弃
    if (d.error) throw new Error(d.error);
    renderDetail(d, my);
  } catch (e) {
    if (my !== detailSeq) return;
    $('db').innerHTML = `<div class="empty">${esc(e.message)}</div>`;
  }
}
const link = (u) => `<a href="${esc(u)}" target="_blank" rel="noopener noreferrer"><i>↗</i>${esc(u)}</a>`;
const K = (k, v) => `<div class="kv2"><span>${esc(k)}</span><b>${esc(v == null || v === '' ? '—' : v)}</b></div>`;
const KL = (k, v) => `<div class="kv2 long"><span>${esc(k)}</span><b>${esc(v == null || v === '' ? '—' : v)}</b></div>`;

function renderDetail(d, my) {
  const isVuln = d.type === 'vulnerability';
  const cv = d.cvss || {};
  /* severity 进的是 class 属性，必须白名单化：语料里 severity 来自 NVD/GitHub/OSV
     等第三方源，m2_enrich 已经踩过这个坑并做了 sevOf() 白名单（见其 panel.js:190
     注释），主体这两处漏了。命中白名单外值时回落到 UNKNOWN。 */
  const sev = SEV_OK.has(String(cv.severity || '').toUpperCase())
    ? String(cv.severity || '').toUpperCase() || 'UNKNOWN' : 'UNKNOWN';
  const catColor = (d.category || '').includes('①') ? '#6b93ff'
    : (d.category || '').includes('②') ? '#4d7cfe'
    : (d.category || '').includes('③') ? '#3fb950' : '#d4a72c';
  const ovTitle = isLive(d) ? '实时情报摘要'
    : ({ knowledge: '威胁技术说明', advisory: '供应链公告内容',
         repo: '工具仓库简介', article: '社区文章摘要' }[d.type] || '漏洞概述');
  $('dh').innerHTML = `
    <h2 title="${esc(d.id)}">${esc(isLive(d) ? (d.title || liveName(d)) : d.id)}</h2>
    ${isVuln ? `<span class="badge ${sev}">${sev}${cv.score != null ? ' ' + cv.score : ''}</span>`
             : isLive(d) ? liveBadge() : typeBadge(d.type)}
    <span class="chip cat" style="--c:${catColor}">${esc(d.category)}</span>
    ${d.kev && d.kev.exploited ? '<span class="chip alert">● 在野利用</span>' : ''}
    <span class="sp"></span>
    <button class="x" id="dcopy" title="复制标识">⧉</button>
    <button class="x" id="dex" title="导出本条 Markdown 情报报告">⤓</button>
    <button class="x close" id="dx" title="收起检查器（Esc）">✕</button>`;
  $('dx').onclick = closeDrawer;
  $('dex').onclick = () => {
    toast('正在生成本条情报报告…');
    location.href = '/api/export?id=' + encodeURIComponent(d.id);
  };
  $('dcopy').onclick = () => copyText(d.id, null);

  const sec = [];
  sec.push(`<div class="sec"><h4>${esc(ovTitle)}</h4>
    <p class="desc-p">${esc(d.desc)}</p>
    <div class="meta-note">
      <b>判定依据：</b>${esc(d.category_reason || '—')}
      &nbsp;·&nbsp; 风险标签 ${esc((d.risk_tags || []).join('、') || '—')}
    </div></div>`);

  const typeKv = [];
  if (d.type === 'repo') {
    typeKv.push(K('Stars', d.stars != null ? (+d.stars).toLocaleString() : '—'),
                K('主要语言', d.language || '—'), K('最近推送', (d.modified || '').slice(0, 10)));
  }
  if (d.type === 'article') {
    typeKv.push(K('作者', d.author || '—'),
                K('阅读量', d.views != null ? (+d.views).toLocaleString() : '—'));
  }
  sec.push(`<div class="sec"><h4>关键指标</h4><div class="kv-grid">
    ${K('标识', d.id)}
    ${K('类型', d.kind || (isVuln ? '漏洞情报 (CVE)' : '知识条目'))}
    ${K('收录日期', (d.published || '—').slice(0, 10))}
    ${K('最后更新', (d.modified || '').slice(0, 10))}
    ${K('状态', d.status || '—')}
    ${K('CVSS 版本', cv.version || (isVuln ? '—' : '不适用'))}
    ${KL('CVSS 向量', cv.vector || (isVuln ? '—' : '不适用'))}
    ${K('数据来源', (d.sources || []).join(' + '))}
    ${typeKv.join('')}
  </div></div>`);

  if (d.type === 'repo' && (d.repo_topics || []).length) {
    sec.push(`<div class="sec"><h4>仓库标签</h4><div class="kv-grid">
      ${d.repo_topics.map((t) => K('topic', t)).join('')}</div></div>`);
  }

  if (d.kev && d.kev.exploited) {
    sec.push(`<div class="sec"><h4>CISA 在野利用情报</h4><div class="kv-grid">
      ${K('加入清单', d.kev.date_added)}${K('整改截止', d.kev.due_date)}
      ${K('勒索软件关联', d.kev.ransomware)}${K('所属厂商', d.kev.vendor)}
    </div><div class="desc-p" style="margin-top:10px;font-size:13px">
      <b>官方整改要求：</b>${esc(d.kev.required_action || '—')}</div></div>`);
  }

  if (d.remediation && d.remediation.length) {
    sec.push(`<div class="sec"><h4>修复建议（自动生成）</h4>
      <ol class="steps">${d.remediation.map((x) => `<li>${esc(x)}</li>`).join('')}</ol></div>`);
  }

  if (d.atlas && d.atlas.length) {
    sec.push(`<div class="sec"><h4>MITRE ATLAS 威胁技术映射</h4>
      ${d.atlas.map((t) => `<div class="paper">
        <b>${esc(t.id)} ${esc(t.name)}
          <span class="chip" style="margin-left:6px">${esc((t.tactics || []).join(' / '))}</span>
          <span class="chip">匹配置信 ${esc(t.score)}</span></b>
        <p>${esc(t.description)}…</p>
        <div style="margin-top:6px">${t.url ? link(t.url) : ''}</div>
      </div>`).join('')}
      ${d.atlas_evidence && d.atlas_evidence.length
        ? `<div class="meta-note">映射依据：${esc(d.atlas_evidence.join('；'))}</div>` : ''}
    </div>`);
  }

  if (d.atlas_mitigations && d.atlas_mitigations.length) {
    sec.push(`<div class="sec"><h4>ATLAS 官方缓解措施</h4>
      ${d.atlas_mitigations.map((m) => `<div class="paper">
        <b>${esc(m.id)} ${esc(m.name)}
          ${(m.category || []).length ? `<span class="chip" style="margin-left:6px">${esc(m.category.join('/'))}</span>` : ''}</b>
        <p>${esc(m.use || m.description || '')}</p>
        <div style="margin-top:5px">${m.url ? link(m.url) : ''}</div>
      </div>`).join('')}</div>`);
  }

  if (d.atlas_cases && d.atlas_cases.length) {
    sec.push(`<div class="sec"><h4>ATLAS 真实案例（关联攻击链）</h4>
      ${d.atlas_cases.map((c) => `<div class="paper">
        <b>${esc(c.name)}</b>
        <p>${esc(c.summary)}…</p>
        ${(c.references || []).slice(0, 2).map((u) => `<div style="margin-top:4px">${link(u)}</div>`).join('')}
      </div>`).join('')}</div>`);
  }

  if (d.cpe && d.cpe.length) {
    const rows = d.cpe.slice(0, 24).map((m) => {
      let rng = '—';
      if (m.end_excl) rng = `&lt; ${esc(m.end_excl)}`;
      else if (m.end_incl) rng = `&le; ${esc(m.end_incl)}`;
      else if (m.start_incl) rng = `&ge; ${esc(m.start_incl)}`;
      return `<tr><td>${esc(m.vendor)}</td><td>${esc(m.product)}</td><td>${rng}</td></tr>`;
    }).join('');
    sec.push(`<div class="sec"><h4>受影响资产（CPE 解析）</h4>
      <table class="tbl"><thead><tr><th>厂商</th><th>产品</th><th>受影响版本</th></tr></thead>
      <tbody>${rows}</tbody></table></div>`);
  }

  if (d.cwe && d.cwe.length) {
    sec.push(`<div class="sec"><h4>弱点类型 CWE</h4><div class="kv-grid">
      ${d.cwe.map((w) => K(w.id, w.name || '—')).join('')}</div></div>`);
  }

  const groups = [
    ['POC / 利用代码', d.poc_links],
    ['补丁 / 修复提交', d.patch_links],
    [isVuln ? '厂商公告 / 权威公告' : '原文 / 相关链接', d.advisory_links],
    ['OSV 供应链参考', d.osv_refs],
  ].filter((g) => g[1] && g[1].length);
  if (groups.length) {
    sec.push(`<div class="sec"><h4>参考链接（按可利用性分组）</h4>
      ${groups.map(([t, list]) => `<div style="margin-bottom:11px">
        <div class="relgrp">${esc(t)} <span style="color:var(--txt-4)">(${list.length})</span></div>
        <div class="linklist">${list.slice(0, 8).map(link).join('')}</div></div>`).join('')}
      </div>`);
  } else if (d.refs && d.refs.length) {
    sec.push(`<div class="sec"><h4>参考链接</h4><div class="linklist">
      ${d.refs.slice(0, 10).map((r) => link(r.url)).join('')}</div></div>`);
  }

  if (d.papers && d.papers.length) {
    sec.push(`<div class="sec"><h4>关联学术论文（自动关联推理）</h4>
      ${d.papers.map((p) => `<div class="paper">
        <b>${esc(p.title)}</b>
        <p>${esc(p.summary)}…</p>
        <div class="mt">关联依据：${esc((p.match_terms || []).join(' / '))} · 强度 ${esc(p.match_score)} · ${esc(p.published)}</div>
        <div style="margin-top:6px">${link(p.url)}</div>
      </div>`).join('')}</div>`);
  }

  if (d.osv_packages && d.osv_packages.length) {
    sec.push(`<div class="sec"><h4>开源供应链公告覆盖</h4>
      <div class="kv-grid">${d.osv_packages.map((p) => K('OSV 包', p)).join('')}</div>
      ${(d.osv_summaries || []).map((x) => `<div class="meta-note">· ${esc(x)}</div>`).join('')}
    </div>`);
  }

  /* —— 模块贡献的详情区块（m2_enrich 的「受影响资产 / POC 搜索」就在这里）—— */
  const modSecs = [];
  for (const { mod, value } of AISEC.collect('detailSections', d.id, d, isVuln)) {
    for (const x of (Array.isArray(value) ? value : [value])) {
      if (x && x.html) modSecs.push({ ...x, _mod: mod });
    }
  }
  const secAt = (a) => modSecs.filter((x) => (x.anchor || 'before-trust') === a).map((x) => x.html);
  const MOD_SLOT = '\u0000MOD:before-trust\u0000';
  sec.push(MOD_SLOT);

  if (d.trust_score != null || d.confidence != null) {
    const sig = (d.exploit_signals || []).map((s) =>
      `<span class="chip">${esc(s.factor)} +${esc(s.points)}</span>`).join('');
    sec.push(`<div class="sec"><h4>证据可信度与交叉验证</h4>
      <div class="trust-grid">
        <div class="tcell"><b>${fmt(d.confidence)}</b><span>综合置信度</span></div>
        <div class="tcell"><b>${fmt(d.trust_score)}</b><span>${esc(d.trust_label || '可信度')}</span></div>
        <div class="tcell"><b>${fmt(d.cross_count)}</b><span>${esc(d.cross_label || '独立来源')}</span></div>
        <div class="tcell"><b>${fmt(d.exploit_score)}</b><span>${esc(d.exploit_label || '可利用性')}</span></div>
      </div>
      <div class="bar trustbar"><i data-w="${Math.max(2, Math.min(100, d.confidence || 0))}"></i></div>
      <div class="meta-note" style="margin-top:8px">
        <b>独立来源：</b>${esc((d.cross_sources || []).map((s) => s.label + (s.source ? '(' + s.source + ')' : '')).join('、') || '—')}
        &nbsp;·&nbsp; <b>时效因子</b> ${fmt(d.freshness)}
      </div>
      ${sig ? `<div style="margin-top:8px">${sig}</div>` : ''}
    </div>`);
  }

  sec.push(`<div class="sec"><h4>情报关系图谱</h4>
    <div id="graphbox" class="graphbox"><div class="latload">正在构建关系图谱…</div></div></div>`);
  sec.push(`<div class="sec"><h4>相关情报推荐</h4>
    <div id="relbox"><div class="latload">正在检索关联情报…</div></div></div>`);

  const html = [];
  for (const h of sec) {
    if (h === MOD_SLOT) html.push(...secAt('before-trust'));
    else html.push(h);
  }
  html.push(...secAt('end'));
  $('db').innerHTML = html.join('');
  $('db').scrollTop = 0;
  animateBars($('db'));
  AISEC.call('detailMounted', d.id, d, isVuln);
  for (const x of modSecs) if (typeof x.mount === 'function') x.mount(d.id, d, isVuln);
  TR.applyDetail();
  loadGraph(d.id, my);
  loadRelated(d.id, my);
}

/* ---------------- 关系图谱（内联 SVG，零外部依赖） ---------------- */
function graphSVG(g) {
  const W = 660, H = 340, cx = W / 2, cy = H / 2;
  const nodes = g.nodes || [], links = g.links || [];
  const center = nodes.find((n) => n.category === 0) || nodes[0];
  if (!center) return '<div class="latload">暂无关系数据</div>';
  const ring = nodes.filter((n) => n !== center);
  const pos = {};
  const n = ring.length || 1;
  ring.forEach((nd, i) => {
    const ang = -Math.PI / 2 + ((i + 0.5) / n) * Math.PI * 2;
    const k = i % 2 === 0 ? 1 : 0.68;                    /* 两环交错，标签不互相压盖 */
    pos[nd.id] = [cx + Math.cos(ang) * 275 * k, cy + Math.sin(ang) * 132 * k];
  });
  const col = (nd) => GCAT[(nd.category || 0) % GCAT.length];
  /* 边：用 path + pathLength=1 做描线入场（stroke-dashoffset 1→0） */
  const edge = links.map((l, i) => {
    const a = pos[l.source] || [cx, cy];
    const b = pos[l.target];
    if (!b) return '';
    return `<path class="gedge" pathLength="1" d="M${a[0].toFixed(1)} ${a[1].toFixed(1)} L${b[0].toFixed(1)} ${b[1].toFixed(1)}"
      stroke="var(--line-3)" stroke-width="1" fill="none" style="animation-delay:${Math.min(i, 24) * 26}ms"/>`;
  }).join('');
  const dots = ring.map((nd, i) => {
    const [x, y] = pos[nd.id];
    const r = nd.symbolSize ? Math.max(5, nd.symbolSize / 6) : 6;
    return `<g class="gnode" data-id="${esc(nd.id)}" style="animation-delay:${120 + Math.min(i, 20) * 32}ms">
      <circle cx="${x.toFixed(1)}" cy="${y.toFixed(1)}" r="${(r + 5).toFixed(1)}" fill="${col(nd)}" fill-opacity=".08"/>
      <circle cx="${x.toFixed(1)}" cy="${y.toFixed(1)}" r="${r.toFixed(1)}"
        fill="${col(nd)}" fill-opacity=".26" stroke="${col(nd)}" stroke-width="1.4"/>
      <text x="${x.toFixed(1)}" y="${(y - r - 6).toFixed(1)}" text-anchor="middle"
        fill="var(--txt-2)" font-size="10.5">${esc(String(nd.name || nd.id).slice(0, 20))}</text></g>`;
  }).join('');
  const legend = (g.categories || []).map((c, i) =>
    `<span class="lgd"><i style="background:${GCAT[i % GCAT.length]}"></i>${esc(c.name)}</span>`).join('');
  // 多跳关联路径示例（CTI 知识图谱：CVE↔组件↔资产↔攻击技术）
  const hops = (g.path_examples || []).map((p) => `<span class="hopchip">${esc(p)}</span>`).join('');
  return `<svg viewBox="0 0 ${W} ${H}" class="gsvg" role="img" aria-label="情报关系图谱">
      <defs><radialGradient id="gcore" cx="50%" cy="50%" r="50%">
        <stop offset="0%" stop-color="var(--accent)" stop-opacity=".45"/>
        <stop offset="100%" stop-color="var(--accent)" stop-opacity=".04"/></radialGradient></defs>
      ${edge}
      <circle class="gping" cx="${cx}" cy="${cy}" r="46" fill="none" stroke="var(--accent-2)" stroke-width="1"/>
      <circle cx="${cx}" cy="${cy}" r="46" fill="url(#gcore)" stroke="var(--accent-2)" stroke-width="1.4"/>
      <text x="${cx}" y="${cy + 4}" text-anchor="middle" fill="var(--txt)"
        font-size="12" font-family="var(--mono)">${esc(String(center.name || center.id).slice(0, 16))}</text>
      ${dots}
    </svg>
    ${hops ? `<div class="ghops">多跳关联：${hops}</div>` : ''}
    <div class="glegend">${legend}</div>`;
}

async function loadGraph(id, my) {
  const box = $('graphbox');
  if (!box) return;
  try {
    const g = await (await fetch('/api/graph?id=' + encodeURIComponent(id))).json();
    if (my != null && my !== detailSeq) return;   // 已切到别的情报，丢弃过期图谱
    if (g.error) throw new Error(g.error);
    box.innerHTML = graphSVG(g);
  } catch (e) {
    if (my != null && my !== detailSeq) return;
    box.innerHTML = '<div class="latload">关系图谱不可用</div>';
  }
}

/* ---------------- 相关情报推荐 ---------------- */
function relRow(x) {
  return `<div class="relrow" data-id="${esc(x.id)}">
    <span class="rid">${esc(x.id)}</span>
    ${x.cvss != null ? `<span class="badge ${esc(x.severity || 'UNKNOWN')}">${esc(x.severity || '')} ${esc(x.cvss)}</span>` : ''}
    <span class="rtitle">${esc(String(x.title || '').slice(0, 62))}</span>
    ${x.exploited ? '<span class="chip alert">在野</span>' : ''}
    ${x.trust_label ? `<span class="chip trust">${esc(x.trust_label)}</span>` : ''}
    <span class="rwhy">${esc((x.rel_reasons || []).join(' · '))}</span>
  </div>`;
}
async function loadRelated(id, my) {
  const box = $('relbox');
  if (!box) return;
  try {
    const d = await (await fetch('/api/related?id=' + encodeURIComponent(id))).json();
    if (my != null && my !== detailSeq) return;   // 已切到别的情报，丢弃过期推荐
    if (d.error) throw new Error(d.error);
    const groups = [
      ['同受影响组件', d.same_product],
      ['同弱点类型', d.same_cwe],
      ['同攻击技术', d.atlas_related],
      ['同风险分类', d.same_category],
    ].filter((g) => g[1] && g[1].length);
    if (!groups.length) { box.innerHTML = '<div class="latload">未找到显著关联的情报</div>'; return; }
    box.innerHTML = groups.map(([t, list]) => `<div style="margin-bottom:4px">
      <div class="relgrp">${esc(t)} <span style="color:var(--txt-4)">(${list.length})</span></div>
      ${list.map(relRow).join('')}</div>`).join('');
    box.querySelectorAll('.relrow').forEach((el) => { el.onclick = () => openDetail(el.dataset.id); });
  } catch (e) {
    if (my != null && my !== detailSeq) return;
    box.innerHTML = '<div class="latload">关联推荐不可用</div>';
  }
}

/* ============================ 11. 实时监测台（视图二） ============================ */
async function renderMonitor() {
  const box = $('monboard');
  if (!box) return;
  box.innerHTML = '<div class="skboard"><div class="sk"></div><div class="sk"></div></div>';
  const get = async (u) => { try { return await (await fetch(u)).json(); } catch (e) { return null; } };
  const [stats, live, latest, sources] = await Promise.all([
    S.stats ? Promise.resolve(S.stats) : get('/api/stats'),
    get('/api/live'),
    get('/api/latest?n=22'),
    get('/api/sources'),
  ]);
  S.stats = stats || S.stats;

  const kpi = (v, l, cls, t) => `<div class="kpi ${cls || ''}"${t ? ` title="${esc(t)}"` : ''}>
      <span>${esc(l)}</span><b data-n="${v == null ? '' : v}">${v == null ? '—' : '0'}</b><i></i></div>`;
  const liveOk = live && live.enabled;
  const stale = live && (live.age_sec == null || live.age_sec > Math.max(120, (live.interval || 30) * 4));
  const ageTxt = live && live.age_sec != null
    ? (live.age_sec < 60 ? live.age_sec + 's' : live.age_sec < 3600 ? Math.floor(live.age_sec / 60) + 'm' + (live.age_sec % 60) + 's' : Math.floor(live.age_sec / 3600) + 'h')
    : '—';
  const sev = stats ? stats.severity || [] : [];
  const cats = stats ? stats.category || [] : [];
  const maxCat = Math.max(1, ...cats.map((c) => c.count || 0));
  const chans = (sources && sources.channels) || [];

  box.innerHTML = `
  <div class="kpirow">
    ${kpi(stats && stats.total, '语料总量')}
    ${kpi(stats && stats.vulnerabilities, '漏洞情报')}
    ${kpi(stats && stats.knowledge, '知识条目')}
    ${kpi(stats && stats.exploited, '在野利用', 'alert')}
    ${kpi(stats && stats.poc, '含 POC', 'warn')}
    ${kpi(live && (live.live_docs != null ? live.live_docs : live.added_total), '实时情报条目', 'ok')}
  </div>

  <div class="boardgrid">
    <div class="panel" style="animation-delay:40ms">
      <header>最新情报流 <span class="ph-sub">/api/latest · 点击任意条目打开检查器</span></header>
      <div class="pbody"><div class="stream" id="monstream">
        ${(latest && latest.items || []).map((x) => {
          const m = TYPE_META[x.type] || {};
          const hot = x.severity === 'CRITICAL' || x.severity === 'HIGH' || x.exploited;
          return `<div class="streamrow ${hot ? 'hot' : ''}" data-id="${esc(x.id)}" title="${esc(x.title || x.id)}">
            <span class="st-date">${esc((x.published || x.modified || '—').slice(0, 10))}</span>
            ${m.tag ? `<span class="badge" style="color:${m.fg};border-color:${m.bd};background:${m.bg}">${m.tag}</span>` : ''}
            ${x.exploited ? '<span class="badge CRITICAL">在野</span>' : ''}
            ${x.is_new ? '<span class="badge LOW">新</span>' : ''}
            <span class="st-title">${esc((x.title || x.id).slice(0, 90))}</span>
            ${x.cvss != null ? `<span class="st-why">CVSS ${esc(x.cvss)}</span>` : ''}
          </div>`;
        }).join('') || '<div class="latload">最新情报流不可用（情报监测模块可能未加载）</div>'}
      </div></div>
    </div>

    <div style="display:flex;flex-direction:column;gap:12px">
      <div class="panel" style="animation-delay:90ms">
        <header>快车道实时监测 <span class="ph-sub">${liveOk ? (stale ? '数据偏旧' : '运行中') : '未启用'}</span></header>
        <div class="pbody">
          <div class="mini"><span>轮询间隔</span><span>${live ? (live.interval || 30) + 's' : '—'}</span></div>
          <div class="mini" style="margin-top:5px"><span>距上轮</span><span>${esc(ageTxt)}</span></div>
          <div class="mini" style="margin-top:5px"><span>上轮耗时</span><span>${live ? (live.last_ms || 0) + ' ms' : '—'}</span></div>
          <div class="mini" style="margin-top:5px"><span>情报源健康度</span><span>${live && live.feed_total ? (live.feed_ok || 0) + ' / ' + live.feed_total : '—'}</span></div>
          <div class="mini" style="margin-top:5px"><span>实时情报条目</span><span>${live ? num(live.live_docs != null ? live.live_docs : live.added_total || 0) : '—'}</span></div>
          <div class="mini" style="margin-top:4px"><span>本轮会话新增</span><span>${live ? num(live.added_total || 0) : '—'}</span></div>
          <div class="bar" style="margin:9px 0 10px"><i data-w="${live && live.feed_total ? Math.round((live.feed_ok || 0) / live.feed_total * 100) : 0}"></i></div>
          ${live && live.per_source ? Object.keys(live.per_source).map((k) => `
            <div class="mini" style="margin-top:4px"><span>${esc(k)}</span><span>+${live.per_source[k]}</span></div>`).join('') : ''}
          ${live && live.feed_fail && Object.keys(live.feed_fail).length
            ? `<div class="meta-note">未盯上的源（多为境外站点）：${esc(Object.keys(live.feed_fail).slice(0, 6).join('、'))}
               <br>→ 本机开代理后重启服务即可恢复</div>` : ''}
          ${live && live.error ? `<div class="meta-note" style="color:var(--warn)">最近错误：${esc(live.error)}</div>` : ''}
        </div>
      </div>

      <div class="panel" style="animation-delay:140ms">
        <header>风险分类分布 <span class="ph-sub">语料口径</span></header>
        <div class="pbody">
          ${cats.map((c) => `<div class="distrow">
            <span class="dl" title="${esc(c.name)}">${esc(shortCat(c.name))}</span>
            <span class="dbar"><i data-w="${Math.round((c.count || 0) / maxCat * 100)}" style="background:linear-gradient(90deg,${c.color || '#4d7cfe'},color-mix(in srgb,${c.color || '#4d7cfe'} 60%,transparent))"></i></span>
            <span class="dn">${num(c.count)}</span></div>`).join('')}
        </div>
      </div>

      <div class="panel" style="animation-delay:190ms">
        <header>语料类型 / 严重度 / 归档 <span class="ph-sub">/api/stats · /api/sources</span></header>
        <div class="pbody">
          ${(stats && stats.kb_type || []).filter(([t]) => t !== 'knowledge')
            .map(([t, c]) => `<div class="mini" style="margin-bottom:6px" title="${esc((TYPE_META[t] || {}).label || t)}"><span>${esc((TYPE_META[t] || {}).tag || t)}</span><span>${num(c)}</span></div>`).join('')}
          ${sev.map(([k, v]) => `<div class="mini" style="margin-bottom:6px"><span>${esc(k)}</span><span>${num(v)}</span></div>`).join('')}
          ${chans.length ? `<div class="bar" style="margin:4px 0 10px"><i data-w="${Math.min(100, Math.round((sources.archive_total_gb || 0) / (sources.target_gb || 10) * 100))}"></i></div>
            <div class="mini"><span>归档总量</span><span>${(sources.archive_total_gb || 0).toFixed(2)} / ${sources.target_gb || 10} GB</span></div>
            ${chans.map((c) => `<div class="mini" style="margin-top:4px"><span title="${esc(c.label)}">${esc(c.label.split('（')[0])}</span>
              <span>${c.gb >= 0.01 ? c.gb.toFixed(2) + ' GB' : (c.bytes / 1024 / 1024).toFixed(1) + ' MB'}</span></div>`).join('')}`
            : '<div class="latload">归档信息不可用（本机未挂载原始数据仓库，不影响检索）</div>'}
        </div>
      </div>
    </div>
  </div>`;

  box.querySelectorAll('b[data-n]').forEach((b) => { if (b.dataset.n !== '') tweenNum(b, +b.dataset.n); });
  animateBars(box);
  box.querySelectorAll('.streamrow').forEach((el) => { el.onclick = () => openDetail(el.dataset.id); });

  /* 模块贡献的监测台区块（契约与 enrichSections / sideSections 一致：
     {id, html, mount}）。m1_monitor「每日按类情报报告」走这里，
     主体只负责插入与挂载，不掺和任何日报细节。
     —— 这是**扩展**既有机制而非改动它：没实现 monitorSections 的模块
     什么都不发生，老模块整包替换不受影响。 */
  const msecs = [];
  AISEC.collect('monitorSections').forEach(({ value }) => {
    (value || []).forEach((s) => { if (s && s.html) msecs.push(s); });
  });
  msecs.forEach((s) => {
    const el = document.createElement('div');
    el.className = 'mo-sec';
    if (s.id) el.id = s.id;
    el.innerHTML = s.html;
    box.appendChild(el);
    if (typeof s.mount === 'function') {
      try { s.mount(el); } catch (e) { console.error('[module] monitorSections.mount 出错', e); }
    }
  });

  requestAnimationFrame(() => repositionSegs());
}

/* ============================ 12. 情报富化台（视图三） ============================ */
/* 预警订阅未读角标：轮询 m2_enrich 的 /api/subscribe，把未读数画在「富化」侧栏项上。
   主体只负责显示数字，不理解订阅语义（模块自治：接口挂了就静默不显示）。

   两处刻意的设计（2026-10-06）：
   ① 订阅数为 0 时不画角标 —— 没有订阅就不会再产生新告警，残留的未读全是历史，
      挂个红点只会让人以为"漏看了消息"，反而干扰判断。
   ② 暴露 AISEC.refreshSubBadge() 给模块用 —— 角标原本只在页面加载时算一次，
      之后每 45 秒轮询。用户在面板里「新增订阅 / 巡检 / 全部已读 / 删除订阅」后，
      侧栏红点要等最多 45 秒才跟着变，用户会以为功能没生效。 */
function initSubBadge() {
  const rail = document.querySelector('.rail-item[data-view="enrich"]');
  if (!rail) return;
  const paint = (n, subs) => {
    let b = rail.querySelector('.rail-badge');
    /* 没订阅就不显示角标（见上方①）。n 为 0 时同样移除。 */
    if (!n || !subs) { if (b) b.remove(); return; }
    if (!b) {
      b = document.createElement('i');
      b.className = 'rail-badge';
      rail.appendChild(b);
    }
    b.textContent = n > 99 ? '99+' : String(n);
  };
  const tick = async () => {
    try {
      const r = await (await fetch('/api/subscribe')).json();
      const st = (r && r.ok && r.status) || {};
      paint(st.unread || 0, st.subs || 0);
    } catch (e) { paint(0, 0); }
  };
  AISEC.refreshSubBadge = tick;      /* 模块在改动订阅数据后调用，立即重算（见上方②） */
  tick();
  setInterval(tick, 45000);
}

async function renderEnrich() {
  const box = $('enrichboard');
  if (!box) return;
  box.innerHTML = '<div class="skboard"><div class="sk"></div><div class="sk"></div></div>';

  /* 模块贡献的富化台区块（契约与 detailSections / sideSections 一致：
     {id, html, mount}）。m2_enrich「资产风险体检」就走这里，主体保持不知道细节。 */
  const secs = [];
  AISEC.collect('enrichSections').forEach(({ value }) => {
    (value || []).forEach((s) => { if (s && s.html) secs.push(s); });
  });
  const head = secs.map((s) => `<div class="en-sec"${s.id ? ` id="${esc(s.id)}"` : ''}>${s.html}</div>`).join('');

  const p = new URLSearchParams();
  p.set('size', '16'); p.set('sort', 'risk'); p.set('q', '');
  if (S.enf === 'exploited') p.set('exploited', '1');
  if (S.enf === 'poc') p.set('poc', '1');
  if (S.enf === 'critical') { p.append('severity', 'CRITICAL'); p.append('severity', 'HIGH'); }
  let r = null;
  try { r = await (await fetch('/api/search?' + p)).json(); } catch (e) { /* 下面统一处理 */ }

  const cand = (!r || !r.results)
    ? '<div class="panel"><div class="empty"><div class="big">富化候选加载失败</div>检索接口不可用或模块未加载</div></div>'
    : `<div class="panel">
    <header>富化候选 · ${r.total} 条 <span class="ph-sub">按风险优先排序 · 点任意一条在右侧检查器查看受影响资产与 POC</span></header>
    <div class="pbody">
      ${r.results.map((x, i) => {
        const sev = sevBadge(x.cvss.severity);
        return `<div class="enrow" data-id="${esc(x.id)}" style="--i:${Math.min(i, 14)}">
          <span class="cve" style="padding-left:0">${esc(x.id)}</span>
          <span class="badge ${sev}">${sev}${x.cvss.score != null ? ' ' + x.cvss.score : ''}</span>
          ${x.exploited ? '<span class="chip alert">● 在野利用</span>' : ''}
          ${x.poc_count ? `<span class="chip alert">POC×${x.poc_count}</span>` : '<span class="chip">无公开 POC</span>'}
          ${x.trust_label ? `<span class="chip trust">◆ ${esc(x.trust_label)}</span>` : ''}
          <span class="en-ttl">${esc(x.title)}</span>
          <span class="en-go">富化 →</span>
        </div>`;
      }).join('')}
    </div>
  </div>`;

  box.innerHTML = head + cand;
  /* 区块挂载（模块自己接管事件；单个区块失败不影响其它区块与候选列表） */
  secs.forEach((s) => {
    if (!s.mount) return;
    const el = s.id ? document.getElementById(s.id) : null;
    if (!el) return;
    try { s.mount(el); } catch (e) { console.error('[enrich] 区块挂载失败：' + s.id, e); }
  });
  box.querySelectorAll('.enrow').forEach((el) => { el.onclick = () => openDetail(el.dataset.id); });
}

/* ================= 13. AI 辅助翻译（本地模型，零 token · 正文不出本机） =================
   走本机后端 /api/qa/translate（Helsinki-NLP/opus-mt-en-zh，CPU 推理）：
   不联网、不花 token、安全情报正文不外发、断网可用。
   模型未下载时点「译」会引导一次性下载（约 300MB，免费）。                        */
const TR_SYS_NOTE = '本地 MarianMT 机器翻译，带安全术语词典校准';

/* 翻译失败原因 → 人能看懂的一句话（本地方案的失败原因只有这几个） */
function TR_MSG(code) {
  const c = String(code || '');
  if (c === 'mt_not_ready') return '翻译模型未就绪 —— 点「译」按钮旁的下载提示，或双击 下载翻译模型.bat（约 300MB，一次性）';
  if (c === 'mt_downloading') return '翻译模型正在下载中，稍候重试（GET /api/qa/mt_status 可看进度）';
  if (c === 'net_unreachable') return '连不上本机服务 —— 确认服务已启动且没走代理拦截 127.0.0.1';
  if (c === 'timeout') return '翻译超时（本机 CPU 推理较慢，可少选几条再试）';
  if (c === 'http_404') return '翻译接口不存在 —— 请重启服务让 m3_qa 模块重新注册';
  return '翻译不可用（' + (c || '未知错误') + '）';
}

const TR = {
  on: false, ready: null, cache: {}, LS: 'asi-trc-v1',
  /* 「自动翻译」覆盖的节点白名单（2026-10-07 从"只翻检索卡片 + 详情"扩到全页）。
     为什么用白名单而不是"扫全页所有文本节点"：界面里大量文案是按钮、标签、
     指标名、分类名（"严重 / 高危 / 在野利用"、"AI 基础设施与推理框架"），
     无差别扫描会把这些固定中文/术语也塞进翻译队列 —— 既慢又可能翻坏。
     下面的选择器只取**内容型文本**：卡片标题、摘要、正文、日报条目、检查器字段值。 */
  SEL: [
    '#results .ttl', '#results .snip',            // 检索结果卡片
    // ★ 不翻左侧「实时监测 · 最新情报」（2026-10-07 用户要求）。
    //   原因不是修不动（.latmain 那套已经修好了），而是这栏**不适合翻**：
    //   ① 它是极窄的列表，译文块插进来会把每条撑成两行，9 条就占满整屏；
    //   ② 侧栏是常驻的，一次扫描要额外算 9 条的 CPU 推理；
    //   ③ 这里的条目本来就是"扫一眼"的，点一下右侧会开详情、详情里全翻。
    '.mo-item-t', '.mo-cat-d',                    // 每日按类报告：条目标题 / 分类说明
    '#db .desc-p', '#db .steps li', '#db .paper b', '#db .paper p',
    '#db .kv2 b', '#db h3',                       // 详情检视器
    '#qaans .ans', '#qaans .ev',                  // 问答答案与证据
    '.mo-sum-i.gen', '.meta-note',                // 报告页脚注
  ],
  MAX_PER_SWEEP: 140,      // 单次扫描上限：整页 100+ 条时先翻可见的，别把 CPU 打满
  init() {
    try { this.on = localStorage.getItem('asi-tr') === '1'; } catch (e) {}
    try { this.cache = JSON.parse(localStorage.getItem(this.LS) || '{}'); } catch (e) { this.cache = {}; }
    /* 清掉缓存里的坏译文（旧版翻译管线产出的退化循环）。
       不这么做的话，后端修好了也白搭 —— 用户看到的是缓存里那份旧结果
       （2026-10-07 用户截图：「左边不正常、右边正常」）。
       顺带清掉 TRV 升级前的僵死条目：老 key 不带版本盐，再也不会被命中，
       留着只是白占 localStorage 配额。 */
    let purged = 0;
    for (const k of Object.keys(this.cache)) {
      if (this.isBadDst(this.cache[k])) { delete this.cache[k]; purged++; }
    }
    try {
      if (localStorage.getItem('asi-trv') !== this.TRV) {
        localStorage.setItem('asi-trv', this.TRV);
        /* 版本变更 = 翻译管线变了 → 整库作废重翻，避免"半新半旧"混在一屏上 */
        this.cache = {};
        purged = -1;
      }
    } catch (e) { /* 存不下就只靠上面的坏译文清理 */ }
    if (purged > 0 || purged === -1) this.save();
    const b = $('trtgl');
    if (b) b.title = 'AI 辅助翻译（英文情报 → 中文）—— 本机模型，零 token、正文不出本机、离线可用';
    /* 悄悄探一次模型状态，只为把 tooltip 写准；失败不影响使用 */
    this.status().then((s) => {
      const btn = $('trtgl');
      if (btn) {
        btn.title = s && s.ready
          ? 'AI 辅助翻译（英文情报 → 中文）—— 本机模型已就绪，离线可用'
          : 'AI 辅助翻译 —— 本机模型尚未下载，点此即可触发一次性下载（约 300MB，免费）';
      }
    }).catch(() => {});
    this.syncBtn();
  },
  syncBtn() { const b = $('trtgl'); if (b) b.classList.toggle('on', this.on); },
  toggle() {
    this.on = !this.on;
    try { localStorage.setItem('asi-tr', this.on ? '1' : '0'); } catch (e) {}
    this.syncBtn();
    if (!this.on) { document.querySelectorAll('.trl').forEach((x) => x.remove()); this.busyTip(''); return; }
    /* 先确认本机模型就绪：未就绪就直接告诉他怎么补（不要铺一屏「翻译中…」再变红） */
    this.probe().then((r) => {
      if (!this.on) return;
      if (!r.ok) {
        toast('AI 翻译不可用：' + r.msg, 7000);
        this.on = false;
        try { localStorage.setItem('asi-tr', '0'); } catch (e) {}
        this.syncBtn();
        return;
      }
      this.applyView('整页');
    });
  },
  _probe: null,
  probe() {
    if (this._probe) return this._probe;
    this._probe = (async () => {
      try {
        const s = await this.status();
        if (s && s.ready) { this._probeOk = true; return { ok: true }; }
        return { ok: false, code: 'mt_not_ready', msg: TR_MSG('mt_not_ready') };
      } catch (e) {
        this._probeOk = false;
        const code = (e && e.code) || 'net_unreachable';
        return { ok: false, code: String(code), msg: TR_MSG(code) };
      }
    })();
    return this._probe;
  },
  /* 查询本机翻译模型状态（/api/qa/mt_status） */
  async status() {
    const r = await fetch('/api/qa/mt_status', { headers: { Accept: 'application/json' } });
    if (!r.ok) throw Object.assign(new Error('HTTP ' + r.status), { code: 'http_' + r.status });
    const d = await r.json();
    this.ready = !!d.ready;
    return d;
  },
  /* ★ 译文缓存版本号（改 translator.py 的翻译行为后必须 +1 —— 否则坏译文复活）。
     为什么需要它：缓存 key 之前只有 hash(原文)，**不含任何"是哪个版本的翻译管线
     产出的"信息**。于是后端把退化循环修好之后，浏览器 localStorage 里那批
     旧代码产出的坏译文仍然命中缓存、原样显示 —— 用户看到的是
     「左侧（旧的 .snip 译文）还是 'a, a, a, e, e, e…'，右侧（刚翻的 .desc-p）
     已经正常了」这种"一半好一半坏"（2026-10-07 用户截图）。
     语义：v 变了 → 所有旧 key 一律 miss → 自动重翻一遍，无需用户手动清缓存。
     历史：
       v1 ——      初始
       v2 2026-10-07 修「重复退化」：strip_dangling 补截断残句形态、
                    首推去掉 repetition_penalty（它会截断正常句）、
                    _gen 摘/拼句首 CVE/GHSA 编号、词表补 ransom/Kirki 变体。 */
  TRV: 'v2',
  hash(s) {
    const key = this.TRV + '\u0000' + s;
    let h = 5381;
    for (let i = 0; i < key.length; i++) h = ((h << 5) + h + key.charCodeAt(i)) | 0;
    return 't' + (h >>> 0).toString(36);
  },
  /* 译文看起来像"重复退化"（模型解码循环）—— 与后端 translator.is_degenerate
     同一套判据的前端镜像。为什么前端也要有：本地缓存里的坏译文不会经过后端，
     必须能在渲染前拦一道，否则老缓存永远显示坏结果。
     命中就丢弃缓存条目、当没翻过 → 下一轮 collect() 会重新请求后端。
     判据（任一命中即退化，只处理"明显不可能是有意义文本"的形态）：
       ① 短 token（≤3 字符）用逗号/空白串成 ≥5 连（", a, a, a, a, a"）；
       ② 短 token（≤4 字符）用连接符串成 ≥5 连（"成本-成本-成本-成本-成本"）；
       ③ token 数 ≥20 且 ≤2 字符的超短 token 占比 >50%；
       ④ 同一非空白字符连续 ≥15 次。 */
  isBadDst(dst) {
    const t = String(dst || '').trim();
    if (t.length < 24) return false;
    const shortRun = (segs, maxLen) => {
      let run = 1, best = 1;
      for (let i = 1; i < segs.length; i++) {
        if (segs[i] === segs[i - 1] && segs[i].length <= maxLen) { run++; if (run > best) best = run; }
        else run = 1;
      }
      return best;
    };
    const segs = t.split(/[,，、;；\s]+/).filter(Boolean);
    if (shortRun(segs, 3) >= 5) return true;
    const segs2 = t.split(/[\-·・—]+/).filter(Boolean);
    if (shortRun(segs2, 4) >= 5) return true;
    if (segs.length >= 20) {
      const short = segs.filter((s) => s.length <= 2).length;
      if (short / segs.length > 0.5) return true;
    }
    if (/(.)\1{14,}/.test(t)) return true;
    return false;
  },
  isZh(s) { const m = s.match(/[\u4e00-\u9fff]/g); return !!(m && m.length / s.length > 0.12); },
  textOf(el) {
    let t = '';
    el.childNodes.forEach((n) => {
      if (n.nodeType === 3) t += n.textContent;
      else if (n.nodeType === 1 && !n.classList.contains('chip') && !n.classList.contains('trl')) t += n.textContent + ' ';
    });
    return t.replace(/\s+/g, ' ').trim();
  },
  worth(tx) {
    if (!tx || tx.length < 6 || tx.length > 4000) return false;
    const urlLen = (tx.match(/https?:\/\/\S+/g) || []).join('').length;
    if (urlLen / tx.length > 0.4) return false;
    const words = tx.replace(/https?:\/\/\S+/g, ' ').match(/[A-Za-z][A-Za-z0-9-]*/g) || [];
    if (words.length < 3) return false;
    /* 纯标识符行（CVE-2026-1234 / CWE-79 / GHSA-xxxx / OSV-…）不翻：翻出来是乱码 */
    if (/^(CVE-\d|CWE-\d|GHSA-|AML\.T|OSV-)/.test(tx) && words.length < 8) return false;
    return !this.isZh(tx);
  },
  save() {
    try {
      const ks = Object.keys(this.cache);
      if (ks.length > 900) { const cut = {}; ks.slice(-500).forEach((k) => { cut[k] = this.cache[k]; }); this.cache = cut; }
      localStorage.setItem(this.LS, JSON.stringify(this.cache));
    } catch (e) { /* 缓存写不进去不阻塞 */ }
  },
  async translate(texts) {
    const out = texts.map((t) => this.cache[this.hash(t)] || null);
    const missIdx = texts.map((t, i) => (out[i] ? -1 : i)).filter((i) => i >= 0);
    if (!missIdx.length) return out;
    /* 本机推理：按 8 条一批串行跑（CPU 推理慢，别并发打爆） */
    let failed = 0, lastErr = null;
    for (let c = 0; c < missIdx.length; c += 8) {
      const idxs = missIdx.slice(c, c + 8);
      const payload = idxs.map((ti) => texts[ti].replace(/\s+/g, ' ').trim());
      const controller = new AbortController();
      const watchdog = setTimeout(() => controller.abort(), 60000);
      try {
        const r = await fetch('/api/qa/translate', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ texts: payload }),
          signal: controller.signal,
        });
        if (!r.ok) throw Object.assign(new Error('HTTP ' + r.status), { code: 'http_' + r.status });
        const d = await r.json();
        const items = d.items || [];
        idxs.forEach((ti, j) => {
          const it = items[j];
          /* skipped=true 表示后端判定无需翻译（已是中文/太短）——保持原样，不当失败 */
          if (!it || it.skipped || !it.dst || it.dst.length <= 1) return;
          /* ★ 退化译文**不入缓存**：入了就会像旧版那样永远显示循环串。
             后端已有一层 is_degenerate 兜底（退化→重试→保原文），这里是第二道：
             万一后端某次仍吐出循环串，宁可前端不显示、下轮再试，也不要污染缓存。 */
          if (this.isBadDst(it.dst)) return;
          this.cache[this.hash(texts[ti])] = it.dst;
          out[ti] = it.dst;
        });
        this.save();
      } catch (e) {
        failed++;
        lastErr = controller.signal.aborted
          ? Object.assign(new Error('翻译超时'), { code: 'timeout' }) : e;
      } finally { clearTimeout(watchdog); }
    }
    if (failed && !out.some((x) => x)) throw lastErr;
    return out;
  },
  run(targets, label) {
    this._chain = (this._chain || Promise.resolve()).then(() => this._run(targets, label));
    return this._chain;
  },
  /* 进度提示挂在顶栏「译」按钮上：按钮常驻，翻几十条时用户能一直看到进度，
     不用盯着一排「AI 翻译中…」占位（日报一屏就有 30+ 条）。 */
  busyTip(msg) {
    const b = $('trtgl');
    if (!b) return;
    if (!msg) {
      b.removeAttribute('data-trbusy');
      b.classList.remove('run');
      b.textContent = '译';
      b.title = 'AI 辅助翻译（英文情报 → 中文）—— 本机模型，零 token、正文不出本机、离线可用';
      return;
    }
    b.setAttribute('data-trbusy', '1');
    b.classList.add('run');
    b.textContent = msg.length > 24 ? '翻译中…' : msg;
    b.title = msg;
  },
  async _run(targets, label) {
    const fresh = targets.filter((t) => t.el.isConnected && !t.el.dataset.tr);
    if (!fresh.length) return;
    fresh.forEach((t) => {
      t.el.dataset.tr = '1';
      const ph = document.createElement('div');
      ph.className = 'trl loading';
      ph.textContent = 'AI 翻译中…';
      t.el.after(ph);
      t.ph = ph;
    });
    const tag = label ? '（' + label + '）' : '';
    this.busyTip('AI 翻译中 0/' + fresh.length + tag);
    let done = 0;
    try {
      /* 一批 8 条翻完就更新一次进度 —— 整页几十条时用户能看到在动，
         而不是对着一个不动的进度条干等一分钟。 */
      for (let c = 0; c < fresh.length; c += 8) {
        const idxs = fresh.slice(c, c + 8);
        const res = await this.translate(idxs.map((t) => t.text));
        idxs.forEach((t, i) => {
          done++;
          if (!t.ph.isConnected) return;
          if (res[i]) { t.ph.classList.remove('loading'); t.ph.textContent = res[i]; }
          else { t.ph.remove(); delete t.el.dataset.tr; }
        });
        this.busyTip('AI 翻译中 ' + done + '/' + fresh.length + tag);
      }
      this.busyTip('已翻译 ' + done + ' 处' + tag);
      setTimeout(() => this.busyTip(''), 2600);
    } catch (e) {
      const msg = TR_MSG((e && e.error && e.error.code) || (e && e.code));
      fresh.forEach((t) => {
        if (t.ph.isConnected) { t.ph.className = 'trl err'; t.ph.textContent = msg; }
        delete t.el.dataset.tr;
      });
      this.busyTip('');
      toast('AI 翻译失败：' + msg, 6000);
    }
  },
  /* 采集当前视图里所有值得翻的节点：可见优先（先翻用户眼前的）、
     跨选择器去重（同一节点可能命中多条）、已翻过的跳过。 */
  collect() {
    const seen = new Set(), out = [];
    const vh = window.innerHeight || 800;
    for (const sel of this.SEL) {
      let nodes;
      try { nodes = document.querySelectorAll(sel); } catch (e) { continue; }
      for (const el of nodes) {
        if (seen.has(el)) continue;
        seen.add(el);
        if (el.dataset.tr) continue;
        const tx = this.textOf(el);
        if (!this.worth(tx)) continue;
        let off = 1;
        try { const r = el.getBoundingClientRect(); off = (r.bottom > 0 && r.top < vh) ? 0 : 1; } catch (e) { /* 隐藏节点按不可见算 */ }
        out.push({ el, text: tx, off });
      }
    }
    out.sort((a, b) => a.off - b.off);
    return out.slice(0, this.MAX_PER_SWEEP);
  },
  /* 全页自动翻译的唯一入口。切视图 / 出检索结果 / 打开详情 / 日报刷新后都调它。 */
  applyView(label) {
    if (!this.on || this._probeOk === false) return;
    const t = this.collect();
    if (!t.length) return;
    this.run(t, label);
  },
  /* 兼容旧调用点（保留函数名，避免别处引用失效） */
  applyList() { this.applyView('检索结果'); },
  applyDetail() { this.applyView('详情'); },
};

/* ============================ 14. 提示条 ============================ */
let tt = null;
function toast(msg, ms) {
  const el = $('toast');
  el.textContent = msg;
  el.classList.add('on');
  clearTimeout(tt);
  tt = setTimeout(() => el.classList.remove('on'), ms || 2600);
}

/* ============================ 15. 启动 ============================ */
async function init() {
  initTheme();
  initSearchUI();
  initPalette();
  initHelp();
  TR.init();
  renderHints();

  /* 恢复面板状态 / 密度（本地持久化，不影响后端） */
  try {
    S.dense = localStorage.getItem('asi-dense') === '1';
    document.body.classList.toggle('dense', S.dense);
    const d = document.querySelector('#density button[data-d="' + (S.dense ? 'list' : 'cozy') + '"]');
    if (d) { document.querySelectorAll('#density button').forEach((x) => x.classList.toggle('on', x === d)); }
    if (localStorage.getItem('asi-sidepanel') === '0') document.querySelector('.view[data-view="search"]').classList.add('nopanel');
  } catch (e) {}
  repositionSegs();
  initRail();
  initSubBadge();          // 预警订阅未读角标（m2_enrich 贡献的接口，主体只显示数字）

  /* URL 深链：?q=…&view=…&detail=…（保留 v3 的全部参数） */
  const sp = new URLSearchParams(location.search);
  if (sp.get('view')) switchView(sp.get('view'));
  if (sp.get('zoom') === '1' || sp.get('mode') === 'read') setZoom(true, true);
  if (sp.get('mode') === 'skim') setZoom(false, true);
  if (sp.get('tr') === '1' && !TR.on) TR.toggle();
  const d0 = sp.get('detail');
  if (d0) setTimeout(() => openDetail(d0), 320);
  const q0 = sp.get('q');
  if (q0) {
    $('q').value = q0;
    if (sp.get('sort')) {
      S.sort = sp.get('sort');
      document.querySelectorAll('#sortseg button').forEach((b) => b.classList.toggle('on', b.dataset.sort === S.sort));
      repositionSegs();
    }
    if (sp.get('severity')) S.f.severity = sp.get('severity').split(',');
    if (sp.get('category')) S.f.category = sp.get('category').split(',');
    if (sp.get('source')) S.f.source = sp.get('source').split(',');
    if (sp.get('exploited') === '1') S.f.exploited = true;
    if (sp.get('poc') === '1') S.f.poc = true;
    if (sp.get('cvss_min')) S.f.cvss_min = sp.get('cvss_min');
    if (sp.get('year_from')) S.f.year_from = sp.get('year_from');
    if (sp.get('year_to')) S.f.year_to = sp.get('year_to');
  }
  /* 性能：统计与检索并发取 —— 旧版先 await stats（~2ms 本机但不为零）、再检索（0.6~1.3s），
     首屏纯串行；现在两路同时发起，等两边都回来再统一渲染侧栏（统计 + 分面同时就位）。 */
  const statsP = (async () => {
    try { S.stats = await (await fetch('/api/stats')).json(); renderTop(); }
    catch (e) { toast('语料统计加载失败：' + e.message); }
  })();
  await Promise.all([statsP, doSearch(!!q0)]);
  renderSide();
  /* 分段控件指示块要在真实布局出来之后量一次：窗口尺寸变化、字体就绪、延迟定时都补一遍，
     避免首次绘制时进度块宽度为 0（用户看到"没有选中态"）。 */
  [0, 80, 260, 700].forEach((d) => setTimeout(repositionSegs, d));
  window.addEventListener('load', () => repositionSegs());
  if (document.fonts && document.fonts.ready) document.fonts.ready.then(() => repositionSegs());
}

/* 全局键盘（不打扰输入框：除 ⌘K 外都在非输入态生效） */
function bindGlobalKeys() {
  document.addEventListener('keydown', (ev) => {
    const tag = (document.activeElement && document.activeElement.tagName) || '';
    const typing = /INPUT|TEXTAREA|SELECT/.test(tag) || (document.activeElement && document.activeElement.isContentEditable);
    /* ⌘K / Ctrl+K：任何状态下都能唤起 */
    if ((ev.metaKey || ev.ctrlKey) && ev.key.toLowerCase() === 'k') {
      ev.preventDefault();
      PAL.open ? closePalette() : openPalette('');
      return;
    }
    if ((ev.metaKey || ev.ctrlKey) && ev.key.toLowerCase() === 'm') { ev.preventDefault(); setZoom(!document.body.classList.contains('zl')); return; }
    if (ev.key === 'Escape') { closePalette(); closeHelp(); closeDrawer(); hideSug(); return; }
    if (typing) return;
    if (ev.key === '/') { ev.preventDefault(); switchView('search'); $('q').focus(); $('q').select(); return; }
    if (ev.key.toLowerCase() === 't' && !ev.metaKey && !ev.ctrlKey) { cycleTheme(); return; }
    if (ev.key === '[') { toggleSide(); return; }
    if (ev.key === ']') { $('stage').classList.contains('insp') ? closeDrawer() : openInspector(); return; }
    if (S.view !== 'search') return;
    if (ev.key === 'ArrowDown' || ev.key === 'j') { ev.preventDefault(); moveSel(1); }
    else if (ev.key === 'ArrowUp' || ev.key === 'k') { ev.preventDefault(); moveSel(-1); }
    else if (ev.key === 'Enter' && S.sel >= 0) { ev.preventDefault(); openSel(); }
  });
}

/* 模块面板"收养"：模块自己插到检索区之后的面板，被外壳搬进对应视图的坞里。
   只搬 DOM 节点（模块内部的事件、样式、类名全都不动）。 */
function adoptModulePanels() {
  const qa = $('qapanel'), dock = $('askdock');
  if (qa && dock && qa.parentNode !== dock) {
    dock.appendChild(qa);
    console.log('[shell] 已把 m3 问答面板接入「问答」视图');
  }
  if (dock && !dock.children.length) {
    dock.innerHTML = '<div class="empty"><div class="big">问答模块未加载</div>把 modules/m3_qa 放回模块目录并重启服务即可。</div>';
  }
}

/* ============================ 16. 启动序列 ============================ */
document.addEventListener('DOMContentLoaded', async () => {
  bindGlobalKeys();
  try { await init(); } catch (e) { console.error('主体初始化失败', e); }
  for (const m of AISEC.list()) {
    if (typeof m.init === 'function') {
      try { m.init(AISEC); } catch (e) { console.error('[module] ' + m.id + '.init 出错', e); }
    }
  }
  adoptModulePanels();
  [0, 150, 500].forEach((d) => setTimeout(() => {
    moveRailPill(document.querySelector('.rail-item.on'));
    repositionSegs();
  }, d));
  if (!AISEC.list().length) {
    console.warn('[module] 未加载任何模块前端（检查 modules/<id>/module.json 的 web 字段）');
  }
});
