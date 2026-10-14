// web/daily.js
// ⚠ 自动生成，请勿直接改本文件 —— 源文件在 modules/m1_monitor/web/daily.js
//   改完跑一次： py -3 tools/组装前端.py
/* ============================================================
   m1_monitor · 每日按类情报报告面板
   ------------------------------------------------------------
   归属：本区块由模块通过 AISEC.register({monitorSections}) 贡献，
   主体 app.js 只负责插进「实时监测台」，不掺和任何细节。

   要解决的现实问题（代码核查结论）：
   /api/live 只给最近几条，检索页导出是"当前查询的快照"——
   **没有"把今天看到的风险按类整理成一份能归档、能下载的报告"**。
   评审要问的是"你们今天查出了什么、分别属于哪一类风险"。

   分类口径（与 core/taxonomy.py:RISK_CATEGORIES 严格一致，不在前端另立一套）：
     ① AI基础设施与推理框架  ② 模型与数据层
     ③ AI应用与智能体       ④ AI供应链与平台
     ⑤–⑪ 通用网络安全类（Web / 系统 / 网络 / 云原生 / 身份 / 恶意代码 / 数据）

   接口：GET /api/daily_reports（列表+每类计数）
        GET /api/daily_report?date=（详情 / ?fmt=md|json|xlsx 下载）
        POST /api/daily_report/generate（手动生成）
   ============================================================ */
(function () {
  'use strict';
  if (window.__m1DailyLoaded) return;      // 组装脚本可能重复注入，防重复绑事件
  window.__m1DailyLoaded = true;

  /* 严重度 → 样式类。**必须白名单化**：severity 来自语料，直接插 class
     等于把 XSS 开在标签上（m2_enrich/panel.js 已记录过这个坑）。

     两个坑要一起堵：
     ① 大小写 —— 后端给小写，但 severity 也可能来自 NVD 原文（'CRITICAL'）。
        不归一化就会全部落到 info，看起来"今天全是资讯"。
     ② **原型链** —— SEV_CLS['__proto__'] 不是 undefined，而是
        Object.prototype，拼进 class 变成 "[object Object]"；
        'constructor' / 'toString' 同理。用 Map 或 hasOwnProperty 隔离。 */
  const SEV_CLS = new Map([
    ['critical', 'crit'], ['high', 'high'], ['medium', 'med'],
    ['low', 'low'], ['info', 'info'],
  ]);
  const SEV_CN = new Map([
    ['critical', '严重'], ['high', '高危'], ['medium', '中危'],
    ['low', '低危'], ['info', '资讯'],
  ]);
  const sevKey = (s) => String(s == null ? '' : s).trim().toLowerCase();
  const sevCls = (s) => SEV_CLS.get(sevKey(s)) || 'info';
  const sevCn = (s) => SEV_CN.get(sevKey(s)) || '资讯';

  /* 链接白名单：只放行 http/https。
     日报的 link 来自 54 个外部源，其中出现 javascript: 就等于把
     XSS 开在"原文"链接上 —— 点一下就执行。用白名单而不是黑名单：
     data: / vbscript: / file: 这些变体多到写不全。 */
  function safeLink(u) {
    const s = String(u == null ? '' : u).trim();
    return /^https?:\/\//i.test(s) ? s : '';
  }

  /* canDownload / emptyReason 由 loadDay 按后端返回的 available_formats
     与 empty_reason 填写。后端对无报告日期返回 404，前端必须先判断，
     否则 <a href> 导航会把用户带到一段 JSON 上。 */
  const state = {
    day: null, list: null, detail: null, busy: false, open: {},
    canDownload: false, emptyReason: '',
  };

  const q = (sel, el) => (el || document).querySelector(sel);
  const qa = (sel, el) => Array.from((el || document).querySelectorAll(sel));

  /* ---------------- 骨架 ---------------- */
  const HTML = `
  <div class="panel mo-daily">
    <header>每日按类 AI 安全风险报告
      <span class="ph-sub">/api/daily_reports · 按 AI 四分类 + 通用类归档 · 保留一个月可下载</span>
      <span class="mo-daily-acts">
        <select id="moDayPick" class="mo-daily-sel" title="选择报告日期"></select>
        <button id="moDayGen" title="按当前分类口径重新汇总今天的情报">重新汇总</button>
        <button id="moDayDl" title="下载 Markdown（.md）">MD</button>
        <button id="moDayXl" title="下载 Excel（.xlsx）">XLSX</button>
        <button id="moDayJs" title="下载原始数据（.json）">JSON</button>
      </span>
    </header>
    <div class="pbody" id="moDayBody"><div class="latload">日报载入中…</div></div>
    <div class="mo-digest" id="moDigest"></div>
  </div>`;

  /* ---------------- 渲染 ---------------- */
  function dayChip(d) {
    const bs = d.by_sev || {};
    const parts = [];
    if (bs.critical) parts.push(`<span class="chip crit">严重 ${bs.critical}</span>`);
    if (bs.high) parts.push(`<span class="chip high">高危 ${bs.high}</span>`);
    if (bs.kev) parts.push(`<span class="chip alert">在野 ${d.kev}</span>`);
    return parts.join(' ');
  }

  function renderDays(list) {
    const days = (list && list.days) || [];
    if (!days.length) {
      return `<div class="latload">还没有日报。点「重新汇总」按今天的分类口径生成一份。</div>`;
    }
    const t = list.today || '';
    return `
      <div class="mini"><span>报告保留</span><span>${esc(String(list.retention_days || 30))} 天（超期自动清理）</span></div>
      <div class="mini" style="margin-top:4px"><span>已归档</span><span>${days.length} 天 · ${esc(list.stats ? list.stats.files : days.length)} 份文件 · ${(list.stats ? list.stats.total_mb : 0).toFixed(2)} MB</span></div>
      ${(list.expired_days && list.expired_days.length)
        ? `<div class="meta-note">已过保留期被清理：${esc(list.expired_days.slice(0, 6).join('、'))}${list.expired_days.length > 6 ? ' …' : ''}（数据未丢失，只是超出一个月）</div>` : ''}
      <div class="mo-daylist">
        ${days.map((d) => `
          <button class="mo-daybtn${d.date === state.day ? ' on' : ''}" data-date="${esc(d.date)}" title="${esc(d.date)}${d.pending ? '（尚未落盘，正在实时汇总）' : ''}">
            <b>${esc(d.date)}</b>
            <span>${esc(String(d.total || 0))} 条 / ${esc(String(d.category_count || 0))} 类</span>
            <span class="mo-daychips">${dayChip(d)}</span>
          </button>`).join('')}
      </div>
      ${t ? `<div class="meta-note">口径：按「系统检测到的日期」分组（fetched_at），分类取自引擎 category 字段（${esc(t)} 为当天实时汇总）。</div>` : ''}`;
  }

  function itemHtml(it) {
    const tags = (it.risk_tags || []).slice(0, 4)
      .map((x) => `<span class="chip">${esc(x)}</span>`).join('');
    const cvss = it.has_cvss ? `<span class="chip">CVSS ${esc(String(it.cvss))}</span>` : '';
    const href = safeLink(it.link);
    /* 条目可点击：点整行打开右侧「情报检查器」（/api/detail?id=…）看全文。
       为什么必须可点：日报里 27 条「资讯」大半是厂商公告/博客，
       标题只有一行、描述被截断，不点开根本读不到内容 —— 评审只能看到一列标题。
       id 来自 live_feed / kev_cache / monitor 的入库记录，都能在语料里定位到。 */
    const rid = String(it.id || '');
    return `<div class="mo-item sev-${sevCls(it.severity)}"${rid ? ` data-id="${esc(rid)}" title="点击查看完整内容"` : ''}>
      <span class="badge ${sevCls(it.severity)}">${esc(sevCn(it.severity))}</span>
      ${it.kev ? '<span class="chip alert">● 在野利用</span>' : ''}
      ${it.poc ? '<span class="chip alert">POC</span>' : ''}
      <span class="mo-item-t">${esc(it.title || '(无标题)')}</span>
      ${cvss}${tags}
      <span class="mo-item-s">${esc(it.source || '—')}${it.published ? ' · ' + esc(it.published) : ''}</span>
      ${href ? `<a class="mo-item-l" href="${esc(href)}" target="_blank" rel="noopener noreferrer" title="在新标签打开原文">原文</a>` : ''}
    </div>`;
  }

  /* 分类色点：color 来自 RISK_CATEGORIES 元数据，但既然是外部数据，
     就按 CSS 十六进制色白名单过一道 —— 免得有人改了元数据表把
     `red;background:url(...)` 这种串塞进 style 属性。 */
  function safeColor(c) {
    return /^#[0-9a-f]{3,8}$/i.test(String(c || '')) ? c : 'var(--txt-4)';
  }

  function renderDetail(d) {
    if (!d) return '';
    if (d.empty_reason === 'expired') {
      return `<div class="latload">${esc(d.date)} 的报告已超出 ${esc(String(d.retention_days || 30))} 天保留期并被清理（数据未丢失，可重新汇总当天数据）。</div>`;
    }
    const cats = (d.categories || []).filter((c) => (c.items || []).length);
    if (!cats.length) {
      return `<div class="latload">${esc(d.date)} 没有采到可分类的情报条目（该日无新增漏洞/文章/KEV）。</div>`;
    }
    const tot = d.total || 0, bs = d.by_sev || {};
    const gcnt = d.general_count || 0;
    return `
      <div class="mo-sum">
        <span class="mo-sum-i"><b>${esc(String(tot))}</b>条目</span>
        <span class="mo-sum-i"><b>${esc(String(d.category_count || cats.length))}</b>分类</span>
        <span class="mo-sum-i crit"><b>${esc(String(bs.critical || 0))}</b>严重</span>
        <span class="mo-sum-i high"><b>${esc(String(bs.high || 0))}</b>高危</span>
        <span class="mo-sum-i alert"><b>${esc(String(d.kev || 0))}</b>在野利用</span>
        <span class="mo-sum-i"><b>${esc(String(d.poc || 0))}</b>含POC</span>
        <span class="mo-sum-i gen">生成于 ${esc(String(d.generated_at || '—').replace('T', ' ').slice(5, 16))}</span>
      </div>
      ${gcnt ? `<div class="meta-note">本报告聚焦 AI 四大类；另有 ${esc(String(gcnt))} 条通用网络安全情报未单独列类，仅计入总数。</div>` : ''}
      ${cats.map((c, i) => `
        <div class="mo-cat">
          <div class="mo-cat-h" data-tog="${esc(c.key || i)}">
            <span class="mo-dot" style="background:${esc(safeColor(c.color))}"></span>
            <b>${esc(c.full || c.key || '')}</b>
            <span class="mo-cat-n">${esc(String(c.count || 0))} 条</span>
            <span class="mo-cat-s">严重 ${esc(String((c.by_sev || {}).critical || 0))} · 高危 ${esc(String((c.by_sev || {}).high || 0))} · 资讯 ${esc(String((c.by_sev || {}).info || 0))}</span>
            ${c.truncated ? `<span class="chip">另 ${esc(String(c.truncated))} 条未展开</span>` : ''}
            <span class="mo-tog">${state.open[c.key || i] === false ? '展开' : '收起'}</span>
          </div>
          ${c.desc ? `<div class="mo-cat-d">${esc(c.desc)}</div>` : ''}
          ${state.open[c.key || i] === false ? '' : `<div class="mo-items">${(c.items || []).map(itemHtml).join('')}</div>`}
        </div>`).join('')}`;
  }

  function paint(root) {
    const body = q('#moDayBody', root);
    if (!body) return;
    // 列表区 + 详情区：日期切换只重画详情，省一次列表请求
    if (!q('.mo-daylist', body)) {
      body.innerHTML = `<div class="mo-split"><div class="mo-left mo-daylist"></div><div class="mo-right" id="moDayDetail"></div></div>`;
      q('.mo-left', body).innerHTML = renderDays(state.list);
      qa('.mo-daybtn', body).forEach((b) => {
        b.onclick = () => { state.day = b.dataset.date; paint(root); loadDay(root); };
      });
    } else {
      q('.mo-left', body).innerHTML = renderDays(state.list);
      qa('.mo-daybtn', body).forEach((b) => {
        b.onclick = () => { state.day = b.dataset.date; paint(root); loadDay(root); };
      });
    }
    const det = q('#moDayDetail', body);
    if (det) det.innerHTML = renderDetail(state.detail);
    qa('.mo-cat-h', body).forEach((h) => {
      h.onclick = () => {
        const k = h.dataset.tog;
        state.open[k] = state.open[k] === false;
        q('#moDayDetail', body).innerHTML = renderDetail(state.detail);
      };
    });
    /* 条目点击 → 打开情报检查器。事件委托绑在明细容器上：
       分类行是折叠重绘的，绑在单个元素上每次重绘都要重绑一遍（漏一次就失效）。
       「原文」链接要豁免 —— 点它是"开新标签看源站"，不是"看站内详情"。 */
    const det2 = q('#moDayDetail', body);
    if (det2 && !det2.dataset.bound) {
      det2.dataset.bound = '1';
      det2.addEventListener('click', (ev) => {
        const a = ev.target.closest && ev.target.closest('a');
        if (a) return;                                   // 原文链接不拦截
        const row = ev.target.closest && ev.target.closest('.mo-item[data-id]');
        if (!row || !row.dataset.id) return;
        if (typeof openDetail === 'function') openDetail(row.dataset.id);
      });
    }
    /* 下载按钮可用性跟着"这天有没有报告"走，而不只是"选没选日期"。
       选了一个没有报告的日期还让按钮亮着，点下去就是 404 导航。 */
    const okDl = !!(state.day && state.canDownload);
    [['#moDayDl', 'md'], ['#moDayXl', 'xlsx'], ['#moDayJs', 'json']].forEach(([sel, fmt]) => {
      const b = q(sel, root);
      if (!b) return;
      b.disabled = !okDl;
      b.title = okDl
        ? '下载 ' + state.day + ' 的 ' + fmt.toUpperCase() + ' 报告'
        : (state.emptyReason === 'expired'
          ? '该日报告已超保留期被清理，无法下载'
          : '该日没有可下载的报告');
    });
    /* 「译」开着就顺手把这一屏的英文翻掉。日报是英文最密的一屏
       （厂商公告 / CISA / OpenAI 新闻标题全是英文），不接这里等于自动翻译
       在监测台完全失效。
       注意：TR 是 app.js 顶层的 const（全局词法绑定，不挂 window），
       所以只能按标识符取，用 window.TR 永远是 undefined。 */
    if (typeof TR !== 'undefined' && TR && TR.on) TR.applyView('日报');
  }

  /* ---------------- 数据 ---------------- */
  async function loadList(root, force) {
    const body = q('#moDayBody', root);
    if (!body) return;
    if (!state.list || force) {
      body.innerHTML = '<div class="latload">日报载入中…</div>';
      try {
        state.list = await (await fetch('/api/daily_reports' + (force ? '?_=' + Date.now() : ''))).json();
      } catch (e) {
        body.innerHTML = '<div class="latload">日报列表加载失败（情报监测模块可能未加载）</div>';
        return;
      }
    }
    const days = (state.list && state.list.days) || [];
    if (!state.day || !days.some((d) => d.date === state.day)) {
      state.day = (state.list && state.list.today) || (days[0] && days[0].date) || null;
    }
    paint(root);
    if (state.day) loadDay(root);
  }

  async function loadDay(root) {
    const det = q('#moDayDetail', root);
    if (!det || !state.day) return;
    det.innerHTML = '<div class="latload">载入 ' + esc(state.day) + ' 明细…</div>';
    try {
      const r = await fetch('/api/daily_report?date=' + encodeURIComponent(state.day));
      state.detail = await r.json();
    } catch (e) {
      state.detail = null;
      state.canDownload = false;
      det.innerHTML = '<div class="latload">明细加载失败</div>';
      return;
    }
    /* 能不能下载只有后端说了算：有落盘文件（available_formats 非空）
       或当天确实有条目。两者都没有时后端会给 404，前端必须先拦下来。 */
    const d = state.detail || {};
    state.canDownload = !!((d.available_formats && d.available_formats.length)
      || (d.total || 0) > 0);
    state.emptyReason = d.empty_reason || '';
    paint(root);
  }

  function download(fmt) {
    if (!state.day) { toast('先选一个日期'); return; }
    /* ★ 后端对"没有报告的日期"返回 404（不造空报告）。
       而 <a href> 触发的是导航，不是 fetch —— 404 时浏览器会直接
       跳过去显示那段 JSON，用户就离开了页面、也看不懂发生了什么。
       所以下载前先判断这一天到底能不能下载，不能就提示，不发请求。 */
    if (!state.canDownload) {
      toast(state.emptyReason === 'expired'
        ? state.day + ' 的报告已超保留期并被清理，无法下载'
        : state.day + ' 没有可下载的报告（该日未采集到条目）', 3600);
      return;
    }
    // 用隐藏 a 触发下载：fetch+blob 在大文件上会占内存，且拿不到文件名
    const a = document.createElement('a');
    a.href = '/api/daily_report?date=' + encodeURIComponent(state.day) + '&fmt=' + fmt;
    a.download = '';
    document.body.appendChild(a);
    a.click();
    a.remove();
    toast('开始下载 ' + state.day + ' 的 ' + fmt.toUpperCase() + ' 报告');
  }

  async function generate(root) {
    if (state.busy) return;
    state.busy = true;
    const b = q('#moDayGen', root);
    if (b) { b.disabled = true; b.textContent = '汇总中…'; }
    try {
      const r = await (await fetch('/api/daily_report/generate', {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ date: state.day || '' }),
      })).json();
      if (r.ok) {
        toast(`已汇总 ${r.date}：${r.total} 条 / ${r.category_count} 类`
          + (r.note ? '（' + r.note + '）' : ''), 5200);
        state.day = r.date;
        state.list = null;
        await loadList(root, true);
      } else {
        toast('汇总失败：' + (r.error || '未知错误'), 5000);
      }
    } catch (e) {
      toast('汇总失败：' + e.message, 5000);
    } finally {
      state.busy = false;
      if (b) { b.disabled = false; b.textContent = '重新汇总'; }
    }
  }

  function bind(root) {
    const g = q('#moDayGen', root);
    if (g) g.onclick = () => generate(root);
    const md = q('#moDayDl', root); if (md) md.onclick = () => download('md');
    const xl = q('#moDayXl', root); if (xl) xl.onclick = () => download('xlsx');
    const js = q('#moDayJs', root); if (js) js.onclick = () => download('json');
    loadList(root, false);
    loadDigest(root);
  }

  /* ==================================================================
     每日报告（/api/daily_digest，core/daily_digest.py）
     ------------------------------------------------------------------
     与上面那份 m1 日报**不是同一套东西**，别混：
       · 上面的 = 情报按风险分类归档（core/daily_report.py，能出 xlsx）
       · 这里     = 「AI 安全四方向」每日报告（core/daily_digest.py）
     ① 基础设施/推理框架 ② 模型与数据层 ③ 应用与智能体 ④ 供应链。
     方向卡的数据 = 当日日报里该方向分类桶的切片（分类口径同检索页）。
     2026-10-07：四个功能模块的运行台账区块已按用户要求整体移除。
     ================================================================== */
  const dst = { list: null, open: {}, detail: {}, busy: false, notes: null, unread: 0 };

  function dDirs() {
    /* 四方向的兜底定义与后端 DIRECTIONS 一致；正常走 list.directions */
    return ((dst.list && dst.list.directions) || [
      { id: 'dir_infra', name: '① AI基础设施/推理框架风险', color: '#e3b04b' },
      { id: 'dir_model', name: '② 模型与数据层风险', color: '#2fbf9e' },
      { id: 'dir_appagent', name: '③ AI应用与智能体风险', color: '#e8913c' },
      { id: 'dir_supply', name: '④ 供应链风险', color: '#f2c94c' },
    ]);
  }

  function dgCard(entry, cell) {
    /* 方向卡与模块卡共用一套卡片渲染（展开指标 / MD·JSON 下载行为一致）。
       方向卡多一条分类色条（颜色来自 taxonomy 的分类色，进 style 前过 #rrggbb）。 */
    if (!cell) {
      return `<div class="mo-dg-card">
        <h4 title="${esc(entry.desc || '')}">${esc(entry.name || entry.id)}</h4>
        <div class="mo-dg-na">该日无报告</div>
        <div class="mo-dg-acts2"><span class="mo-dg-nodl">无可下载文件</span></div>
      </div>`;
    }
    const color = (cell.color || entry.color || '');
    const accent = (/^#[0-9a-fA-F]{6}$/.test(color)
      ? ` style="border-left:3px solid ${esc(color)}"` : '');
    const open = dst.open[entry.id] === true;
    const ms = (cell.metrics || []).map((x) =>
      `<div class="mo-dg-m"><span>${esc(x.k)}</span><b>${esc(x.v)}</b></div>`).join('');
    /* ★ 下载按钮**常驻卡片**，不藏在展开区里。
       原来只在 open 时渲染，用户看到的是一排纯文字卡片，
       根本不知道"能下载、要先点一下" —— 这就是"每日报告怎么下载"
       那个问题的由来。展开只是看更多指标，不该成为下载的前置条件。 */
    const dls = `
      <div class="mo-dg-acts2">
        <button data-dl="md" data-m="${esc(entry.id)}"${cell.has_md ? '' : ' disabled'}
          title="${cell.has_md ? '下载 ' + esc(entry.name || entry.id) + ' 的 Markdown 报告'
                          : '该条目当日没有落盘的 md 文件（可下载 JSON）'}">MD</button>
        <button data-dl="json" data-m="${esc(entry.id)}"
          title="下载原始 JSON（含全部明细）">JSON</button>
      </div>`;
    const body = open ? `<div class="mo-dg-detail">${ms}</div>` : '';
    return `<div class="mo-dg-card${open ? ' on' : ''}" data-mod="${esc(entry.id)}"${accent}>
      <h4 title="${esc(entry.desc || cell.headline || '')}">${esc(cell.module_name || entry.name || entry.id)}
        <span class="mo-dg-hint">点此展开指标</span></h4>
      <p>${esc(cell.headline || '')}</p>
      <div class="mo-dg-metrics">${(cell.metrics || []).slice(0, 3).map((x) =>
        `<span class="mo-dg-tag">${esc(x.k)} <b>${esc(x.v)}</b></span>`).join('')}</div>
      ${body}${dls}</div>`;
  }

  function renderDigest() {
    const L = dst.list;
    if (!L) return '<div class="latload">每日报告载入中…</div>';
    const dirs = dDirs();
    const notes = ((dst.notes && dst.notes.items) || []).filter((n) => !n.read).slice(0, 3);
    const head = `
      <div class="mo-dg-head">
        <b>每日报告 · AI 安全四方向</b>
        <span class="ph-sub">/api/daily_digest · 每天 ${esc(String(L.daily_at || '23:30'))} 自动生成 · 近 3 天缺失自动补齐 · 保留 ${esc(String(L.retention_days || 30))} 天</span>
        <span class="mo-dg-acts">
          <select id="moDgDay" class="mo-daily-sel" title="选择日期">
            ${(L.days || []).map((d) => `<option value="${esc(d)}"${d === dst.day ? ' selected' : ''}>${esc(d)}</option>`).join('')}
          </select>
          <button id="moDgGen" title="立即生成所选日期的四方向报告">立即生成</button>
          <button id="moDgNote" title="通知">${dst.unread ? '通知 ' + dst.unread : '通知'}</button>
        </span>
      </div>`;
    const noteBar = notes.length ? `
      <div class="mo-dg-notes">${notes.map((n) => `
        <div class="mo-dg-note"><b>${esc(n.title || '')}</b>
          <span>${(n.modules || []).map((m) => esc(m.module_name || m.module || '')).join(' · ')}</span>
          <em>${esc(String(n.ts || '').replace('T', ' '))}</em></div>`).join('')}
      </div>` : '';
    const day = dst.day;
    if (!day) return head + noteBar + '<div class="latload">还没有任何每日报告。点「立即生成」。</div>';
    const grid = (L.grid || []).find((g) => g.date === day);
    if (!grid) return head + noteBar + `<div class="latload">${esc(day)} 没有报告。</div>`;
    /* 当天真有几份报告才给"打包下载"（与后端 zip 的 404 判据一致，
       亮着点下去只会得到"该日期没有任何报告"）。
       ★ 两个坑：
         ① grid.modules 是**字典**不是数组，没有 .length，必须按下标取；
         ② 还要过滤掉值为 falsy 的 —— 后端异常返回时可能留 `{"dir_x": null}`，
            直接数 keys 会把空格子也数进去，显示"4/4 有报告"
            却只有 3 张卡片，用户点 ZIP 下去又只拿到 3 份。 */
    const cells = grid.modules || {};
    const dirCards = dirs.map((d) => dgCard(d, cells[d.id])).join('');
    const dirGot = dirs.filter((d) => cells[d.id]).length;
    return head + noteBar + `
      <div class="mo-dg-dayline">
        <span class="mo-dg-daytag">${esc(day)}</span>
        <span class="mo-dg-dayn">共 ${esc(String(dirGot))} / 4 个方向有报告</span>
      </div>
      ${dirGot > 1 ? `<div class="mo-dg-bulk">
        <button id="moDgZip" title="把当天 ${esc(String(dirGot))} 份方向报告一次打包下载（md + json + 清单）">
          ⤓ 打包下载当天全部 ${esc(String(dirGot))} 份（ZIP）</button>
        <span class="mo-dg-bulk-tip">四个方向一次拿走，含 README 清单</span>
      </div>` : ''}
      <div class="mo-dg-grid">${dirCards}</div>`;
  }

  function paintDigest(root) {
    const box = q('#moDigest', root);
    if (!box) return;
    box.innerHTML = renderDigest();
    const sel = q('#moDgDay', box);
    if (sel) sel.onchange = () => { dst.day = sel.value; paintDigest(root); };
    const g = q('#moDgGen', box); if (g) g.onclick = () => dgGenerate(root);
    const z = q('#moDgZip', box);
    if (z) z.onclick = (ev) => { ev.stopPropagation(); dgDownloadZip(dst.day); };
    const n = q('#moDgNote', box);
    if (n) n.onclick = () => {
      const ids = ((dst.notes && dst.notes.items) || []).filter((x) => !x.read).map((x) => x.id);
      if (!ids.length) { toast('没有未读通知'); return; }
      fetch('/api/daily_digest/notifications/read', {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ids }),
      }).then(() => { dst.notes = null; loadNotes(root); toast('已标记 ' + ids.length + ' 条通知为已读'); })
        .catch(() => toast('标记失败', 3000));
    };
    qa('.mo-dg-card[data-mod]', box).forEach((el) => {
      el.onclick = (ev) => {
        if (ev.target.closest('[data-dl]')) return;       // 下载按钮不触发展开
        const id = el.dataset.mod;
        dst.open[id] = dst.open[id] !== true;
        paintDigest(root);
      };
    });
    qa('[data-dl]', box).forEach((b) => {
      b.onclick = (ev) => {
        ev.stopPropagation();
        dgDownload(b.dataset.m, b.dataset.dl, dst.day);
      };
    });
    if (typeof TR !== 'undefined' && TR && TR.on) TR.applyView('每日报告');
  }

  async function loadNotes(root) {
    try {
      dst.notes = await (await fetch('/api/daily_digest/notifications?limit=20')).json();
      dst.unread = (dst.notes && dst.notes.unread) || 0;
    } catch (e) { dst.notes = null; }
  }

  async function loadDigest(root) {
    const box = q('#moDigest', root);
    if (!box) return;
    box.innerHTML = '<div class="latload">每日报告载入中…</div>';
    try {
      const r = await fetch('/api/daily_digest?days=' + ((dst.list && dst.list.days) ? dst.list.days.length : 31));
      const j = await r.json();
      if (j && j.days) {
        dst.list = j;
        if (!dst.day || !(j.days || []).includes(dst.day)) dst.day = (j.days || [])[0] || null;
      } else if (j && j.error) {
        box.innerHTML = `<div class="latload">每日报告不可用：${esc(j.error)}</div>`;
        return;
      }
    } catch (e) {
      box.innerHTML = '<div class="latload">每日报告加载失败（服务未重启时会走到这里）</div>';
      return;
    }
    await loadNotes(root);
    paintDigest(root);
  }

  function dgDownload(mid, fmt, day) {
    if (!day) { toast('先选一个日期'); return; }
    const a = document.createElement('a');
    a.href = '/api/daily_digest?module=' + encodeURIComponent(mid)
      + '&date=' + encodeURIComponent(day) + '&fmt=' + fmt;
    a.download = '';
    document.body.appendChild(a); a.click(); a.remove();
    toast('开始下载 ' + day + ' 的 ' + fmt.toUpperCase() + ' 报告');
  }

  /* 打包下载：当天全部方向报告一次拿走。按钮的可见性由 renderDigest 按
     "当天真有 ≥2 份报告"决定，与后端 zip 的 404 判据对齐 ——
     不亮一个点下去就 404 的按钮。 */
  function dgDownloadZip(day) {
    if (!day) { toast('先选一个日期'); return; }
    const a = document.createElement('a');
    a.href = '/api/daily_digest?date=' + encodeURIComponent(day) + '&fmt=zip';
    a.download = '';
    document.body.appendChild(a); a.click(); a.remove();
    toast('开始打包下载 ' + day + ' 的四方向报告（ZIP）', 3600);
  }

  async function dgGenerate(root) {
    if (dst.busy) return;
    dst.busy = true;
    toast('正在生成 ' + (dst.day || '今天') + ' 的四方向报告…', 3000);
    try {
      const r = await (await fetch('/api/daily_digest/generate', {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ date: dst.day || '' }),
      })).json();
      if (r.generated && r.generated.length) {
        toast(`已生成 ${r.generated.length} 份方向报告 · ${r.date}`, 5200);
        dst.day = r.date; dst.list = null;
        await loadNotes(root);
        await loadDigest(root);
      } else {
        toast(r.date ? '该日没有任何产出，未生成报告（不造空报告）' : '生成失败：' + (r.error || '未知'), 5000);
      }
    } catch (e) { toast('生成失败：' + e.message, 5000); }
    finally { dst.busy = false; }
  }

  /* 对外暴露（测试用） */
  window.M1Daily = {
    bind, HTML, state, renderDays, renderDetail, download, generate,
    dst, renderDigest, loadDigest, dgDownload, dgGenerate,
  };

  /* ---------------- 注册进主体 ---------------- */
  AISEC.register({
    id: 'm1_daily',
    name: '每日情报报告',
    monitorSections() {
      return [{ id: 'moDailyReport', html: HTML, mount: bind }];
    },
  });
})();