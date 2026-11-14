// web/panel.js
// ⚠ 自动生成，请勿直接改本文件 —— 源文件在 modules/m2_enrich/web/panel.js
//   改完跑一次： py -3 tools/组装前端.py
/* ============================================================
   m2_enrich · 情报富化 —— 模块前端面板（负责人：成员B）
   ------------------------------------------------------------
   详情抽屉：受影响资产定位、POC / EXP 搜索、修复方案生成。
   富化台视图：资产风险体检（上传 word/excel/txt）· 攻击面测绘实查 · 预警订阅。
   主体只提供占位符，模块自己决定内容与事件。
   接口：GET /api/assets · GET|POST /api/poc · POST|GET /api/asset_scan
         GET /api/asset_search(|/status) · GET|POST /api/subscribe*
   ============================================================ */
(function () {
  // 主体 app.js 的全局能力（$ / esc / toast / S / openDetail / TYPE_META / renderTop …）
  // 是同一份全局脚本作用域，模块直接拿来用即可，不需要 import。
  /* ---------------- 受影响资产定位 / POC 搜索（详情抽屉面板，来自 aisec-D_1.3） ---------------- */
  const CONF_CN = { high: '高', medium: '中', low: '低' };
  const CONF_CLS = { high: 'chip ok', medium: 'chip', low: 'chip alert' };
  const METHOD_CN = { nvd_api: 'NVD', llm_extract: 'LLM', cpe_match: 'CPE字典' };
  const POC_TYPE_CN = { exploit_code: '利用代码', scanner: '扫描器', environment: '环境搭建',
                        payload: 'Payload', analysis: '分析报告', other: '其他' };
  const REL_CLS = { 高: 'chip ok', 中: 'chip', 低: 'chip alert' };

  /* 受影响互联网资产定位（第二部分）：测绘语法 —— 只生成查询，不发起扫描 */
  function surveyHtml(sv) {
    if (!sv) return '';
    if (sv.error) return `<div class="meta-note">${esc(sv.error)}</div>`;
    const PLAT = [['fofa', 'FOFA'], ['shodan', 'Shodan'], ['quake', 'Quake'],
                  ['zoomeye', 'ZoomEye'], ['google', 'Google']];
    const act = PLAT.filter(([k]) => (sv[k] || []).length);
    if (!act.length) return `<div class="meta-note">未能生成测绘语法</div>`;
    const tabs = act.map(([k, label], i) =>
      `<button class="chip sv-tab${i === 0 ? ' on' : ''}" data-plat="${k}">${label} · ${sv[k].length}</button>`).join('');
    const panes = act.map(([k, label], i) => `
      <div class="sv-pane" data-plat="${k}" style="display:${i === 0 ? 'block' : 'none'}">
        ${sv[k].map((x) => `<div class="sv-q" data-q="${esc(x.q)}" title="点击复制 · ${esc(x.why)}">
            <code>${esc(x.q)}</code>${x.product ? `<span class="chip">${esc(x.product)}</span>` : ''}</div>`).join('')}
      </div>`).join('');
    const ver = (sv.version_narrow || []).length
      ? `<div class="meta-note" style="margin-top:8px">版本收窄：${esc(sv.version_narrow.join('；'))}</div>` : '';
    return `<div class="sv">
      <div class="mini" style="margin-bottom:6px">互联网资产测绘语法
        <span class="chip" title="本系统只生成查询语法，不发起任何扫描/探测">只生成语法 · 不扫描</span></div>
      <div class="sv-tabs">${tabs}</div>${panes}${ver}
      <div class="meta-note" style="margin-top:8px">${esc(sv.note || '')}</div>
      <div class="meta-note">${esc(sv.compliance || '')}</div>
    </div>`;
  }

  function bindSurvey(el) {
    el.querySelectorAll('.sv-tab').forEach((b) => {
      b.onclick = () => {
        el.querySelectorAll('.sv-tab').forEach((x) => x.classList.toggle('on', x === b));
        el.querySelectorAll('.sv-pane').forEach((p) =>
          p.style.display = (p.dataset.plat === b.dataset.plat) ? 'block' : 'none');
      };
    });
    el.querySelectorAll('.sv-q').forEach((q) => {
      q.onclick = async () => {
        const text = q.dataset.q || '';
        try { await navigator.clipboard.writeText(text); toast('已复制：' + text); }
        catch (e) { toast('复制失败，请手动选中：' + text); }
      };
    });
  }

  async function loadAssets(id) {
    const el = $('assetsPanel'); if (!el) return;
    try {
      const r = await (await fetch('/api/assets?id=' + encodeURIComponent(id))).json();
      if (r.error) throw new Error(r.error);
      renderAssets(el, r);
    } catch (e) { el.innerHTML = `<div class="empty">资产定位失败：${esc(e.message)}</div>`; }
  }

  function renderAssets(el, r) {
    const assets = r.assets || [];
    const hint = r.hint ? `<div class="meta-note" style="margin-bottom:10px">${esc(r.hint)}</div>` : '';
    const sv = surveyHtml(r.survey);
    if (!assets.length) {
      el.innerHTML = `${hint}<div class="meta-note">未识别到受影响资产（该 CVE 可能没有 CPE 映射）</div>${sv}`;
      bindSurvey(el);
      return;
    }
    const cards = assets.map((a) => {
      const conf = CONF_CLS[a.confidence] || 'chip';
      const aff = (a.affected_versions || []).join('；') || '—';
      const unaff = (a.unaffected_versions || []).join('；') || '—';
      const method = METHOD_CN[a.extraction_method] || a.extraction_method || '—';
      return `<div class="paper">
        <b>${esc(a.vendor)}/${esc(a.product)}
          <span class="${conf}" style="margin-left:6px">置信 ${CONF_CN[a.confidence] || a.confidence}</span>
          <span class="chip" style="margin-left:4px">${esc(method)}</span></b>
        <p>受影响：${esc(aff)}<br>不受影响：${esc(unaff)}</p>
        ${a.cpe ? `<div class="mt">${esc(a.cpe)}</div>` : ''}
      </div>`;
    }).join('');
    el.innerHTML = `${hint}${cards}${sv}`;
    bindSurvey(el);
  }

  function bindPocButtons(id) {
    const q = $('pocQuick'), f = $('pocFull');
    if (q) q.onclick = () => runPoc(id, 1);
    if (f) f.onclick = () => runPoc(id, 0);
  }

  /* 问题二（纯前端优化，不改后端速度）：
     ① 请求发出前立即显示非阻塞 loading；
     ② 10s 未返回追加「耗时较长」提示；
     ③ 同一 CVE（按 quick 维度分开）结果进 sessionStorage 缓存 30 分钟，命中先展示缓存再后台静默刷新；
     ④ POC 搜索本就是按钮触发（懒加载），不随详情打开自动发起；
     ⑤ 全部为页面内 loading，无 alert / 阻塞式提示。 */
  const POC_CACHE_TTL = 30 * 60 * 1000;   // 30 分钟
  let _pocHintTimer = null;               // 「耗时较长」提示的 10s 计时器
  let _pocPollTimer = null;               // 轮询句柄

  function pocCacheKey(id, quick) { return 'asi-poc-' + id + '-' + (quick ? '1' : '0'); }

  function pocCacheGet(id, quick) {
    try {
      const raw = sessionStorage.getItem(pocCacheKey(id, quick));
      if (!raw) return null;
      const o = JSON.parse(raw);
      if (!o || typeof o.t !== 'number' || (Date.now() - o.t) > POC_CACHE_TTL) return null;
      return o.v || null;
    } catch (e) { return null; }
  }

  function pocCacheSet(id, quick, st) {
    try { sessionStorage.setItem(pocCacheKey(id, quick), JSON.stringify({ t: Date.now(), v: st })); }
    catch (e) { /* 缓存不可用（隐私模式/写满）时静默降级，不影响搜索 */ }
  }

  /* 立即显示 loading；10s 后若仍未完成，追加「耗时较长」说明（不打断、不替换内容） */
  function pocLoading(out, quick) {
    out.innerHTML = `<div class="poc-loading" role="status" aria-live="polite">
        <span class="rspin"></span>
        <div class="poc-loading-txt">${quick ? '正在搜索 POC 线索…' : '正在搜索 POC 线索（完整搜索，含 GitHub，约数分钟）…'}</div>
        <div class="poc-loading-hint" style="display:none">POC 搜索涉及多源检索与 LLM 分析，耗时较长，请稍候…</div>
      </div>`;
    if (_pocHintTimer) clearTimeout(_pocHintTimer);
    const hint = out.querySelector('.poc-loading-hint');
    _pocHintTimer = setTimeout(() => { if (hint && out.contains(hint)) hint.style.display = 'block'; }, 10000);
  }

  function pocStopLoading() {
    if (_pocHintTimer) { clearTimeout(_pocHintTimer); _pocHintTimer = null; }
  }

  async function runPoc(id, quick) {
    const out = $('pocOut'); if (!out) return;
    // ③ 缓存命中：立即展示上次结果，再后台静默刷新（不弹 loading，不打搅用户）
    const cached = pocCacheGet(id, quick);
    if (cached) {
      renderPoc(out, cached);
      pocRefresh(id, quick, out, /*silent*/ true);
      return;
    }
    // ① 未命中：请求发出前立即显示非阻塞 loading
    pocLoading(out, quick);
    pocRefresh(id, quick, out, false);
  }

  async function pocRefresh(id, quick, out, silent) {
    try {
      // force=1：显式点击要的就是「现在抓一次」。否则服务端对已完成的 CVE 直接返回缓存，
      // 先点「快速搜索」再点「完整搜索」会拿到第一次的旧结果（看不出差别，像按钮坏了）。
      await fetch('/api/poc?id=' + encodeURIComponent(id) + '&quick=' + quick + '&force=1', { method: 'POST' });
    } catch (e) {
      if (!silent) { pocStopLoading(); out.innerHTML = `<div class="empty">启动失败：${esc(e.message)}</div>`; }
      return;
    }
    pocPoll(id, quick, out);
  }

  function pocPoll(id, quick, out) {
    if (_pocPollTimer) clearInterval(_pocPollTimer);
    _pocPollTimer = setInterval(async () => {
      let st;
      try { st = await (await fetch('/api/poc?id=' + encodeURIComponent(id))).json(); }
      catch (e) {
        clearInterval(_pocPollTimer); _pocPollTimer = null; pocStopLoading();
        out.innerHTML = `<div class="empty">查询失败：${esc(e.message)}</div>`;
        return;
      }
      if (!st.running) {
        clearInterval(_pocPollTimer); _pocPollTimer = null; pocStopLoading();
        renderPoc(out, st);
        pocCacheSet(id, quick, st);            // ③ 落缓存（含最终结果，供下次秒开）
      }
      // 仍在运行：保持现有 loading（「耗时较长」提示由 pocLoading 里的 10s 计时器负责）
    }, 2000);
  }

  function renderPoc(out, st) {
    if (st.error) { out.innerHTML = `<div class="empty">搜索失败：${esc(st.error)}</div>`; return; }
    const rs = st.results || [];
    if (!rs.length) { out.innerHTML = `<div class="meta-note">未找到 POC（可尝试「完整搜索」）</div>`; return; }

    // ② 精度优化：按「匹配等级」分组展示，折叠只是提到该组件 / 官方仓库的条目
    const TIER = {
      A: { name: '确证 POC / EXP（含 CVE 编号或来自 Metasploit · Nuclei · Exploit-DB）', open: true },
      B: { name: '较可能相关（描述提到 CVE 或带产品名+漏洞词）', open: true },
      C: { name: '仅提及该组件的项目（非利用代码，已折叠）', open: false },
      D: { name: '官方组件仓库 / 无关（已折叠）', open: false },
    };
    const groups = { A: [], B: [], C: [], D: [] };
    rs.forEach((r) => { (groups[r.match_tier] || groups.D).push(r); });
    // 供「生成复现环境」使用：POC 线索按等级 A→B→C 排序取 URL（D 是噪声不入）
    window.__lastPocUrls = groups.A.concat(groups.B, groups.C)
      .map((r) => r && r.url).filter(Boolean).slice(0, 5);
    const count = Object.keys(groups).map((k) => `${k}:${groups[k].length}`).join(' · ');

    const card = (r) => {
      const type = POC_TYPE_CN[r.poc_type] || r.poc_type || '其他';
      const rel = REL_CLS[r.reliability] || 'chip';
      const code = r.code_content
        ? `<div class="mt" style="margin-top:6px;word-break:break-all">${esc(r.code_content.slice(0, 200))}${r.code_content.length > 200 ? '…' : ''}</div>` : '';
      return `<div class="paper">
        <b>${esc(r.title || r.url)}
          <span class="chip" style="margin-left:6px">${esc(r.source)}</span>
          ${r.match_tier ? `<span class="chip" style="margin-left:4px" title="A=确证相关 B=较可能 C=仅提及组件 D=官方/无关">${esc(r.match_tier)}</span>` : ''}
          <span class="chip" style="margin-left:4px">${esc(type)}</span>
          <span class="${rel}" style="margin-left:4px">${esc(r.reliability || '低')}</span>
          ${r.relevance_score != null ? `<span class="chip" style="margin-left:4px">相关 ${r.relevance_score}</span>` : ''}</b>
        ${code}
        <div style="margin-top:6px">${link(r.url)}</div>
      </div>`;
    };

    out.innerHTML = `<div class="meta-note" style="margin-bottom:6px">共 ${rs.length} 条，按相关性分级：
        ${esc(count)}　·　排序依据 = 匹配等级 A→D，同级别内按相关性/可靠性/star</div>`
      + Object.keys(groups).filter((k) => groups[k].length).map((k) => {
        const g = groups[k];
        const head = `<div class="meta-note" style="margin:8px 0 4px;font-weight:600">▸ ${esc(TIER[k].name)}（${g.length}）</div>`;
        const body = g.map(card).join('');
        return TIER[k].open
          ? head + body
          : `<details style="margin:6px 0"><summary class="meta-note" style="cursor:pointer">${esc(TIER[k].name)}（${g.length}）— 点开查看</summary>${body}</details>`;
      }).join('');
  }

/* ============================================================
   m2_enrich · 情报富化台「资产风险体检」（2026-10-03 新增）
   ------------------------------------------------------------
   用户需求：富化台内容太少 —— 要能上传公司互联网资产（word / txt / excel），
   用检测模块 1 的情报自动分析这些资产面临的风险。

   归属：本区块由模块通过 AISEC.register({enrichSections}) 贡献，
   主体 app.js 只负责把它插进「情报富化台」视图，不掺和任何细节。
   接口：POST /api/asset_scan（上传）· GET /api/asset_scan（列表 / ?id= 取值 / ?md=1 导出）
   ============================================================ */
const ASCAN = (() => {
  const RK = { 严重: 'crit', 高: 'high', 中: 'med', 低: 'low', 无已知风险: 'info', 待确认: 'info' };
  const CONF_CN = { high: '高', medium: '中', low: '低' };
  // 严重度来自语料，必须**白名单化**再拼进 class —— 直接插值等于把 XSS 开在 badge 上
  // （桩测试实测：severity 里塞 <img onerror> 会原样注入）。
  const SEVS = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN'];
  const sevOf = (x) => {
    const s = String(x || '').toUpperCase();
    return SEVS.includes(s) ? s : 'UNKNOWN';
  };
  let last = null;                    // 最近一次报告（导出 / 重渲染用）
  let root = null;

  const q = (sel, el) => (el || root).querySelector(sel);
  const qa = (sel, el) => Array.from((el || root).querySelectorAll(sel));

  function riskChip(level) {
    const cls = RK[level] || 'info';
    return `<span class="en-rk ${cls}">${esc(level)}</span>`;
  }

  /* ---------------- 上传交互 ---------------- */
  function bind(el) {
    root = el;
    const file = q('#enFile'), drop = q('#enDrop');
    q('#enPick').onclick = () => file.click();
    file.onchange = () => { if (file.files && file.files[0]) upload(file.files[0]); file.value = ''; };
    q('#enSample').onclick = () => run('/api/asset_scan?sample=1', 'POST');
    q('#enHistBtn').onclick = toggleHist;
    ['dragenter', 'dragover'].forEach((ev) => drop.addEventListener(ev, (e) => {
      e.preventDefault(); drop.classList.add('drag');
    }));
    ['dragleave', 'drop'].forEach((ev) => drop.addEventListener(ev, (e) => {
      e.preventDefault(); drop.classList.remove('drag');
    }));
    drop.addEventListener('drop', (e) => {
      const f = e.dataTransfer && e.dataTransfer.files && e.dataTransfer.files[0];
      if (f) upload(f);
    });
    drop.onclick = (e) => { if (!e.target.closest('button')) file.click(); };
    loadHist();
  }

  /* 传入 pct（有真实百分比）时改用圆形进度环：填充与中间数字同步走，
     适合"上传/解析"这种可量化、又只占一小块区域的等待。
     不传 pct（时长不可量化）→ 保持旋转圈，不显示百分比。 */
  function prog(msg, spin, pct) {
    const p = q('#enProg');
    if (!p) return;
    p.style.display = '';
    if (typeof pct === 'number') {
      const v = Math.max(0, Math.min(100, pct));
      p.innerHTML = `<div class="loading with-ring"><span class="ring sm" style="--p:${(v / 100).toFixed(3)}">`
        + '<svg viewBox="0 0 48 48" aria-hidden="true"><circle class="track" cx="24" cy="24" r="20"></circle>'
        + '<circle class="ind" cx="24" cy="24" r="20"></circle></svg>'
        + `<span class="num">${Math.round(v)}%</span></span><span>${esc(msg)}</span></div>`;
    } else {
      p.innerHTML = `<div class="loading">${esc(msg)}${spin ? '<span class="rspin"></span>' : ''}</div>`;
    }
  }

  function hideProg() {
    const p = q('#enProg');
    if (p) { p.style.display = 'none'; p.innerHTML = ''; }
  }

  function fail(msg) {
    hideProg();
    const box = q('#enResult');
    if (box) box.innerHTML = `<div class="empty"><div class="big">体检失败</div>${esc(msg)}</div>`;
    toast('体检失败：' + msg, 6000);
  }

  function upload(f) {
    if (f.size > 24 * 1024 * 1024) { toast('文件超过 24MB，请拆分后再上传'); return; }
    const fd = new FormData();
    fd.append('file', f, f.name);
    prog(`正在解析并比对情报库：${f.name}`, true);
    fetch('/api/asset_scan', { method: 'POST', body: fd })
      .then((r) => r.json())
      .then((r) => {
        if (!r || !r.ok) throw new Error((r && r.error) || '体检失败');
        show(r.report); loadHist();
      })
      .catch((e) => fail(e.message));
  }

  function run(url, method) {
    prog('正在解析并比对情报库…', true);
    fetch(url, { method: method || 'GET' })
      .then((r) => r.json())
      .then((r) => { if (!r || !r.ok) throw new Error((r && r.error) || '请求失败'); show(r.report); loadHist(); })
      .catch((e) => fail(e.message));
  }

  /* ---------------- 报告渲染 ---------------- */
  function show(rep) {
    last = rep;
    q('#enProg').style.display = 'none';
    q('#enResult').innerHTML = reportHtml(rep);
    const ex = q('#enExport');
    if (ex) ex.onclick = () => exportMd(rep.id, rep.filename);
    const ag = q('#enAgain');
    if (ag) ag.onclick = () => q('#enFile').click();
    qa('.en-f[data-id]', q('#enResult')).forEach((row) => {
      row.onclick = () => openDetail(row.dataset.id);
    });
    qa('.en-more', q('#enResult')).forEach((b) => {
      b.onclick = () => {
        const box = b.parentElement;
        box.querySelectorAll('.en-f.hide').forEach((x) => x.classList.remove('hide'));
        b.remove();
      };
    });
    qa('.en-host-row', q('#enResult')).forEach((row) => {
      row.onclick = () => {
        const p = row.dataset.cve;
        if (p) openDetail(p);
      };
    });
  }

  function reportHtml(rep) {
    const s = (rep.risk || {}).summary || {};
    const f = rep.file || {};
    const warn = f.warn ? `<div class="en-warn">⚠️ ${esc(f.warn)}</div>` : '';
    const kev = (s.kev_ids || []).length
      ? `<div class="en-kev"><b>⚠️ 已被在野利用（CISA KEV）</b>${s.kev_ids.map((c) =>
          `<a class="en-kev-i" data-id="${esc(c)}" href="javascript:void(0)">${esc(c)}</a>`).join('')}</div>` : '';
    return `
      <div class="panel en-rep">
        <header>体检报告 · ${esc(s.cve_hits || 0)} 条漏洞命中
          <span class="ph-sub">${esc(rep.filename)} · ${esc(f.kind || '')} · ${esc(String(f.chars || 0))} 字符 · 耗时 ${esc(String(rep.elapsed_ms || 0))}ms · 比对情报库 ${esc(String(s.scanned_docs || 0))} 条</span>
        </header>
        <div class="pbody">
          ${warn}
          <div class="en-kpis">
            ${kpi('资产主机', s.hosts, '')}
            ${kpi('软件组件', s.products, s.products_no_version ? `其中 ${s.products_no_version} 个未填版本` : '')}
            ${kpi('命中 CVE', s.cve_hits, '')}
            ${kpi('严重', s.critical, '', 'crit')}
            ${kpi('高危', s.high, '', 'high')}
            ${kpi('在野利用', s.exploited, '', s.exploited ? 'crit' : '')}
          </div>
          ${kev}
          <div class="en-ops">
            <button class="btn ghost sm" id="enExport">⬇ 导出 Markdown 报告</button>
            <button class="btn ghost sm" id="enAgain">↻ 换一份资产清单</button>
            <span class="meta-note" style="margin:0">判定依据：${esc(rep.basis || '')}</span>
          </div>
        </div>
      </div>
      ${hostTable(rep)}
      ${prodCards(rep)}
      ${ledger(rep)}`;
  }

  function kpi(label, v, sub, cls) {
    return `<div class="en-kpi ${cls || ''}"><b>${esc(String(v == null ? 0 : v))}</b>
      <span>${esc(label)}</span>${sub ? `<i>${esc(sub)}</i>` : ''}</div>`;
  }

  function hostTable(rep) {
    const hosts = ((rep.risk || {}).hosts) || [];
    if (!hosts.length) return '';
    const rows = hosts.map((h) => {
      const comps = (h.components || []).map((c) =>
        `<span class="chip">${esc(c.name)}${c.version ? ' ' + esc(c.version) : ''}</span>`).join('') || '<span class="meta-note">—</span>';
      const top = (h.findings || []);
      return `<tr class="en-host-row" data-cve="">
        <td class="en-host">${esc(h.name)}</td>
        <td><span class="chip">${esc(h.type)}</span><span class="chip">${esc(h.scope || '')}</span></td>
        <td class="en-host-risk">${riskChip(h.risk_level)}</td>
        <td class="en-num">${esc(String(h.cve_count || 0))}${h.kev_count ? ` <span class="chip alert">在野 ${h.kev_count}</span>` : ''}</td>
        <td class="en-comps">${comps}</td>
      </tr>`;
    }).join('');
    return `<div class="panel en-tblwrap">
      <header>资产主机风险 · ${hosts.length} 个主机 <span class="ph-sub">主机风险 = 该主机同一行承载软件的风险最大值</span></header>
      <div class="pbody">
        <table class="en-tbl">
          <thead><tr><th>主机 / 域名</th><th>类型</th><th>风险</th><th>命中</th><th>承载组件</th></tr></thead>
          <tbody>${rows}</tbody>
        </table>
      </div>
    </div>`;
  }

  function prodCards(rep) {
    const prods = ((rep.risk || {}).products) || [];
    if (!prods.length) return '';
    const cards = prods.map((p) => {
      const fs = p.findings || [];
      const list = fs.map((x, i) => findingRow(x, i >= 6)).join('')
        + (fs.length > 6 ? `<button class="en-more">展开其余 ${fs.length - 6} 条命中</button>` : '')
        + (fs.length === 0 ? '<div class="meta-note">情报库中未匹配到该产品/版本的已知漏洞（可能未收录，或该版本不受影响）</div>' : '');
      return `<div class="panel en-prod">
        <header>${esc(p.display || p.name)} <span class="chip">${esc(p.version || '版本未知')}</span>
          ${riskChip(p.risk_level)}
          <span class="chip">命中 ${esc(String(p.cve_count || 0))}</span>
          ${p.kev_count ? `<span class="chip alert">● 在野利用 ${p.kev_count}</span>` : ''}
          <span class="ph-sub">${esc(p.vendor || '')}</span>
        </header>
        <div class="pbody">
          <div class="en-raw meta-note">清单原行：${esc((p.raw || '').slice(0, 150))}</div>
          ${list}
        </div>
      </div>`;
    }).join('');
    return `<div class="en-prods">${cards}</div>`;
  }

  function findingRow(x, hide) {
    const sev = sevOf(x.severity);
    const rem = (x.remediation || []).length
      ? `<div class="en-rem">处置建议：${esc((x.remediation || []).join(' '))}</div>` : '';
    const tags = [
      x.kev_added ? `<span class="chip alert">KEV ${esc(x.kev_added)}</span>` : '',
      x.trust_label ? `<span class="chip trust">${esc(x.trust_label)}</span>` : '',
      (x.risk_tags || []).slice(0, 3).map((t) => `<span class="chip">${esc(t)}</span>`).join(''),
      (x.cwe || []).length ? `<span class="chip">${esc(x.cwe.join(' '))}</span>` : '',
      x.poc ? `<span class="chip">POC×${x.poc}</span>` : '',
      x.patch ? `<span class="chip ok">补丁×${x.patch}</span>` : '',
    ].join('');
    return `<div class="en-f${hide ? ' hide' : ''}" data-id="${esc(x.id)}">
      <div class="en-f-l1">
        <span class="cve">${esc(x.id)}</span>
        <span class="badge ${sev}">${esc(sev)}${x.score != null ? ' ' + esc(String(x.score)) : ''}</span>
        ${x.exploited ? '<span class="chip alert">● 在野利用</span>' : ''}
        <span class="en-f-ttl">${esc(x.title || '')}</span>
        <span class="en-go">详情 →</span>
      </div>
      <div class="en-f-l2">
        <span class="en-ev">版本依据：${esc(x.evidence || '')}</span>
        <span class="chip">置信 ${esc(x.confidence || '')}</span>
        <span class="chip">${esc(x.published || '')}</span>
        ${tags}
      </div>${rem}
    </div>`;
  }

  function ledger(rep) {
    const a = rep.assets || {};
    const block = (t, arr, fmt) => (!arr || !arr.length) ? '' : `<div class="en-lg"><b>${esc(t)}</b>
      <div class="en-lg-v">${arr.slice(0, 40).map((x) => `<span class="chip">${esc(fmt(x))}</span>`).join('')}</div></div>`;
    const html = block('端口 / 服务', a.ports, (x) => x)
      + block('操作系统', a.os, (x) => x)
      + block('URL', a.urls, (x) => x.url)
      + block('联系邮箱', a.emails, (x) => x)
      + block('文件中已点名的 CVE', a.cves_in_doc, (x) => x);
    if (!html) return '';
    return `<div class="panel en-ledger"><header>资产台账明细 <span class="ph-sub">从文件里抽出的其它可用信息</span></header>
      <div class="pbody">${html}</div></div>`;
  }

  /* ---------------- 历史 / 导出 ---------------- */
  function loadHist() {
    fetch('/api/asset_scan').then((r) => r.json()).then((r) => {
      if (!r || !r.ok) return;
      q('#enHist').dataset.items = JSON.stringify(r.items || []);
      if (q('#enHist').style.display !== 'none') renderHist(r.items || []);
    }).catch(() => {});
  }

  function toggleHist() {
    const box = q('#enHist');
    const show = box.style.display === 'none';
    box.style.display = show ? '' : 'none';
    if (show) {
      try { renderHist(JSON.parse(box.dataset.items || '[]')); } catch (e) { renderHist([]); }
    }
  }

  function renderHist(items) {
    const box = q('#enHist');
    if (!items.length) {
      box.innerHTML = '<div class="meta-note" style="padding:6px 2px">暂无体检记录。</div>';
      box.dataset.items = '[]';
      return;
    }
    box.dataset.items = JSON.stringify(items);
    box.innerHTML = `<div class="panel"><header>历史体检 · ${items.length} 次 <span class="ph-sub">点一次回看完整报告</span></header>
      <div class="pbody">${items.map((it) => {
        const s = it.summary || {};
        return `<div class="en-hist-row" data-id="${esc(it.id)}">
          <span class="en-hist-f">${esc(it.filename || '')}</span>
          <span class="chip">${esc((it.file || {}).kind || '')}</span>
          <span class="chip">主机 ${esc(String(s.hosts || 0))}</span>
          <span class="chip">组件 ${esc(String(s.products || 0))}</span>
          <span class="chip">命中 ${esc(String(s.cve_hits || 0))}</span>
          ${s.exploited ? `<span class="chip alert">在野 ${esc(String(s.exploited))}</span>` : ''}
          <span class="en-hist-t">${esc(it.created_at || '')}</span>
          <span class="en-go">查看 →</span>
        </div>`;
      }).join('')}</div></div>`;
    qa('.en-hist-row', box).forEach((r) => {
      r.onclick = () => fetch('/api/asset_scan?id=' + encodeURIComponent(r.dataset.id))
        .then((x) => x.json())
        .then((x) => { if (x && x.ok) { show(x.report); window.scrollTo({ top: 0, behavior: 'smooth' }); } })
        .catch(() => toast('读取失败'));
    });
  }

  function exportMd(id, filename) {
    fetch('/api/asset_scan?id=' + encodeURIComponent(id) + '&md=1')
      .then((r) => r.blob())
      .then((b) => {
        const a = document.createElement('a');
        a.href = URL.createObjectURL(b);
        a.download = (filename || '资产体检').replace(/\.[^.]+$/, '') + '_资产风险体检报告.md';
        document.body.appendChild(a); a.click(); a.remove();
        setTimeout(() => URL.revokeObjectURL(a.href), 4000);
        toast('已导出 Markdown 报告');
      })
      .catch(() => toast('导出失败'));
  }

  const HTML = `
    <div class="en-scan-head">
      <div class="en-scan-ttl">
        <b>资产风险体检</b>
        <span class="chip">Word / Excel / TXT</span>
        <span class="chip trust">检测模块 1 情报比对</span>
        <span class="chip" title="按 NVD 原始 CPE 版本区间判定，非关键词命中">按版本区间判定</span>
      </div>
      <div class="en-scan-ops">
        <button class="btn ghost sm" id="enPick">选择文件</button>
        <button class="btn ghost sm" id="enSample">载入示例</button>
        <button class="btn ghost sm" id="enHistBtn">历史记录</button>
      </div>
    </div>
    <div class="en-drop" id="enDrop">
      <input type="file" id="enFile" hidden
             accept=".docx,.doc,.xlsx,.xls,.txt,.csv,.tsv,.md,.json,.log,.xml,.ini,.conf">
      <div class="en-drop-ic">
        <svg viewBox="0 0 24 24" width="22" height="22" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
          <path d="M12 16V4m0 0L7.5 8.5M12 4l4.5 4.5"></path><path d="M4 15v3.5A1.5 1.5 0 005.5 20h13a1.5 1.5 0 001.5-1.5V15"></path>
        </svg>
      </div>
      <div class="en-drop-t">把公司资产清单拖到这里，或点击选择文件</div>
      <div class="en-drop-s">.docx / .doc（Word）· .xlsx / .xls（Excel）· .txt / .csv —— 单文件 ≤ 24MB；
        文件只在本机解析，不外发、不联网</div>
    </div>
    <div id="enProg" class="en-prog" style="display:none"></div>
    <div id="enResult"></div>
    <div id="enHist" class="en-hist" style="display:none"></div>`;

  return { HTML, bind };
})();

/* ============================================================
   m2_enrich · 公司 CMDB 连接 + 资产风险自动分析（2026-10-04 新增）
   ------------------------------------------------------------
   用户需求：要一个接口能连公司 CMDB，自动分析资产的风险性/脆弱性，
   给出「优先解决什么 / 怎么解决 / 怎么检查已解决」的报告，并能下载文件。
   放在「资产风险体检（公司互联网资产清单）」区块正下方。

   接入三种模式：
     · REST 直连  —— 填 CMDB 地址（凭证走环境变量 AISEC_CMDB_TOKEN，不进请求/代码）
     · 粘贴数据  —— 直接把 CMDB 导出的 JSON / CSV / TSV 贴进来（离线兜底，永远可用）
     · 上传文件  —— 上传 CMDB 导出的 word / excel / txt
   接口：POST /api/cmdb_scan · GET /api/cmdb_scan(?id=|?md=1) · GET /api/cmdb_scan/config
   ============================================================ */
const ACMDB = (() => {
  const SEVS = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN'];
  const sevOf = (x) => { const s = String(x || '').toUpperCase(); return SEVS.includes(s) ? s : 'UNKNOWN'; };
  const RK = { 严重: 'crit', 高: 'high', 中: 'med', 低: 'low', 无已知风险: 'info', 待确认: 'info' };
  let root = null;
  let last = null;
  let submitting = false;
  let pickedFiles = [];   /* 文件模式：多选的文件（可逐个移除，合并出一份报告） */
  let pickedDbs = [];     /* 数据库模式：多选的 .db（可逐个移除，合并成一份报告） */
  const q = (sel, el) => (el || root).querySelector(sel);
  const qa = (sel, el) => Array.from((el || root).querySelectorAll(sel));

  function riskChip(level) {
    const cls = RK[level] || 'info';
    return `<span class="en-rk ${cls}">${esc(level)}</span>`;
  }

  /* 同 prog(enProg)：有 pct 走圆形进度环，没有则走旋转圈 */
  function prog(msg, spin, pct) {
    const p = q('#cmProg');
    if (!p) return;
    p.style.display = '';
    if (typeof pct === 'number') {
      const v = Math.max(0, Math.min(100, pct));
      p.innerHTML = `<div class="loading with-ring"><span class="ring sm" style="--p:${(v / 100).toFixed(3)}">`
        + '<svg viewBox="0 0 48 48" aria-hidden="true"><circle class="track" cx="24" cy="24" r="20"></circle>'
        + '<circle class="ind" cx="24" cy="24" r="20"></circle></svg>'
        + `<span class="num">${Math.round(v)}%</span></span><span>${esc(msg)}</span></div>`;
    } else {
      p.innerHTML = `<div class="loading">${esc(msg)}${spin ? '<span class="rspin"></span>' : ''}</div>`;
    }
  }
  function hideProg() { const p = q('#cmProg'); if (p) { p.style.display = 'none'; p.innerHTML = ''; } }
  function fail(msg) {
    hideProg();
    const box = q('#cmResult');
    if (box) box.innerHTML = `<div class="empty"><div class="big">分析失败</div>${esc(msg)}</div>`;
    toast('CMDB 分析失败：' + msg, 6000);
  }

  /* 触发浏览器下载。fetch 拿到的 ?md=1 响应是 text/markdown，走 blob 下载
     才能保住中文文件名与 UTF-8 内容（直接 a.href=URL 会让部分浏览器
     按 GBK 猜编码，中文报告变乱码）。 */
  function downloadBlob(blob, filename) {
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    a.remove();
    // 立刻 revoke 会让 Safari/Edge 的下载中断，延迟释放
    setTimeout(() => URL.revokeObjectURL(url), 10000);
  }

  /* 带上传进度的 POST（2026-10-06）。
     fetch() 没有 upload progress 事件，几百 MB 的库直传时界面完全没反馈，
     用户会以为卡死并重复点「开始分析」。XMLHttpRequest 的
     upload.onprogress 给出真实的已发送字节数。

     返回 { data, blob }：md=1 时 data 为空、blob 有内容；
     非 md 时 data 是解析好的 JSON，blob 留空。 */
  function postWithProgress(url, headers, blob, totalBytes) {
    return new Promise((resolve, reject) => {
      const xhr = new XMLHttpRequest();
      xhr.open('POST', url, true);
      xhr.responseType = 'blob';
      if (headers) {
        Object.keys(headers).forEach((k) => {
          try { xhr.setRequestHeader(k, headers[k]); } catch (e) { /* 非法头名忽略 */ }
        });
      }
      let done = false;
      const finish = (fn, arg) => { if (done) return; done = true; fn(arg); };

      xhr.upload.onprogress = (ev) => {
        if (!ev.lengthComputable || !totalBytes) return;
        const pct = Math.min(99, Math.floor((ev.loaded / totalBytes) * 100));
        // 上传阶段显示百分比；到 99% 就切文案 —— 剩下的时间全在服务端分析，
        // 继续显示"上传中"会误导用户以为还在传。
        // 上传阶段有真实字节进度 → 圆形进度环（填充与数字同步）；
        // 到 99% 剩下的时间全在服务端解析，属不可量化等待，改回旋转圈。
        if (pct >= 99) {
          prog('上传完成，服务端解析中（几百 MB 的库约需 30~60 秒，请稍候）…', true);
        } else {
          prog(`正在上传 ${(ev.loaded / 1048576).toFixed(0)} / ${(totalBytes / 1048576).toFixed(0)} MB`, false, pct);
        }
      };

      xhr.onload = async () => {
        if (xhr.status < 200 || xhr.status >= 300) {
          // 服务端错误也是 blob，读出 JSON 里的 error 文案给用户看
          let msg = `服务返回 ${xhr.status}`;
          try {
            const txt = xhr.response && xhr.response.text ? await xhr.response.text() : '';
            if (txt) { const j = JSON.parse(txt); if (j && j.error) msg = j.error; }
          } catch (e) { /* 非 JSON 错误体，用状态码兜底 */ }
          return finish(reject, new Error(msg));
        }
        // responseType 是 blob：非 md 响应要自己 text()→JSON 还原成对象，
        // 调用方按 j.data.ok 取报告。
        let data = null;
        try {
          const txt = xhr.response && xhr.response.text ? await xhr.response.text() : '';
          if (txt) data = JSON.parse(txt);
        } catch (e) {
          return finish(reject, new Error('服务端返回的不是合法 JSON'));
        }
        finish(resolve, { blob: xhr.response, data: data });
      };
      xhr.onerror = () => finish(reject, new Error('网络中断，请检查连接后重试'));
      xhr.ontimeout = () => finish(reject, new Error('上传超时，请重试或改用「库在服务器上？直接填路径」'));
      xhr.onabort = () => finish(reject, new Error('已取消'));
      xhr.send(blob);
    });
  }

  function mode() {
    const els = qa('.cm-tab');
    for (const e of els) if (e.classList.contains('on')) return e.dataset.mode;
    return 'inline';
  }

  /* ================================================================
     邮件投递（2026-10-06）：分析完成后把报告发到指定邮箱
     ---------------------------------------------------------------
     设计上刻意做得很轻：勾选框默认不勾，未配 SMTP 时给出可操作提示但不
     禁用分析 —— 发邮件是附加能力，不该拦住主流程。
     ================================================================ */
  const MAIL_OK = /^[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,24}$/;

  function mailCfg() {
    const on = (q('#cmMailOn') || {}).checked;
    const to = String((q('#cmMailTo') || {}).value || '').trim();
    const fmt = (q('#cmMailFmt') || {}).value || 'md';
    const mask = (q('#cmMailMask') || {}).value || 'basic';
    return { on: !!on, to: to, fmt: ['md', 'xlsx', 'both'].indexOf(fmt) >= 0 ? fmt : 'md',
             mask: mask === 'strict' ? 'strict' : 'basic' };
  }

  /* 收集发信收件人：逗号/分号/顿号/空格都当分隔符（从 Excel 粘贴很常见） */
  function mailRecipients(to) {
    return String(to || '').split(/[,;，；、\s]+/).map((s) => s.trim().replace(/^<|>$/g, ''))
      .filter(Boolean);
  }

  /* 勾了但没填邮箱 —— 提交前拦下并说清，别等 30 秒分析完才发现没发出去 */
  function mailPreflight() {
    const m = mailCfg();
    if (!m.on) return { skip: true };
    if (!m.to) return { error: '已勾选「发到邮箱」，但收件邮箱没填' };
    const all = mailRecipients(m.to);
    const bad = all.filter((x) => !MAIL_OK.test(x));
    if (!all.length) return { error: '收件邮箱格式不正确' };
    if (bad.length) {
      return { error: '邮箱格式不正确：' + bad.slice(0, 3).join('、') };
    }
    /* 勾了"分别发"就两边都要校验 —— 否则第一封发出去、第二封失败，用户还以为都发了 */
    let to2 = '';
    if ((q('#cmMailSplit') || {}).checked) {
      const v2 = String((q('#cmMailTo2') || {}).value || '').trim();
      if (!v2) return { error: '已勾选「另一份发给不同的人」，但第二个收件邮箱没填' };
      const a2 = mailRecipients(v2);
      const b2 = a2.filter((x) => !MAIL_OK.test(x));
      if (!a2.length) return { error: '第二个收件邮箱格式不正确' };
      if (b2.length) return { error: '第二个邮箱格式不正确：' + b2.slice(0, 3).join('、') };
      to2 = a2.join(',');
    }
    return { to: all.join(','), mask: m.mask, fmt: m.fmt, split: to2 };
  }

  function buildSubmitQuery(opts) {
    const qy = [];
    if (opts && opts.md) qy.push('md=1');
    const p = mailPreflight();
    if (p.error) { toast(p.error, 5000); return '?cancel=1'; }
    if (!p.skip) {
      qy.push('mail=' + encodeURIComponent(p.to));
      qy.push('mask=' + encodeURIComponent(p.mask));
      /* ★ 2026-10-06 修复：这里原本是 `fmt === 'both' ? 'md' : fmt`，
         想让"两份都发"先发 md、再由一个叫 afterSubmitMail() 的函数补发 xlsx。
         但那个函数**从未存在过**（全仓库只有这行注释提到它），后果是：
         用户选「两份都发」只收到一份七章制 md，且后端的 both 分支永远不可达。
         现改为原样直传 —— 后端 both 分支会同时构建七章制正文 + xlsx 附件。 */
      qy.push('fmt=' + p.fmt);
      if (p.split) qy.push('mail2=' + encodeURIComponent(p.split));
    }
    return qy.length ? '?' + qy.join('&') : '';
  }

  function paintMailNote(txt, bad) {
    const n = q('#cmMailNote');
    if (!n) return;
    n.textContent = txt || '';
    n.style.color = bad ? 'var(--danger,#ff5a52)' : '';
  }

  function bindMailUi() {
    const on = q('#cmMailOn'), row = q('#cmMailRow');
    if (on && row) on.onchange = () => { row.style.display = on.checked ? '' : 'none'; };

    /* 「另一份发给不同的人」：勾上才展开第二组输入 */
    const more = q('#cmMailMore'), sp = q('#cmMailSplit'), spRow = q('#cmMailSplitRow');
    if (on && more) more.style.display = on.checked ? '' : 'none';
    if (sp && spRow) {
      sp.onchange = () => {
        spRow.style.display = sp.checked ? '' : 'none';
        const lbl = q('#cmMailSplitLbl');
        const f = ((q('#cmMailFmt') || {}).value) || 'md';
        const other = f === 'xlsx' ? '七章制 Markdown 报告' : '简略台账 xlsx';
        if (lbl) lbl.textContent = sp.checked
          ? '另一份（' + other + '）发给：' : '';
      };
    }
    /* 切换发送格式时，第二份的说明文字要跟着变（一份 md 一份 xlsx 互补） */
    const fmtSel = q('#cmMailFmt');
    if (fmtSel && sp) fmtSel.onchange = () => { if (sp.checked) sp.onchange(); };

    /* 输入时实时校验邮箱，失焦后立刻反馈 —— 不要等提交才知道打错字 */
    const to = q('#cmMailTo');
    if (to) {
      to.onblur = () => {
        const v = String(to.value || '').trim();
        if (!v) { paintMailNote(''); return; }
        const all = mailRecipients(v);
        const bad = all.filter((x) => !MAIL_OK.test(x));
        if (!all.length) paintMailNote('请输入有效邮箱，如 zhang@qq.com', true);
        else if (bad.length) paintMailNote('格式不正确：' + bad.slice(0, 3).join('、'), true);
        else paintMailNote(`将发送给 ${all.length} 个收件人：${all.join('、')}`);
      };
    }
    const to2 = q('#cmMailTo2');
    if (to2) {
      to2.onblur = () => {
        const v = String(to2.value || '').trim();
        if (!v) return;
        const bad = mailRecipients(v).filter((x) => !MAIL_OK.test(x));
        if (bad.length) paintMailNote('第二个邮箱格式不正确：' + bad.join('、'), true);
      };
    }

    /* 两个下载按钮：简略台账 / 七章制 Markdown，原有导出不受影响 */
    const dl = q('#cmDlMd');
    if (dl) dl.onclick = () => downloadTickets();
    const df = q('#cmDlFull');
    if (df) df.onclick = () => downloadFullMd();

    checkMailSetup();
  }

  /* 下载简略台账：直接开新窗口让浏览器落盘（Content-Disposition 已由服务端设置） */
  function downloadTickets() {
    const id = (last && last.id) || '';
    const u = '/api/cmdb_scan/tickets' + (id ? '?id=' + encodeURIComponent(id) : '');
    const a = document.createElement('a');
    a.href = u; a.target = '_blank'; a.rel = 'noopener';
    document.body.appendChild(a); a.click(); a.remove();
    toast('正在生成简略台账（按责任人/等级/三步期限组织）…', 4000);
  }

  /* 下载七章制 Markdown（原有能力，保留入口）。
     ★ 2026-10-07 修：原来只写 `a.href` + `target=_blank`，**没设 download**。
       下载与否完全押在服务端有没有发 `Content-Disposition: attachment`；
       服务端那两个 md=1 分支恰好漏了 → 浏览器内联渲染 text/markdown，
       用户点「下载」看到的是一整页 Markdown 源码（用户截图）。
       现在改成 fetch + blob + `a.download`：**不再依赖服务端响应头**，
       即使后端哪天又漏了，也照样落盘；而且能拿到失败时的 JSON 报错
       （原来 `a.href` 打开新标签，出错只会在新标签里显示一段 JSON，用户看不懂）。 */
  async function downloadFullMd() {
    const id = (last && last.id) || '';
    if (!id) { toast('请先完成一次 CMDB 分析，再下载报告', 4000); return; }
    const u = '/api/cmdb_scan?id=' + encodeURIComponent(id) + '&md=1';
    try {
      const r = await fetch(u, { headers: { Accept: 'text/markdown,text/plain,*/*' } });
      if (!r.ok) {
        let msg = 'HTTP ' + r.status;
        try { const j = await r.json(); if (j && j.error) msg = j.error; } catch (e) { /* 非 JSON 就用状态码 */ }
        toast('七章制 Markdown 导出失败：' + msg, 6000);
        return;
      }
      const blob = await r.blob();
      downloadBlob(new Blob([blob], { type: 'text/markdown;charset=utf-8' }),
        'CMDB风险评估报告_' + String(id).slice(-8) + '.md');
      toast('已开始下载七章制 Markdown 报告', 3600);
    } catch (e) {
      toast('七章制 Markdown 导出失败：' + (e && e.message ? e.message : '网络不可达'), 6000);
    }
  }

  /* 查 SMTP 是否已配置：未配置就明确告诉用户去哪填，别让发送静默失败 */
  let _mailSetup = null;
  async function checkMailSetup() {
    try {
      const r = await (await fetch('/api/cmdb_scan/mail')).json();
      _mailSetup = r || {};
      if (_mailSetup.configured) {
        /* 只报"能不能发、走哪台服务器"，不回显发信账号（账号属敏感信息）。 */
        paintMailNote('邮件已就绪（' + _mailSetup.host + ':' + _mailSetup.port +
          (_mailSetup.ssl ? '，SSL）' : '，明文/STARTTLS）'));
      } else {
        paintMailNote('未配置 SMTP，暂时无法发信。在 secrets.env 里填 AISEC_SMTP_HOST / ' +
          'AISEC_SMTP_USER / AISEC_SMTP_PASS（QQ/163 填授权码，不是登录密码）。', true);
        const on = q('#cmMailOn');
        /* 不禁用勾选：用户可能正在看文档，之后配好了就能用。只提示，不阻拦。 */
        if (on) on.title = 'SMTP 尚未配置，发送会失败并提示原因';
      }
    } catch (e) {
      _mailSetup = { configured: false };
      paintMailNote('无法获取邮件配置状态（服务可能刚重启，稍后自动重试）', true);
    }
  }

  /* 分析响应里带回 mail 状态 → 给用户明确回执（发出去了 / 没发 / 为什么没发） */
  function reportMailFeedback(mail) {
    if (!mail) return;
    if (mail.ok && mail.queued) {
      const n = (mail.to || []).length;
      const what = mail.fmt === 'xlsx' ? '简略台账 xlsx'
        : mail.fmt === 'both' ? '两份报告' : '七章制报告';
      toast(`已提交发送「${what}」至 ${n} 个收件人`
        + (mail.to2 ? `；另一份发给 ${(mail.to2 || []).length} 人` : '')
        + `（${mail.mask === 'strict' ? '严格脱敏' : '基础脱敏'}）`, 5000);
      if (mail.warn2) toast('第二份未发出：' + mail.warn2, 9000);
      /* 后台线程在发，稍后回来查真实结果（SMTP 认证/网络失败只有这里才知道） */
      setTimeout(pollMailResult, 2500);
    } else if (mail.error) {
      toast('报告已生成，但邮件未发送：' + mail.error, 9000);
    }
  }

  async function pollMailResult() {
    try {
      const r = await (await fetch('/api/cmdb_scan/mail')).json();
      const last = r && r.last;
      if (!last) return;
      if (last.ok) {
        toast('邮件已成功发送', 4000);
        paintMailNote('上次发送成功：' + (last.to || []).join('、'));
      } else {
        toast('邮件发送失败：' + (last.error || '未知原因'), 9000);
        paintMailNote('上次发送失败：' + (last.error || '未知原因'), true);
      }
    } catch (e) { /* 状态查询失败不影响报告本身，忽略 */ }
  }

  /* 历史报告详情里的「补发邮件」：POST /api/cmdb_scan/mail */
  async function mailExistingReport(rid) {
    const to = String((q('#cmMailTo') || {}).value || '').trim()
      || window.prompt('把报告发到哪个邮箱？（多个用逗号分隔）', '');
    if (!to) return;
    const all = mailRecipients(to);
    const bad = all.filter((x) => !MAIL_OK.test(x));
    if (!all.length || bad.length) {
      toast('邮箱格式不正确：' + (bad.length ? bad.slice(0, 3).join('、') : to), 5000);
      return;
    }
    const mask = (q('#cmMailMask') || {}).value === 'strict' ? 'strict' : 'basic';
    const fmt = (q('#cmMailFmt') || {}).value || 'md';
    try {
      const r = await (await fetch('/api/cmdb_scan/mail', {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ id: rid, to: all.join(','), mask: mask, fmt: fmt }),
      })).json();
      if (!r || !r.ok) { toast('发送失败：' + ((r && r.error) || '未知原因'), 8000); return; }
      const what = fmt === 'xlsx' ? '简略台账 xlsx' : fmt === 'both' ? '两份报告' : '七章制报告';
      toast(`已提交发送「${what}」到 ${all.length} 个收件人`, 5000);
      setTimeout(pollMailResult, 2500);
    } catch (e) {
      toast('发送请求失败：' + (e.message || '网络错误'), 6000);
    }
  }
  /* 暴露给报告详情页按钮用 */
  if (typeof AISEC !== 'undefined') { AISEC.cmdbMail = mailExistingReport; }

  function mode() {
    const els = qa('.cm-tab');
    for (const e of els) if (e.classList.contains('on')) return e.dataset.mode;
    return 'inline';
  }

  function switchMode(m) {
    qa('.cm-tab').forEach((e) => e.classList.toggle('on', e.dataset.mode === m));
    ['rest', 'sqlite', 'inline', 'file'].forEach((k) => {
      const p = q('#cmPane-' + k);
      if (p) p.style.display = (k === m) ? '' : 'none';
    });
  }

  /* 读文件 → base64（文件模式用，与资产体检的上传互不干扰） */
  function readFileB64(file) {
    return new Promise((res, rej) => {
      const rd = new FileReader();
      rd.onload = () => res(String(rd.result).split(',')[1]);
      rd.onerror = () => rej(new Error('读取文件失败'));
      rd.readAsDataURL(file);
    });
  }

  const fmtSize = (n) => n >= 1048576 ? (n / 1048576).toFixed(1) + ' MB'
    : n >= 1024 ? (n / 1024).toFixed(0) + ' KB' : n + ' B';

  /* 文件清单渲染（file / sqlite 两个上传区共用一套，只换数组与容器 id）
     files  = 待渲染的 File 数组（引用，改完调用方需自行重渲染）
     boxSel = 容器选择器
     unit   = 清单尾部的量词说明（**不含「个」字**，拼接时统一加，避免出「个个」） */
  function renderFileList(boxSel, files, unit) {
    const box = q(boxSel);
    if (!box) return;
    if (!files.length) { box.style.display = 'none'; box.innerHTML = ''; return; }
    box.style.display = '';
    box.innerHTML = files.map((f, i) =>
      `<div class="cm-file-i" data-i="${i}"><span class="n" title="${esc(f.name)}">${esc(f.name)}</span>` +
      `<span class="s">${fmtSize(f.size)}</span><button class="x" data-i="${i}" title="移除">×</button></div>`
    ).join('') + `<div class="meta-note" style="margin-top:4px">共 ${files.length} ${esc(unit)}</div>`;
    qa('.cm-file-i .x', box).forEach((b) => {
      b.onclick = () => { files.splice(Number(b.dataset.i), 1); renderFileList(boxSel, files, unit); };
    });
  }

  function renderFiles() { renderFileList('#cmFileList', pickedFiles, '个文件，分析时合并为一份报告'); }
  function renderDbs() {
    renderFileList('#cmDbList', pickedDbs, '个数据库，分析时合并为一份报告');
    const clr = q('#cmDbClear');
    if (clr) clr.style.display = pickedDbs.length ? '' : 'none';
  }

  /* 把 File 追加进目标数组（同名同大小去重），并重渲染清单。
     target / list 传同一个数组：splice 是原地改，引用不变，
     renderFileList 内部再拿它渲染 —— 移除按钮才能作用到同一份数据。 */
  function addFiles(target, list, fs, rerender) {
    let added = 0;
    for (const f of fs) {
      if (!target.some((x) => x.name === f.name && x.size === f.size)) { target.push(f); added++; }
    }
    if (added) rerender();
    return added;
  }

  async function submit() {
    if (submitting) { toast('分析进行中，请稍候…'); return; }
    const m = mode();
    const body = { mode: m };
    let fileUpload = null;   /* 文件模式：二进制直传（blob + 清单头），不走 base64 */
    if (m === 'rest') {
      body.url = (q('#cmUrl') || {}).value.trim();
      body.path = (q('#cmPath') || {}).value.trim();
      body.auth_type = (q('#cmAuth') || {}).value;
      if (!body.url) { toast('请填写 CMDB 地址'); return; }
    } else if (m === 'sqlite') {
      body.path = (q('#cmDbPath') || {}).value.trim();
      body.tables = (q('#cmDbTables') || {}).value.trim();
      // ★ 两条路（2026-10-06）：上传 .db（浏览器直传，服务端落临时盘）优先，
      //   没传文件时才回退到「填服务器本地路径」（老用法，服务端直接读盘）。
      if (pickedDbs.length) {
        fileUpload = {
          blob: new Blob(pickedDbs),
          manifest: {
            mode: 'sqlite',
            tables: body.tables,
            name: pickedDbs.length === 1 ? pickedDbs[0].name
                : pickedDbs.map((f) => f.name).join('、').slice(0, 120),
            files: pickedDbs.map((f) => ({ filename: f.name, size: f.size })),
          },
        };
      } else if (!body.path) {
        toast('请拖入或选择 SQLite 数据库文件（.db / .sqlite），或填写服务器上的数据库路径');
        return;
      }
    } else if (m === 'inline') {
      body.text = (q('#cmText') || {}).value.trim();
      if (!body.text) { toast('请粘贴 CMDB 导出的 JSON / CSV 数据'); return; }
    } else {
      if (!pickedFiles.length) { toast('请选择 CMDB 导出的资产文件'); return; }
      // ★ 二进制直传（2026-10-05）：body = 文件原始字节按序拼接（Blob 惰性引用，
      //   不占内存），清单放 X-Cmdb-Manifest 头。旧方案 366MB 文件要 base64 成
      //   490MB 字符串再 JSON.stringify，浏览器直接卡死几分钟。
      fileUpload = {
        blob: new Blob(pickedFiles),
        manifest: {
          mode: 'file',
          name: pickedFiles.length === 1 ? pickedFiles[0].name
              : pickedFiles.map((f) => f.name).join('、'),
          files: pickedFiles.map((f) => ({ filename: f.name, size: f.size })),
        },
      };
    }
    const wantMd = !!(q('#cmMd') || {}).checked;
    /* ★ 先做邮件预检（2026-10-06）：勾了发信却把邮箱打错，等分析完 40 秒才发现
       没发出去是糟糕的体验。校验不通过就直接停下，别白跑一次分析。 */
    const _mp = mailPreflight();
    if (_mp.error) { toast(_mp.error, 5000); return; }
    submitting = true;
    const goBtn = q('#cmGo');
    if (goBtn) { goBtn.disabled = true; goBtn.textContent = '分析中…'; }
    let progMsg = '正在连接 CMDB 并比对情报库…';
    let totalBytes = 0;
    if (m === 'file' && fileUpload) {
      const mb = pickedFiles.reduce((s, f) => s + (f.size || 0), 0) / 1048576;
      totalBytes = pickedFiles.reduce((s, f) => s + (f.size || 0), 0);
      progMsg = `已接收 ${pickedFiles.length} 个文件（共 ${mb >= 1 ? mb.toFixed(0) + ' MB' : '<1 MB'}），多进程解析中，大文件约需十几秒到几十秒…`;
    } else if (m === 'file') {
      progMsg = '正在解析文件并比对情报库…';
    } else if (m === 'sqlite') {
      if (fileUpload) {
        const mb = pickedDbs.reduce((s, f) => s + (f.size || 0), 0) / 1048576;
        totalBytes = pickedDbs.reduce((s, f) => s + (f.size || 0), 0);
        progMsg = `已接收 ${pickedDbs.length} 个数据库（共 ${mb >= 1 ? mb.toFixed(0) + ' MB' : '<1 MB'}），` +
          '正在本机解析并比对情报库，大库约需十几秒到几十秒…';
      } else {
        progMsg = '正在读取本地数据库并比对情报库…';
      }
    }
    prog(progMsg, true);

    const hdrs = fileUpload
      ? { 'Content-Type': 'application/octet-stream',
          'X-Cmdb-Manifest': encodeURIComponent(JSON.stringify(fileUpload.manifest)) }
      : { 'Content-Type': 'application/json' };
    /* ★ 邮件参数走 query（2026-10-06）：不污染 body 协议，
       fetch 与 XMLHttpRequest 两条分支都能原样复用同一个 URL。 */
    const apiUrl = '/api/cmdb_scan' + buildSubmitQuery({ md: wantMd });

    /* ★ 上传进度（2026-10-06）：大库直传要一分多钟，原来全程只有一句静态文案，
       用户盯着不动的进度条会以为卡死了。fetch() 没有上传进度事件，
       所以超过 8MB 改用 XMLHttpRequest —— 它的 upload.onprogress 真实反映
       已发送字节数。分段显示「上传 xx% → 等待分析」，让用户知道还在动。
       小文件仍走 fetch（少一层 XHR 复杂度，样例数据上传占比高）。 */
    const XHR_THRESHOLD = 8 * 1024 * 1024;
    if (fileUpload && totalBytes > XHR_THRESHOLD && typeof XMLHttpRequest !== 'undefined') {
      submitting = false;
      if (goBtn) { goBtn.disabled = false; goBtn.textContent = '▶ 开始分析'; }
      // 进度回调由 postWithProgress 内部驱动，这里不 await 到 finally，
      // 避免和下面的 fetch 分支重复复位按钮状态。
      postWithProgress(apiUrl, hdrs, fileUpload.blob, totalBytes)
        .then((j) => {
          if (wantMd) {
            downloadBlob(j.blob, 'CMDB资产风险分析报告.md');
            hideProg(); toast('已下载 Markdown 报告');
            return;
          }
          if (!j.data || !j.data.ok) throw new Error((j.data && j.data.error) || '分析失败');
          show(j.data.report); loadHist();
          reportMailFeedback(j.data.mail);
        })
        .catch((e) => fail(e.message || '上传失败'));
      return;
    }

    try {
      const r = await fetch(apiUrl, {
        method: 'POST', headers: hdrs,
        body: fileUpload ? fileUpload.blob : JSON.stringify(body),
      });
      if (wantMd) {
        if (!r.ok) { const e = await r.json().catch(() => ({})); throw new Error(e.error || '分析失败'); }
        const blob = await r.blob();
        const a = document.createElement('a');
        a.href = URL.createObjectURL(blob);
        a.download = 'CMDB资产风险分析报告.md';
        document.body.appendChild(a); a.click(); a.remove();
        setTimeout(() => URL.revokeObjectURL(a.href), 4000);
        hideProg();
        toast('已下载 Markdown 报告');
        return;
      }
      const d = await r.json();
      if (!d || !d.ok) throw new Error((d && d.error) || '分析失败');
      show(d.report); loadHist();
      reportMailFeedback(d.mail);
    } catch (e) { fail(e.message); }
    finally {
      submitting = false;
      if (goBtn) { goBtn.disabled = false; goBtn.textContent = '▶ 开始分析'; }
    }
  }

  function show(rep) {
    last = rep;
    hideProg();
    q('#cmResult').innerHTML = reportHtml(rep);
    const ex = q('#cmExport');
    if (ex) ex.onclick = () => exportMd(rep.id);
    const ag = q('#cmAgain');
    if (ag) ag.onclick = () => { switchMode('inline'); const t = q('#cmText'); if (t) t.focus(); };
    // 优先处置清单：点一条直达 CVE 详情
    qa('.cm-prio', q('#cmResult')).forEach((row) => {
      row.onclick = () => { const c = row.dataset.cve; if (c) openDetail(c); };
    });
    // 在野利用 CVE 链接（kev）→ 详情
    qa('.en-kev-i', q('#cmResult')).forEach((a) => {
      a.onclick = () => { const c = a.dataset.id; if (c) openDetail(c); };
    });
    // 组件命中明细（en-f）→ 详情
    qa('.en-f[data-id]', q('#cmResult')).forEach((row) => {
      row.onclick = () => openDetail(row.dataset.id);
    });
    // 展开其余命中（en-more）
    qa('.en-more', q('#cmResult')).forEach((b) => {
      b.onclick = () => {
        const box = b.parentElement;
        box.querySelectorAll('.en-f.hide').forEach((x) => x.classList.remove('hide'));
        b.remove();
      };
    });
    window.scrollTo({ top: 0, behavior: 'smooth' });
  }

  function reportHtml(rep) {
    const s = (rep.risk || {}).summary || {};
    const prio = rep.priority || [];
    const kev = (s.kev_ids || []).length
      ? `<div class="en-kev"><b>⚠️ 已被在野利用（CISA KEV）</b>${s.kev_ids.map((c) =>
          `<a class="en-kev-i" data-id="${esc(c)}" href="javascript:void(0)">${esc(c)}</a>`).join('')}</div>` : '';
    const prioHtml = prio.length ? `<div class="panel en-tblwrap">
      <header>优先处置清单 <span class="ph-sub">现在先修什么 → 怎么修 → 怎么检查已修复 · 点一条直达漏洞详情</span></header>
      <div class="pbody"><div class="cm-prio-list">${prio.slice(0, 10).map(prioRow).join('')}</div></div>
    </div>` : '';
    return `
      <div class="panel en-rep">
        <header>CMDB 资产风险分析 · ${esc(s.cve_hits || 0)} 条漏洞命中
          <span class="ph-sub">${esc(rep.source_name || '')} · 耗时 ${esc(String(rep.elapsed_ms || 0))}ms · 比对情报库 ${esc(String(s.scanned_docs || 0))} 条</span>
        </header>
        <div class="pbody">
          ${rep.warn ? `<div class="en-warn">⚠️ ${esc(rep.warn)}</div>` : ''}
          <div class="en-kpis">
            ${kpi('资产主机', s.hosts, '')}
            ${kpi('软件组件', s.products, '')}
            ${kpi('命中 CVE', s.cve_hits, '')}
            ${kpi('严重', s.critical, '', 'crit')}
            ${kpi('高危', s.high, '', 'high')}
            ${kpi('在野利用', s.exploited, '', s.exploited ? 'crit' : '')}
            ${kpi('待处置优先级', prio.length, '', '')}
          </div>
          ${kev}
          <div class="en-ops">
            <button class="btn ghost sm" id="cmExport">⬇ 下载报告（.md）</button>
            <button class="btn ghost sm" id="cmAgain">↻ 再分析一次</button>
            <span class="meta-note" style="margin:0">判定依据：${esc(rep.basis || '')}</span>
          </div>
        </div>
      </div>
      ${prioHtml}
      ${hostTable(rep)}
      ${prodCards(rep)}`;
  }

  function kpi(label, v, sub, cls) {
    return `<div class="en-kpi ${cls || ''}"><b>${esc(String(v == null ? 0 : v))}</b>
      <span>${esc(label)}</span>${sub ? `<i>${esc(sub)}</i>` : ''}</div>`;
  }

  function prioRow(p) {
    const sev = sevOf(p.severity);
    const plan = p.plan || {};
    const ups = (plan.upgrade || []).map((u) =>
      `<span class="chip">升级 ${esc(u.component)} → ${esc(u.target)}</span>`).join('') || '';
    const cfgs = (plan.config || []).slice(0, 2).map((c) =>
      `<span class="chip">加固 ${esc(c.item)}</span>`).join('') || '';
    const verif = (plan.verify || []).slice(0, 2).map((v) =>
      `<span class="chip ok">验收 ${esc(v)}</span>`).join('') || '';
    const rem = (p.remediation || []).length
      ? `<div class="cm-prio-rem">处置：${esc(p.remediation.join('；'))}</div>` : '';
    const why = p.exploited
      ? `<span class="chip alert">● 在野利用${p.kev_added ? ' ' + esc(p.kev_added) : ''}</span>`
      : '';
    return `<div class="cm-prio" data-cve="${esc(p.cve)}">
      <div class="cm-prio-l1">
        <span class="cve">${esc(p.cve)}</span>
        <span class="badge ${sev}">${esc(sev)}${p.score != null ? ' ' + esc(String(p.score)) : ''}</span>
        ${why}
        <span class="cm-prio-host">${esc(p.host || '')}</span>
        <span class="en-go">详情 →</span>
      </div>
      <div class="cm-prio-ttl">${esc(p.title || '')}</div>
      <div class="cm-prio-l2">${ups}${cfgs}${verif}</div>${rem}
    </div>`;
  }

  function hostTable(rep) {
    const hosts = ((rep.risk || {}).hosts) || [];
    if (!hosts.length) return '';
    const rows = hosts.map((h) => {
      const comps = (h.components || []).map((c) =>
        `<span class="chip">${esc(c.name)}${c.version ? ' ' + esc(c.version) : ''}</span>`).join('') || '<span class="meta-note">—</span>';
      return `<tr>
        <td class="en-host">${esc(h.name)}</td>
        <td><span class="chip">${esc(h.type)}</span><span class="chip">${esc(h.scope || '')}</span></td>
        <td class="en-host-risk">${riskChip(h.risk_level)}</td>
        <td class="en-num">${esc(String(h.cve_count || 0))}${h.kev_count ? ` <span class="chip alert">在野 ${h.kev_count}</span>` : ''}</td>
        <td class="en-comps">${comps}</td>
      </tr>`;
    }).join('');
    return `<div class="panel en-tblwrap">
      <header>资产主机风险 · ${hosts.length} 个主机 <span class="ph-sub">主机风险 = 该主机承载软件风险的最大值</span></header>
      <div class="pbody"><table class="en-tbl">
        <thead><tr><th>主机 / IP</th><th>类型</th><th>风险</th><th>命中</th><th>承载组件</th></tr></thead>
        <tbody>${rows}</tbody></table></div>
    </div>`;
  }

  function prodCards(rep) {
    const prods = ((rep.risk || {}).products) || [];
    if (!prods.length) return '';
    const cards = prods.map((p) => {
      const fs = p.findings || [];
      const list = fs.map((x, i) => cmFinding(x, i >= 6)).join('')
        + (fs.length > 6 ? `<button class="en-more">展开其余 ${fs.length - 6} 条命中</button>` : '')
        + (fs.length === 0 ? '<div class="meta-note">情报库中未匹配到该产品/版本的已知漏洞（可能未收录，或该版本不受影响）</div>' : '');
      return `<div class="panel en-prod">
        <header>${esc(p.display || p.name)} <span class="chip">${esc(p.version || '版本未知')}</span>
          ${riskChip(p.risk_level)}
          <span class="chip">命中 ${esc(String(p.cve_count || 0))}</span>
          ${p.kev_count ? `<span class="chip alert">● 在野利用 ${p.kev_count}</span>` : ''}
          <span class="ph-sub">${esc(p.vendor || '')}</span></header>
        <div class="pbody">${list}</div>
      </div>`;
    }).join('');
    return `<div class="en-prods">${cards}</div>`;
  }

  function cmFinding(x, hide) {
    const sev = sevOf(x.severity);
    const rem = (x.remediation || []).length
      ? `<div class="en-rem">处置建议：${esc((x.remediation || []).join(' '))}</div>` : '';
    const tags = [
      x.kev_added ? `<span class="chip alert">KEV ${esc(x.kev_added)}</span>` : '',
      x.trust_label ? `<span class="chip trust">${esc(x.trust_label)}</span>` : '',
      (x.risk_tags || []).slice(0, 3).map((t) => `<span class="chip">${esc(t)}</span>`).join(''),
      (x.cwe || []).length ? `<span class="chip">${esc(x.cwe.join(' '))}</span>` : '',
      x.poc ? `<span class="chip">POC×${x.poc}</span>` : '',
      x.patch ? `<span class="chip ok">补丁×${x.patch}</span>` : '',
    ].join('');
    return `<div class="en-f${hide ? ' hide' : ''}" data-id="${esc(x.id)}">
      <div class="en-f-l1">
        <span class="cve">${esc(x.id)}</span>
        <span class="badge ${sev}">${esc(sev)}${x.score != null ? ' ' + esc(String(x.score)) : ''}</span>
        ${x.exploited ? '<span class="chip alert">● 在野利用</span>' : ''}
        <span class="en-f-ttl">${esc(x.title || '')}</span>
        <span class="en-go">详情 →</span>
      </div>
      <div class="en-f-l2">
        <span class="en-ev">版本依据：${esc(x.evidence || '')}</span>
        <span class="chip">置信 ${esc(x.confidence || '')}</span>
        <span class="chip">${esc(x.published || '')}</span>
        ${tags}
      </div>${rem}
    </div>`;
  }

  /* 历史 + 导出 */
  function loadHist() {
    fetch('/api/cmdb_scan').then((r) => r.json()).then((r) => {
      if (!r || !r.ok) return;
      q('#cmHist').dataset.items = JSON.stringify(r.items || []);
      if (q('#cmHist').style.display !== 'none') renderHist(r.items || []);
    }).catch(() => {});
  }

  function toggleHist() {
    const box = q('#cmHist');
    const show = box.style.display === 'none';
    box.style.display = show ? '' : 'none';
    if (show) { try { renderHist(JSON.parse(box.dataset.items || '[]')); } catch (e) { renderHist([]); } }
  }

  function renderHist(items) {
    const box = q('#cmHist');
    if (!items.length) {
      box.innerHTML = '<div class="meta-note" style="padding:6px 2px">暂无 CMDB 分析记录。</div>';
      box.dataset.items = '[]';
      return;
    }
    box.dataset.items = JSON.stringify(items);
    box.innerHTML = `<div class="panel"><header>历史分析 · ${items.length} 次 <span class="ph-sub">点一次回看完整报告</span></header>
      <div class="pbody">${items.map((it) => {
        const s = it.summary || {};
        return `<div class="en-hist-row" data-id="${esc(it.id)}">
          <span class="en-hist-f">${esc(it.source_name || '')}</span>
          <span class="chip">${esc(it.source || '')}</span>
          <span class="chip">主机 ${esc(String(s.hosts || 0))}</span>
          <span class="chip">命中 ${esc(String(s.cve_hits || 0))}</span>
          <span class="chip">优先级 ${esc(String(it.priority_count || 0))}</span>
          ${s.exploited ? `<span class="chip alert">在野 ${esc(String(s.exploited))}</span>` : ''}
          <span class="en-hist-t">${esc(it.created_at || '')}</span>
          <span class="en-go">查看 →</span>
        </div>`;
      }).join('')}</div></div>`;
    qa('.en-hist-row', box).forEach((r) => {
      r.onclick = () => fetch('/api/cmdb_scan?id=' + encodeURIComponent(r.dataset.id))
        .then((x) => x.json())
        .then((x) => { if (x && x.ok) { show(x.report); window.scrollTo({ top: 0, behavior: 'smooth' }); } })
        .catch(() => toast('读取失败'));
    });
  }

  function exportMd(id) {
    fetch('/api/cmdb_scan?id=' + encodeURIComponent(id) + '&md=1')
      .then((r) => r.blob())
      .then((b) => {
        const a = document.createElement('a');
        a.href = URL.createObjectURL(b);
        a.download = 'CMDB资产风险分析报告_' + id + '.md';
        document.body.appendChild(a); a.click(); a.remove();
        setTimeout(() => URL.revokeObjectURL(a.href), 4000);
        toast('已下载 Markdown 报告');
      })
      .catch(() => toast('导出失败'));
  }

  function loadConfig() {
    fetch('/api/cmdb_scan/config').then((r) => r.json()).then((r) => {
      const box = q('#cmCfg');
      if (!box || !r || !r.ok) return;
      const chips = [];
      if (r.url_configured) chips.push(`<span class="chip ok" title="${esc(r.url)}">CMDB 地址已配置</span>`);
      if (r.token_configured) chips.push('<span class="chip ok">凭证已配置（环境变量）</span>');
      if (!r.url_configured && !r.token_configured) {
        chips.push('<span class="chip" title="REST 直连需配置；也可直接粘贴 CMDB 导出数据，无需任何配置">未配置 · 可用「粘贴数据」模式</span>');
      }
      box.innerHTML = chips.join('');
    }).catch(() => {});
  }

  function bind(el) {
    root = el;
    qa('.cm-tab').forEach((t) => { t.onclick = () => switchMode(t.dataset.mode); });
    q('#cmGo').onclick = submit;
    q('#cmHistBtn').onclick = toggleHist;
    bindMailUi();

    /* —— 上传文件（CSV/Excel/Word）—— */
    q('#cmPick').onclick = () => q('#cmFile').click();
    (q('#cmFile') || {}).onchange = (e) => {
      /* 多选累积：重复选同名同大小文件去重；选完清空 input 以便继续追加 */
      const fs = Array.from((e.target && e.target.files) || []);
      addFiles(pickedFiles, pickedFiles, fs, renderFiles);
      e.target.value = '';
    };

    /* —— 数据库文件（.db，可拖可点，可多选）——
       与上传区同一套交互，但只收数据库扩展名：拖进来一个 .xlsx 会被
       sqlite3 打开失败，报错难懂，所以在入口就拦掉并说清原因。 */
    const dbInput = q('#cmDbFile');
    const dbDrop = q('#cmDbDrop');
    const DB_EXT = /\.(db|sqlite|sqlite3|db3)$/i;
    const acceptDbs = (fs) => {
      const good = [], bad = [];
      for (const f of fs) (DB_EXT.test(f.name) ? good : bad).push(f);
      if (good.length) addFiles(pickedDbs, pickedDbs, good, renderDbs);
      if (bad.length) {
        toast(`已忽略 ${bad.length} 个非数据库文件（${bad.slice(0, 2).map((f) => f.name).join('、')}` +
          `${bad.length > 2 ? ' 等' : ''}）——本模式只接受 .db / .sqlite；` +
          '若手里是 CSV / Excel，请切到「上传文件」', 7000);
      }
    };
    if (dbInput) {
      dbInput.onchange = (e) => {
        acceptDbs(Array.from((e.target && e.target.files) || []));
        e.target.value = '';            // 清空以便继续追加选择
      };
    }
    if (dbDrop) {
      ['dragenter', 'dragover'].forEach((ev) => dbDrop.addEventListener(ev, (e) => {
        e.preventDefault(); e.stopPropagation();
        dbDrop.classList.add('drag');
      }));
      ['dragleave', 'dragend'].forEach((ev) => dbDrop.addEventListener(ev, (e) => {
        e.preventDefault(); e.stopPropagation();
        /* 拖到子元素上会冒泡出 dragleave，用 relatedTarget 判是不是真离开 */
        if (!e.relatedTarget || !dbDrop.contains(e.relatedTarget)) dbDrop.classList.remove('drag');
      }));
      dbDrop.addEventListener('drop', (e) => {
        e.preventDefault(); e.stopPropagation();
        dbDrop.classList.remove('drag');
        const dt = e.dataTransfer;
        if (dt && dt.files && dt.files.length) acceptDbs(Array.from(dt.files));
      });
      dbDrop.onclick = (e) => { if (!e.target.closest('button') && dbInput) dbInput.click(); };
    }
    const clearDb = q('#cmDbClear');
    if (clearDb) clearDb.onclick = () => { pickedDbs = []; renderDbs(); };

    (q('#cmText') || {}).onkeydown = (e) => { if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') submit(); };
    switchMode('inline');
    loadConfig();
    loadHist();
  }

  const HTML = `
    <div class="en-scan-head">
      <div class="en-scan-ttl">
        <b>公司 CMDB 连接 · 资产风险分析</b>
        <span class="chip trust">连 CMDB 自动评估脆弱性</span>
        <span class="chip" title="复用资产体检的 NVD CPE 版本区间判定">按版本区间判定</span>
        <span id="cmCfg" class="as-status"></span>
      </div>
      <div class="en-scan-ops">
        <button class="btn sm" id="cmGo">▶ 开始分析</button>
        <button class="btn ghost sm" id="cmHistBtn">历史记录</button>
      </div>
    </div>
    <div class="panel as-bar">
      <div class="pbody">
        <div class="cm-tabs">
          <button class="cm-tab" data-mode="rest">REST 直连</button>
          <button class="cm-tab" data-mode="sqlite">数据库文件</button>
          <button class="cm-tab" data-mode="inline">粘贴数据</button>
          <button class="cm-tab" data-mode="file">上传文件</button>
        </div>
        <div id="cmPane-rest" style="display:none" class="cm-pane">
          <div class="as-form">
            <input id="cmUrl" class="as-in" type="text" spellcheck="false"
                   placeholder="CMDB 接口地址，如 https://cmdb.example.com/api/v1/assets">
          </div>
          <div class="as-form" style="margin-top:6px">
            <input id="cmPath" class="as-in" type="text" spellcheck="false"
                   placeholder="路径（可选），如 /list 或 /search?status=online" style="flex:1 1 auto">
            <select id="cmAuth" class="as-sel" title="认证方式">
              <option value="bearer">Bearer Token</option>
              <option value="basic">Basic（user:pass）</option>
              <option value="header">自定义 Header</option>
            </select>
          </div>
          <div class="meta-note" style="margin-top:8px">凭证走环境变量 <code>AISEC_CMDB_TOKEN</code>（或 config.json 的 cmdb 段），不进请求、不写代码、不下发。支持常见返回结构（data/items/result/records 数组或单个对象）。</div>
        </div>
        <div id="cmPane-sqlite" style="display:none" class="cm-pane">
          <input type="file" id="cmDbFile" hidden multiple
                 accept=".db,.sqlite,.sqlite3,.db3">
          <div class="cm-drop" id="cmDbDrop">
            <div class="en-drop-ic">
              <svg viewBox="0 0 24 24" width="22" height="22" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
                <ellipse cx="12" cy="5.5" rx="7.5" ry="3"></ellipse>
                <path d="M4.5 5.5v6c0 1.66 3.36 3 7.5 3s7.5-1.34 7.5-3v-6"></path>
                <path d="M4.5 11.5v6c0 1.66 3.36 3 7.5 3s7.5-1.34 7.5-3v-6"></path>
              </svg>
            </div>
            <div class="en-drop-t">把 CMDB 的 SQLite 库拖到这里，或点击选择文件</div>
            <div class="en-drop-s">.db / .sqlite / .sqlite3 —— 可按住 Ctrl / Shift 一次选多个库
              （资产库与漏洞台账库分开存放时一起传进来，自动合并分析）；
              文件只在本机解析，服务端临时落盘，分析完即删，不外发</div>
          </div>
          <div class="cm-dbrow">
            <div id="cmDbList" class="cm-files" style="display:none;flex:1 1 auto"></div>
            <button class="btn ghost sm" id="cmDbClear" style="flex:none;display:none">清空</button>
          </div>
          <div class="as-form" style="margin-top:10px">
            <input id="cmDbTables" class="as-in" type="text" spellcheck="false"
                   placeholder="表名（可选，逗号分隔，如 middleware_instance,database_instance；留空则自动抽取全部软件资产表）">
          </div>
          <details class="cm-alt">
            <summary>库在服务器上？直接填路径（不上传）</summary>
            <div class="as-form" style="margin-top:6px">
              <input id="cmDbPath" class="as-in" type="text" spellcheck="false"
                     placeholder="SQLite 数据库文件路径，如 data/cmdb.db">
            </div>
            <div class="meta-note" style="margin-top:6px">已上传的文件优先于这里填的路径；两者都为空时才报错。填了就直接读服务器本地文件，不经过浏览器。</div>
          </details>
        </div>
        <div id="cmPane-inline" class="cm-pane">
          <textarea id="cmText" class="cm-text" spellcheck="false"
                    placeholder="粘贴 CMDB 导出的数据（JSON 数组 / JSON 对象 / CSV / TSV），如：
[{&quot;name&quot;:&quot;官网&quot;,&quot;ip&quot;:&quot;1.2.3.4&quot;,&quot;product&quot;:&quot;Apache HTTP Server&quot;,&quot;version&quot;:&quot;2.4.49&quot;,&quot;port&quot;:&quot;80&quot;}]
或表头为 name,ip,product,version,port 的 CSV。字段别名自动识别（主机名/域名/IP/组件/版本/端口/负责人…）。Ctrl+Enter 提交"></textarea>
        </div>
        <div id="cmPane-file" style="display:none" class="cm-pane">
          <input type="file" id="cmFile" hidden multiple
                 accept=".json,.csv,.tsv,.txt,.docx,.doc,.xlsx,.xls,.md">
          <button class="btn ghost" id="cmPick">选择 CMDB 导出的资产文件</button>
          <span class="meta-note">可按住 Ctrl / Shift 一次选多个文件（xlsx / csv / docx…），合并分析出一份报告 —— 文件只在本机解析，不外发</span>
          <div id="cmFileList" class="cm-files" style="display:none;margin-top:8px"></div>
        </div>
        <label class="asub-kevline" style="margin-top:8px"><input type="checkbox" id="cmMd"> 分析完成后直接下载 Markdown 报告（不展示在页面上）</label>
      </div>
    </div>
    <div id="cmProg" class="en-prog" style="display:none"></div>
    <!-- ★ 分析后把报告发到邮箱（2026-10-06）—— 四种模式通用，不只是上传文件 -->
    <div class="cm-mail" id="cmMail">
      <label class="cm-mail-ck">
        <input type="checkbox" id="cmMailOn">
        <span>分析完成后把报告发到邮箱</span>
      </label>
      <div class="cm-mail-row" id="cmMailRow" style="display:none">
        <input id="cmMailTo" class="as-in" type="text" spellcheck="false"
               placeholder="收件邮箱，多个用逗号分隔，如 zhang@qq.com, ops@company.com">
        <select id="cmMailFmt" class="as-sel" title="发送哪一份报告">
          <option value="md">七章制报告（完整推导）</option>
          <option value="xlsx">简略台账 xlsx（便于派单）</option>
          <option value="both">两份都发</option>
        </select>
        <select id="cmMailMask" class="as-sel" title="脱敏级别">
          <option value="basic">脱敏·基础（推荐）</option>
          <option value="strict">脱敏·严格</option>
        </select>
      </div>
      <div class="cm-mail-more" id="cmMailMore" style="display:none">
        <label class="cm-mail-ck sm">
          <input type="checkbox" id="cmMailSplit">
          <span>另一份发给不同的人（如领导只看完整版、运维只收台账）</span>
        </label>
        <div id="cmMailSplitRow" style="display:none">
          <div class="cm-mail-lbl" id="cmMailSplitLbl"></div>
          <input id="cmMailTo2" class="as-in" type="text" spellcheck="false"
                 placeholder="第二个收件邮箱">
        </div>
      </div>
      <div class="meta-note cm-mail-note" id="cmMailNote"></div>
    </div>
    <!-- 两份报告都可下载，原有 Markdown 导出不受影响 -->
    <div class="cm-mail-ops" id="cmDlOps">
      <button class="btn ghost sm" id="cmDlMd">⬇ 下载简略台账 xlsx</button>
      <button class="btn ghost sm" id="cmDlFull">⬇ 下载七章制 Markdown</button>
    </div>
    <div id="cmResult"></div>
    <div id="cmHist" class="en-hist" style="display:none"></div>`;

  return { HTML, bind };
})();

/* ============================================================
   m2_enrich · 攻击面测绘「实查」（2026-10-03 第二轮新增）
   ------------------------------------------------------------
   用户需求：asset_locator 只给语法不给数据，是"给你一把钥匙但不帮你开门"。
   现在接 FOFA / Shodan / Quake / ZoomEye 实查：全网暴露总量 + 国家/ASN/组织分布。
   无 Key 时自动进入确定性「演示模式」（结果显式标注，绝不冒充真实数据）；
   Key 走环境变量 AISEC_FOFA_KEY / AISEC_SHODAN_KEY / AISEC_QUAKE_KEY / AISEC_ZOOMEYE_KEY。
   接口：GET /api/asset_search · GET /api/asset_search/status
   ============================================================ */
const ASURF = (() => {
  const PLAT_CN = { fofa: 'FOFA', shodan: 'Shodan', quake: 'Quake', zoomeye: 'ZoomEye' };
  let root = null;
  const q = (sel, el) => (el || root).querySelector(sel);
  const qa = (sel, el) => Array.from((el || root).querySelectorAll(sel));

  /* 横向条形（国家 / ASN / 组织 / 端口分布）。脏数据防线：null 项直接剔除 */
  function facetBar(title, items, accent) {
    items = (items || []).filter(Boolean);
    if (!items.length) return '';
    const max = Math.max.apply(null, items.map((x) => x.count || 0)) || 1;
    const rows = items.slice(0, 10).map((x) => `
      <div class="as-bar-row">
        <span class="as-bar-k" title="${esc(x.value)}">${esc(x.value)}</span>
        <span class="as-bar-v"><i class="${accent || ''}" style="width:${Math.max(3, Math.round((x.count || 0) / max * 100))}%"></i></span>
        <b>${esc(String(x.count || 0))}</b>
      </div>`).join('');
    return `<div class="as-facet"><div class="as-facet-t">${esc(title)}</div>${rows}</div>`;
  }

  function resultHtml(r) {
    if (!r || r.ok === false) {
      return `<div class="empty"><div class="big">实查失败</div>${esc((r && r.error) || '未知错误')}
        ${r && r.hint ? `<div class="meta-note" style="margin-top:6px">${esc(r.hint)}</div>` : ''}</div>`;
    }
    const demo = r.demo
      ? `<div class="as-demo"><b>⚠️ 演示模式</b>${esc(r.demo_note || '')}</div>` : '';
    const badges = [
      `<span class="chip">${esc(PLAT_CN[r.platform] || r.platform)}</span>`,
      `<span class="chip" title="查询语法"><code>${esc(r.query)}</code></span>`,
      `<span class="chip">${r.mode === 'real' ? '真实数据' : '演示数据'}</span>`,
      `耗时 ${esc(String(r.took_ms || 0))}ms`,
    ].join('');
    const samples = (r.samples || []).filter(Boolean).length
      ? `<div class="panel as-samples"><header>暴露样本 · 前 ${Math.min(r.samples.filter(Boolean).length, 20)} 条
           <span class="ph-sub">来自测绘平台索引快照 · 命中≠受影响，处置前先核对版本</span></header>
         <div class="pbody"><table class="en-tbl"><thead><tr>
           <th>主机 / IP</th><th>端口</th><th>国家</th><th>组织 / ASN</th><th>指纹</th>
         </tr></thead><tbody>${r.samples.filter(Boolean).slice(0, 20).map((s) => `
           <tr><td class="en-host">${esc(s.host || s.ip || '—')}</td>
           <td>${esc(s.port || '—')}</td>
           <td>${esc(s.country || '—')}</td>
           <td>${esc(s.org || s.asn || '—')}</td>
           <td>${esc(s.product || s.title || '—')}</td></tr>`).join('')}</tbody></table></div></div>`
      : '';
    return `
      ${demo}
      <div class="panel as-total">
        <header>全网暴露总览 <span class="ph-sub">${badges}</span></header>
        <div class="pbody">
          <div class="as-total-n"><b>${esc(String(r.total != null ? r.total : '—'))}</b>
            <span>台资产命中该语法</span></div>
          <div class="as-facets">
            ${facetBar('国家 / 地区分布', r.countries, 'c1')}
            ${facetBar('ASN 分布', r.asns, 'c2')}
            ${facetBar('所属组织', r.orgs, 'c3')}
            ${facetBar('端口分布', r.ports, 'c4')}
          </div>
          <div class="meta-note">${esc(r.compliance || '')}</div>
        </div>
      </div>
      ${samples}
      ${(r.alternatives || []).filter(Boolean).length ? `<div class="panel as-alts"><header>换一条语法试试</header>
        <div class="pbody">${r.alternatives.filter(Boolean).filter((x) => x.q !== r.query).map((x) => `
          <div class="sv-q" data-q="${esc(x.q)}" title="${esc(x.why || '')}"><code>${esc(x.q)}</code>
            ${x.product ? `<span class="chip">${esc(x.product)}</span>` : ''}
            <span class="en-go">实查 →</span></div>`).join('')}</div></div>` : ''}`;
  }

  async function loadStatus() {
    try {
      const r = await (await fetch('/api/asset_search/status')).json();
      const box = q('#asStatus');
      if (!box || !r || !r.platforms) return;
      box.innerHTML = Object.keys(r.platforms).map((k) => {
        const p = r.platforms[k];
        return `<span class="chip ${p.configured ? 'ok' : ''}"
          title="${p.configured ? '已配置 Key，走真实查询' : '未配置 ' + esc(p.env) + '，点击实查自动进入演示模式'}">
          ${esc(p.label)} ${p.configured ? '✓' : '·演示'}</span>`;
      }).join('');
    } catch (e) { /* 角标失败不阻塞 */ }
  }

  async function run(forceDemo) {
    const out = q('#asOut');
    const plat = (q('#asPlat') || {}).value || 'fofa';
    let input = (q('#asQ') || {}).value || '';
    input = input.trim();
    if (!input) { toast('先输入 CVE 编号或测绘语法'); return; }
    const isCve = /^CVE-\d{4}-\d{4,}$/i.test(input);
    out.style.display = '';
    out.innerHTML = '<div class="loading">正在查询测绘平台…<span class="rspin"></span></div>';
    const p = new URLSearchParams({ platform: plat, samples: '1' });
    if (forceDemo) p.set('demo', '1');
    if (isCve) p.set('id', input); else p.set('q', input);
    try {
      const r = await (await fetch('/api/asset_search?' + p)).json();
      out.innerHTML = resultHtml(r);
      qa('.sv-q[data-q]', out).forEach((row) => {
        row.onclick = () => { q('#asQ').value = row.dataset.q; run(false); };
      });
      if (r.demo) toast('演示模式：未配置该平台 Key，以下为确定性演示数据', 5000);
    } catch (e) {
      out.innerHTML = `<div class="empty"><div class="big">实查失败</div>${esc(e.message)}</div>`;
    }
  }

  function bind(el) {
    root = el;
    q('#asGo').onclick = () => run(false);
    q('#asDemo').onclick = () => run(true);
    q('#asQ').onkeydown = (e) => { if (e.key === 'Enter') run(false); };
    loadStatus();
  }

  const HTML = `
    <div class="en-scan-head">
      <div class="en-scan-ttl">
        <b>攻击面测绘实查</b>
        <span class="chip">FOFA / Shodan / Quake / ZoomEye</span>
        <span class="chip trust">只查平台索引 · 不扫描任何主机</span>
        <span id="asStatus" class="as-status"></span>
      </div>
    </div>
    <div class="panel as-bar">
      <div class="pbody as-form">
        <select id="asPlat" class="as-sel">
          <option value="fofa">FOFA</option><option value="shodan">Shodan</option>
          <option value="quake">Quake</option><option value="zoomeye">ZoomEye</option>
        </select>
        <input id="asQ" class="as-in" type="text" spellcheck="false"
               placeholder="输入 CVE 编号（如 CVE-2024-37032，自动选最优语法）或直接粘贴测绘语法（如 body=&quot;Ollama is running&quot;）">
        <button class="btn sm" id="asGo">🌐 实查</button>
        <button class="btn ghost sm" id="asDemo" title="强制查看演示模式效果">演示模式</button>
      </div>
    </div>
    <div id="asOut" style="display:none"></div>`;

  return { HTML, bind };
})();

/* ============================================================
   m2_enrich · 漏洞预警订阅与推送（2026-10-03 第二轮新增）
   ------------------------------------------------------------
   把「用户主动来查」升级成「系统主动告诉用户」：订阅产品 / 厂商 / CVE /
   关键词 / 仅 KEV，模块 1 情报库增量更新时自动匹配，推送到前端通知栏与
   Webhook（企微 / 钉钉 / 飞书群机器人，环境变量 AISEC_WEBHOOK_URL）。
   接口：GET|POST /api/subscribe · POST /api/subscribe/update|delete|check|read
         GET /api/subscribe/alerts
   ============================================================ */
const ASUB = (() => {
  const KIND_CN = { product: '产品', vendor: '厂商', cve: 'CVE', keyword: '关键词', kev: '仅 KEV 在野' };
  const SEVS = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN'];
  const sevOf = (x) => { const s = String(x || '').toUpperCase(); return SEVS.includes(s) ? s : 'UNKNOWN'; };
  let root = null;
  const q = (sel, el) => (el || root).querySelector(sel);
  const qa = (sel, el) => Array.from((el || root).querySelectorAll(sel));

  function subRow(s) {
    return `<div class="asub-sub" data-id="${esc(s.id)}">
      <span class="chip">${esc(KIND_CN[s.kind] || s.kind)}</span>
      <b class="asub-val">${esc(s.name || s.value)}</b>
      ${s.value && s.kind !== 'kev' ? `<code class="asub-code">${esc(s.value)}</code>` : ''}
      ${s.min_severity ? `<span class="chip">${esc(s.min_severity)}+</span>` : ''}
      ${s.kev_only ? '<span class="chip alert">仅 KEV</span>' : ''}
      ${s.ai_min ? `<span class="chip">AI≥${esc(String(s.ai_min))}</span>` : ''}
      ${s.webhook ? '<span class="chip" title="该订阅独立推送的 Webhook">⇱ webhook</span>' : ''}
      <span class="asub-sp"></span>
      <button class="btn ghost sm asub-toggle" title="启用 / 暂停">${s.enabled ? '⏸ 暂停' : '▶ 启用'}</button>
      <button class="btn ghost sm asub-del">✕ 删除</button>
    </div>`;
  }

  function alertRow(a) {
    const sev = sevOf(a.severity);
    return `<div class="en-f asub-al${a.read ? '' : ' unread'}" data-id="${esc(a.doc_id || '')}">
      <div class="en-f-l1">
        <span class="cve">${esc(a.doc_id || '—')}</span>
        <span class="badge ${sev}">${esc(sev)}${a.score != null ? ' ' + esc(String(a.score)) : ''}</span>
        ${a.kev ? '<span class="chip alert">● 在野利用</span>' : ''}
        <span class="en-f-ttl">${esc(a.title || '')}</span>
        <span class="en-go">详情 →</span>
      </div>
      <div class="en-f-l2">
        <span class="chip" title="命中的订阅">◎ ${esc(a.sub_name || '')}</span>
        <span class="chip">${esc(a.ts || '')}</span>
        ${a.pushed ? '<span class="chip ok">已推 Webhook</span>' : ''}
      </div>
    </div>`;
  }

  function renderStatus(st) {
    const box = q('#asubStatus');
    if (box) box.innerHTML = [
      `订阅 ${st.enabled}/${st.subs}`,
      `未读 <b class="${st.unread ? 'asub-unread-n' : ''}">${st.unread}</b>`,
      st.last_check ? `上次巡检 ${esc(st.last_check)}` : '尚未巡检',
      st.webhook ? '<span class="chip ok">全局 Webhook ✓</span>' : '',
      st.daemon ? '<span class="chip ok">后台巡检中</span>' : '<span class="chip">后台待命</span>',
    ].filter(Boolean).map((x) => `<span class="asub-sti">${x}</span>`).join('');
  }

  async function refresh() {
    try {
      const [st, al] = await Promise.all([
        fetch('/api/subscribe').then((r) => r.json()),
        fetch('/api/subscribe/alerts?limit=50').then((r) => r.json()),
      ]);
      /* 本模块任何改动订阅数据的操作都会走这里 → 顺手让侧栏未读角标跟着重算，
         否则用户点了「全部已读」/ 删除订阅，红点还要等最多 45 秒才消失。 */
      try { if (window.AISEC && typeof AISEC.refreshSubBadge === 'function') AISEC.refreshSubBadge(); }
      catch (e) { /* 主体还没初始化完，忽略 */ }
      if (st && st.ok) {
        renderStatus(st.status || {});
        const subs = (st.subs || []).filter(Boolean);   // 数组混进 null 不能崩整个列表
        q('#asubSubs').innerHTML = subs.length
          ? subs.map(subRow).join('')
          : '<div class="meta-note" style="padding:4px 2px">还没有订阅 —— 订阅 "ollama"、"log4j" 或某个 CVE，新情报进库时自动匹配并推送。</div>';
        /* 该订阅产生的未读告警数 —— 删订阅不删告警，这里要能提前告知用户 */
        const unreadBy = {};
        ((al && al.alerts) || []).forEach((a) => {
          if (a && !a.read && a.sub_id) unreadBy[a.sub_id] = (unreadBy[a.sub_id] || 0) + 1;
        });
        qa('.asub-sub', q('#asubSubs')).forEach((row) => {
          row.querySelector('.asub-toggle').onclick = async () => {
            const on = !row.querySelector('.asub-toggle').textContent.includes('启用');
            await fetch('/api/subscribe/update', { method: 'POST',
              headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify({ id: row.dataset.id, enabled: on }) });
            refresh();
          };
          row.querySelector('.asub-del').onclick = async () => {
            /* 删订阅不删告警（要留复盘依据），所以这里必须先说清"你还欠几条没读"，
               否则用户删完订阅，侧栏红点还挂着，会以为是 bug。 */
            const un = unreadBy[row.dataset.id] || 0;
            const name = row.querySelector('.asub-val');
            const label = name ? name.textContent.trim() : '该订阅';
            const msg = un
              ? `删除订阅「${label}」？\n\n该订阅产生的 ${un} 条历史告警会保留，但删除后不会再产生新告警。\n（可在下方通知栏点开查看，或点「全部已读」清掉角标）`
              : `删除订阅「${label}」？\n\n该订阅没有未读的历史告警。`;
            if (!confirm(msg)) return;
            const r = await fetch('/api/subscribe/delete', { method: 'POST',
              headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify({ id: row.dataset.id }) }).then((x) => x.json()).catch(() => null);
            if (!r || !r.ok) { toast('删除失败，请重试'); return; }
            toast(un ? `已删除订阅，保留 ${un} 条历史告警` : '已删除订阅', 4000);
            refresh();
          };
        });
      }
      const alerts = ((al && al.alerts) || []).filter(Boolean);
      q('#asubAlerts').innerHTML = alerts.length
        ? alerts.map(alertRow).join('')
        : '<div class="meta-note" style="padding:4px 2px">暂无告警。有新情报命中订阅条件时，这里会出现通知。</div>';
      qa('.asub-al', q('#asubAlerts')).forEach((row) => {
        row.onclick = async () => {
          if (row.dataset.id) openDetail(row.dataset.id);
        };
      });
    } catch (e) { /* 角标失败不阻塞 */ }
  }

  async function addSub() {
    const kind = (q('#asubKind') || {}).value || 'product';
    const value = ((q('#asubValue') || {}).value || '').trim();
    const minSev = (q('#asubSev') || {}).value || '';
    const aiMin = (q('#asubAi') || {}).value || '';
    const kevOnly = !!(q('#asubKev') || {}).checked;
    const webhook = ((q('#asubHook') || {}).value || '').trim();
    if (kind !== 'kev' && !value) { toast('订阅内容不能为空'); return; }
    const body = { kind, value, min_severity: minSev, kev_only: kevOnly, webhook };
    if (aiMin) body.ai_min = aiMin;
    try {
      const r = await (await fetch('/api/subscribe', { method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body) })).json();
      if (!r.ok) throw new Error(r.error || '添加失败');
      q('#asubValue').value = '';
      q('#asubHook').value = '';
      toast('已订阅：' + (r.sub ? r.sub.name : value));
      refresh();
      const c = await fetch('/api/subscribe/check', { method: 'POST' }).then((x) => x.json());
      if (c && c.ok && c.new) toast(`立即巡检：命中 ${c.new} 条新告警`, 5000);
      refresh();
    } catch (e) { toast(e.message, 5000); }
  }

  function bind(el) {
    root = el;
    q('#asubAdd').onclick = addSub;
    q('#asubCheck').onclick = async () => {
      q('#asubCheck').disabled = true;
      try {
        const r = await fetch('/api/subscribe/check', { method: 'POST' }).then((x) => x.json());
        toast(r && r.ok ? `巡检完成：新增 ${r.new} 条告警` : '巡检失败', 4000);
      } catch (e) { toast('巡检失败'); }
      q('#asubCheck').disabled = false;
      refresh();
    };
    q('#asubReadAll').onclick = async () => {
      await fetch('/api/subscribe/read', { method: 'POST',
        headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ all: true }) });
      refresh();
    };
    q('#asubValue').onkeydown = (e) => { if (e.key === 'Enter') addSub(); };
    refresh();
  }

  const HTML = `
    <div class="en-scan-head">
      <div class="en-scan-ttl">
        <b>漏洞预警订阅</b>
        <span class="chip trust">情报库更新 → 自动匹配 → 推送</span>
        <span class="chip" title="对接企微/钉钉/飞书群机器人，环境变量 AISEC_WEBHOOK_URL">Webhook 推送</span>
      </div>
      <div class="en-scan-ops">
        <button class="btn ghost sm" id="asubCheck">⚡ 立即巡检</button>
        <button class="btn ghost sm" id="asubReadAll">全部已读</button>
      </div>
    </div>
    <div class="panel">
      <header>订阅条件 <span id="asubStatus" class="asub-status"></span></header>
      <div class="pbody">
        <div class="asub-form">
          <select id="asubKind" class="as-sel" title="订阅类型">
            <option value="product">产品</option><option value="vendor">厂商</option>
            <option value="cve">CVE</option><option value="keyword">关键词</option>
            <option value="kev">仅 KEV 在野（全部）</option>
          </select>
          <input id="asubValue" class="as-in" type="text" spellcheck="false"
                 placeholder="订阅内容：产品名（ollama）/ 厂商 / CVE-2024-37032 / 关键词；选「仅 KEV」可留空">
          <select id="asubSev" class="as-sel" title="最低严重度">
            <option value="">不限严重度</option><option value="LOW">LOW+</option>
            <option value="MEDIUM">MEDIUM+</option><option value="HIGH">HIGH+</option>
            <option value="CRITICAL">仅 CRITICAL</option>
          </select>
          <select id="asubAi" class="as-sel" title="AI 相关度门槛">
            <option value="">不限 AI 分</option><option value="0.3">AI≥0.3</option>
            <option value="0.6">AI≥0.6</option><option value="0.8">AI≥0.8</option>
          </select>
          <button class="btn sm" id="asubAdd">＋ 订阅</button>
        </div>
        <label class="asub-kevline"><input type="checkbox" id="asubKev"> 仅接收已被在野利用（CISA KEV）的漏洞</label>
        <input id="asubHook" class="as-in asub-hook" type="text" spellcheck="false"
               placeholder="该订阅独立 Webhook 地址（可选，留空用全局 AISEC_WEBHOOK_URL）">
        <div id="asubSubs" class="asub-subs"></div>
      </div>
    </div>
    <div class="panel">
      <header>告警通知栏 <span class="ph-sub">新情报命中订阅条件时自动出现 · 点一条直达漏洞详情</span></header>
      <div class="pbody"><div id="asubAlerts"></div></div>
    </div>`;

  return { HTML, bind, refresh };
})();

/* ============================================================
   m2_enrich · 漏洞修复方案生成（详情抽屉面板）
   ------------------------------------------------------------
   「生成修复方案」按钮：基于漏洞描述 + CWE + 受影响组件/版本区间 +
   KEV + CVSS 向量 + 官方补丁，产出升级路径 / 配置加固（含代码）/
   临时缓解 / 验证方法。有 LLM Key 走 LLM 定制，无 Key 自动降级模板模式。
   接口：GET /api/remediation?id=...（&force=1 重生成 &md=1 导出）
   ============================================================ */
const REMED = (() => {
  const SEVS = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN'];
  const sevOf = (x) => { const s = String(x || '').toUpperCase(); return SEVS.includes(s) ? s : 'UNKNOWN'; };

  function planHtml(p) {
    const r = p.risk || {};
    const src = p.generated_by === 'llm'
      ? '<span class="chip ok" title="已配置 LLM Key，方案结合漏洞细节定制">LLM 定制</span>'
      : '<span class="chip" title="未配置 LLM Key，按 NVD 元数据（CWE/CVSS/KEV）确定性推导；配置 AISEC_LLM_API_KEY 可获得代码级定制">模板模式</span>';
    const refs = (p.references || []).map((u) => `<div class="mt">${link(u)}</div>`).join('');
    const cfg = (p.config || []).map((c) => `
      <div class="rem-cfg">
        <b>${esc(c.item || '')}</b>
        <p>${esc(c.detail || '')}</p>
        ${c.code ? `<pre class="rem-code">${esc(c.code)}</pre>` : ''}
      </div>`).join('');
    const lst = (t, arr) => (arr || []).length
      ? `<div class="rem-sec"><b>${esc(t)}</b>${arr.map((x) => `<div class="rem-li">${esc(x)}</div>`).join('')}</div>` : '';
    const ups = (p.upgrade || []).map((u) => `
      <div class="rem-li"><b>${esc(u.component || '')}</b> → ${esc(u.target || '')}
        ${u.note ? `<span class="meta-note">${esc(u.note)}</span>` : ''}</div>`).join('');
    return `
      <div class="asub-status" style="margin:0 0 8px">${src}
        <span class="chip">${esc(p.generated_at || '')}</span>
        ${r.kev ? `<span class="chip alert">KEV 在野 · 截止 ${esc(r.kev_due || '?')}</span>` : ''}
        ${r.cvss_score != null ? `<span class="badge ${sevOf(r.severity)}">${esc(sevOf(r.severity))} ${esc(String(r.cvss_score))}</span>` : ''}
        ${p.cached ? '<span class="chip">缓存</span>' : ''}
      </div>
      <div class="rem-sum">${esc(p.summary || '')}</div>
      ${ups ? `<div class="rem-sec"><b>升级路径</b>${ups}</div>` : ''}
      ${cfg ? `<div class="rem-sec"><b>配置 / 代码级加固</b>${cfg}</div>` : ''}
      ${lst('临时缓解', p.mitigations)}
      ${lst('验证方法', p.verify)}
      ${refs ? `<div class="rem-sec"><b>参考</b>${refs}</div>` : ''}
      <div class="meta-note" style="margin-top:6px">${esc(p.disclaimer || '')}</div>`;
  }

  async function run(out, cid, force) {
    out.innerHTML = '<div class="loading">正在生成修复方案…<span class="rspin"></span></div>';
    try {
      const r = await (await fetch('/api/remediation?id=' + encodeURIComponent(cid)
        + (force ? '&force=1' : ''))).json();
      if (!r || !r.ok) throw new Error((r && r.error) || '生成失败');
      out.innerHTML = planHtml(r.plan);
    } catch (e) {
      out.innerHTML = `<div class="empty">修复方案生成失败：${esc(e.message)}</div>`;
    }
  }

  function bind(cid) {
    const btn = $('remBtn'), out = $('remOut'), re = $('remRe');
    if (btn) btn.onclick = () => { btn.disabled = true; run(out, cid).finally(() => { btn.disabled = false; }); };
    if (re) re.onclick = () => run(out, cid, true);
  }

  function sectionHtml() {
    return `<div class="sec"><h4>修复方案生成（LLM / 模板双模式）</h4>
      <div id="remPanel">
        <button class="btn ghost" id="remBtn">🛠 生成修复方案</button>
        <div id="remOut" style="margin-top:10px"></div>
      </div></div>`;
  }

  return { bind, sectionHtml };
})();

  /* ============================================================
     STIX 2.1 / TAXII 2.1 标准导出（ASTIX）
     导出 Bundle 给 Splunk/QRadar/OpenCTI；TAXII 端点供 SIEM 订阅拉取。
     ============================================================ */
  const ASTIX = (() => {
    const HTML = `
    <div class="panel as-bar">
      <header>STIX 2.1 / TAXII 2.1 标准导出
        <span class="ph-sub">安全行业标准格式 · 企业可直接导入 SIEM（Splunk / QRadar / OpenCTI）</span></header>
      <div class="pbody">
        <div class="as-form">
          <select class="as-sel" id="stixSev">
            <option value="LOW">全部严重度</option>
            <option value="MEDIUM">MEDIUM 及以上</option>
            <option value="HIGH">HIGH 及以上</option>
            <option value="CRITICAL">仅 CRITICAL</option>
          </select>
          <label class="asub-kevline"><input type="checkbox" id="stixKev"> 仅 KEV（在野利用）</label>
          <input class="as-in" id="stixDays" type="number" min="1" placeholder="近 N 天（空=全部）" style="flex:0 1 150px">
          <input class="as-in" id="stixLimit" type="number" min="1" max="5000" placeholder="条数上限，默认 2000" style="flex:0 1 170px">
          <button class="btn" id="stixGo">⬇ 导出 STIX Bundle</button>
          <button class="btn ghost" id="stixMd">导出摘要 .md</button>
        </div>
        <div id="stixOut" style="margin-top:10px"></div>
        <div class="meta-note" style="margin-top:10px">TAXII 2.1 订阅端点（SIEM 侧可用 taxii2-client 拉取）：
          <code>${location.origin}/taxii2/</code> → collections：
          <code>all</code> / <code>kev</code> / <code>critical</code>。
          设置环境变量 <code>AISEC_TAXII_KEY</code> 后需带 <code>Authorization: Bearer</code> 头。</div>
      </div>
    </div>`;

    function dl(name, blob) {
      const a = document.createElement('a');
      a.href = URL.createObjectURL(blob);
      a.download = name;
      a.click();
      setTimeout(() => URL.revokeObjectURL(a.href), 4000);
    }

    function params(el) {
      const p = new URLSearchParams();
      p.set('sev', el.querySelector('#stixSev').value);
      if (el.querySelector('#stixKev').checked) p.set('kev', '1');
      const days = el.querySelector('#stixDays').value.trim();
      if (days) p.set('days', days);
      const lim = el.querySelector('#stixLimit').value.trim();
      if (lim) p.set('limit', lim);
      return p;
    }

    function bind(el) {
      el.querySelector('#stixGo').onclick = async () => {
        const out = el.querySelector('#stixOut');
        out.innerHTML = '<div class="loading">正在序列化 STIX 2.1 Bundle…</div>';
        try {
          const r = await fetch('/api/stix?' + params(el));
          const d = await r.json();
          if (!d || d.ok !== true || !d.bundle) throw new Error((d && d.error) || '导出失败');
          dl(d.filename || 'stix-bundle.json',
             new Blob([JSON.stringify(d.bundle, null, 1)], { type: 'application/stix+json;version=2.1' }));
          const kevN = (d.bundle.objects || []).filter((o) => (o.labels || []).includes('kev')).length;
          out.innerHTML = `<div class="meta-note">✅ 已导出 <b>${d.count}</b> 条 vulnerability SDO
            （Bundle ID <code>${esc(String(d.bundle.id || ''))}</code>${kevN ? '，含 KEV ' + kevN + ' 条' : ''}）</div>`;
        } catch (e) { out.innerHTML = `<div class="meta-note">❌ ${esc(String(e.message || e))}</div>`; }
      };
      el.querySelector('#stixMd').onclick = async () => {
        try {
          const r = await fetch('/api/stix?' + params(el) + '&md=1');
          dl('stix-summary.md', new Blob([await r.text()], { type: 'text/markdown' }));
          toast('摘要已下载');
        } catch (e) { toast('导出失败：' + (e.message || e)); }
      };
    }
    return { HTML, bind };
  })();

  /* ============================================================
     处置工具箱（TBOX，详情抽屉）：复现环境生成
     ============================================================ */
  const TBOX = (() => {
    function sectionHtml() {
      return `<div class="sec"><h4>处置工具箱 · 复现环境生成</h4><div id="tbox">
        <div class="as-form">
          <button class="btn ghost" id="tbEnv">🐳 生成复现环境 (zip)</button>
        </div>
        <div id="tbOut" style="margin-top:9px"></div>
      </div></div>`;
    }

    async function bind(el, cid) {
      el.querySelector('#tbEnv').onclick = async () => {
        const out = el.querySelector('#tbOut');
        out.innerHTML = '<div class="loading">正在生成复现环境包…</div>';
        try {
          const pocs = (window.__lastPocUrls || []);
          const r = await fetch('/api/vuln_env', {
            method: 'POST', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ id: cid, poc_urls: pocs }),
          });
          const d = await r.json();
          if (!d || d.ok !== true || !d.b64) throw new Error((d && d.error) || '生成失败');
          const bin = atob(d.b64);
          const bytes = new Uint8Array(bin.length);
          for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
          const a = document.createElement('a');
          a.href = URL.createObjectURL(new Blob([bytes], { type: 'application/zip' }));
          a.download = d.filename || (cid + '-env.zip');
          a.click();
          setTimeout(() => URL.revokeObjectURL(a.href), 4000);
          const p = d.plan || {};
          const warns = (p.warnings || []).map((w) => `<div>⚠ ${esc(w)}</div>`).join('');
          out.innerHTML = `<div class="meta-note">✅ ${esc(d.filename)}（${d.bytes} 字节）
            已下载。镜像 <code>${esc(p.image || '?')}</code>，端口 ${esc(String(p.port || '?'))}。
            在有 Docker 的授权机器上 <code>docker compose up -d && python verify.py</code>。
            ${warns}</div>`;
        } catch (e) { out.innerHTML = `<div class="meta-note">❌ ${esc(String(e.message || e))}</div>`; }
      };
    }
    return { sectionHtml, bind };
  })();

  /* ============================================================
     端口测绘（2026-10-08 新增）—— 授权资产 TCP 探测
     接口：POST /api/port_scan（扫描）· GET /api/port_scan（历史）
     合规：仅限授权资产；TCP connect（nmap -sT 同级），不发探测载荷。
     ============================================================ */
  const APORT = (() => {
    let root = null;
    const q = (sel, el) => (el || root).querySelector(sel);
    const HTML = `
      <div class="en-scan-head">
        <div class="en-scan-ttl">
          <b>端口测绘</b>
          <span class="chip">TCP connect 扫描</span>
          <span class="chip trust">nmap -sT 同级</span>
          <span class="chip" title="仅对已授权资产使用；扫描未授权主机可能违法">仅授权资产</span>
          <span class="chip trust" title="扫描后自动与本地情报库交叉验证（服务指纹 → CVE），可出工单">漏洞关联</span>
        </div>
      </div>
      <div class="as-form">
        <input id="psHost" placeholder="域名或 IP，如 www.deepseek.com 或 10.0.0.1">
        <input id="psPorts" placeholder="端口，如 80,443,8000-8010（留空=常见 100 端口）">
        <button class="btn" id="psGo">开始扫描</button>
      </div>
      <div id="psProg" style="display:none" class="en-prog"></div>
      <div id="psOut" style="margin-top:10px"></div>`;

    /* 风险等级 → 样式类（白名单映射，防脏数据注入 class） */
    const rkCls = (lv) => lv === '严重' ? 'crit' : lv === '高' ? 'high'
      : lv === '中' ? 'med' : lv === '低' ? 'low' : 'na';

    function renderResult(r) {
      const out = q('#psOut');
      if (!r || !r.ok) { out.innerHTML = `<div class="empty"><div class="big">扫描失败</div>${esc((r && r.error) || '')}</div>`; return; }
      const ops = r.open_ports || [];
      const corr = r.correlation || {};
      const rows = ops.map((p) => `<tr>
          <td><b>${esc(String(p.port))}</b></td>
          <td><code>${esc(p.service || 'unknown')}</code></td>
          <td>${p.product ? `<code>${esc(p.product)}</code>${p.version ? ' <b>' + esc(p.version) + '</b>' : ''}`
                        : '<span class="dim">未识别</span>'}</td>
          <td><span class="en-rk ${rkCls(p.risk_level)}">${esc(p.risk_level || '—')}</span></td>
          <td>${p.cve_count ? p.cve_count : '—'}</td>
          <td>${p.max_score ? esc(String(p.max_score)) : '—'}</td>
          <td>${p.kev_count ? '<b class="hot">KEV</b>' : ''}</td>
          <td>${esc(p.top || '—')}</td>
          <td class="mono" title="${esc(p.ident_src || '')}">${esc(p.ident_conf || '—')}</td>
        </tr>`).join('');
      out.innerHTML = `
        <div class="meta-note">✅ ${esc(r.host)}（${esc(r.ip)}）扫 ${r.scanned} 端口，
          <b>开放 ${r.open_count}</b> · 识别指纹 ${corr.identified || 0} ·
          命中 CVE <b>${corr.cve_hits || 0}</b>（CRITICAL ${corr.critical || 0} / HIGH ${corr.high || 0} /
          在野 ${corr.exploited || 0}）· 耗时 ${r.elapsed_ms}ms</div>
        ${corr.kev_ids && corr.kev_ids.length ? `<div class="meta-note hot">⚠ 在野利用（CISA KEV）：${esc(corr.kev_ids.slice(0, 8).join('、'))}</div>` : ''}
        ${r.correlation_error ? `<div class="meta-note">⚠ 情报关联失败（端口结果不受影响）：${esc(r.correlation_error)}</div>` : ''}
        <table class="tbl">
          <thead><tr><th>端口</th><th>服务</th><th>产品指纹</th><th>风险</th><th>CVE</th><th>最高CVSS</th><th>KEV</th><th>最高风险编号</th><th>置信</th></tr></thead>
          <tbody>${rows || '<tr><td colspan="9">无开放端口（或全部被防火墙过滤）</td></tr>'}</tbody>
        </table>
        <div class="as-form" style="margin-top:10px">
          <button class="btn ghost sm" id="psMd">下载工单报告（CMDB 风格）</button>
        </div>
        <div class="meta-note">${esc(r.note || '')}${corr.identified ? '<br>Web 端口已做最小化 HEAD 探测（仅取 Server 响应头，不带攻击载荷）。' : ''}<br>${esc(r.disclaimer || '')}</div>`;
      const md = q('#psMd');
      if (md) md.onclick = () => {
        fetch('/api/port_scan?md=1')
          .then((x) => { if (!x.ok) throw new Error('HTTP ' + x.status); return x.blob(); })
          .then((b) => {
            const a = document.createElement('a');
            a.href = URL.createObjectURL(b);
            a.download = '端口测绘工单报告_' + (r.host || '') + '.md';
            document.body.appendChild(a); a.click(); a.remove();
            setTimeout(() => URL.revokeObjectURL(a.href), 4000);
          })
          .catch(() => toast('导出失败（需先完成一次扫描）'));
      };
    }

    function bind(el) {
      root = el;
      q('#psGo').onclick = async () => {
        const host = q('#psHost').value.trim();
        if (!host) { toast('请输入域名或 IP'); return; }
        const prog = q('#psProg');
        prog.style.display = ''; prog.innerHTML = '<div class="loading">扫描中（端口探测 → 指纹识别 → 情报关联）…<span class="rspin"></span></div>';
        try {
          const r = await (await fetch('/api/port_scan', {
            method: 'POST', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ host, ports: q('#psPorts').value.trim() }),
          })).json();
          renderResult(r);
        } catch (e) { q('#psOut').innerHTML = `<div class="empty">扫描失败：${esc(e.message)}</div>`; }
        finally { prog.style.display = 'none'; prog.innerHTML = ''; }
      };
    }
    return { HTML, bind };
  })();

  /* ============================================================
     项目成分扫描 SCA（2026-10-08 新增）—— zip/文件夹 → 依赖 → CVE 报告
     接口：POST /api/project_scan · GET /api/project_scan(?id=|?md=1)
     ============================================================ */
  const APROJ = (() => {
    let root = null;
    const q = (sel, el) => (el || root).querySelector(sel);
    /* 客户端清单文件筛选：与后端 _MANIFEST_PATTERNS 同口径（文件夹模式下
       只读这些小文件，目录里几万个 node_modules 文件不会进浏览器内存） */
    const MANIFEST_RE = /(^|\/)(requirements[\w.-]*\.txt|pyproject\.toml|package\.json|package-lock\.json|pom\.xml|build\.gradle(?:\.kts)?|go\.mod|[\w.-]+\.csproj|composer\.json|Gemfile(?:\.lock)?)$/i;
    const MAX_ZIP = 10 * 1024 * 1024 * 1024;   // 与后端 LARGE_BODY / MAX_ZIP_TOTAL 一致
    const HTML = `
      <div class="en-scan-head">
        <div class="en-scan-ttl">
          <b>项目成分扫描（SCA）</b>
          <span class="chip">依赖清单</span>
          <span class="chip trust">情报库 CPE 版本区间判定</span>
          <span class="chip trust" title="zip 走二进制流式直传，边传边落盘，字节不进内存">单包 ≤ 10GB</span>
        </div>
      </div>
      <div class="en-drop" id="pjDrop">
        <input type="file" id="pjFile" hidden accept=".zip">
        <input type="file" id="pjDir" hidden webkitdirectory multiple>
        <div class="en-drop-ic">
          <svg viewBox="0 0 24 24" width="22" height="22" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M12 16V4m0 0L7.5 8.5M12 4l4.5 4.5"></path><path d="M4 15v3.5A1.5 1.5 0 005.5 20h13a1.5 1.5 0 001.5-1.5V15"></path></svg>
        </div>
        <div class="en-drop-t">把项目 zip 包拖到这里，或点击选择（也可用下方按钮选整个文件夹）</div>
        <div class="en-drop-s">支持 requirements.txt / pyproject.toml / package.json / package-lock.json /
          pom.xml / build.gradle / go.mod / *.csproj / composer.json / Gemfile —— 单包 ≤ 10GB，本机解析不外发</div>
      </div>
      <div class="as-form" style="margin-top:8px">
        <button class="btn ghost sm" id="pjDirBtn">选择文件夹（只读依赖清单，不上传其他文件）</button>
      </div>
      <div id="pjProg" style="display:none" class="en-prog"></div>
      <div id="pjOut" style="margin-top:10px"></div>`;

    function renderRep(rep) {
      const out = q('#pjOut');
      const s = rep.summary || {};
      const crit = s.critical || 0, high = s.high || 0, expl = s.exploited || 0;
      const level = (crit || expl) ? '高风险' : (high ? '中风险' : (s.cve_hits ? '低风险' : '未发现已知风险'));
      const riskComp = (rep.components || []).filter((c) => c.cve_count > 0);
      const rows = riskComp.slice(0, 30).map((c) => `<tr>
          <td><code>${esc(c.name)}</code></td>
          <td>${esc(c.version || '未提供')}</td>
          <td><span class="en-rk ${c.risk_level === '严重' ? 'crit' : c.risk_level === '高' ? 'high' : 'med'}">${esc(c.risk_level)}</span></td>
          <td>${c.cve_count}</td>
          <td>${esc(c.max_score || '—')}</td>
          <td>${c.kev_count ? '<b class="hot">KEV</b>' : ''}</td>
          <td>${esc(c.top || '—')}</td>
        </tr>`).join('');
      out.innerHTML = `
        <div class="meta-note">✅ <b>${esc(rep.source)}</b>（${esc(rep.source_kind || '')}）·
          组件 ${s.components || 0}（版本 ${s.with_version || 0}）·
          命中 CVE <b>${s.cve_hits || 0}</b>（CRITICAL ${crit} / HIGH ${high} / 在野 ${expl}）·
          整体 ${esc(level)}</div>
        ${s.kev_ids && s.kev_ids.length ? `<div class="meta-note hot">⚠ 在野利用：${esc(s.kev_ids.slice(0, 8).join('、'))}</div>` : ''}
        <table class="tbl">
          <thead><tr><th>组件</th><th>版本</th><th>风险</th><th>CVE</th><th>最高CVSS</th><th>KEV</th><th>最高风险编号</th></tr></thead>
          <tbody>${rows || '<tr><td colspan="7">未命中已知 CVE</td></tr>'}</tbody>
        </table>
        <div class="as-form" style="margin-top:10px">
          <button class="btn ghost sm" id="pjMd">下载 Markdown 报告</button>
        </div>`;
      q('#pjMd').onclick = () => exportMd2(rep.id, rep.source);
    }

    function exportMd2(id, name) {
      fetch('/api/project_scan?id=' + encodeURIComponent(id) + '&md=1')
        .then((r) => r.blob())
        .then((b) => {
          const a = document.createElement('a');
          a.href = URL.createObjectURL(b);
          a.download = (name || '项目').replace(/\.[^.]+$/, '') + '_成分安全评估报告.md';
          document.body.appendChild(a); a.click(); a.remove();
          setTimeout(() => URL.revokeObjectURL(a.href), 4000);
        })
        .catch(() => toast('导出失败'));
    }

    function progHtml(txt, pct) {
      const p = q('#pjProg');
      p.style.display = '';
      p.innerHTML = `<div class="loading">${esc(txt)}${pct != null ? ' <b>' + pct + '%</b>' : ''}<span class="rspin"></span></div>`;
    }
    function progOff() { const p = q('#pjProg'); p.style.display = 'none'; p.innerHTML = ''; }
    function showErr(msg) {
      q('#pjOut').innerHTML = `<div class="empty"><div class="big">扫描失败</div>${esc(msg)}</div>`;
    }

    /* zip 二进制流式直传：application/octet-stream + X-Project-Name 头。
       用 XHR 而非 fetch —— 上传进度（xhr.upload.onprogress）只有 XHR 有；
       10GB 级上传没有进度条用户只会以为卡死。服务端 iter_body 边收边落盘。 */
    function uploadZip(f) {
      if (!/\.zip$/i.test(f.name)) { toast('请上传 .zip 包'); return; }
      if (f.size > MAX_ZIP) { toast('单包上限 10GB（当前 ' + (f.size / 1073741824).toFixed(2) + 'GB）'); return; }
      progHtml('上传中（流式直传，服务端边收边落盘）…', 0);
      const xhr = new XMLHttpRequest();
      xhr.open('POST', '/api/project_scan?name=' + encodeURIComponent(f.name));
      xhr.setRequestHeader('Content-Type', 'application/octet-stream');
      xhr.setRequestHeader('X-Project-Name', f.name);
      xhr.upload.onprogress = (e) => {
        if (e.lengthComputable) {
          const pct = Math.round((e.loaded / e.total) * 100);
          progHtml(e.loaded >= e.total ? '上传完成，服务端解析依赖并比对情报库…' : '上传中（流式直传）…', pct);
        }
      };
      xhr.onload = () => {
        let r = null;
        try { r = JSON.parse(xhr.responseText); } catch (_) {}
        progOff();
        if (!r || !r.ok) { showErr((r && r.error) || ('HTTP ' + xhr.status)); return; }
        renderRep(r);
      };
      xhr.onerror = () => { progOff(); showErr('网络中断（大包上传建议保持网络稳定后重试）'); };
      xhr.send(f);
    }

    /* 文件夹导入：只读依赖清单文本（与后端解析器同口径的白名单），
       POST files:[{path, content}] —— 目录里其余文件一个字节都不离开本机。 */
    async function uploadDir(files) {
      const picked = [];
      for (const f of files) {
        const path = (f.webkitRelativePath || f.name || '').replace(/\\/g, '/');
        if (!MANIFEST_RE.test(path)) continue;
        if (f.size > 2 * 1024 * 1024) continue;          // 清单文件都是小文本
        picked.push(f);
        if (picked.length >= 200) break;
      }
      if (!picked.length) { toast('该文件夹里没找到依赖清单（requirements.txt / package.json / pom.xml 等）'); return; }
      const rootName = (picked[0].webkitRelativePath || '').split('/')[0] || '文件夹导入';
      progHtml('读取 ' + picked.length + ' 个清单文件并比对情报库…');
      try {
        const payload = [];
        for (const f of picked) {
          const path = f.webkitRelativePath || f.name;
          payload.push({ path, content: await f.text() });
        }
        const r = await (await fetch('/api/project_scan', {
          method: 'POST', headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ name: rootName, files: payload }),
        })).json();
        progOff();
        if (!r || !r.ok) { showErr((r && r.error) || '扫描失败'); return; }
        renderRep(r);
      } catch (e) { progOff(); showErr(e.message || String(e)); }
    }

    function bind(el) {
      root = el;
      const file = q('#pjFile'), dir = q('#pjDir'), drop = q('#pjDrop');
      q('#pjDirBtn').onclick = () => dir.click();
      drop.onclick = (e) => { if (e.target === drop || e.target.closest('.en-drop-ic') || e.target.closest('.en-drop-t') || e.target.closest('.en-drop-s')) file.click(); };
      file.onchange = () => { if (file.files && file.files[0]) uploadZip(file.files[0]); file.value = ''; };
      dir.onchange = () => { if (dir.files && dir.files.length) uploadDir(Array.from(dir.files)); dir.value = ''; };
      ['dragenter', 'dragover'].forEach((ev) => drop.addEventListener(ev, (e) => { e.preventDefault(); drop.classList.add('drag'); }));
      ['dragleave', 'drop'].forEach((ev) => drop.addEventListener(ev, (e) => { e.preventDefault(); drop.classList.remove('drag'); }));
      drop.addEventListener('drop', (e) => {
        const fs = e.dataTransfer && e.dataTransfer.files;
        if (fs && fs.length) {
          if (fs.length === 1 && fs[0].name.toLowerCase().endsWith('.zip')) uploadZip(fs[0]);
          else uploadDir(Array.from(fs));
        }
      });
    }
    return { HTML, bind };
  })();

/* ---------------- 注册进主体 ---------------- */
AISEC.register({
  id: 'm2_enrich',
  name: '情报富化',
  /* 富化台视图里的模块区块（主体负责插进视图，模块负责内容与事件） */
  enrichSections() {
    return [
      {
        id: 'enAssetScan',
        html: ASCAN.HTML,
        mount: (el) => ASCAN.bind(el),
      },
      {
        id: 'enCmdb',
        html: ACMDB.HTML,
        mount: (el) => ACMDB.bind(el),
      },
      {
        id: 'enSurvey',
        html: ASURF.HTML,
        mount: (el) => ASURF.bind(el),
      },
      {
        id: 'enSubscribe',
        html: ASUB.HTML,
        mount: (el) => ASUB.bind(el),
      },
      {
        id: 'enStix',
        html: ASTIX.HTML,
        mount: (el) => ASTIX.bind(el),
      },
      {
        id: 'enPortScan',
        html: APORT.HTML,
        mount: (el) => APORT.bind(el),
      },
      {
        id: 'enProjectScan',
        html: APROJ.HTML,
        mount: (el) => APROJ.bind(el),
      },
    ];
  },
  detailSections(id, d, isVuln) {
    if (!isVuln) return null;                        // 只有漏洞条目才有资产 / POC
    return [
      {
        anchor: 'before-trust',                      // 落在「证据可信度」之前，与原合并版位置一致
        html: `<div class="sec"><h4>受影响资产定位（NVD 三路提取）</h4>
          <div id="assetsPanel"><div class="loading">正在提取受影响资产…</div></div></div>`,
        mount: (cid) => loadAssets(cid),
      },
      {
        anchor: 'before-trust',
        html: `<div class="sec"><h4>POC / EXP 搜索</h4><div id="pocPanel">
          <button class="btn ghost" id="pocQuick">⚡ 快速搜索</button>
          <button class="btn ghost" id="pocFull">🔍 完整搜索（含 GitHub，约数分钟）</button>
          <div id="pocOut" style="margin-top:10px"></div>
        </div></div>`,
        mount: (cid) => bindPocButtons(cid),
      },
      {
        anchor: 'before-trust',
        html: REMED.sectionHtml(),
        mount: (cid) => REMED.bind(cid),
      },
      {
        anchor: 'before-trust',
        html: TBOX.sectionHtml(),
        mount: (cid) => TBOX.bind(document.getElementById('tbox') || document.body, cid),
      },
    ];
  },
});
})();
