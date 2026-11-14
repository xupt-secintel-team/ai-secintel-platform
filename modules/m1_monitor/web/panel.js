/* ============================================================
   m1_monitor · 情报监测 —— 模块前端面板（负责人：成员A）
   ------------------------------------------------------------
   本文件是模块自己的前端，主体（core/web/app.js）不需要为它改一行：
   通过 AISEC.register 注册三个钩子 ——
     sideSections()  往左侧栏放「实时监测 · 最新情报」「多源归档」两张卡
     sideMounted()   卡片渲染完成后拉数据、绑按钮
     init()          绑「深度同步」按钮 + 起 30s 实时监测指示灯
   接口：/api/live · /api/sources · GET|POST /api/refresh
   ============================================================ */
(function () {
  // 主体 app.js 的全局能力（$ / esc / toast / S / openDetail / TYPE_META / renderTop …）
  // 是同一份全局脚本作用域，模块直接拿来用即可，不需要 import。
  /* ============================================================
     多源归档体量（/api/sources）：CVE/NVD · 安全社区 · 厂商公告 ·
     安全博客 · 学术论文 · 模型仓库 —— 原始数据仓库体量一览
     ============================================================ */
  async function loadSources(force) {
    const box = $('srcbody');
    if (!box) return;
    try {
      const d = await (await fetch('/api/sources' + (force ? '?_=' + Date.now() : ''))).json();
      const ch = d.channels || [];
      const pct = Math.min(100, Math.round((d.archive_total_gb || 0) / (d.target_gb || 10) * 100));
      box.innerHTML = `
        <div class="mini"><span>归档总量</span><span>${(d.archive_total_gb || 0).toFixed(2)} GB / ${d.target_gb} GB</span></div>
        <div class="bar" style="margin:6px 0 12px"><i style="width:${pct}%;background:linear-gradient(90deg,var(--accent),var(--accent-3))"></i></div>
        ${ch.map((c) => `
          <div style="margin-bottom:9px">
            <div class="mini"><span title="${esc(c.label)}">${esc(c.label.split('（')[0])}</span><span>${c.gb >= 0.01 ? c.gb.toFixed(2) + ' GB' : (c.bytes / 1024 / 1024).toFixed(1) + ' MB'}</span></div>
            <div class="bar"><i style="width:${Math.max(3, Math.round(c.bytes / Math.max(1, ch[0].bytes) * 100))}%"></i></div>
          </div>`).join('')}
        <div class="mini" style="margin-top:11px"><span>已入索引文档</span><span>${(d.corpus && d.corpus.documents || 0).toLocaleString()}</span></div>
        <div class="mini"><span>语料词项</span><span>${(d.corpus && d.corpus.terms || 0).toLocaleString()}</span></div>
        <div class="mini" style="opacity:.62"><span>仓库路径</span><span>${esc(d.archive_dir || '')}</span></div>
        ${(!ch.length && !(d.archive_total_gb || 0))
          ? `<div class="mini" style="opacity:.62"><span>状态</span><span title="本机没有这个目录：原始数据仓库未挂载">未挂载（不影响检索）</span></div>` : ''}`;
    } catch (e) {
      box.textContent = '归档信息加载失败';
    }
  }

  /* ============================================================
     RU —— 实时增量同步（情报监测模块 UI）
     POST /api/refresh 触发 → 轮询 /api/refresh 进度 → 完成后热刷新
     ============================================================ */
  const STAGE_CN = { init: '启动', live: '博客/社区源', kev: 'KEV 在野目录', nvd: 'NVD 增量',
    papers: 'arXiv 论文', github: 'GitHub', csdn: 'CSDN 文章', enrich: '富化', save: '落盘', done: '完成' };
  const RU = {
    timer: null, watch: null, sig: '',
    async status() { return (await fetch('/api/refresh')).json(); },
    render(st) {
      if (!st) return;
      const btn = $('refbtn'), stat = $('refstat'), fs = $('forcesync');
      if (!btn) return;
      const L = window.__AISEC_LOAD;      // v10：外壳提供的加载态组件（任务条）
      btn.classList.toggle('run', !!st.running);
      btn.disabled = !!st.running;
      if (fs) { fs.classList.toggle('run', !!st.running); fs.disabled = !!st.running; }
      /* 按钮锁定的悬停提示：同步进行中说明"为什么锁、锁到什么时候"；
         空闲时恢复成各自的功能说明。disabled 按钮仍会触发 hover，
         title 提示在锁住时也能看到。 */
      btn.title = '启动一次深度增量同步（全关键词 NVD / arXiv / GitHub / CSDN）';
      if (fs) fs.title = '强制同步所有数据源（中英文全量：快车道博客/社区 + NVD/KEV/arXiv/GitHub/CSDN）';
      if (st.running) {
        const sc = STAGE_CN[st.stage] || st.stage || '同步';
        const pct = Math.round(st.pct || 0);
        const lockWhy = `同步进行中（${sc} ${pct}%）—— ${st.detail || '后台正在拉取数据'}。`
          + '为避免重复同步互相打架，同步期间按钮暂时锁定，本轮跑完自动恢复（顶栏可见进度）';
        stat.innerHTML = `<span class="rspin"></span>${esc(sc)} ${pct}%`;
        stat.title = st.detail || '';
        btn.title = lockWhy;
        if (fs) fs.title = lockWhy;
        /* 同步进度是可量化的（后端给 pct + 阶段）→ 顶栏任务条走确定进度 */
        if (L) { L.Taskbar.show(); L.Taskbar.set(st.pct || 0, 100); }
        this.poll();
      } else if (st.error) {
        if (L) L.Taskbar.hide(400);
        stat.textContent = '同步失败';
        stat.title = st.error;
      } else if (st.last_sync) {
        if (L) L.Taskbar.hide(400);
        stat.textContent = '已同步 ' + String(st.last_sync).replace('T', ' ').slice(5, 16);
        stat.title = '上次增量同步：' + st.last_sync;
      } else {
        if (L) L.Taskbar.hide(400);
        stat.textContent = '';
      }
    },
    poll() {
      if (this.timer) return;
      this.timer = setInterval(async () => {
        const st = await this.status().catch(() => null);
        if (!st) return;
        this.render(st);
        if (!st.running) {
          clearInterval(this.timer); this.timer = null;
          this.done(st);
        }
      }, 1600);
    },
    async trigger(force) {
      if ($('refbtn').disabled || (force && $('forcesync') && $('forcesync').disabled)) return;
      const url = force ? '/api/force_sync' : '/api/refresh';
      try {
        const resp = await fetch(url, { method: 'POST' });
        if (resp.status === 409) {          // 已有同步在跑（启动补抓 / 定时 / 手动）→ 转入进度轮询
          /* 409 响应体带当前进度状态：把"现在在同步什么、到哪一步了"一并告诉用户 */
          const s = await resp.json().catch(() => null);
          const cur = s && s.status || {};
          const sc = STAGE_CN[cur.stage] || cur.stage || '';
          toast(`已有同步在跑${sc ? `（${sc} ${Math.round(cur.pct || 0)}%：${cur.detail || '请稍候'}）` : '，请稍候'}——顶栏可见进度`, 5000);
          this.poll();
          return;
        }
        if (!resp.ok) {
          /* 404 = 前端比后端新（force_sync 是新加的路由，旧进程里不存在）→ 引导重启服务 */
          toast(force ? '全源同步接口不可用（HTTP ' + resp.status + '）—— 这是新加的后端接口，请重启服务后重试'
                      : ('增量同步启动失败（HTTP ' + resp.status + '）'), 6000);
          return;
        }
        const r = await resp.json();
        if (r.started) {
          toast(force ? '已启动全源强制同步（中英全部数据源）…' : '已启动实时增量同步（8 源）…');
          this.render(r.status || { running: true, stage: 'live', pct: 0 });
        } else if (r.running) {
          toast('同步进行中，请稍候');
          this.poll();
        } else {
          toast('同步接口响应异常（' + (r.error || '未知错误') + '）—— 请重启服务后重试', 6000);
        }
      } catch (e) { toast('启动失败：' + e.message, 5000); }
    },
    done(st) {
      if (st.error) { toast('同步失败：' + st.error, 5000); return; }
      const s = st.summary || {};
      const parts = [];
      if (s.live_added) parts.push(`博客/社区 +${s.live_added}`);
      if (s.nvd_new) parts.push(`新漏洞 +${s.nvd_new}`);
      if (s.kev_new) parts.push(`在野利用 +${s.kev_new}`);
      if (s.papers_new) parts.push(`论文 +${s.papers_new}`);
      if (s.articles_new) parts.push(`文章 +${s.articles_new}`);
      if (s.repos_new) parts.push(`工具仓库 +${s.repos_new}`);
      if (s.advisories_new) parts.push(`供应链公告 +${s.advisories_new}`);
      if (s.nvd_updated) parts.push(`更新 ${s.nvd_updated} 条`);
      toast('⟳ 实时同步完成' + (parts.length ? '：' + parts.join(' / ') : '（本轮无新增）'), 6500);
      this.reload();
    },
    async reload() {
      try {
        S.stats = await (await fetch('/api/stats')).json();
        renderTop(); renderSide();
      } catch (e) {}
      this.loadLatest();
      doSearch(false);
      // 用户正停在监测台时，把大盘也一并热刷新（旧版只刷侧栏和检索，监测台要切走再切回才更新）
      if (S.view === 'monitor' && typeof renderMonitor === 'function') renderMonitor();
    },
    async loadLatest() {
      const body = $('latestbody');
      if (!body) return;
      try {
        const d = await (await fetch('/api/latest?n=9')).json();
        const t = TYPE_META;
        const items = d.items || [];
        /* ★ v11（A4）：实时流此前"说出现就出现"，实时感弱。
           这里记住上一轮已显示的 id，只给**真正新增**的行播插入动画
           （整表重绘不重放动画 —— 15s 一轮，全量闪一次会很吵）。 */
        const prevIds = this._ids;
        this._ids = new Set(items.map((x) => x.id));
        const fresh = prevIds ? new Set(items.filter((x) => !prevIds.has(x.id)).map((x) => x.id)) : null;
        body.innerHTML = items.map((x, xi) => {
          const m = t[x.type] || {};
          const sev = x.severity === 'CRITICAL' || x.severity === 'HIGH';
          /* 标题**不再在 JS 里 slice**：侧栏本来就窄，再砍一刀就只剩
             "Prompt Injec…" 这种连语义都读不出来的残片（用户截图反馈）。
             完整标题靠 CSS ellipsis 截断 + title 悬停提示，
             点击任意行打开右侧检查器看全文。
             ★ 标题必须**独占一个纵向容器 .latmain**（别把这层壳删掉"简化"）：
             翻译块是 TR 用 el.after() 插进来的**兄弟节点**，而 .lat 是不换行的
             flex 行 —— 译文块一旦成为并列 flex item，就会和日期/徽章/标题抢同一条
             横向空间：标题被压成竖排窄条、整行撑出横向滚动条（用户截图反馈）。 */
          const ttl = (x.title || x.id || '').slice(0, 120);
          const isFresh = fresh && fresh.has(x.id);
          return `<div class="lat${isFresh ? ' lat-new' : ''}" data-id="${esc(x.id)}"${isFresh ? ` style="--i:${xi}"` : ''} title="${esc(ttl)}&#10;点击查看完整内容">
            <span class="latd">${esc(x.published || x.modified || '—')}</span>
            ${m.idc ? `<span class="badge" style="color:${m.fg};border-color:${m.bd};background:${m.bg}">${m.tag}</span>` : ''}
            ${x.is_new ? '<span class="badge newb">新</span>' : ''}
            ${x.exploited ? '<span class="badge" style="color:var(--danger,#ff6369);border-color:rgba(255,90,82,.42);background:rgba(255,90,82,.12)">在野</span>' : ''}
            <span class="latmain"><span class="latt ${sev ? 'hot' : ''}">${esc(ttl)}</span></span>
            ${x.cvss ? `<span class="latc">${x.cvss}</span>` : ''}
          </div>`;
        }).join('');
        body.querySelectorAll('.lat').forEach((el) => { el.onclick = () => openDetail(el.dataset.id); });
        /* 这里**不再**调 TR.applyView('最新情报')（2026-10-07 去掉，用户要求）。
           侧栏太窄，翻出来的译文块会把每条撑成两行、9 条就占满整屏；
           而且条目本来就是"扫一眼"的，点一下右侧会开详情、详情里全翻。
           ★ 但 .latmain 这层壳**留着别删**（注释里那句话仍然成立）：
           万一以后有人把 '#latestbody .latt' 加回 TR.SEL，译文块会成为
           .lat 的并列 flex item，标题会被压成竖排一条、整行撑出横向滚动条。
           有这层壳，译文块就落在标题下方的纵向容器里，挤不坏布局。 */
      } catch (e) { body.textContent = '最新情报加载失败'; }
    },
    async init() {
      const st = await this.status().catch(() => null);
      if (st) { this.sig = (st.last_sync || '') + '|' + (st.finished_at || ''); this.render(st); }
      // 周期巡检：服务端定时自动同步完成后，前端无感热刷新
      this.watch = setInterval(async () => {
        if (document.hidden || this.timer) return;
        const st = await this.status().catch(() => null);
        if (!st) return;
        const sig = (st.last_sync || '') + '|' + (st.finished_at || '');
        if (st.running) { this.render(st); return; }
        if (sig !== this.sig) {
          this.sig = sig;
          this.render(st);
          this.done(st);
        }
      }, 120000);
    },
  };

  /* ============================================================
     LV —— 快车道实时监测（live.py：30s/轮，新信息 1 分钟内可见）
     前端每 30s 取一次 /api/live：刷新指示灯；一旦有新条目入索引，
     自动无感热刷新最新情报流与统计。
     ============================================================ */
  const LV = {
    timer: null, lastTotal: 0, lastTs: 0, first: true,
    async status() { return (await fetch('/api/live')).json(); },
    fmtAge(s) {
      if (s == null) return '—';
      if (s < 60) return s + 's';
      if (s < 3600) return Math.floor(s / 60) + 'm' + (s % 60) + 's';
      return Math.floor(s / 3600) + 'h';
    },
    render(d) {
      const wrap = $('livewrap'), txt = $('livestat');
      if (!wrap || !txt) return;
      if (!d || !d.enabled) {
        wrap.className = 'livewrap off';
        txt.textContent = '实时监测未启用';
        return;
      }
      const age = d.age_sec;
      const iv = d.interval || 30;
      const stale = age == null || age > Math.max(120, iv * 4);
      wrap.className = 'livewrap' + (stale ? ' stale' : '');
      const srcs = d.per_source || {};
      const nz = Object.keys(srcs).filter((k) => srcs[k] > 0)
        .map((k) => k + '+' + srcs[k]).join(' ');
      txt.textContent = `实时监测 ${iv}s · ${this.fmtAge(age)}前 · ${d.last_ms || 0}ms`
        + (nz ? ' · ' + nz : '')
        + (d.feed_total ? ` · 源 ${d.feed_ok || 0}/${d.feed_total}` : '')
        + (d.added_total ? ` · 已入索引 ${d.added_total}` : '');
      wrap.title = `快车道每 ${iv}s 一轮；新信息公开后约 1 分钟内可见。`
        + `\n最近一轮：${d.last_poll || '—'}（${d.last_ms || 0}ms，新增 ${d.last_batch || 0} 条）`
        + `\n累计入索引：${d.added_total || 0} 条`
        + (d.feed_total ? `\n情报源健康度：成功 ${d.feed_ok || 0} / ${d.feed_total}`
            + (d.feed_fail && Object.keys(d.feed_fail).length
               ? `\n未盯上的源（多为境外站点）：${Object.keys(d.feed_fail).slice(0, 8).join('、')}`
                 + `\n→ 本机开代理后重启（启动服务.bat 会自动探测 7890/7897）即可恢复`
               : '') : '')
        + (d.error ? `\n最近错误：${d.error}` : '');
    },
    async tick() {
      let d = null;
      try { d = await this.status(); } catch (e) { return; }
      if (!d) return;
      this.render(d);
      const total = d.added_total || 0;
      if (this.first) { this.lastTotal = total; this.first = false; return; }
      if (total > this.lastTotal) {
        const n = total - this.lastTotal;
        this.lastTotal = total;
        const r = d.recent && d.recent[0];
        toast(`⚡ 实时情报 +${n} 条` + (r ? `：${(r.title || r.id).slice(0, 34)}` : ''), 5200);
        RU.reload();
      }
    },
    init() {
      this.tick();
      this.timer = setInterval(() => { if (!document.hidden) this.tick(); }, 30000);
    },
  };


  /* ============================================================
     TS —— 高频漏洞周期统计（周/月/年，横向条形图 + 报告）
     GET /api/trend_stats?period=weekly|monthly|yearly
     2026-10-08 改版：从左侧窄栏迁到监测台主区（占整行宽度），
     图表改横向条形（左标签 + 中横条 + 右数值），对齐「风险分类分布」风格。
     ============================================================ */
  const TS = {
    period: 'weekly',
    HTML: `
      <div class="panel mo-trend">
        <header>高频漏洞统计
          <span class="ph-sub">周 / 月 / 年 · 按漏洞发布日期 · AI 四分类 / CWE / 产品 / 高危 CVE 榜</span>
          <span class="mo-trend-acts">
            <button class="tr-tab" data-period="weekly">周</button>
            <button class="tr-tab" data-period="monthly">月</button>
            <button class="tr-tab" data-period="yearly">年</button>
            <button id="trMd" class="mo-dl" title="下载该周期 Markdown 报告">导出报告</button>
          </span>
        </header>
        <div class="pbody" id="trendbox"><div class="latload">载入中…</div></div>
      </div>`,
    mount(root) {
      const box = root.querySelector('#trendbox');
      root.querySelectorAll('[data-period]').forEach((b) => {
        b.onclick = () => { TS.period = b.dataset.period; TS.load(); };
      });
      const mdb = root.querySelector('#trMd');
      if (mdb) mdb.onclick = () => TS.exportMd(TS._last);
      TS.load();
    },
    async load() {
      const wrap = $('trendbox');
      if (!wrap) return;
      // 高亮当前周期按钮
      document.querySelectorAll('.mo-trend [data-period]').forEach((b) =>
        b.classList.toggle('on', b.dataset.period === TS.period));
      try {
        const d = await (await fetch('/api/trend_stats?period=' + TS.period)).json();
        TS._last = d;
        TS.render(wrap, d);
      } catch (e) { wrap.innerHTML = '<div class="latload">加载失败</div>'; }
    },
    render(wrap, d) {
      if (!d || d.error) { wrap.innerHTML = `<div class="latload">${esc((d && d.error) || '加载失败')}</div>`; return; }
      const topCwe = d.top_cwe || [];
      const topProd = d.top_product || [];
      const topCve = d.top_cve || [];
      const sev = TS.sevBar(d.by_severity || []);
      const aiRisk = TS.aiRiskSvg(d.by_ai_risk || [], d.total_entries);

      // 横向条形：高频弱点类型（TOP 10，条长按 count 归一）
      const cweBars = TS.hbars(topCwe.slice(0, 10), (t) => t.cwe, (t) => t.count,
        (t) => `点击查看 ${esc(t.cwe)} 关联漏洞`, true, 'cwe');
      // 横向条形：高频受影响产品（TOP 10）
      const prodBars = TS.hbars(topProd.slice(0, 10), (t) => t.product, (t) => t.count,
        (t) => `受影响产品 ${esc(t.product)}`, false, '');
      // 横向条形：高危 CVE 榜（TOP 10，条长按 CVSS 归一，红色系）
      const cveBars = TS.hbars(topCve.slice(0, 10), (t) => t.cve, (t) => t.cvss || 0,
        (t) => `${esc(t.cve)} · CVSS ${esc(t.cvss != null ? t.cvss : '—')} · ${esc(t.title || '')}`,
        false, 'cve', true);

      wrap.innerHTML = `
        <div class="tr-range">${esc(d.start)} ~ ${esc(d.end)} · 窗口内新发漏洞 ${d.total_cves} 个 · 在野利用 ${d.kev_count} 个 · 按发布日期统计</div>
        ${aiRisk}
        ${sev}
        <div class="tr-grid">
          <div class="tr-col">
            <div class="tr-chart-ttl">高频弱点类型（CWE）TOP 10</div>
            ${cweBars || '<div class="latload">窗口内无 CWE 记录</div>'}
          </div>
          <div class="tr-col">
            <div class="tr-chart-ttl">高频受影响产品 TOP 10</div>
            ${prodBars || '<div class="latload">窗口内无产品记录</div>'}
          </div>
        </div>
        <div class="tr-chart-ttl">高危 CVE 榜 TOP 10（按 CVSS）</div>
        ${cveBars || '<div class="latload">窗口内无 CVE 记录</div>'}`;

      wrap.querySelectorAll('.tr-hbar[data-id]').forEach((el) => {
        el.onclick = () => openDetail(el.dataset.id);
      });
      // 动画：横条宽度从 0 涨到目标
      requestAnimationFrame(() => {
        wrap.querySelectorAll('.tr-fill').forEach((b) => {
          b.style.width = b.dataset.w + '%';
          delete b.dataset.w;
        });
      });
    },
    /* AI 安全风险四分类：垂直柱状图（柱顶标数值，口径=语料 category 字段） */
    aiRiskSvg(byAi, totalEntries) {
      if (!byAi || !byAi.length) return '';
      // 与 daily_digest 方向卡同一组强调色（①紫 ②青 ③绿 ④琥珀），通用桶灰色
      const colors = ['#e3b04b', '#2fbf9e', '#e8913c', '#f2c94c', '#62666d'];
      const w = 640, h = 190, padT = 26, padB = 40, padX = 14;
      const max = Math.max(1, ...byAi.map((x) => x.count || 0));
      const n = byAi.length;
      const slot = (w - padX * 2) / n;
      const bw = Math.min(64, Math.round(slot * 0.52));
      const bars = byAi.map((x, i) => {
        const cnt = x.count || 0;
        const bh = Math.max(2, Math.round((h - padT - padB) * cnt / max));
        const cx = padX + slot * i + slot / 2;
        const bx = cx - bw / 2;
        const by = h - padB - bh;
        const lines = String(x.short || x.category || '').split('\n');
        const labels = lines.map((ln, j) =>
          `<text x="${cx}" y="${h - padB + 15 + j * 12}" font-size="9.5" fill="var(--txt-3,#8a8f98)" text-anchor="middle">${esc(ln)}</text>`).join('');
        return `<rect x="${bx}" y="${by}" width="${bw}" height="${bh}" rx="3" fill="${colors[i % colors.length]}"><title>${esc(x.category)}：${cnt} 个</title></rect>`
          + `<text x="${cx}" y="${by - 6}" font-size="11.5" font-weight="600" fill="var(--txt,#f7f8f8)" text-anchor="middle">${cnt.toLocaleString()}</text>`
          + labels;
      }).join('');
      const axis = `<line x1="${padX}" y1="${h - padB}" x2="${w - padX}" y2="${h - padB}" stroke="var(--line,#23262b)" stroke-width="1"/>`;
      const ttl = totalEntries != null
        ? `AI 安全风险四分类分布（窗口内情报条目 ${(+totalEntries).toLocaleString()} 条：漏洞+文章+论文，按发布日期）`
        : 'AI 安全风险四分类分布（柱顶为窗口内新发漏洞数）';
      return `<div class="tr-chart">
        <div class="tr-chart-ttl">${ttl}</div>
        <svg viewBox="0 0 ${w} ${h}" preserveAspectRatio="xMidYMid meet" style="width:100%;height:auto">${axis}${bars}</svg>
      </div>`;
    },
    /* 横向条形图：左标签 + 中横条（宽度按 value 归一）+ 右数值 */
    hbars(items, labelFn, valFn, titleFn, clickable, kind, isCve) {
      if (!items.length) return '';
      const max = Math.max(1, ...items.map((t) => valFn(t) || 0));
      const fillCls = isCve ? 'tr-fill tr-fill-cve' : 'tr-fill';
      return items.map((t, i) => {
        const v = valFn(t) || 0;
        const w = Math.max(2, Math.round(v / max * 100));
        const cve = isCve ? t.cve : (kind === 'cwe' ? t.cwe : '');
        const tail = isCve
          ? `<span class="tr-val tr-cvss">${esc(t.cvss != null ? t.cvss : '—')}</span>`
          : `<span class="tr-val">${v}</span>`;
        const flag = isCve && t.kev ? '<span class="tr-kev">KEV</span>' : '';
        return `<div class="tr-hbar" ${clickable && cve ? `data-id="${esc(cve)}"` : ''} title="${titleFn(t)}">
          <span class="tr-lbl">${esc(labelFn(t))}${flag}</span>
          <span class="tr-bar"><i class="${fillCls}" data-w="${w}"></i></span>
          ${tail}
        </div>`;
      }).join('');
    },
    /* 严重度分布条（沿用原分色段条） */
    sevBar(bySev) {
      if (!bySev.length) return '';
      const total = bySev.reduce((a, s) => a + s.count, 0) || 1;
      const colors = { CRITICAL: '#ff5a52', HIGH: '#f0a72e', MEDIUM: '#e3b04b', LOW: '#4acc8a', UNKNOWN: '#968e79' };
      const segs = bySev.map((s) => {
        const w = Math.max(0, Math.round(s.count / total * 100));
        return `<span class="tr-seg" style="width:${w}%;background:${colors[s.severity] || '#62666d'}" title="${esc(s.label)}：${s.count}"></span>`;
      }).join('');
      const legend = bySev.map((s) => `<span class="tr-leg"><i style="background:${colors[s.severity] || '#62666d'}"></i>${esc(s.label)} ${s.count}</span>`).join('');
      return `<div class="tr-chart">
        <div class="tr-chart-ttl">严重度分布</div>
        <div class="tr-segbar">${segs}</div>
        <div class="tr-legwrap">${legend}</div>
      </div>`;
    },
    exportMd(d) {
      fetch('/api/trend_stats?period=' + TS.period + '&md=1')
        .then((r) => r.blob())
        .then((b) => {
          const a = document.createElement('a');
          a.href = URL.createObjectURL(b);
          a.download = '高频漏洞' + (d ? d.label : '') + '_' + TS.period + '.md';
          document.body.appendChild(a); a.click(); a.remove();
          setTimeout(() => URL.revokeObjectURL(a.href), 4000);
        })
        .catch(() => toast('导出失败'));
    },
  };


/* ---------------- 注册进主体 ---------------- */
AISEC.register({
  id: 'm1_monitor',
  name: '情报监测',

  /* 左侧栏卡片（anchor：top 顶部 / after-corpus 语料构成之后） */
  sideSections() {
    return [
      {
        anchor: 'top',
        html: `<div class="card">
          <h3>实时监测 · 最新情报 <button id="latgo" title="按最新优先浏览全部">全部</button></h3>
          <div class="body" id="latestbody"><div class="latload">载入中…</div></div>
        </div>`,
      },
      {
        anchor: 'after-corpus',
        html: `<div class="card">
          <h3>多源归档 <button id="srcgo" title="查看各渠道归档体量">刷新</button></h3>
          <div class="body" id="srcbody"><div class="latload">载入中…</div></div>
        </div>`,
      },
    ];
  },

  /* 监测台主区宽卡（占主区整行宽度，横向条形图） */
  monitorSections() {
    return [{ id: 'moTrendStats', html: TS.HTML, mount: (el) => TS.mount(el) }];
  },

  /* 卡片渲染完成后：拉最新情报 + 归档体量，绑刷新按钮 */
  sideMounted(root) {
    RU.loadLatest();
    loadSources();
    const go = root.querySelector('#srcgo');
    if (go) go.onclick = () => loadSources(true);
  },

  init() {
    const btn = document.getElementById('refbtn');
    if (btn) btn.onclick = () => RU.trigger();      // 顶栏「深度同步」
    const fs = document.getElementById('forcesync');
    if (fs) fs.onclick = () => RU.trigger(true);    // 检索区「全源同步」
    RU.init();
    LV.init();                                       // 30s 实时监测指示灯
    this.initProxy();                                // 出网代理设置（检索区「代理」按钮）
  },

  /* 出网代理：读当前值 / 展开面板 / 保存（POST /api/config/proxy，实时生效） */
  initProxy() {
    const pset = document.getElementById('proxyset');
    const panel = document.getElementById('proxypanel');
    if (!pset || !panel) return;
    const input = document.getElementById('proxyin');
    const save = document.getElementById('proxysave');
    const hint = document.getElementById('proxyhint');
    const setHint = (t, ok) => { hint.textContent = t || ''; hint.style.color = ok ? 'var(--accent-2)' : 'var(--txt-4)'; };
    pset.onclick = async () => {
      const show = panel.style.display === 'none';
      panel.style.display = show ? 'flex' : 'none';
      if (!show) return;
      try {
        const r = await (await fetch('/api/config/proxy')).json();
        input.value = r.proxy || '';
        setHint(r.proxy ? `当前：${r.proxy}` : '未设置（将自动探测）', true);
      } catch (e) { setHint('读取失败', false); }
    };
    save.onclick = async () => {
      const val = input.value.trim();
      try {
        const r = await (await fetch('/api/config/proxy', {
          method: 'POST', headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ proxy: val })
        })).json();
        if (r.ok) {
          setHint(val ? `已保存并生效：${r.proxy}` : '已清除，回到自动探测', true);
          toast(val ? '代理已生效：' + r.proxy : '已清除代理，回到自动探测');
        } else {
          setHint('保存失败：' + (r.error || '未知'), false);
        }
      } catch (e) { setHint('保存失败：' + e.message, false); }
    };
  },
});
})();
