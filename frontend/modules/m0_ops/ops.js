// web/ops.js
// ⚠ 自动生成，请勿直接改本文件 —— 源文件在 modules/m0_ops/web/ops.js
//   改完跑一次： py -3 tools/组装前端.py
/* ops.js —— m0_ops「多智能体编排」前端面板
 *
 * 给评委/用户看多 Agent 协作全过程的窗口：
 *   感知智能体（盯实时情报流）→ 编排智能体（优先级/限流分派）
 *   → 富化执行智能体（资产定位 + POC）→ 研判智能体（结构化简报）
 *
 * 数据全部来自本模块后端：
 *   GET  /api/ops/status  四个智能体与节拍阈值
 *   GET  /api/ops/trace   协作留痕（谁、何时、做了什么、成败、耗时）
 *   GET  /api/ops/briefs  产出的处置简报
 *   POST /api/ops/scan_now 人工触发一轮编排（演示用）
 *
 * 通过 AISEC.register({enrichSections}) 挂进「情报富化台」（最后一个区块）。
 */
(() => {
  const AGENTS = [
    { key: 'perception',      cls: 'a', name: '感知智能体',   role: '盯实时情报流，发现 KEV / CVSS≥9 新事件' },
    { key: 'orchestrator',    cls: 'b', name: '编排智能体',   role: '定优先级、限流分派、跨实例去重' },
    { key: 'enrich_executor', cls: 'c', name: '富化执行智能体', role: '自动拉受影响资产版本 + POC 线索' },
    { key: 'brief_analyst',   cls: 'd', name: '研判智能体',   role: '生成结构化处置简报（LLM/模板双模式）' },
    { key: 'decision',        cls: 'e', name: '决策智能体',   role: '综合五维信号产出 P0/P1/P2 可执行处置决策' },
    { key: 'challenger',      cls: 'f', name: '质疑智能体',   role: '红蓝自博弈：攻击者视角挑战决策，产出更稳结论' },
  ];

  function agentLast(trace, key) {
    const hit = (trace || []).find((r) => r && r.agent === key);
    if (!hit) return { text: '待命 — 尚无本轮动作', fail: false };
    return { text: hit.action + (hit.detail ? ' · ' + hit.detail : ''), fail: hit.ok === false };
  }

  function statusHtml() {
    const cards = AGENTS.map((a) => `
      <div class="ops-agent is-idle" data-ag="${a.key}">
        <i class="ops-dot"></i>
        <b>${a.name}</b>
        <div class="ops-role">${a.role}</div>
        <div class="ops-last">加载中…</div>
      </div>`).join('');
    return `
    <div class="panel as-bar">
      <header>多智能体编排 · 事件驱动处置
        <span class="asub-status" id="opsStat"></span></header>
      <div class="pbody">
        <div class="ops-runbar" id="opsRun"></div>
        <div class="ops-agents">${cards}</div>
        <div class="ops-cols">
          <div>
            <div class="ops-t">协作留痕（谁在何时做了什么）<small>GET /api/ops/trace</small></div>
            <div class="ops-trace" id="opsTrace"><div class="meta-note">…</div></div>
          </div>
          <div>
            <div class="ops-t">自动产出的处置简报<small>GET /api/ops/briefs</small></div>
            <div class="ops-briefs" id="opsBriefs"><div class="meta-note">…</div></div>
          </div>
        </div>
        <details class="ops-fold" style="margin-top:11px">
          <summary class="ops-t">基础设施指标与阈值告警<small>GET /api/metrics</small></summary>
          <div class="ops-metrics" id="opsMetrics"><div class="meta-note">加载中…</div></div>
        </details>
        <details class="ops-fold" style="margin-top:11px">
          <summary class="ops-t">处置决策卡（决策智能体 · P0/P1/P2 · 可解释）<small>GET /api/ops/decisions</small></summary>
          <div class="ops-decisions" id="opsDecisions"><div class="meta-note">…</div></div>
        </details>
        <details class="ops-fold" style="margin-top:11px">
          <summary class="ops-t">处置闭环 · 回填记忆库（越用越聪明）<small>POST /api/ops/disposition</small></summary>
          <div class="ops-memory" id="opsMemory"><div class="meta-note">…</div></div>
        </details>
        <div class="ops-runbar" style="margin-top:11px">
          <button class="btn" id="opsScan">▶ 立即编排一轮</button>
          <span id="opsScanOut" class="meta-note" style="margin:0">后台守护线程按节拍自动巡检；演示时可手动触发一轮看全程留痕</span>
          <span class="ops-sp"></span>
          <input class="as-in" id="opsDecideId" placeholder="CVE-2025-63389" style="flex:0 1 200px" title="输入一个 CVE，现场走一遍富化→简报→决策全链路">
          <button class="btn" id="opsDecideNow">⚡ 现场决策演示</button>
        </div>
      </div>
    </div>`;
  }

  async function refresh(root) {
    const run = root.querySelector('#opsRun');
    const stat = root.querySelector('#opsStat');
    const mtBox = root.querySelector('#opsMetrics');
    const traceBox = root.querySelector('#opsTrace');
    const briefBox = root.querySelector('#opsBriefs');
    const decBox = root.querySelector('#opsDecisions');
    const memBox = root.querySelector('#opsMemory');
    const [st, tr, bf, dc, mem, mt] = await Promise.all([
      fetch('/api/ops/status').then((r) => r.json()).catch(() => null),
      fetch('/api/ops/trace?n=30').then((r) => r.json()).catch(() => null),
      fetch('/api/ops/briefs?n=6').then((r) => r.json()).catch(() => null),
      fetch('/api/ops/decisions?n=6').then((r) => r.json()).catch(() => null),
      fetch('/api/ops/disposition/stats').then((r) => r.json()).catch(() => null),
      fetch('/api/metrics').then((r) => r.json()).catch(() => null),
    ]);

    /* 基础设施指标与告警 */
    if (mtBox) {
      if (mt && mt.ts) {
        const lvl = mt.alert_level || 'ok';
        const badges = { ok: '全绿', warn: '有告警', critical: '严重' };
        const alerts = (mt.alerts || []).map((a) => `
          <div class="ops-mt-alert is-${esc(a.level || 'warn')}">
            <span class="ops-mt-lv">${esc(a.level || '')}</span>
            <span class="ops-mt-msg">${esc(a.msg || '')}</span>
            <span class="ops-mt-adv">${esc(a.advice || '')}</span>
          </div>`).join('');
        const p = mt.process || {}, dk = mt.disk || {}, fd = mt.feed || {},
              ht = mt.http || {}, lg = mt.logs || {};
        const pct = dk.free_pct == null ? null : Number(dk.free_pct);
        const freeCls = pct == null ? '' : (pct < 5 ? 'is-crit' : pct < 10 ? 'is-warn' : 'is-ok');
        const tiles = [
          ['磁盘剩余', pct == null ? '—' : pct.toFixed(1) + '%', freeCls],
          ['进程内存', p.rss_mb == null ? '—' : Number(p.rss_mb).toFixed(0) + ' MB',
            p.rss_mb == null ? '' : (p.rss_mb > 2048 ? 'is-warn' : 'is-ok')],
          ['实时流', fd.last_poll_age_sec == null ? '—'
            : (fd.last_poll_age_sec > 180 ? '（已停更 ' + Number(fd.last_poll_age_sec).toFixed(0) + 's）'
              : Number(fd.last_poll_age_sec).toFixed(0) + 's 前'),
            fd.thread_alive === false ? 'is-crit' : 'is-ok'],
          ['采集源', fd.feed_ok == null ? '—' : fd.feed_ok + ' 个成功'
            + (fd.feed_fail_count ? ' / ' + fd.feed_fail_count + ' 失败' : ''),
            fd.feed_fail_count ? 'is-warn' : 'is-ok'],
          ['请求 P95', ht.p95_ms == null ? '—' : Number(ht.p95_ms).toFixed(0) + ' ms',
            ht.p95_ms > 8000 ? 'is-warn' : 'is-ok'],
          ['错误率', ht.requests == null ? '—'
            : Number(ht.err_rate_pct || 0).toFixed(1) + '%（' + (ht.errors || 0) + '/' + (ht.requests || 0) + '）',
            ht.err_rate_pct > 5 ? 'is-warn' : 'is-ok'],
          ['日志占用', lg.total_human || '—',
            lg.over_limit_count ? 'is-warn' : 'is-ok'],
          ['运行时长', mt.uptime_sec == null ? '—' : Number(mt.uptime_sec).toFixed(0) + ' s', ''],
        ];
        mtBox.innerHTML = `
          <div class="ops-mt-head">
            <span class="ops-mt-badge is-${esc(lvl)}">${esc(badges[lvl] || lvl)}</span>
            <span class="meta-note" style="margin:0">采样于 ${esc(mt.ts)} · PID ${esc(mt.pid)} · Python ${esc(mt.python || '')}</span>
          </div>
          <div class="ops-mt-tiles">
            ${tiles.map((t) => `<div class="ops-mt-tile ${t[2]}">
              <span class="ops-mt-k">${esc(t[0])}</span><span class="ops-mt-v">${esc(t[1])}</span>
            </div>`).join('')}
          </div>
          ${alerts ? '<div class="ops-mt-alerts">' + alerts + '</div>'
            : '<div class="meta-note">全部指标在阈值内 —— 磁盘、内存、实时流、请求时延、日志占用均正常</div>'}`;
      } else if (mtBox) {
        mtBox.innerHTML = '<div class="meta-note">指标接口不可用（core/server.py 未启用 metrics 模块）</div>';
      }
    }

    /* 运行条 */
    if (st && st.agents) {
      const on = !!st.running;
      run.innerHTML = `<span class="${on ? 'ops-run-on' : 'ops-run-off'}">● ${on ? '编排器运行中' : '编排器未运行'}</span>
        <span>节拍 <b>${st.interval_sec}s</b>/轮</span>
        <span>触发条件 <b>KEV 或 CVSS≥${st.high_cvss_threshold}</b></span>
        <span>单轮限流 <b>${st.max_per_cycle}</b> 事件</span>
        <span>已去重事件 <b>${st.seen_ids}</b></span>
        <span>最近一轮 <b>${esc(String(st.last_cycle || '—'))}</b></span>`;
      stat.innerHTML = `<span>${st.agents.length} 个智能体</span>` + (on ? '<span>自动巡检</span>' : '');
      root.querySelectorAll('.ops-agent').forEach((el) => el.classList.remove('is-idle'));
    } else {
      run.innerHTML = '<span class="ops-run-off">● 编排器接口不可用（模块未启用）</span>';
    }

    /* 智能体卡最近动作 */
    const trace = (tr && tr.trace) || [];
    AGENTS.forEach((a) => {
      const el = root.querySelector(`.ops-agent[data-ag="${a.key}"]`);
      if (!el) return;
      const last = agentLast(trace, a.key);
      el.querySelector('.ops-last').innerHTML =
        `<span class="${last.fail ? 'ops-fail' : ''}">${esc(last.text)}</span>`;
    });

    /* trace 时间线 */
    traceBox.innerHTML = trace.length
      ? trace.slice(0, 14).map((r) => {
          const ag = AGENTS.find((x) => x.key === r.agent);
          const cls = ag ? ('ops-ag-' + ag.cls) : '';
          const label = ag ? ag.name : String(r.agent || '?');
          return `<div class="ops-row" title="${esc(r.detail || '')}">
            <span class="ops-time">${esc(r.t || '')}</span>
            <span class="ops-ag ${cls}">${esc(label)}</span>
            <span class="ops-act">${esc(r.action || '')}${r.detail ? ' · ' + esc(r.detail) : ''}</span>
            <span class="${r.ok === false ? 'ops-no' : 'ops-ok'}">${r.ok === false ? '✗' : '✓'}</span>
            <span class="ops-ms">${r.ms ? Number(r.ms).toFixed(0) + 'ms' : ''}</span>
          </div>`;
        }).join('')
      : '<div class="meta-note">暂无留痕 —— 点「立即编排一轮」看四个智能体的完整协作过程</div>';

    /* 简报 */
    const briefs = (bf && bf.briefs) || [];
    briefBox.innerHTML = briefs.length
      ? briefs.map((b) => {
          const ev = b.event || {};
          return `<div class="ops-brief">
            <span class="ops-bid">${esc(String(ev.id || '?'))}</span>
            <span class="ops-bmeta">CVSS ${ev.cvss == null ? '—' : ev.cvss}${ev.kev ? ' · KEV 在野利用' : ''} · ${esc(String(b.ts || ''))}${b.brief_mode === 'llm' ? ' · LLM' : ' · 模板'}</span>
            <div class="ops-btext">${esc(String(b.brief || ''))}</div>
          </div>`;
        }).join('')
      : '<div class="meta-note">暂无简报 —— 编排器发现 KEV / 高危事件后自动产出</div>';

    briefBox.querySelectorAll('.ops-brief').forEach((el) => {
      el.onclick = () => el.classList.toggle('open');
    });

    /* 处置决策卡（含 XAI 推理链 + 处置回填） */
    const decisions = (dc && dc.decisions) || [];
    decBox.innerHTML = decisions.length
      ? decisions.map((d) => {
          const pri = (d.priority || '').toUpperCase();
          const priCls = pri === 'P0' ? 'ops-p0' : (pri === 'P1' ? 'ops-p1' : 'ops-p2');
          const sig = d.signals || {};
          const actions = (d.actions || []).map((a, i) =>
            `<div class="ops-act-row"><b>${i + 1}. ${esc(a.step || '')}</b>${a.component ? ' <code>' + esc(a.component) + '</code>' : ''} — ${esc(a.target || '')}</div>`).join('');
          const verify = (d.verify || []).map((v) => `<div class="ops-verify-row">✓ ${esc(v)}</div>`).join('');
          // XAI 推理链：哪条规则 → 什么结论
          const reasoning = (d.reasoning || []).map((r) =>
            `<div class="ops-reason"><span class="ops-reason-rule">${esc(r.rule || '')}</span>
              <span class="ops-reason-ev">证据：${esc(r.evidence || '')}</span>
              <span class="ops-reason-concl">→ ${esc(r.conclusion || '')}</span></div>`).join('');
          // 历史回填提示
          const hist = d.history || {};
          const histHtml = hist.same_cve
            ? `<div class="ops-hist">♻ 该漏洞已有处置记录（${esc(hist.same_cve_records && hist.same_cve_records[0] ? hist.same_cve_records[0].status_label : '')}），已自动复用结论</div>`
            : (hist.related && hist.related.length
              ? `<div class="ops-hist">♻ 关联 ${hist.related.length} 个同组件漏洞的处置经验</div>` : '');
          // 红蓝自博弈结果（质疑智能体挑战 → 抗辩收敛）
          const adv = d.adversarial || {};
          const advHtml = adv.rounds
            ? `<div class="ops-adv">
                <div class="ops-adv-hd ${adv.stabilized ? '' : 'ops-adv-fix'}">⚔ 红蓝自博弈 · ${esc(adv.conclusion || '')}（${adv.challenge_count} 条质疑 · ${(adv.fixes || []).length} 处修正）</div>
                ${adv.rounds.map((r) => `<div class="ops-adv-row">
                  <span class="ops-adv-q">${esc(r.challenge || '')}</span>
                  <span class="ops-adv-v ${r.verdict === '采纳' ? 'ok' : (r.verdict === '部分采纳' ? 'part' : 'rej')}">${esc(r.verdict || '')}</span>
                  <div class="ops-adv-d">抗辩：${esc(r.defense || '')}</div>
                </div>`).join('')}
              </div>` : '';
          // 溯源归因（漏洞 → 利用者 → ATT&CK 战术链路）
          const attr = d.attribution || {};
          const attrHtml = attr.actor
            ? `<div class="ops-attr">
                <div class="ops-attr-hd">🧭 溯源归因：<b>${esc(attr.actor.label || '未知')}</b>
                  ${attr.actor.confidence ? `<span class="ops-attr-conf">置信度 ${Math.round((attr.actor.confidence || 0) * 100)}%</span>` : ''}
                  ${attr.kev ? '<span class="ops-sig kev">KEV 在野</span>' : ''}</div>
                <div class="ops-attr-chain">${(attr.kill_chain || []).map((s, i) =>
                  `<span class="ops-chain-step">${i + 1}. ${esc(s.tactic_name || s.tactic)}</span>`).join(' → ')}</div>
                ${(attr.actor.evidence || []).map((e) => `<div class="ops-attr-ev">· ${esc(e)}</div>`).join('')}
              </div>` : '';
          return `<div class="ops-decision" data-cve="${esc(String(d.cve || ''))}">
            <div class="ops-dec-hd">
              <span class="ops-pri ${priCls}">${esc(pri || '?')}</span>
              <b>${esc(String(d.cve || '?'))}</b>
              <span class="ops-dec-goal">${esc(String(d.decision || ''))}</span>
            </div>
            <div class="ops-dec-signals">
              ${sig.kev ? '<span class="ops-sig kev">KEV 在野利用</span>' : ''}
              ${sig.cvss ? `<span class="ops-sig">CVSS ${esc(sig.cvss)}</span>` : ''}
              ${sig.poc_available ? `<span class="ops-sig">${esc(sig.poc_available)} 条公开 POC</span>` : ''}
              ${sig.assets_exposed ? `<span class="ops-sig">${esc(sig.assets_exposed)} 类资产暴露</span>` : ''}
              <span class="ops-sig">${esc(String(d.rationale || ''))}</span>
            </div>
            ${histHtml}
            ${advHtml}
            ${attrHtml}
            ${actions ? `<div class="ops-dec-actions">${actions}</div>` : ''}
            ${verify ? `<div class="ops-dec-verify">${verify}</div>` : ''}
            <div class="ops-dec-foot">
              <button class="ops-mini-btn" data-xai="${esc(String(d.cve || ''))}">🔍 查看推理依据</button>
              <span class="ops-sp"></span>
              <button class="ops-mini-btn ops-resolve" data-resolve="${esc(String(d.cve || ''))}">✓ 已修复</button>
              <button class="ops-mini-btn ops-verify" data-verify="${esc(String(d.cve || ''))}">✔ 已验证</button>
              <button class="ops-mini-btn ops-fp" data-fp="${esc(String(d.cve || ''))}">✗ 误报</button>
            </div>
            <div class="ops-xai" id="xai-${esc(String(d.cve || ''))}" hidden>
              ${reasoning || '<div class="meta-note">暂无显式推理链</div>'}
            </div>
          </div>`;
        }).join('')
      : '<div class="meta-note">暂无决策卡 —— 决策智能体发现 KEV/高危事件后自动产出</div>';

    /* 处置闭环回填记忆库统计 */
    if (mem && mem.ok !== false) {
      const byComp = Object.entries(mem.by_component || {}).slice(0, 5)
        .map(([k, v]) => `<span class="ops-mem-chip"><code>${esc(k)}</code> ×${v}</span>`).join('');
      memBox.innerHTML = `<div class="ops-mem-hd">
          <span>已沉淀 <b>${mem.total}</b> 条处置经验</span>
          <span>${(mem.by_status && mem.by_status.resolved) || 0} 已修复 · ${(mem.by_status && mem.by_status.verified) || 0} 已验证</span>
        </div>
        <div class="ops-mem-note">处置完成后点决策卡上的按钮回填，系统自动沉淀「同 CVE 秒判 + 同组件关联」经验</div>
        ${byComp ? `<div class="ops-mem-chips">${byComp}</div>` : '<div class="meta-note">尚无组件级沉淀 —— 回填一条处置后自动生成</div>'}`;
    } else {
      memBox.innerHTML = '<div class="meta-note">回填记忆库接口不可用</div>';
    }
  }

  function bind(root) {
    const scanBtn = root.querySelector('#opsScan');
    const out = root.querySelector('#opsScanOut');
    const decideBtn = root.querySelector('#opsDecideNow');
    const decideInp = root.querySelector('#opsDecideId');
    const decBox = root.querySelector('#opsDecisions');
    if (scanBtn && !scanBtn._bound) {
      scanBtn._bound = true;
      scanBtn.onclick = async () => {
        out.textContent = '正在编排（感知 → 分派 → 富化 → 研判 → 决策）…';
        try {
          const r = await fetch('/api/ops/scan_now', { method: 'POST' });
          const d = await r.json();
          if (d && d.ok) {
            out.textContent = `本轮：发现 ${d.events} 个事件，处理 ${(d.processed || []).length} 个${d.skipped ? `，限流跳过 ${d.skipped}` : ''}${(d.processed || []).length ? ' —— 简报+决策已产出' : '（无新增 KEV/高危，或已出过）'}`;
            refresh(root);
          } else out.textContent = '编排失败：' + ((d && d.error) || '未知错误');
        } catch (e) { out.textContent = '网络错误'; }
      };
    }
    if (decideBtn && !decideBtn._bound) {
      decideBtn._bound = true;
      decideBtn.onclick = async () => {
        const cid = (decideInp.value || '').trim();
        if (!cid) { out.textContent = '请先输入 CVE 编号，如 CVE-2025-63389'; return; }
        out.textContent = `正在对 ${cid} 走全链路（富化 → 简报 → 决策）…`;
        try {
          const r = await fetch('/api/ops/decide_now?id=' + encodeURIComponent(cid), { method: 'POST' });
          const d = await r.json();
          if (d && d.ok) {
            const perf = d.perf || {};
            out.textContent = `决策完成：${d.decision.priority} · ${d.decision.decision}（端到端 ${perf.total_ms || '?'}ms）`;
            refresh(root);
          } else out.textContent = '决策失败：' + ((d && d.error) || '未知错误');
        } catch (e) { out.textContent = '网络错误'; }
      };
    }
    // XAI 推理链展开 + 处置回填按钮（事件委托，刷新后仍有效）
    if (decBox && !decBox._bound) {
      decBox._bound = true;
      decBox.addEventListener('click', async (e) => {
        const t = e.target;
        const cve = t.getAttribute('data-xai') || t.getAttribute('data-resolve') ||
                   t.getAttribute('data-verify') || t.getAttribute('data-fp');
        if (!cve) return;
        if (t.hasAttribute('data-xai')) {
          const box = decBox.querySelector('#xai-' + cve);
          if (box) box.hidden = !box.hidden;
          return;
        }
        let status = '';
        if (t.hasAttribute('data-resolve')) status = 'resolved';
        else if (t.hasAttribute('data-verify')) status = 'verified';
        else if (t.hasAttribute('data-fp')) status = 'false_positive';
        if (!status) return;
        try {
          const r = await fetch('/api/ops/disposition', {
            method: 'POST', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ cve, status, actor: '演示操作' }),
          });
          const d = await r.json();
          if (d && d.ok) {
            out.textContent = `已回填：${cve} → ${d.record.status_label}，同类漏洞下次将秒判/关联`;
            refresh(root);
          } else out.textContent = '回填失败：' + ((d && d.error) || '未知错误');
        } catch (err) { out.textContent = '网络错误'; }
      });
    }
    refresh(root);
    if (!bind._timer) bind._timer = setInterval(() => {
      const el = document.getElementById('opsTrace');
      if (el) refresh(el.closest('.panel'));
    }, 20000);
  }

  AISEC.register({
    id: 'm0_ops',
    name: '智能编排',
    // 导出 refresh：让 tools/_test_ops_panel.js 能在 DOM 桩里直接驱动渲染。
    // 面板逻辑（指标落位/告警转义）必须能被回归测到，光靠肉眼刷新页面不算验证。
    refresh,
    enrichSections() {
      return [
        {
          id: 'opsOrchestrator',
          html: statusHtml(),
          mount: (el) => bind(el),
        },
      ];
    },
  });
})();
