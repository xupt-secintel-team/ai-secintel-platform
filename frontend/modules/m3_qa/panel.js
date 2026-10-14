// web/panel.js
// ⚠ 自动生成，请勿直接改本文件 —— 源文件在 modules/m3_qa/web/panel.js
//   改完跑一次： py -3 tools/组装前端.py
/* ============================================================
   m3_qa · 情报问答 —— 模块前端面板（负责人：成员C）
   ------------------------------------------------------------
   补齐「模块3 只有后端 /api/chat、前端没有对话入口」的缺口：
   在搜索框下方插入一个对话面板（Ask → RAG 回答 + 引用来源可点开详情）。

   接口：POST /api/chat  {q, history, base_url, api_key, model}
         → {answer, conclusion, evidence[], sources[], used_llm}

   ★ v2.4 答案呈现（本次改造）：
       · 结论置顶：后端产出 conclusion（上限 3600 字），前端单独成块展示，
         带字数徽标与「复制结论」，不再让用户从一堆证据里自己拼结论；
       · 原始详细资料：evidence[] 逐条渲染（编号/严重度/CVSS/日期/组件/摘要），
         点「详情」就地展开完整字段（懒加载 /api/detail），并可一键跳检查器；
       · 结论正文里的 CVE/GHSA 编号自动变成可点按钮，点开即详情 —— 快速跳转。

   ★ v2.5 结论里补上「内容分析」：
       结论分两层（后端拼好，前端不用感知）——
       ① 结论（内容要点）：命中资料正文/处置字段抽出的编号要点（<ol> 渲染，
          续行归入同一项），直接回答问题"资料说了什么"；
       ② 情报汇总（来源与风险统计）：原有的命中数/风险分布/时间跨度/数据来源。
       结论里的所有情报编号（CVE-/GHSA-/DSKB:/CSDN:/XZ:/AQK:/GH-PROJ:）都可点，
       点击打开该条完整情报 —— 结论与原始资料之间不再有"断头路"。

   LLM 配置存在浏览器 localStorage（asi_qa_cfg），不写进代码、不进版本库；
   不填 Key 时后端自动降级为「检索证据模板回答」，照样能用。
   ============================================================ */
(function () {
  const CFG_KEY = 'asi_qa_cfg';
  const LIMIT_DEFAULT = 3600;
  const QUICK = [
    '最近被在野利用的高危漏洞有哪些？',
    '提示词注入（prompt injection）怎么防？',
    'Ollama 有哪些远程代码执行漏洞？',
    '数据安全法对企业的要求是什么？',
  ];
  const history = [];          // [{role:'user'|'assistant', content, conclusion, evidence[]}]
  let busy = false;

  const cfg = () => {
    try { return JSON.parse(localStorage.getItem(CFG_KEY) || '{}'); } catch (e) { return {}; }
  };
  const saveCfg = (c) => { try { localStorage.setItem(CFG_KEY, JSON.stringify(c)); } catch (e) {} };

  /* 轻量 Markdown → HTML（只处理标题/列表/粗体/代码/链接，避免引外部库）
     按空行分块后逐块判断类型，而不是用 `</p><p>` 硬替换换行 ——
     后者会在标题后面留下游离的 </p>，浏览器虽能容错但 DOM 结构不干净。 */
  function mdInline(s) {
    return s
      .replace(/\[([^\]]{2,140})\]\((https?:\/\/[^)\s]+)\)/g,
        (m, txt, url) => `<a href="${url}" target="_blank" rel="noopener noreferrer">${txt}</a>`)
      .replace(/\*\*([^*]+)\*\*/g, '<b>$1</b>')
      // LLM 偶尔写出只开不闭的 `**`（截图实测：结论卡显示裸星号）——
      // 成对粗体已被上一行替换，这里把残留的孤立 `**` 清掉，不再显示乱码。
      .replace(/\*\*/g, '')
      .replace(/(^|\W)_([^_\n]+)_(?=\W|$)/g, '$1<i>$2</i>')
      .replace(/`([^`\n]+)`/g, '<code>$1</code>')
      .replace(/\n/g, '<br>');
  }

  function md(t) {
    let src = esc(t || '');
    src = src.replace(/```([\s\S]*?)```/g, (m, c) => `<pre class="qa-code">${c.trim()}</pre>`);
    return src.split(/\n{2,}/).map((raw) => {
      const b = raw.trim();
      if (!b) return '';
      if (b.indexOf('<pre') === 0) return b;
      if (/^#{1,4}\s?/.test(b)) return `<h5>${mdInline(b.replace(/^#{1,4}\s?/, ''))}</h5>`;
      const lines = b.split('\n');
      // 有序列表：「1. **要点标题**」+ 缩进续行（要点正文）→ 归入同一个 <li>
      const isOl = (x) => /^\s*\d{1,2}[.、)]\s+/.test(x);
      if (lines.some(isOl)) {
        let out = '', cur = null, rest = [];
        lines.forEach((x) => {
          if (isOl(x)) {
            if (cur !== null) out += `<li>${cur}</li>`;
            cur = mdInline(x.replace(/^\s*\d{1,2}[.、)]\s+/, ''));
          } else if (cur !== null) {
            cur += '<br>' + mdInline(x.trim());        // 续行挂到当前项
          } else {
            rest.push(x);
          }
        });
        if (cur !== null) out += `<li>${cur}</li>`;
        return `<ol>${out}</ol>` + (rest.length ? `<p>${mdInline(rest.join('\n'))}</p>` : '');
      }
      const items = lines.filter((x) => /^\s*[-*]\s+/.test(x));
      if (items.length) {
        const rest = lines.filter((x) => !/^\s*[-*]\s+/.test(x)).join('\n').trim();
        return '<ul>' + items.map((x) => `<li>${mdInline(x.replace(/^\s*[-*]\s+/, ''))}</li>`).join('')
          + '</ul>' + (rest ? `<p>${mdInline(rest)}</p>` : '');
      }
      return `<p>${mdInline(b)}</p>`;
    }).join('')
      .replace(/<\/ol>\s*<ol>/g, '')      // 相邻同型列表合并，别把编号列表拆成多个 <ol>
      .replace(/<\/ul>\s*<ul>/g, '');
  }

  /* 正文里的情报编号 → 可点按钮（跳过 HTML 标签内部，避免污染属性值）。
     除漏洞编号外，知识库/文章/仓库条目编号（DSKB: / CSDN: / XZ: / AQK: / GH-PROJ:）
     同样可点 —— 结论里的"要点出处"要能一键跳到该条详情。 */
  function linkifyCve(html) {
    return html.replace(
      /<[^>]*>|CVE-\d{4}-\d{4,7}|GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}|(?:DSKB|CSDN|XZ|AQK|GH-PROJ|NVD|KEV):[A-Za-z0-9_\-/.]+/gi,
      (m) => (m.charAt(0) === '<' ? m : `<button class="qa-cve" data-id="${m}">${m}</button>`))
      // 编号外面那层方括号/书名号去掉 —— 按钮本身就是"可点来源"的样子，套括号反而碍眼
      .replace(/[\[〔]\s*(<button class="qa-cve"[^>]*>[^<]*<\/button>)\s*[\]〕]/g, '$1');
  }

  const SEV_CLS = (sev) => ({
    CRITICAL: 'critical', HIGH: 'high', MEDIUM: 'medium', LOW: 'low',
  }[(sev || '').toUpperCase()] || 'unknown');

  /* ── 原始详细资料：单条卡片 ───────────────────────────────── */
  function evRow(m, mi, i, e) {
    const sev = (e.severity || '').toUpperCase();
    const open = !!(m._open && m._open.has(i));
    const line = `<div class="qa-ev-line">
        <span class="qa-ev-id">${esc(e.id)}</span>
        <span class="qa-sev ${SEV_CLS(sev)}">${esc(sev)}${cvssNum(e.cvss) ? ' ' + esc(cvssNum(e.cvss)) : ''}</span>
        ${e.exploited ? '<span class="qa-flag alert">在野利用</span>' : ''}
        ${e.poc_count ? `<span class="qa-flag">POC ${esc(e.poc_count)}</span>` : ''}
        <span class="qa-ev-title">${esc(e.title || '')}</span>
        <span class="qa-ev-date">${esc(e.published || '')}</span>
        <span class="qa-ev-go">${open ? '收起 ▴' : '详情 ▾'}</span>
      </div>`;
    const head = `<div class="qa-ev-item${open ? ' on' : ''}" data-mi="${mi}" data-i="${i}">${line}`;

    if (!open) {
      return head + (e.summary ? `<div class="qa-ev-sum">${esc(e.summary)}</div>` : '') + '</div>';
    }

    const kvs = [];
    if (cvssNum(e.cvss)) kvs.push(`<div class="qa-kv"><span>CVSS</span><b>${esc(cvssNum(e.cvss))} · ${esc(sev)}</b></div>`);
    if (e.published) kvs.push(`<div class="qa-kv"><span>收录</span><b>${esc(e.published)}</b></div>`);
    if ((e.products || []).length) kvs.push(`<div class="qa-kv"><span>受影响组件</span><b>${esc((e.products || []).join('、'))}</b></div>`);
    if ((e.cwe || []).length) kvs.push(`<div class="qa-kv"><span>弱点类型</span><b>${esc((e.cwe || []).join('、'))}</b></div>`);
    if ((e.sources || []).length) kvs.push(`<div class="qa-kv"><span>来源</span><b>${esc((e.sources || []).join(' + '))}</b></div>`);
    if (e.trust_label) kvs.push(`<div class="qa-kv"><span>可信度</span><b>${esc(e.trust_label)}${e.confidence != null ? ' / ' + esc(e.confidence) : ''}</b></div>`);

    return `${head}
      <div class="qa-ev-detail">
        ${kvs.length ? `<div class="qa-ev-kvs">${kvs.join('')}</div>` : ''}
        <div class="qa-ev-more">${evDetailBody(m, i)}</div>
        <div class="qa-ev-open"><button class="qa-mini qa-lnk-open" data-id="${esc(e.id)}">在检查器中打开 ↗</button></div>
      </div>
    </div>`;
  }

  /* ── 展开后的完整详情（懒加载 /api/detail） ───────────────── */
  function evDetailBody(m, i) {
    const c = (m._cache || {})[i];
    if (c === undefined) return '<div class="qa-ev-load">正在读取完整情报…</div>';
    if (c === null) return '<div class="qa-ev-load">详情暂不可用（该条目不在详情索引里）</div>';
    return renderDetail(c);
  }

  function renderDetail(d) {
    const out = [];
    if (d.desc) out.push(`<p class="qa-ev-desc">${esc(d.desc)}</p>`);
    if (d.category) out.push(`<div class="qa-ev-note">分类：${esc(d.category)}${d.category_reason ? '（' + esc(d.category_reason) + '）' : ''}</div>`);
    if (d.kev && d.kev.exploited) {
      out.push(`<div class="qa-ev-note alert">⚠ CISA 在野利用清单：加入 ${esc(d.kev.date_added || '—')}`
        + `${d.kev.due_date ? ' · 整改截止 ' + esc(d.kev.due_date) : ''}`
        + `${d.kev.ransomware ? ' · 勒索软件关联：' + esc(d.kev.ransomware) : ''}</div>`);
    }
    if ((d.remediation || []).length) {
      out.push('<div class="qa-ev-note"><b>修复建议</b></div><ol class="qa-ev-steps">'
        + (d.remediation || []).slice(0, 5).map((x) => `<li>${esc(x)}</li>`).join('') + '</ol>');
    }
    const links = [].concat(
      (d.poc_links || []).map((u) => ['POC', u]),
      (d.advisory_links || []).map((u) => ['公告', u]),
      (d.patch_links || []).map((u) => ['补丁', u]),
      (d.refs || []).map((r) => ['参考', r && r.url ? r.url : r]),
    ).filter((x) => x[1]);
    if (links.length) {
      out.push('<div class="qa-ev-links">'
        + links.slice(0, 8).map(([t, u]) =>
          `<a href="${esc(u)}" target="_blank" rel="noopener noreferrer"><i>${esc(t)}</i>${esc(String(u).slice(0, 66))}</a>`).join('')
        + '</div>');
    }
    if ((d.papers || []).length) {
      out.push('<div class="qa-ev-note"><b>关联研究</b></div>'
        + (d.papers || []).slice(0, 3).map((p) =>
          `<div class="qa-ev-paper">${esc(p.title)}${p.url ? ` <a href="${esc(p.url)}" target="_blank" rel="noopener noreferrer">↗</a>` : ''}</div>`).join(''));
    }
    return out.length ? out.join('') : '<div class="qa-ev-load">该条目无更多字段</div>';
  }

  /* ── 推理链（2026-10-06）：把后端 reasoning_chain 画出来 ────────────
     多跳检索过去是黑箱：用户只看到一段结论，不知道系统查了什么、为什么
     这么查、哪一步没查到就停了。这里逐跳列出「检索式 / 派生依据 / 命中数 /
     耗时 / 派生的新实体」，让"跨文档推理"可核对。 */
  function chainHtml(m) {
    const c = m.reasoning_chain;
    if (!c || typeof c !== 'object') return '';
    const hops = (c.hops || []).filter((h) => h && typeof h === 'object');
    if (!hops.length) return '';
    const num = (v) => (v == null ? '—' : esc(v));
    // 第 1 跳是多路并行检索式（原问题 / 跨来源召回 / 条件算子），后端每路
    // 各记一条，所以 hops 里会有多条 hop:1。用 sub/routes 标成 "跳1·2/3"，
    // 否则按 hops.length 数步数会把 2 跳说成 3 步。
    const hopNo = (h) => {
      const base = '跳' + num(h.hop);
      if (h.routes > 1 && h.sub != null) return base + '·' + num(h.sub) + '/' + num(h.routes);
      return base;
    };
    const rows = hops.map((h) => {
      if (h.skipped) {
        return `<div class="qa-hop stop">
          <span class="qa-hop-no">跳${num(h.hop)}</span>
          <span class="qa-hop-basis">${esc(h.basis || '已停止深化')}</span>
        </div>`;
      }
      const ents = Array.isArray(h.derived_entities) ? h.derived_entities : [];
      return `<div class="qa-hop">
        <span class="qa-hop-no">${hopNo(h)}</span>
        <div class="qa-hop-main">
          <div class="qa-hop-q">${esc(h.query || '')}</div>
          <div class="qa-hop-meta">命中 <b>${num(h.hits)}</b> · 新增 <b>${num(h.new_docs)}</b>${h.ms != null ? ' · ' + esc(h.ms) + 'ms' : ''}</div>
          <div class="qa-hop-basis">${esc(h.basis || '')}</div>
          ${ents.length ? `<div class="qa-hop-ent">派生实体：${esc(ents.join('、'))}</div>` : ''}
        </div>
      </div>`;
    }).join('');
    const tail = [];
    if (c.strategy) tail.push(esc(c.strategy));
    if (c.generation) tail.push('生成 ' + esc(c.generation));
    const total = (m.elapsed_ms != null ? m.elapsed_ms : c.total_ms);
    if (total != null) tail.push('总耗时 ' + esc(total) + 'ms');
    // 步数用后端 hop_count（真实跳数），没有才退回记录条数
    const steps = (c.hop_count != null && c.hop_count > 0) ? c.hop_count : hops.length;
    return `<details class="qa-chain">
      <summary><span class="qa-tag ghost">推理链</span> ${steps} 跳 / ${hops.length} 次检索${tail.length ? ' · ' + tail.join(' · ') : ''}</summary>
      <div class="qa-chain-list">${rows}</div>
    </details>`;
  }

  /* ── 助手消息：结论块 + 推理链 + 原始资料块 ───────────────────── */
  function aiBody(m, mi) {
    const concl = (m.conclusion != null ? m.conclusion : (m.content || '')).trim();
    const limit = m.limit || LIMIT_DEFAULT;
    const ev = m.evidence || [];
    const hit = concl.length >= limit;
    const chain = chainHtml(m);
    // 流式中：显示打字光标 + 阶段提示，资料/推理链等 done 后再上（此时还没有）
    const cursor = m._streaming ? '<span class="qa-caret"></span>' : '';
    const streamHint = m._streaming
      ? '<div class="qa-ev-note">正在生成，答案将逐字显示…</div>' : '';

    // 流式正文走「纯文本增量渲染」：Markdown 解析留到 done 后一次性完成。
    // 若流式期间每帧都 md() 重解析 + innerHTML 全量替换，会把结论块每帧销毁重建、
    // 光标 span 每帧重建导致 qa-blink 动画从头再跑 —— 这才是频闪根因。
    const streamBody = m._streaming
      ? `<span class="qa-stream">${esc(m.conclusion != null ? m.conclusion : (m.content || ''))}</span>${cursor}`
      : linkifyCve(md(concl));

    const conclHtml = `<div class="qa-concl">
      <div class="qa-concl-hd">
        <span class="qa-tag">结论</span>
        <span class="qa-cnt${hit ? ' hit' : ''}">${concl.length} / ${limit} 字</span>
        <span class="qa-sp"></span>
        <button class="qa-mini" data-copyconcl="${mi}">复制结论</button>
      </div>
      <div class="qa-concl-bd">${streamBody}</div>
      ${m.truncated ? '<div class="qa-ev-note">结论已达字数上限被截断，完整情报见下方原始资料。</div>' : ''}
    </div>${streamHint}`;

    const related = (m.related || []).filter((r) => r && typeof r === 'object' && r.id);
    const relatedHtml = related.length ? `<div class="qa-rel">
      <div class="qa-ev-hd">
        <span class="qa-tag info">猜你还想看</span>
        <span class="qa-hint">基于本次问题的组件 / 弱点关联推荐</span>
      </div>
      <div class="qa-rel-list">
        ${related.map((r) => {
          const sev = (r.severity || '').toUpperCase();
          const cls = sev === 'CRITICAL' || sev === 'HIGH' ? 'chip alert' : 'chip';
          return `<button class="qa-rel-item" data-open="${esc(r.id)}">
            <span class="${cls}">${esc(r.severity || 'UNKNOWN')}</span>
            <span class="qa-rel-id">${esc(r.id)}</span>
            ${cvssNum(r.cvss) ? `<span class="qa-rel-cvss">CVSS ${esc(cvssNum(r.cvss))}</span>` : ''}
            ${r.exploited ? '<span class="qa-rel-kev">KEV</span>' : ''}
            <span class="qa-rel-title">${esc(r.title || '')}</span>
            <span class="qa-rel-reason">${esc(r.reason || '')}</span>
          </button>`;
        }).join('')}
      </div>
    </div>` : '';

    if (!ev.length) return `<div class="qa-body">${conclHtml}${chain}${relatedHtml}${sourceChips(m.sources)}</div>`;

    // 脏数据防御：evidence 里混进 null / 非对象（后端异常或第三方数据时有可能），
    // 不过滤的话 evRow 会在 e.severity 上抛错，整个 render 中断 → 面板白屏。
    // 过滤时保留**原始下标**：_open / _cache 都是按原始下标存的，重排会点错条目。
    const rows = ev.map((e, i) => ({ e, i })).filter((x) => x.e && typeof x.e === 'object');
    if (!rows.length) return `<div class="qa-body">${conclHtml}${chain}${relatedHtml}${sourceChips(m.sources)}</div>`;

    const allOpen = m._all !== false;
    return `<div class="qa-body">${conclHtml}${chain}${relatedHtml}
      <div class="qa-ev">
        <div class="qa-ev-hd">
          <span class="qa-tag ghost">原始详细资料</span>
          <b>${rows.length}</b> 条${m.evidence_total > rows.length ? `（命中 ${m.evidence_total} 条）` : ''}
          <span class="qa-hint">点击任意一条看完整情报</span>
          <span class="qa-sp"></span>
          <button class="qa-mini" data-evall="${mi}">${allOpen ? '收起全部' : '展开全部'}</button>
        </div>
        <div class="qa-ev-list"${allOpen ? '' : ' hidden'}>
          ${rows.map((x) => evRow(m, mi, x.i, x.e)).join('')}
        </div>
      </div>
    </div>`;
  }

  function bubble(m, mi) {
    if (m.role === 'user') {
      return `<div class="qa-msg me">
        <div class="qa-who">我</div>
        <div class="qa-body">${esc(m.content)}</div>
      </div>`;
    }
    return `<div class="qa-msg ai" data-mi="${mi}">
      <div class="qa-who">AI 情报分析师</div>
      ${aiBody(m, mi)}
    </div>`;
  }

  /* 旧结构兜底：只有 sources 没有 evidence 时仍渲染一排编号 chip */
  function sourceChips(sources) {
    if (!sources || !sources.length) return '';
    const items = sources.map((s) => {
      const sev = (s.severity || '').toUpperCase();
      const cls = sev === 'CRITICAL' || sev === 'HIGH' ? 'chip alert' : 'chip';
      return `<button class="${cls} qa-src" data-id="${esc(s.id)}" title="${esc(s.title || '')}">
        ${esc(s.id)}${cvssNum(s.cvss) ? ' · ' + esc(cvssNum(s.cvss)) : ''}</button>`;
    }).join('');
    return `<div class="qa-srcs"><span class="qa-slab">引用来源</span>${items}</div>`;
  }

  function render() {
    const box = $('qa-msgs');
    if (!box) return;
    if (!history.length) {
      box.innerHTML = `<div class="qa-empty">直接提问，例如：<b>最近有哪些在野利用的高危漏洞？</b><br>
        回答会<b>先给一条结论</b>（上限 ${LIMIT_DEFAULT} 字，含命中数、风险分布、最该处置的编号），
        再把每条<b>原始情报</b>列在下面 —— 点开任意一条即可查看完整详情。</div>`;
      return;
    }
    box.innerHTML = history.map((m, i) => bubble(m, i)).join('');
    bindMsg(box);
    box.scrollTop = box.scrollHeight;
  }

  /* 流式增量渲染（问题三）：token 逐字到达时不再全量重建 #qa-msgs（那会每次销毁重建
     整条消息列表、重跑 rise 入场动画、整段 Markdown 重解析 → 频闪）。改为 rAF 节流
     （每帧至多一次），只更新「正在流式生成的那条」结论块 + 字数计数。 */
  let _streamRaf = 0;
  function scheduleStreamRender(m) {
    if (_streamRaf) return;
    _streamRaf = requestAnimationFrame(() => {
      _streamRaf = 0;
      if (!m._streaming) return;          // 已结束：最终 render() 已接管，不再追加光标
      const idx = history.indexOf(m);
      const box = $('qa-msgs');
      if (!box || idx < 0) return;
      const msg = box.querySelector('.qa-msg[data-mi="' + idx + '"]');
      if (!msg) return;
      const raw = (m.conclusion != null ? m.conclusion : (m.content || ''));
      // 增量追加：只把「上次已渲染长度」之后的新增字符 append 进文本节点。
      // 不 innerHTML、不重跑 Markdown、不重建光标 —— 已有内容零触碰，杜绝频闪。
      const stream = msg.querySelector('.qa-stream');
      if (stream) {
        const prev = m._renderedLen || 0;
        if (raw.length > prev) {
          let tn = stream.firstChild;
          if (!tn || tn.nodeType !== 3) { tn = document.createTextNode(''); stream.appendChild(tn); }
          tn.appendData(raw.slice(prev));
          m._renderedLen = raw.length;
        }
      }
      const cnt = msg.querySelector('.qa-cnt');
      if (cnt) cnt.textContent = raw.length + ' / ' + (m.limit || LIMIT_DEFAULT) + ' 字';
    });
  }

  /* ── 消息区交互（每次重渲染后重绑） ───────────────────────── */
  function bindMsg(box) {
    box.querySelectorAll('.qa-ev-line').forEach((el) => {
      el.onclick = () => {
        const item = el.parentNode;
        const mi = +item.dataset.mi, i = +item.dataset.i;
        const m = history[mi];
        if (!m) return;
        if (!m._open) m._open = new Set();
        if (m._open.has(i)) { m._open.delete(i); render(); }
        else { m._open.add(i); render(); loadDetail(m, i); }
      };
    });
    box.querySelectorAll('.qa-lnk-open').forEach((b) => {
      b.onclick = (ev) => { ev.stopPropagation(); jumpDetail(b.dataset.id); };
    });
    box.querySelectorAll('[data-evall]').forEach((b) => {
      b.onclick = () => {
        const m = history[+b.dataset.evall];
        if (!m) return;
        m._all = m._all === false;                 // 展开全部 ⇄ 收起全部
        if (m._all) {
          m._open = new Set((m.evidence || []).map((_, i) => i));
          render();
          (m.evidence || []).forEach((_, i) => loadDetail(m, i));
        } else {
          m._open = new Set();
          render();
        }
      };
    });
    box.querySelectorAll('[data-copyconcl]').forEach((b) => {
      b.onclick = () => {
        const m = history[+b.dataset.copyconcl];
        if (!m) return;
        copyText((m.conclusion != null ? m.conclusion : m.content) || '');
        b.textContent = '已复制';
        setTimeout(() => { b.textContent = '复制结论'; }, 1400);
      };
    });
    box.querySelectorAll('.qa-cve, .qa-src').forEach((b) => {
      b.onclick = () => jumpDetail(b.dataset.id);
    });
    box.querySelectorAll('.qa-rel-item').forEach((b) => {
      b.onclick = () => jumpDetail(b.dataset.open);
    });
  }

  function copyText(t) {
    try {
      if (navigator.clipboard && navigator.clipboard.writeText) { navigator.clipboard.writeText(t); return; }
    } catch (e) { /* 退化到 textarea 方案 */ }
    const ta = document.createElement('textarea');
    ta.value = t; ta.style.position = 'fixed'; ta.style.opacity = '0';
    document.body.appendChild(ta); ta.select();
    try { document.execCommand('copy'); } catch (e) {}
    document.body.removeChild(ta);
  }

  /* 跳详情：优先用主体检查器，缺失时退回 URL 直达 */
  function jumpDetail(id) {
    if (!id) return;
    if (typeof openDetail === 'function') { openDetail(id); return; }
    location.href = '/?detail=' + encodeURIComponent(id);
  }

  /* 懒加载单条完整详情 → 写进消息缓存 → 局部刷新，不整屏重排 */
  async function loadDetail(m, i) {
    if (!m._cache) m._cache = {};
    if (m._cache[i] !== undefined) return;
    const e = (m.evidence || [])[i];
    if (!e || !e.id) { m._cache[i] = null; return; }
    m._cache[i] = undefined;                        // 占位：避免并发重复请求
    try {
      const d = await (await fetch('/api/detail?id=' + encodeURIComponent(e.id))).json();
      m._cache[i] = (d && !d.error) ? d : null;
    } catch (err) {
      m._cache[i] = null;
    }
    const box = $('qa-msgs');
    if (!box) return;
    const node = box.querySelector(`.qa-ev-item[data-mi="${history.indexOf(m)}"][data-i="${i}"] .qa-ev-more`);
    if (node) node.innerHTML = evDetailBody(m, i);
  }

  function status(msg, cls) {
    const el = $('qa-stat');
    if (el) { el.textContent = msg || ''; el.className = 'qa-stat ' + (cls || ''); }
  }

  // —— 流式问答（SSE）：2026-10-08 针对「大模型 55.6s 整段返回」改造 ——
  // POST /api/chat/stream 逐帧推 stage/token/done；失败自动回退 POST /api/chat。
  // 首字时间从「整段生成完才返回」降到 ~10s 内，全程可见阶段进度。
  function _mkMsg(q) {
    const m = { role: 'assistant', content: '', conclusion: '', evidence: [],
                sources: [], related: [], _open: new Set(), _cache: {}, _all: true,
                _streaming: true, _renderedLen: 0 };
    return m;
  }

  async function askStream(q, c, m, onFirstToken) {
    if (_streamRaf) { cancelAnimationFrame(_streamRaf); _streamRaf = 0; }   // 清掉上一问遗留的节流帧
    const resp = await fetch('/api/chat/stream', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        q,
        history: history.slice(-7, -1),
        base_url: c.base_url || undefined,
        api_key: c.api_key || undefined,
        model: c.model || undefined,
      }),
    });
    if (!resp.ok || !resp.body) throw new Error('HTTP ' + resp.status);
    const reader = resp.body.getReader();
    const dec = new TextDecoder();
    let buf = '', result = null, errMsg = '', sawToken = false;
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      buf += dec.decode(value, { stream: true });
      let idx;
      while ((idx = buf.indexOf('\n\n')) >= 0) {
        const frame = buf.slice(0, idx); buf = buf.slice(idx + 2);
        let ev = '', data = '';
        for (const line of frame.split('\n')) {
          if (line.startsWith('event:')) ev = line.slice(6).trim();
          else if (line.startsWith('data:')) data += line.slice(5).trim();
        }
        if (!ev || !data) continue;
        let payload = null;
        try { payload = JSON.parse(data); } catch (_) { continue; }
        if (ev === 'stage') {
          status(payload.msg || '处理中…', 'run');
        } else if (ev === 'token') {
          if (payload.t === '\0') continue;          // 结束标记
          m.content += payload.t;
          m.conclusion = m.content;
          if (!sawToken) {
            sawToken = true;
            onFirstToken && onFirstToken();
            m._renderedLen = m.conclusion.length;     // 首 token 已随 render() 落为纯文本，后续只 append 增量
          } else scheduleStreamRender(m);              // 增量更新，rAF 节流，每帧至多一次
        } else if (ev === 'done') {
          result = payload;
        } else if (ev === 'error') {
          errMsg = payload.error || '未知错误';
        }
      }
    }
    if (errMsg && !result) throw new Error(errMsg);
    if (!result) { if (!m.content) throw new Error('流中断且无内容'); 
      result = { answer: m.content, conclusion: m.content, evidence: [], sources: [], used_llm: true }; }
    return result;
  }

  async function ask(qOverride) {
    const input = $('qa-q');
    const q = (qOverride != null ? qOverride : (input ? input.value : '')).trim();
    if (!q || busy) return;
    if (input && qOverride == null) input.value = '';
    busy = true;
    history.push({ role: 'user', content: q });
    render();
    status('检索中 · 智能体规划 → 工具取证 → 流式生成…', 'run');
    const t0 = Date.now();
    const m = _mkMsg();
    let streamed = false;
    try {
      const c = cfg();
      let r = null;
      try {
        r = await askStream(q, c, m, () => {
          // 首字到达：把流式消息挂进会话并渲染（用户立刻看见字往外蹦）
          if (!streamed) {
            streamed = true;
            if (!history.includes(m)) history.push(m);
            render();
          }
        });
        if (streamed && !history.includes(m)) history.push(m);
      } catch (streamErr) {
        // 流式不可用（旧服务/代理缓冲/网络中断）→ 回退整段接口
        if (streamed && m.content) {
          // 已经吐了一半流：别浪费，直接按已有内容收尾
          r = { answer: m.content, conclusion: m.content, evidence: [], sources: [],
                used_llm: true, partial: true };
          status('流式连接中断，已展示部分答案（' + ((Date.now() - t0) / 1000).toFixed(1) + 's）', 'warn');
        } else {
          console.warn('[qa] 流式失败，回退整段:', streamErr.message);
          status('流式不可用，整段生成中…', 'run');
          r = await (await fetch('/api/chat', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
              q,
              history: history.slice(-7, -1),
              base_url: c.base_url || undefined,
              api_key: c.api_key || undefined,
              model: c.model || undefined,
            }),
          })).json();
        }
      }
      if (r.error && !r.answer) throw new Error(r.error);
      const concl = (r.conclusion != null ? r.conclusion : (r.answer || '')).trim();
      const ev = r.evidence || [];
      m.content = r.answer || m.content || '（空回答）';
      m.conclusion = concl || m.content || '（空回答）';
      m.limit = r.conclusion_limit || LIMIT_DEFAULT;
      m.truncated = !!r.conclusion_truncated;
      m.evidence = ev;
      m.evidence_total = r.evidence_total || ev.length;
      m.sources = r.sources || [];
      m.related = r.related || [];
      m._streaming = false;
      if (!history.includes(m)) history.push(m);
      status(`${r.used_llm ? `大模型生成（${r.model || 'deepseek-chat'}）`
        : (r.llm_error ? `大模型调用失败，已降级为检索模板：${r.llm_error}`
                       : '检索证据模板（未配置 LLM Key）')}`
        + ` · 结论 ${(r.conclusion_chars || concl.length)} 字 · 原始资料 ${ev.length} 条`
        + ` · ${((Date.now() - t0) / 1000).toFixed(1)}s`
        + (streamed ? ' · 流式' : ''),
        r.used_llm ? 'ok' : (r.llm_error ? 'warn' : 'ok'));
      // 默认先展开前 3 条（其余点开再加载），避免一屏塞满、也更省请求
      ev.slice(0, 3).forEach((_, i) => m._open.add(i));
      render();
      ev.slice(0, 3).forEach((_, i) => loadDetail(m, i));
    } catch (e) {
      history.push({ role: 'assistant', content: '问答服务异常：' + e.message,
                     conclusion: '问答服务异常：' + e.message, evidence: [], sources: [] });
      status('调用失败：' + e.message, 'err');
    } finally {
      busy = false;
      render();
    }
  }

  function panelHtml() {
    return `<div class="qa-card">
      <div class="qa-hd">
        <span class="qa-ic">💬</span>
        <b>情报问答</b>
        <span class="qa-sub">结论先行 · 原始资料可点开</span>
        <span class="qa-stat" id="qa-stat"></span>
        <span class="qa-sp"></span>
        <button class="qa-mini" id="qa-cfgbtn" title="配置大模型（存在本机浏览器，不进代码库）">模型设置</button>
        <button class="qa-mini" id="qa-clearbtn" title="开始新会话">新会话</button>
      </div>
      <div class="qa-cfg" id="qa-cfg">
        <select id="qa-provider" title="选服务商就自动填好接口地址与模型，你只需粘 Key"></select>
        <input id="qa-model" placeholder="模型，如 deepseek-chat">
        <input id="qa-base" placeholder="base_url，如 https://api.deepseek.com">
        <input id="qa-key" type="password" placeholder="API Key（仅存本机 localStorage）">
        <button class="qa-mini" id="qa-cfgsave">保存</button>
      </div>
      <div class="qa-msgs" id="qa-msgs"></div>
      <div class="qa-vec" id="qa-vec"></div>
      <div class="qa-quick">${QUICK.map((x) => `<button class="qa-q">${esc(x)}</button>`).join('')}</div>
      <div class="qa-input">
        <textarea id="qa-q" rows="1" placeholder="问点什么，例如：Log4j2 的影响范围与处置建议（Enter 发送，Shift+Enter 换行）"></textarea>
        <button class="btn" id="qa-go">提问</button>
      </div>
    </div>`;
  }

  function bind() {
    const q = $('qa-q');
    $('qa-go').onclick = () => ask();
    q.addEventListener('keydown', (e) => {
      if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); ask(); }
    });
    q.addEventListener('input', () => {                     // 高度自适应
      q.style.height = 'auto';
      q.style.height = Math.min(120, q.scrollHeight) + 'px';
    });
    document.querySelectorAll('.qa-quick .qa-q').forEach((b) => {
      b.onclick = () => ask(b.textContent);
    });
    $('qa-clearbtn').onclick = () => {
      history.length = 0; render(); status('已开始新会话', 'ok');
    };
    const c = cfg();
    $('qa-model').value = c.model || '';
    $('qa-base').value = c.base_url || '';
    $('qa-key').value = c.api_key || '';
    $('qa-cfgbtn').onclick = () => { $('qa-cfg').classList.toggle('on'); };
    $('qa-cfgsave').onclick = () => {
      saveCfg({ provider: $('qa-provider') ? $('qa-provider').value : '',
                model: $('qa-model').value.trim(), base_url: $('qa-base').value.trim(),
                api_key: $('qa-key').value.trim() });
      $('qa-cfg').classList.remove('on');
      status('模型配置已保存（本机浏览器）', 'ok');
    };
    render();
    probeServer();
  }

  /* 问一下服务端：有没有通过环境变量配好大模型（配了就不用手填 Key）+ 语义索引状态 */
  async function probeServer() {
    try {
      const st = await (await fetch('/api/qa/status')).json();
      if (st.env_key) {
        status(`服务端已配置模型：${st.model}`, 'ok');
        const btn = $('qa-cfgbtn');
        if (btn) btn.title = '服务端已用环境变量配好 Key；这里手填的值会临时覆盖它';
      } else if (st.qa_package === false) {
        status('问答后端未就绪：' + (st.note || ''), 'warn');
      } else {
        /* 服务端没设 AISEC_LLM_API_KEY 时，还要看浏览器端有没有保存过配置 ——
           只看服务端会把「已在本机存了 Key」的用户误导成"配置丢了"（2026-10-07 实测反馈） */
        const c = cfg();
        if (c.api_key && (c.base_url || c.model)) {
          status(`已用本机浏览器配置（${c.model || '自定义模型'}）；服务端未设 AISEC_LLM_API_KEY，此处配置优先`, 'ok');
        } else {
          status('未配置模型：可在「模型设置」临时填，或让服务端设 AISEC_LLM_API_KEY', 'warn');
        }
      }
      fillProviders(st.providers);
      renderVector(st);
    } catch (e) { /* 状态探测失败不影响提问 */ }
  }

  /* 供应商预设：选一个 → 自动填好 base_url / model，用户只需粘 Key 保存。
     站点列表来自后端 /api/qa/status 的 providers（源头 qa/config.py），前端不硬编码。 */
  function fillProviders(list) {
    const sel = $('qa-provider');
    if (!sel || !list || !list.length) return;
    sel.innerHTML = list.map((p) => `<option value="${esc(p.id)}">${esc(p.label || p.id)}</option>`).join('');
    const c = cfg();
    let id = c.provider || '';
    if (!id) {
      const norm = (u) => (u || '').replace(/\/+$/, '');
      const hit = list.find((p) => p.base_url && norm(p.base_url) === norm(c.base_url));
      id = hit ? hit.id : (list.some((p) => p.id === 'deepseek') ? 'deepseek' : list[0].id);
    }
    sel.value = id;
    sel.onchange = () => applyProvider(list, sel.value);
    if (!c.base_url && !c.model) applyProvider(list, sel.value, true);
  }

  function applyProvider(list, id, silent) {
    const p = (list || []).find((x) => x.id === id);
    if (!p) return;
    if ($('qa-base')) $('qa-base').value = p.base_url || '';
    if ($('qa-model')) $('qa-model').value = p.model || '';
    if (!silent) status(`已选 ${p.label || id}：接口地址与模型已填好，粘上 Key 点保存即可`, 'ok');
  }

  /* ① 语义索引状态：已建库就说明「关键词 + 语义」混合检索在生效 */
  let vecTimer = null;
  function renderVector(st) {
    const el = $('qa-vec');
    if (!el) return;
    const n = st.vector_count || 0;
    if (n > 0) {
      el.innerHTML = `<span class="qa-vecdot on"></span>语义索引已就绪 <b>${n}</b> 条`
        + `（本地模型 ${esc((st.vector_model || '').split('/').pop() || '—')}，零费用、不联网）`;
      el.className = 'qa-vec ok';
    } else {
      el.innerHTML = `<span class="qa-vecdot"></span>语义索引未建：当前只用关键词检索（功能正常）`
        + `<button class="qa-mini" id="qa-vecbuild">建索引</button>`;
      el.className = 'qa-vec';
      const b = $('qa-vecbuild');
      if (b) b.onclick = buildVector;
    }
  }

  async function buildVector() {
    const el = $('qa-vec');
    el.className = 'qa-vec run';
    el.innerHTML = '正在建语义索引（本地 CPU 编码 8 万余条，可中断后重跑）…';
    try {
      const r = await (await fetch('/api/qa/build_vector', {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ limit: 0, batch: 64 }),
      })).json();
      if (r.error) { el.innerHTML = '建索引失败：' + esc(r.error); el.className = 'qa-vec warn'; return; }
      if (vecTimer) clearInterval(vecTimer);
      vecTimer = setInterval(async () => {
        try {
          const p = await (await fetch('/api/qa/build_vector')).json();
          const pct = p.total ? Math.floor((p.processed || 0) * 100 / p.total) : 0;
          el.innerHTML = `建语义索引 ${p.processed || 0}/${p.total || '?'}（${pct}%）· `
            + `${p.rate || 0} 条/秒 · 预计剩余 ${Math.round((p.eta || 0) / 60)} 分钟`;
          if (p.done || !p.running) {
            clearInterval(vecTimer); vecTimer = null;
            if (p.error) { el.className = 'qa-vec warn'; el.innerHTML = '建索引失败：' + esc(p.error); return; }
            probeServer();
          }
        } catch (e) { /* 轮询失败继续 */ }
      }, 3000);
    } catch (e) {
      el.className = 'qa-vec warn';
      el.innerHTML = '建索引请求失败：' + esc(e.message);
    }
  }

  AISEC.register({
    id: 'm3_qa',
    name: '情报问答',
    // 导出 chainHtml 供 tools/_test_qa_chain.js 在 DOM 桩里断言。
    // 推理链是"跨文档推理"唯一可视的证据，渲染错了（步数算错/不转义/
    // 跳数重复被当成多次跳）用户看不出来，必须有回归钉住。
    chainHtml,
    init() {
      const box = document.querySelector('.searchbox');
      if (!box || $('qapanel')) return;
      const sec = document.createElement('section');
      sec.id = 'qapanel';
      sec.innerHTML = panelHtml();
      box.parentNode.insertBefore(sec, box.nextSibling);
      bind();
      console.log('[m3_qa] 对话面板已挂载');
    },
  });
})();
