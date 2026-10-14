# -*- coding: utf-8 -*-
"""模块侧 v11：① #fff → 令牌；② 追加 :active / 入场编排 / 触屏目标；
   ③ m1 panel.js 实时流"新条目插入动画"（只对真正新增的行播）。"""
import io, sys, os
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
R = r'C:\Users\丁\Desktop\aisec-D_2.0'

HEAD = """

/* ==========================================================================
   v11 纪律层（模块侧）
   --------------------------------------------------------------------------
   ① :active —— 本模块此前 **0 条按压反馈**：按钮点下去毫无动静，用户会以为
      "没点上"而重复点。这里统一补 transform 按压（只动合成层，零重排）。
   ② 入场编排 —— 复用外壳的 viewIn 关键帧，面板切进来时与检索视图同一节奏，
      不再"切到富化台/监测台就很平"。
   ③ 触屏目标 —— 无 hover 的设备上行高抬到 44px（手指点得中）。
   颜色已全部改走核心令牌（v11 颜色收敛），模块不再自带灰阶。
   ========================================================================== */
%s:active{transform:scale(.975)}
%s{transition:transform .18s var(--spring,cubic-bezier(.34,1.56,.64,1)),background .16s ease,color .16s ease,border-color .16s ease}
%s{animation:viewIn .5s var(--ease-out) both}
%s{animation:viewIn .5s var(--ease-out) both}
@media (hover:none){
  %s{min-height:44px}
}
"""

MODS = [
    (r'modules\m0_ops\web\ops.css',
     '.ops-mini-btn,details.ops-fold>summary',
     'details.ops-fold>summary',
     '.ops-fold,.ops-agent,.ops-row',
     '.ops-agent,.ops-row',
     '.ops-mini-btn,.ops-row'),
    (r'modules\m1_monitor\web\daily.css',
     '.mo-daily-sel,.mo-daybtn,.mo-cat-h,.mo-item,.mo-dg-card,.tr-tab,.tr-id,.tr-hbar[data-id],.mo-daily-acts button,.mo-dg-acts button,.mo-dg-acts2 button',
     '.mo-daybtn,.mo-cat-h,.mo-item,.tr-tab,.tr-hbar[data-id]',
     '.mo-day,.mo-dg-card,.mo-item',
     '.mo-dg-card,.mo-dg-acts',
     '.mo-item,.tr-tab,.mo-daybtn,.mo-cat-h'),
    (r'modules\m2_enrich\web\panel.css',
     '.sv-tab,.en-drop,.en-f,.en-more,.en-hist-row,.cm-tab,.cm-drop,.cm-prio,.cm-mail-ck,.cm-file-i .x',
     '.sv-tab,.en-f,.en-more,.cm-tab,.cm-file-i .x',
     '.sv-card,.en-sec,.cm-pane,.asub-card',
     '.en-hist-row,.cm-drop',
     '.sv-tab,.cm-tab,.en-f,.en-more,.cm-mail-ck'),
    (r'modules\m3_qa\web\panel.css',
     '.qa-mini,.qa-src,.qa-q,.qa-cve,.qa-ev-line,.qa-rel-item,.qa-chain>summary',
     '.qa-src,.qa-q,.qa-rel-item,.qa-chain>summary',
     '.qa-card,.qa-msg,.qa-ev,.qa-rel-item',
     '.qa-src',
     '.qa-rel-item,.qa-src,.qa-mini'),
]

for rel, act, trans, blk1, blk2, touch in MODS:
    p = os.path.join(R, rel)
    s = open(p, encoding='utf-8').read()
    o = s
    s = s.replace('#fff;', 'var(--txt-on-solid);').replace('#fff}', 'var(--txt-on-solid)}')
    s = s.replace('#ffffff;', 'var(--txt-on-solid);')
    s = s.rstrip() + HEAD % (act, trans, blk1, blk2, touch)
    open(p, 'w', encoding='utf-8', newline='').write(s)
    print(f'{rel}: Δ{len(s)-len(o):+d}B')

# ---- m1 panel.js：实时流"新条目插入动画"（A4） ----
PJ = os.path.join(R, r'modules\m1_monitor\web\panel.js')
s = open(PJ, encoding='utf-8').read()
o = s
OLD = """        const d = await (await fetch('/api/latest?n=9')).json();
        const t = TYPE_META;
        body.innerHTML = (d.items || []).map((x) => {"""
NEW = """        const d = await (await fetch('/api/latest?n=9')).json();
        const t = TYPE_META;
        const items = d.items || [];
        /* ★ v11（A4）：实时流此前"说出现就出现"，实时感弱。
           这里记住上一轮已显示的 id，只给**真正新增**的行播插入动画
           （整表重绘不重放动画 —— 15s 一轮，全量闪一次会很吵）。 */
        const prevIds = this._ids;
        this._ids = new Set(items.map((x) => x.id));
        const fresh = prevIds ? new Set(items.filter((x) => !prevIds.has(x.id)).map((x) => x.id)) : null;
        body.innerHTML = items.map((x, xi) => {"""
if OLD in s:
    s = s.replace(OLD, NEW)
    print('m1 panel.js: loadLatest 头部已注入')
else:
    print('!! m1 panel.js: loadLatest 头部未匹配')

OLD2 = """          return `<div class="lat" data-id="${esc(x.id)}" title="${esc(ttl)}&#10;点击查看完整内容">"""
NEW2 = """          const isFresh = fresh && fresh.has(x.id);
          return `<div class="lat${isFresh ? ' lat-new' : ''}" data-id="${esc(x.id)}"${isFresh ? ` style="--i:${xi}"` : ''} title="${esc(ttl)}&#10;点击查看完整内容">"""
if OLD2 in s:
    s = s.replace(OLD2, NEW2)
    print('m1 panel.js: 行模板已注入 lat-new')
else:
    print('!! m1 panel.js: 行模板未匹配')

if s != o:
    open(PJ, 'w', encoding='utf-8', newline='').write(s)
