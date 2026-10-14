# -*- coding: utf-8 -*-
"""
交付物配图生成器（技术报告 + 技术讲解 PPT 共用）
================================================================
输出 PNG 到 测试报告/figures/，全部矢量绘制、200dpi，可直接插入 Word/PPT。

    python tools/_gen_figures.py

图清单：
  arch          系统总体分层架构
  flow_monitor  情报监测数据流（含质量分级与双过滤）
  flow_submit   提交链接「秒级收录」决策流程
  flow_enrich   情报富化流水线
  flow_qa       情报问答（深度理解 → 多跳检索 → 溯源生成）
  seq_agents    六智能体协作时序
  flow_cache    索引缓存「精确命中 / 尾部增量 / 全量重建」判定
  perf          性能实测柱状图
"""
import os

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt                       # noqa: E402
from matplotlib.patches import FancyBboxPatch, FancyArrowPatch  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT = os.path.join(ROOT, "测试报告", "figures")
os.makedirs(OUT, exist_ok=True)

for _f in ("Microsoft YaHei", "SimHei", "SimSun", "DengXian"):
    try:
        matplotlib.font_manager.findfont(_f, fallback_to_default=False)
        plt.rcParams["font.sans-serif"] = [_f]
        break
    except Exception:
        continue
plt.rcParams["axes.unicode_minus"] = False

C = {
    "bg": "#ffffff", "ink": "#1f2933", "sub": "#5b6b7c",
    "blue": "#2f6fed", "blue_l": "#e8f0fe",
    "green": "#12805c", "green_l": "#e3f5ee",
    "orange": "#b25e02", "orange_l": "#fdf1e0",
    "purple": "#6b3fa0", "purple_l": "#f0e9fa",
    "red": "#b4232a", "red_l": "#fdeaea",
    "gray": "#eef1f5", "line": "#8a97a6",
}


def _ax(title, w=11.0, h=6.2, xlim=(0, 100), ylim=(0, 100)):
    fig, ax = plt.subplots(figsize=(w, h), dpi=200)
    ax.set_xlim(*xlim)
    ax.set_ylim(*ylim)
    ax.axis("off")
    fig.patch.set_facecolor(C["bg"])
    ax.set_title(title, fontsize=15, color=C["ink"], pad=14, fontweight="bold")
    return fig, ax


def box(ax, x, y, w, h, text, fc=C["blue_l"], ec=C["blue"], tc=C["ink"],
        fs=9, lw=1.4, align="center", va="center"):
    ax.add_patch(FancyBboxPatch((x, y), w, h, boxstyle="round,pad=0.35,rounding_size=1.6",
                                linewidth=lw, edgecolor=ec, facecolor=fc, zorder=2))
    ax.text(x + w / 2, y + h / 2 + (h * 0.10 if va == "bottom" else 0), text,
            ha="center", va="center", fontsize=fs, color=tc, zorder=3, linespacing=1.45)


def arrow(ax, x1, y1, x2, y2, color=C["line"], lw=1.5, style="-|>", ls="-", rad=0.0):
    ax.add_patch(FancyArrowPatch((x1, y1), (x2, y2), arrowstyle=style, mutation_scale=13,
                                 linewidth=lw, color=color, linestyle=ls, zorder=4,
                                 connectionstyle="arc3,rad=%s" % rad))


def label(ax, x, y, t, fs=8, color=C["sub"]):
    ax.text(x, y, t, ha="center", va="center", fontsize=fs, color=color, zorder=5)


def save(fig, name):
    p = os.path.join(OUT, name + ".png")
    fig.savefig(p, bbox_inches="tight", facecolor=C["bg"], dpi=200)
    plt.close(fig)
    print("  →", p)
    return p


# ---------------------------------------------------------------- 1. 总体架构
def fig_arch():
    fig, ax = _ax("图 1  系统总体分层架构", h=7.0)
    layers = [
        ("应用呈现层", C["purple_l"], C["purple"], 1,
         "控制台前端 · 模块面板（监测 / 富化 / 问答 / 编排）｜Markdown 报告导出 · 关系图谱 · 交叉验证看板"),
        ("智能体层（模块0 编排）", C["orange_l"], C["orange"], 1,
         "感知 → 编排 → 富化执行 → 研判 → 决策 → 质疑（六智能体，事件驱动 + 全程留痕）"),
        ("能力层（三大功能模块）", C["blue_l"], C["blue"], 3,
         "① 情报监测 m1：48 源 / 定时增量 / 15s 快车道 / 提交即收录\n"
         "② 情报富化 m2：论文关联 · 资产定位 · POC 搜集 · CVSS 与影响评估\n"
         "③ 情报问答 m3：意图解析 · 多跳推理 · 工具调用 · 溯源生成"),
        ("检索引擎层（core）", C["green_l"], C["green"], 2,
         "BM25 倒排 + 语义向量混合检索 · 分面聚合 · 意图解析\n"
         "索引缓存（精确命中 / 尾部增量）· 写锁并发保护 · 可信度与交叉验证"),
        ("数据层", C["gray"], C["line"], 2,
         "语料库 104,055 条（漏洞 65,015 + 知识 37,699 + 论文 189）\n"
         "48 个情报源：NVD / CISA KEV / arXiv / 中文社区 / GitHub Advisory …"),
    ]
    heights = [11, 11, 22, 15, 15]
    y = 92
    for (name, fc, ec, n, txt), h in zip(layers, heights):
        box(ax, 3, y - h, 26, h, name, fc, ec, fs=10.5)
        ax.text(31.5, y - h / 2, txt, fontsize=8.6, color=C["ink"],
                va="center", ha="left", linespacing=1.8)
        y -= h + 2.4
    return save(fig, "arch")


# ---------------------------------------------------------------- 2. 监测流程
def fig_flow_monitor():
    fig, ax = _ax("图 2  情报监测数据流（含质量分级与双过滤）", h=5.4)
    steps = [
        ("48 个情报源\nNVD/KEV/arXiv/社区", C["blue_l"], C["blue"]),
        ("采集\n定时增量 + 15s 快车道\n+ 用户提交链接", C["blue_l"], C["blue"]),
        ("归一化\n字段对齐 / 日期修复\n去重 by link", C["green_l"], C["green"]),
        ("质量分级\n优/良/中/差\n四维打分 + 惩罚项", C["orange_l"], C["orange"]),
        ("双过滤\n极差过滤 + 近重过滤\n（含誓必留痕）", C["red_l"], C["red"]),
        ("落盘 + 增量索引\nBM25 倒排 + 语义向量", C["purple_l"], C["purple"]),
        ("前端呈现\n最新情报置顶\n质量徽章", C["gray"], C["line"]),
    ]
    x, w, h = 1.5, 13.2, 15
    for i, (t, fc, ec) in enumerate(steps):
        box(ax, x, 62, w, h, t, fc, ec, fs=8.4)
        if i < len(steps) - 1:
            arrow(ax, x + w, 62 + h / 2, x + w + 0.9, 62 + h / 2, C["line"], 1.5)
        x += w + 1.0
    # 过滤分支
    box(ax, 55.5, 34, 26, 12, "过滤命中 → 返回原因，不落盘不索引\n（前端提示「已过滤」并说明依据）",
        C["red_l"], C["red"], fs=8.4)
    arrow(ax, 55.5 + 13, 62, 68.5, 46.5, C["red"], 1.5, ls="--")
    label(ax, 78, 54, "不通过", fs=8, color=C["red"])
    box(ax, 12, 34, 26, 12, "秒级可达：提交 → 抓取 → 判定 → 置顶\n实测端到端 < 3s（要求 ≤ 1 小时）",
        C["green_l"], C["green"], fs=8.4)
    arrow(ax, 25, 34, 25, 61, C["green"], 1.5, ls="--")
    return save(fig, "flow_monitor")


# ---------------------------------------------------------------- 3. 提交收录
def fig_flow_submit():
    fig, ax = _ax("图 3  提交链接「秒级收录」决策流程", h=6.0)
    y = 82
    box(ax, 34, y, 32, 9, "用户提交文章链接\nPOST /api/submit_article", C["blue_l"], C["blue"], fs=9.5)
    arrow(ax, 50, y, 50, y - 5, C["line"])
    y -= 14
    box(ax, 34, y, 32, 9, "抓取正文（persist=0，先不落盘）\n识别平台 / 提取标题正文发布时间", C["blue_l"], C["blue"], fs=9)
    arrow(ax, 50, y, 50, y - 5, C["line"])
    y -= 14
    box(ax, 34, y, 32, 9, "按 link 查重（引擎内加锁 find_id_by_link）", C["green_l"], C["green"], fs=9)
    arrow(ax, 50, y, 50, y - 5, C["line"])
    y -= 14
    box(ax, 34, y, 32, 8, "① 质量极差？", C["orange_l"], C["orange"], fs=9.5)
    arrow(ax, 34, y + 4, 16, y + 4, C["red"], 1.5)
    box(ax, 2, y + 0.5, 13, 7, "过滤：不收录\n返回极差依据", C["red_l"], C["red"], fs=8.2)
    arrow(ax, 50, y, 50, y - 5, C["line"])
    y -= 13
    box(ax, 34, y, 32, 8, "② 过分相同（近重）？\n标题相似 ≥0.9 或 正文包含率 ≥0.6", C["orange_l"], C["orange"], fs=9)
    arrow(ax, 34, y + 4, 16, y + 4, C["red"], 1.5)
    box(ax, 2, y + 0.5, 13, 7, "过滤：疑转载\n给出相似文章", C["red_l"], C["red"], fs=8.2)
    arrow(ax, 50, y, 50, y - 5, C["line"])
    y -= 13
    box(ax, 34, y, 32, 9, "通过 → 落盘 + 富化 + 增量索引 + 置顶 feed\n前端显示质量徽章（优/良/中/差）",
        C["green_l"], C["green"], fs=9)
    label(ax, 50, 6, "全流程实测 < 3s；两道过滤均有「留痕」：被吞异常统一登记，绝不静默失效", fs=8.4)
    return save(fig, "flow_submit")


# ---------------------------------------------------------------- 4. 富化流程
def fig_flow_enrich():
    fig, ax = _ax("图 4  情报富化流水线（论文 / 资产 / POC / 影响评估）", h=5.6)
    box(ax, 38, 76, 24, 12, "一条情报\n（CVE / 公告 / 文章）", C["blue_l"], C["blue"], fs=9.5)
    branches = [
        ("论文关联\narXiv / S2 语义匹配\n标题+摘要 双通道", C["purple_l"], C["purple"]),
        ("受影响资产定位\nCPE / 产品指纹\n互联网暴露面", C["orange_l"], C["orange"]),
        ("POC 搜集与分级\nA/B/C/D 可信度\nExploitDB/GitHub", C["green_l"], C["green"]),
        ("CVSS 与影响评估\nKEV / 可利用性\nATLAS 战术映射", C["red_l"], C["red"]),
    ]
    x = 4
    for t, fc, ec in branches:
        arrow(ax, 50, 76, x + 10, 60, C["line"], 1.4, rad=0.15)
        box(ax, x, 44, 21, 16, t, fc, ec, fs=8.6)
        x += 23
    arrow(ax, 50, 44, 50, 32, C["line"])
    box(ax, 30, 18, 40, 12, "富化结果合并 → 写入 enriched_cache\n详情面板按维度展示 + 交叉验证标记",
        C["gray"], C["line"], fs=9)
    return save(fig, "flow_enrich")


# ---------------------------------------------------------------- 5. 问答流程
def fig_flow_qa():
    fig, ax = _ax("图 5  情报问答流程（深度理解 → 跨文档检索 → 溯源生成）", h=6.0)
    seq = [
        ("自然语言提问\n「vLLM 有哪些 RCE？影响哪些资产？」", C["blue_l"], C["blue"]),
        ("意图解析\n硬约束提取（KEV/CVSS/年份）\n条件链降噪 · 指代消解", C["purple_l"], C["purple"]),
        ("跨文档语义检索\nBM25 + 向量混合 · 多跳推理\n结构化筛选走精确路径", C["green_l"], C["green"]),
        ("工具调用（8 个）\n检索 / 详情 / 资产 / POC\n统计 / 图谱 / 对比 / 导出", C["orange_l"], C["orange"]),
        ("答案生成 + 引用溯源\n逐条标注来源文档与字段名", C["red_l"], C["red"]),
    ]
    y = 80
    for t, fc, ec in seq:
        box(ax, 26, y, 48, 12, t, fc, ec, fs=9)
        if y > 30:
            arrow(ax, 50, y, 50, y - 2.5, C["line"])
        y -= 15
    box(ax, 26, 8, 48, 10, "全过程 TraceRecorder 留痕：谁/何时/调用什么工具/命中多少条/耗时",
        C["gray"], C["line"], fs=8.6)
    return save(fig, "flow_qa")


# ---------------------------------------------------------------- 6. 智能体时序
def fig_seq_agents():
    fig, ax = _ax("图 6  六智能体协作时序（事件驱动 · 全程留痕）", h=6.2)
    actors = ["实时情报流", "① Perception\n感知", "② Orchestrator\n编排",
              "③ EnrichExecutor\n富化执行", "④ BriefAnalyst\n研判",
              "⑤ Decision\n决策", "⑥ Challenger\n质疑"]
    xs = [6, 20, 34, 48, 62, 76, 90]
    for x, a in zip(xs, actors):
        box(ax, x - 6, 88, 12, 9, a, C["blue_l"], C["blue"], fs=7.6)
        ax.plot([x, x], [12, 88], color="#dfe4ea", lw=1, zorder=1)
    steps = [
        (0, 1, "新情报事件（CVSS ≥ 阈值 / KEV / AI 相关）", C["blue"]),
        (1, 2, "上报候选（去重 + 初步打分）", C["purple"]),
        (2, 1, "分派指令（优先级 + 限流 max_per_cycle）", C["orange"]),
        (2, 3, "执行富化：资产定位 + POC 缓存", C["green"]),
        (3, 2, "回传富化结果（成功 / 失败均记录）", C["green"]),
        (2, 4, "交付候选集", C["orange"]),
        (4, 2, "研判简报（结论 + 依据 + 处置建议）", C["red"]),
        (2, 5, "五维信号（CVSS/KEV/POC/资产/修复）", C["orange"]),
        (5, 5, "产出 P0/P1/P2 决策卡 + XAI 推理链", C["red"]),
        (5, 6, "对抗审视（攻击者视角挑战）", C["red"]),
        (6, 5, "修正误判 → 更稳健决策（回填记忆库）", C["green"]),
    ]
    y = 80
    for a, b, t, c in steps:
        arrow(ax, xs[a], y, xs[b], y, c, 1.5)
        ax.text((xs[a] + xs[b]) / 2, y + 2.0, t, ha="center", fontsize=7.2, color=C["ink"])
        y -= 6.2
    label(ax, 50, 5, "节拍 60s / 轮，每轮最多处置 3 条；state 与 trace 均可通过 /api/ops/* 审计", fs=8.0)
    return save(fig, "seq_agents")


# ---------------------------------------------------------------- 7. 缓存判定
def fig_flow_cache():
    fig, ax = _ax("图 7  索引加载：精确命中 / 尾部增量 / 全量重建", h=5.6)
    box(ax, 36, 78, 28, 10, "启动：加载 corpus.json", C["blue_l"], C["blue"], fs=9.5)
    arrow(ax, 50, 78, 50, 70, C["line"])
    box(ax, 36, 60, 28, 10, "存在 .idxcache？", C["gray"], C["line"], fs=9.5)
    arrow(ax, 36, 65, 14, 65, C["red"], 1.5)
    box(ax, 1, 60.5, 12, 9, "全量重建\n（~355s）", C["red_l"], C["red"], fs=8.4)
    arrow(ax, 50, 60, 50, 52, C["line"])
    box(ax, 30, 42, 40, 10, "按缓存记录的 id 顺序重排 docs", C["green_l"], C["green"], fs=9.2)
    arrow(ax, 50, 42, 50, 34, C["line"])
    box(ax, 30, 24, 40, 10, "尾部新增条数 = 0？", C["gray"], C["line"], fs=9.2)
    arrow(ax, 30, 29, 14, 29, C["green"], 1.5)
    box(ax, 1, 24.5, 12, 9, "精确命中\n直接复用", C["green_l"], C["green"], fs=8.4)
    arrow(ax, 50, 24, 50, 16, C["line"])
    box(ax, 24, 6, 52, 10, "新增 ≤ 5000 条 → 复用旧索引 + 只给尾部增量建索引\n（A/B 验证：检索结果与倒排表、df、dl、id_map 与全量重建完全一致）",
        C["orange_l"], C["orange"], fs=8.6)
    arrow(ax, 76, 29, 88, 29, C["red"], 1.5)
    box(ax, 78, 24.5, 20, 9, "超阈值 → 全量重建", C["red_l"], C["red"], fs=8.4)
    return save(fig, "flow_cache")


# ---------------------------------------------------------------- 8. 性能
def fig_perf():
    fig, ax = plt.subplots(figsize=(11, 5.4), dpi=200)
    groups = [
        ("检索接口（端到端，含序列化+传输）",
         ["空查询", "中文查询", "带筛选", "sort=trust", "分页末段"],
         [15.3, 15.7, 2.8, 14.7, 13.2], C["blue"]),
        ("核心接口（端到端）",
         ["/api/stats", "/api/latest", "/api/live", "/api/detail", "/api/related"],
         [14.9, 43.0, 2.8, 2.2, 33.8], C["green"]),
    ]
    fig.patch.set_facecolor(C["bg"])
    for i, (title, xs, ys, col) in enumerate(groups):
        a = fig.add_subplot(1, 2, i + 1)
        b = a.bar(range(len(xs)), ys, color=col, width=0.62)
        a.set_xticks(range(len(xs)))
        a.set_xticklabels(xs, fontsize=8.4, color=C["ink"])
        a.set_title(title, fontsize=10.5, color=C["ink"], pad=10)
        a.set_ylabel("耗时中位数 (ms)", fontsize=8.6, color=C["sub"])
        a.tick_params(labelsize=8.4, colors=C["sub"])
        for s in ("top", "right"):
            a.spines[s].set_visible(False)
        for s in ("left", "bottom"):
            a.spines[s].set_color("#d7dde4")
        a.grid(axis="y", color="#eef1f5", lw=0.8)
        a.set_axisbelow(True)
        for r, v in zip(b, ys):
            a.text(r.get_x() + r.get_width() / 2, v + max(ys) * 0.03, "%.1f" % v,
                   ha="center", fontsize=8, color=C["ink"])
    fig.suptitle("图 8  性能实测（10.4 万条语料，本机回环，中位数）",
                 fontsize=15, fontweight="bold", color=C["ink"], y=1.0)
    fig.tight_layout(rect=(0, 0, 1, 0.94))
    return save(fig, "perf")


if __name__ == "__main__":
    print("生成配图 →", OUT)
    fig_arch()
    fig_flow_monitor()
    fig_flow_submit()
    fig_flow_enrich()
    fig_flow_qa()
    fig_seq_agents()
    fig_flow_cache()
    fig_perf()
    print("完成")
