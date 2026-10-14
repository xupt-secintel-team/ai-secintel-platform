# -*- coding: utf-8 -*-
"""生成竞赛技术报告需要的三张矢量式插图（白底，适合 Word/PDF 打印）。

图 1  系统总体架构与模块分层      → 报告 §2.2
图 2  系统工作流程图（端到端）    → 报告 §2.7
图 3  六智能体工作流程图          → 报告 §4.2

用法：
    <venv python> tools/_gen_report_figures.py
输出：
    tools/_report_figs/arch.png  flow.png  agents.png
"""
import os
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.patches import FancyBboxPatch, FancyArrowPatch

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, "_report_figs")
os.makedirs(OUT, exist_ok=True)

plt.rcParams["font.sans-serif"] = ["Microsoft YaHei", "SimHei", "DengXian"]
plt.rcParams["axes.unicode_minus"] = False
plt.rcParams["font.size"] = 10.5

# 配色（浅底深字，打印友好）
C_BG = "#FFFFFF"
C_CORE = "#1F4E79"      # 深蓝：核心层
C_MOD = "#2E75B6"       # 蓝：业务模块
C_AGENT = "#548235"     # 绿：智能体层
C_APP = "#BF8F00"       # 橙：应用层
C_DATA = "#7030A0"      # 紫：数据层
C_LINE = "#404040"
C_TEXT = "#1A1A1A"
C_SUB = "#5A5A5A"


def box(ax, x, y, w, h, face, edge=None, alpha=0.14, lw=1.3, radius=0.02):
    """画一个圆角矩形（半透明填充 + 实线边框）"""
    b = FancyBboxPatch((x, y), w, h,
                       boxstyle="round,pad=0.012,rounding_size=%.3f" % (radius),
                       linewidth=lw, edgecolor=edge or face,
                       facecolor=face, alpha=alpha, zorder=1)
    ax.add_patch(b)
    return b


def label(ax, x, y, text, size=10.5, color=C_TEXT, bold=False, ha="center",
          va="center", zorder=5):
    ax.text(x, y, text, fontsize=size, color=color, ha=ha, va=va,
            fontweight="bold" if bold else "normal", zorder=zorder)


def arrow(ax, x1, y1, x2, y2, color=C_LINE, lw=1.5, style="-|>", rad=0.0,
          ls="-", mutate=9):
    ax.annotate("", xy=(x2, y2), xytext=(x1, y1), zorder=4,
                arrowprops=dict(arrowstyle=style, color=color, lw=lw,
                                linestyle=ls, mutation_scale=mutate,
                                connectionstyle="arc3,rad=%.2f" % rad,
                                shrinkA=1, shrinkB=1))


def canvas(w, h):
    fig, ax = plt.subplots(figsize=(w, h), dpi=200)
    fig.patch.set_facecolor(C_BG)
    ax.set_facecolor(C_BG)
    ax.set_xlim(0, 100)
    ax.set_ylim(0, 100)
    ax.axis("off")
    ax.set_aspect("auto")
    return fig, ax


# ══════════════════════════════════════════════════════════════════
# 图 1：系统总体架构与模块分层
# ══════════════════════════════════════════════════════════════════
def fig_arch():
    fig, ax = canvas(10.2, 7.0)
    label(ax, 50, 96, "图 · AI-SecIntel 系统总体架构（微内核 + 插件化，五层单向依赖）",
          size=12.5, bold=True)

    layers = [
        (78.5, C_APP,   "应用层",  "单页控制台 · 检索工作区 · 实时监测台 · 情报问答 · 关系图谱",
         "双.html/js + 原生 CSS，无构建，双击即用"),
        (64.5, C_AGENT, "智能体层（m0_ops）", "感知 → 编排 → 富化执行 → 研判 → 决策 → 质疑（六智能体，事件驱动）",
         "处置闭环回填记忆库 · 全链路 trace 留痕"),
        (50.5, C_MOD,   "业务模块层（插件）", "m1_monitor 情报监测　│　m2_enrich 情报富化　│　m3_qa 情报问答",
         "module.json 契约 + 注册中心反向装配，模块间不互相 import"),
        (36.5, C_CORE,  "核心宿主 core/", "HTTP 服务 · 四级评分检索引擎 · 可信度评估 · ATLAS 知识库 · 关系图谱 · 报告导出",
         "路径/网络/日志/追踪基础设施　│　性能画像 envprofile · 兼容层 compat"),
        (22.5, C_DATA,  "数据层 data/", "语料 104,055 条（漏洞 65,341 / 威胁知识 37,724 / 论文 204）· 倒排索引 · 磁盘缓存",
         "JSONL / JSON 明文明码存储，可离线审计；索引缓存支持尾部增量"),
    ]

    H = 11.0
    positions = []
    for idx, (y0, color, title, body, note) in enumerate(layers):
        box(ax, 6, y0 - H / 2, 88, H, color)
        # 左侧色条
        ax.add_patch(plt.Rectangle((6, y0 - H / 2), 1.1, H, color=color,
                                   alpha=0.85, zorder=3))
        label(ax, 12.5, y0 + 2.6, title, size=11.5, bold=True, color=color, ha="left")
        label(ax, 33.5, y0 + 2.6, body, size=9.6, color=C_TEXT, ha="left")
        label(ax, 12.5, y0 - 2.2, note, size=8.8, color=C_SUB, ha="left")
        positions.append(y0)

    for i in range(len(positions) - 1):
        y_hi, y_lo = positions[i], positions[i + 1]
        arrow(ax, 50, y_hi - H / 2 - 0.4, 50, y_lo + H / 2 + 0.4,
              color=C_LINE, lw=1.6)
    # 单向依赖标注（放在最底层框与横切框之间的留白里）
    label(ax, 50, 14.2, "单向依赖：上层可调用下层，下层不反向依赖（依赖倒置由注册表实现）",
          size=8.6, color=C_SUB)

    # 右侧：横切关注点（正文拆两行，避免溢出边框）
    box(ax, 6, 2.0, 88, 9.5, "#8A8A8A", alpha=0.07, lw=1.0)
    label(ax, 50, 8.6, "横切关注点（贯穿五层）", size=9.8, bold=True, color="#444444")
    label(ax, 50, 5.6,
          "性能画像降档（low/mid/high）　│　跨平台兼容层（Python 3.7+ / Windows·Linux·macOS）　│　静默异常留痕与治理",
          size=8.2, color=C_SUB)
    label(ax, 50, 3.4,
          "并发写锁与原子落盘　│　config.json 集中配置（Key 不进代码）　│　可复跑的验证工具链",
          size=8.2, color=C_SUB)

    fp = os.path.join(OUT, "arch.png")
    fig.savefig(fp, facecolor=C_BG, bbox_inches="tight", pad_inches=0.12)
    plt.close(fig)
    return fp


# ══════════════════════════════════════════════════════════════════
# 图 2：系统工作流程图（端到端）
# ══════════════════════════════════════════════════════════════════
def fig_flow():
    fig, ax = canvas(11.0, 7.6)
    label(ax, 50, 96.5, "图 · AI-SecIntel 系统工作流程图（端到端）", size=12.5, bold=True)

    def node(x, y, w, h, title, sub, color, lw=1.3):
        box(ax, x - w / 2, y - h / 2, w, h, color, lw=lw)
        if sub:
            label(ax, x, y + h / 2 - 2.0, title, size=10.2, bold=True, color=color)
            label(ax, x, y - h / 2 + 2.0, sub, size=8.4, color=C_SUB)
        else:
            label(ax, x, y, title, size=10.2, bold=True, color=color)

    # ── 左列：采集侧 ──
    label(ax, 14, 88, "① 情报采集与准入", size=10.5, bold=True, color=C_MOD)
    node(14, 79, 24, 10, "48 个情报源", "NVD / GitHub / arXiv / 厂商公告 …", C_MOD)
    node(14, 66, 24, 10, "双通道采集", "快车道 15s + 深同步分钟级", C_MOD)
    node(14, 53, 24, 10, "质量分级 + 双过滤", "0–100 分四级 · 质量极差 / 过分相同", C_MOD)
    node(14, 40, 24, 10, "AI 相关性闸门", "阈值 0.45，四类信号综合判定", C_MOD)
    node(14, 27, 24, 10, "统一 schema 落盘", "JSONL + 原子写 + 并发写锁", C_DATA)

    for a, b in ((74, 71), (61, 58), (48, 45), (35, 32)):
        arrow(ax, 14, a, 14, b, lw=1.5)

    # ── 中列：索引 ──
    label(ax, 40, 88, "② 索引与服务", size=10.5, bold=True, color=C_CORE)
    box(ax, 29, 7.5, 22, 64.5, C_CORE, alpha=0.07, lw=1.2)
    label(ax, 40, 64.0, "倒排索引 · 三级缓存判定", size=10.0, bold=True, color=C_CORE)
    label(ax, 40, 58.5, "精确命中 / 尾部增量 / 全量重建", size=8.8, color=C_SUB)
    label(ax, 40, 52.0, "冷启动 355s → 8.9s", size=9.4, bold=True, color="#C00000")
    label(ax, 40, 45.0, "四级评分检索引擎", size=10.0, bold=True, color=C_CORE)
    label(ax, 40, 39.5, "BM25 + 领域短语 + 概念空间 + 业务信号", size=8.6, color=C_SUB)
    label(ax, 40, 33.0, "结构化查询操作符", size=10.0, bold=True, color=C_CORE)
    label(ax, 40, 27.5, "product: / cvss>=N / kev:yes", size=8.6, color=C_SUB)
    label(ax, 40, 20.5, "HTTP 统一网关 · 插件路由装配", size=9.6, bold=True, color=C_CORE)

    arrow(ax, 26.5, 27, 29.5, 27, lw=1.6)

    # ── 右列：服务输出 ──
    label(ax, 72, 88, "③ 三条能力主线", size=10.5, bold=True, color=C_MOD)
    node(72, 79, 26, 11, "情报监测 m1_monitor", "实时监测台 · 秒级收录 · 快车道推送", C_MOD)
    node(72, 65, 26, 11, "情报富化 m2_enrich", "论文 / 资产 / POC / 影响评估 四维富化", C_MOD)
    node(72, 51, 26, 11, "情报问答 m3_qa", "意图解析 · 混合检索 · 多跳 · 答案溯源", C_MOD)
    node(72, 37, 26, 11, "知识图谱 / 报告导出", "多跳关联 · ATLAS 战术映射 · Word/PDF", C_MOD)

    arrow(ax, 51.5, 55, 58.5, 79, lw=1.4, rad=-0.12)
    arrow(ax, 51.5, 50, 58.5, 65, lw=1.4, rad=-0.05)
    arrow(ax, 51.5, 45, 58.5, 51, lw=1.4, rad=0.05)
    arrow(ax, 51.5, 40, 58.5, 37, lw=1.4, rad=0.12)

    # ── 底部：编排闭环 ──
    box(ax, 58, 12, 46, 14, C_AGENT, alpha=0.10, lw=1.2)
    label(ax, 81, 21.5, "④ 智能编排闭环（事件驱动 · 60s 节拍）", size=10.2,
          bold=True, color=C_AGENT)
    label(ax, 81, 16.5, "感知 → 编排 → 富化执行 → 研判 → 决策，质疑做红方对抗并回注决策",
          size=9.4, color=C_TEXT)
    arrow(ax, 72, 31.5, 72, 26.5, color=C_AGENT, lw=1.6)
    arrow(ax, 46.5, 19, 58, 19, color=C_AGENT, lw=1.4, ls="--")

    # 底部：前端
    box(ax, 5, 3.5, 46, 10, C_APP, alpha=0.10, lw=1.1)
    label(ax, 28, 9.5, "⑤ 浏览器端单页控制台", size=10.2, bold=True, color=C_APP)
    label(ax, 28, 5.5, "检索 / 监测 / 富化 / 问答 四视图　·　检索中位 15ms　·　提交收录 <3s",
          size=8.8, color=C_SUB)
    arrow(ax, 16, 22, 16, 13.8, color=C_APP, lw=1.5)

    fp = os.path.join(OUT, "flow.png")
    fig.savefig(fp, facecolor=C_BG, bbox_inches="tight", pad_inches=0.12)
    plt.close(fig)
    return fp


# ══════════════════════════════════════════════════════════════════
# 图 3：六智能体工作流程图
# ══════════════════════════════════════════════════════════════════
def fig_agents():
    fig, ax = canvas(11.0, 6.9)
    label(ax, 50, 96, "图 · 六智能体工作流程图（感知 → 编排 → 富化执行 → 研判 → 决策，质疑对抗审视）",
          size=12.5, bold=True)

    # ── 输入条（顶部） ──
    box(ax, 8, 83.5, 84, 9, C_MOD, alpha=0.08, lw=1.0)
    label(ax, 50, 89.8, "输入：监测模块快车道情报流（data/live_feed.jsonl 尾部增量）",
          size=9.4, color=C_MOD, bold=True)
    label(ax, 50, 85.9, "触发条件：CVSS ≥ 9.0　/　已入 CISA KEV　/　AI 安全相关",
          size=8.4, color=C_SUB)

    # ── 主干：六个角色横向排列 ──
    roles = [
        ("① 感知", "Perception", "监听实时流\n筛选高价值事件", C_MOD),
        ("② 编排", "Orchestrator", "优先级排序\n限流分派 60s/轮", C_CORE),
        ("③ 富化执行", "EnrichExecutor", "资产定位\nPOC 缓存检索", C_MOD),
        ("④ 研判", "BriefAnalyst", "证据链汇总\n输出研判简报", C_MOD),
        ("⑤ 决策", "DecisionAgent", "P0/P1/P2\n可解释推理链", C_AGENT),
        ("⑥ 质疑", "ChallengerAgent", "红方对抗审视\n命中就地修正", "#C00000"),
    ]
    xs = [11, 25, 39, 53, 67, 81]
    W, H = 12.5, 17
    CY = 70.0
    for (seq, en, desc, color), x in zip(roles, xs):
        box(ax, x - W / 2, CY - H / 2, W, H, color, lw=1.4)
        label(ax, x, CY + 5.0, seq, size=11.0, bold=True, color=color)
        label(ax, x, CY + 2.0, en, size=8.0, color=C_SUB)
        label(ax, x, CY - 4.6, desc, size=8.6, color=C_TEXT)

    for i in range(len(xs) - 1):
        arrow(ax, xs[i] + W / 2 + 0.4, CY, xs[i + 1] - W / 2 - 0.4, CY, lw=1.8)

    # 红蓝自博弈说明：放在主干与结果层之间，左侧留出竖直连线的通道
    label(ax, 17, 55.5,
          "⑤ → ⑥ 红蓝自博弈：质疑智能体对决策做对抗审视，命中盲区即就地修正"
          "（实测 CVSS 9.8 误判 P1 自动升档 P0）",
          size=9.0, color="#C00000", bold=True, ha="left")

    # ── 结果层：三块产出与沉淀 ──
    box(ax, 4, 35, 29, 14, C_CORE, alpha=0.09, lw=1.1)
    label(ax, 18.5, 46.0, "产出落盘 · 可追溯", size=9.8, bold=True, color=C_CORE)
    label(ax, 18.5, 41.2, "ops_events（事件流水）· ops_briefs（研判简报）", size=8.2, color=C_SUB)
    label(ax, 18.5, 37.4, "ops_decisions（处置决策）· trace（协作留痕）", size=8.2, color=C_SUB)

    box(ax, 35.5, 35, 29, 14, C_DATA, alpha=0.09, lw=1.1)
    label(ax, 50, 46.0, "处置闭环回填 · 自我进化", size=9.8, bold=True, color=C_DATA)
    label(ax, 50, 41.2, "DispositionStore → data/dispositions.json", size=8.2, color=C_SUB)
    label(ax, 50, 37.4, "同 CVE 秒判 · 同组件关联 · 越用越准", size=8.2, color=C_SUB)

    box(ax, 67, 35, 29, 14, C_AGENT, alpha=0.09, lw=1.1)
    label(ax, 81.5, 46.0, "溯源归因 · CTI 多跳图谱", size=9.8, bold=True, color=C_AGENT)
    label(ax, 81.5, 41.2, "威胁主体画像（含置信度）+ ATT&CK 战术链路", size=8.2, color=C_SUB)
    label(ax, 81.5, 37.4, "/api/graph?hops=N 返回可解释多跳路径", size=8.2, color=C_SUB)

    # 结果层内部的记忆回流（框间留白处，不压框体）
    label(ax, 50, 30.5,
          "记忆库反向喂养决策 →「决策 → 回填 → 复用 → 更准决策」自我进化闭环",
          size=8.8, color=C_SUB)

    # ── 消费条（底部） ──
    box(ax, 8, 8, 84, 11, C_APP, alpha=0.08, lw=1.0)
    label(ax, 50, 15.4, "消费：编排面板 · 决策卡片 · /api/ops/* 三个审计接口",
          size=9.4, color=C_APP, bold=True)
    label(ax, 50, 11.2, "status（3.7ms）　·　events（最近 50 条）　·　trace（50 条 / 23.3ms）",
          size=8.4, color=C_SUB)

    # ── 纵向连线：统一走最左侧通道，避开所有文字 ──
    arrow(ax, 10, 83.5, 10, CY + H / 2 + 0.4, color=C_MOD, lw=1.6)
    arrow(ax, 10, CY - H / 2 - 0.4, 10, 49.1, color=C_LINE, lw=1.6)
    arrow(ax, 10, 35, 10, 19.1, color=C_APP, lw=1.6)

    fp = os.path.join(OUT, "agents.png")
    fig.savefig(fp, facecolor=C_BG, bbox_inches="tight", pad_inches=0.12)
    plt.close(fig)
    return fp


if __name__ == "__main__":
    for fn in (fig_arch, fig_flow, fig_agents):
        p = fn()
        print("[OK] %s  (%.1f KB)" % (p, os.path.getsize(p) / 1024))
