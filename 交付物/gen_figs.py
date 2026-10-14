# -*- coding: utf-8 -*-
"""生成 AI-SecIntel 竞赛技术报告的高质量配图（真实数据）。"""
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib import font_manager
from matplotlib.patches import FancyBboxPatch
import matplotlib.ticker as mticker
import os

# 中文字体
for fp in [r"C:\Windows\Fonts\msyh.ttc", r"C:\Windows\Fonts\simhei.ttf"]:
    if os.path.exists(fp):
        font_manager.fontManager.addfont(fp)
plt.rcParams["font.family"] = "Microsoft YaHei"
plt.rcParams["axes.unicode_minus"] = False

OUT = r"E:\aisec-D_3\aisec-D_2.0(1)\aisec-D_2.0\交付物\图"
os.makedirs(OUT, exist_ok=True)

# 配色（专业深蓝 + 香槟金点缀，呼应项目视觉）
INK = "#0b0a08"
BLUE = "#2f5d9e"
GOLD = "#c89b3c"
TEAL = "#2fbf9e"
GREY = "#8a8f98"

def style_ax(ax):
    for s in ["top", "right"]:
        ax.spines[s].set_visible(False)
    ax.spines["left"].set_color(GREY)
    ax.spines["bottom"].set_color(GREY)
    ax.tick_params(colors="#444", labelsize=11)
    ax.set_facecolor("white")

# ---------------------------------------------------------------------------
# 图1：资产风险分析闭环（三大能力架构图）—— 第6章新增 6.10 节
# ---------------------------------------------------------------------------
def fig_asset_loop():
    fig, ax = plt.subplots(figsize=(11, 5.6), dpi=200)
    ax.set_xlim(0, 100); ax.set_ylim(0, 52); ax.axis("off")

    def box(x, y, w, h, title, lines, fc, tc="white", fs=11):
        ax.add_patch(FancyBboxPatch((x, y), w, h, boxstyle="round,pad=0,rounding_size=1.2",
                                    facecolor=fc, edgecolor="none", zorder=2))
        ax.text(x+w/2, y+h-4.2, title, ha="center", va="center",
                color=tc, fontsize=fs+1.5, fontweight="bold", zorder=3)
        for i, ln in enumerate(lines):
            ax.text(x+w/2, y+h-8.2-i*5.2, ln, ha="center", va="center",
                    color=tc, fontsize=fs-2.2, alpha=0.92, zorder=3)

    # 三路输入（公司资产的三种载体）
    box(2, 34, 26, 15, "① CMDB 资产分析", ["对接公司 CMDB", "rest / inline / file 三模式", "脆弱性 + 处置优先级"], BLUE, fs=10)
    box(37, 34, 26, 15, "② 项目成分扫描 (SCA)", ["导入 zip / 代码目录", "识别依赖清单 → 匹配 CVE", "出 CMDB 风格风险报告"], TEAL, fs=10)
    box(72, 34, 26, 15, "③ 端口测绘", ["域名/IP → 并发 TCP 扫描", "开放端口 + 服务 + banner", "仅限授权目标"], GOLD, tc=INK, fs=10)

    # 中间汇聚层
    ax.add_patch(FancyBboxPatch((18, 17), 64, 11, boxstyle="round,pad=0,rounding_size=1.2",
                                facecolor="#f4efe3", edgecolor=GOLD, linewidth=1.4, zorder=2))
    ax.text(50, 24.6, "统一资产风险分析引擎", ha="center", va="center",
            color=INK, fontsize=13, fontweight="bold", zorder=3)
    ax.text(50, 20.2, "复用 CPE 版本区间匹配 + CWE/CVSS/KEV 处置推导（同一套判据）",
            ha="center", va="center", color="#555", fontsize=10, zorder=3)

    # 结论层
    ax.add_patch(FancyBboxPatch((18, 3), 64, 9, boxstyle="round,pad=0,rounding_size=1.2",
                                facecolor=INK, edgecolor="none", zorder=2))
    ax.text(50, 9.6, "直接对公司资产进行分析并得出结论", ha="center", va="center",
            color="white", fontsize=13.5, fontweight="bold", zorder=3)
    ax.text(50, 5.2, "优先修谁 → 怎么修 → 怎么验收，报告可下载",
            ha="center", va="center", color="#d9d9d9", fontsize=10, zorder=3)

    # 箭头
    for cx in [15, 50, 85]:
        ax.annotate("", xy=(cx, 29.2), xytext=(cx, 34),
                    arrowprops=dict(arrowstyle="-|>", color=GOLD, lw=1.6))
    ax.annotate("", xy=(50, 13.2), xytext=(50, 17),
                arrowprops=dict(arrowstyle="-|>", color=GOLD, lw=1.8))

    ax.set_title("图 6-5  资产风险分析闭环：三种资产入口，汇聚为同一结论",
                 fontsize=13, color=INK, pad=12, fontweight="bold")
    fig.tight_layout()
    fig.savefig(os.path.join(OUT, "img_asset_loop.png"), bbox_inches="tight", facecolor="white")
    plt.close(fig)

# ---------------------------------------------------------------------------
# 图2：语料风险分类分布（第8章）—— 真实 corpus.json 数据
# ---------------------------------------------------------------------------
def fig_corpus_dist():
    cats = ["① AI基础设施与推理框架", "② 模型与数据层", "③ AI应用与智能体", "④ AI供应链与平台",
            "⑤ Web应用与API安全", "⑥ 系统与二进制安全", "⑦ 网络与协议安全", "⑧ 云原生与容器安全",
            "⑨ 身份与访问管理", "⑩ 恶意代码与威胁活动", "⑪ 数据安全与密码学".replace("⑪", "十一")]
    vals = [414, 741, 1139, 538, 30326, 22370, 3729, 362, 6822, 429, 3659]
    # 反转使最大在最上（横向条形图）
    cats_r = cats[::-1]; vals_r = vals[::-1]
    colors = []
    for c in cats_r:
        colors.append(GOLD if (c.startswith(("①", "②", "③", "④"))) else BLUE)

    fig, ax = plt.subplots(figsize=(10.5, 6.2), dpi=200)
    bars = ax.barh(range(len(cats_r)), vals_r, color=colors, height=0.66)
    ax.set_yticks(range(len(cats_r)))
    ax.set_yticklabels(cats_r, fontsize=10.5)
    ax.set_xlabel("情报条数（条）", fontsize=11)
    for i, (b, v) in enumerate(zip(bars, vals_r)):
        ax.text(v + 250, i, f"{v:,}", va="center", fontsize=9.5, color="#333")
    ax.set_xlim(0, 34000)
    style_ax(ax)
    # 图例
    from matplotlib.patches import Patch
    ax.legend(handles=[Patch(color=GOLD, label="AI 安全四类（合计 2,832 条）"),
                       Patch(color=BLUE, label="传统/通用安全七类")],
              loc="lower right", fontsize=10, frameon=False)
    ax.set_title("图 8-1  平台语料风险分类分布（真实语料 corpus.json，共 70,529 条）",
                 fontsize=13, color=INK, pad=12, fontweight="bold")
    fig.tight_layout()
    fig.savefig(os.path.join(OUT, "img_corpus_dist.png"), bbox_inches="tight", facecolor="white")
    plt.close(fig)

# ---------------------------------------------------------------------------
# 图3：接口性能实测（第9章）—— 表9-1 真实数据
# ---------------------------------------------------------------------------
def fig_perf():
    apis = ["search\n空查询", "search\n中文", "search\n带筛选", "search\nsort=trust",
            "stats", "latest\nn=22", "live", "detail", "related", "assets", "suggest", "corpus\ngzip"]
    med = [15.3, 15.7, 2.8, 14.7, 14.9, 43.0, 2.8, 2.2, 33.8, 22.1, 8.7, 139.3]
    colors = [GOLD if v == max(med) else BLUE for v in med]

    fig, ax = plt.subplots(figsize=(10.5, 5.4), dpi=200)
    bars = ax.bar(range(len(apis)), med, color=colors, width=0.6)
    ax.set_xticks(range(len(apis)))
    ax.set_xticklabels(apis, fontsize=8.5)
    ax.set_ylabel("中位耗时（ms）", fontsize=11)
    for i, (b, v) in enumerate(zip(bars, med)):
        ax.text(i, v + 2.5, f"{v:.1f}", ha="center", fontsize=8.8, color="#333")
    ax.set_ylim(0, 160)
    style_ax(ax)
    ax.axhline(16.5, color=GOLD, lw=1.2, ls="--", alpha=0.7)
    ax.text(4.5, 19.5, "检索类接口中位 ≤16.5ms", color=GOLD, fontsize=9.5, ha="center")
    ax.set_title("图 9-1  核心接口中位耗时实测（十万级语料，据表 9-1）",
                 fontsize=13, color=INK, pad=12, fontweight="bold")
    fig.tight_layout()
    fig.savefig(os.path.join(OUT, "img_perf.png"), bbox_inches="tight", facecolor="white")
    plt.close(fig)

# ---------------------------------------------------------------------------
# 图4：创新点全景（第10章）
# ---------------------------------------------------------------------------
def fig_innovation():
    fig, ax = plt.subplots(figsize=(11, 5.2), dpi=200)
    ax.set_xlim(0, 100); ax.set_ylim(0, 46); ax.axis("off")
    items = [
        ("微内核 + 插件化", "架构", BLUE),
        ("四级评分 + 结构化查询", "检索", BLUE),
        ("Agentic RAG + 多跳回退", "问答", TEAL),
        ("15s 快车道 + 深同步", "监测", TEAL),
        ("POC 五源 + 资产三路提取", "富化", TEAL),
        ("资产分析闭环", "落地", GOLD),
        ("尾部增量索引缓存", "工程", GREY),
        ("可验证 · 可留痕 · 可自愈", "工程", GREY),
    ]
    for i, (name, tag, c) in enumerate(items):
        col = i % 4; row = i // 4
        x = 2 + col * 24.5; y = 34 - row * 20
        ax.add_patch(FancyBboxPatch((x, y), 21, 12, boxstyle="round,pad=0,rounding_size=1.2",
                                    facecolor=c, edgecolor="none", zorder=2))
        ax.text(x+10.5, y+8, name, ha="center", va="center", color="white",
                fontsize=10.5, fontweight="bold", zorder=3)
        ax.text(x+10.5, y+3.2, tag, ha="center", va="center", color="white",
                fontsize=8.5, alpha=0.85, zorder=3)
    ax.text(50, 2, "八项创新点，共同支撑「面向 AI 安全的资产风险分析平台」定位",
            ha="center", va="center", color=INK, fontsize=12.5, fontweight="bold")
    ax.set_title("图 10-1  创新点全景总览", fontsize=13, color=INK, pad=10, fontweight="bold")
    fig.tight_layout()
    fig.savefig(os.path.join(OUT, "img_innovation.png"), bbox_inches="tight", facecolor="white")
    plt.close(fig)

for fn in [fig_asset_loop, fig_corpus_dist, fig_perf, fig_innovation]:
    fn()
    print("generated:", fn.__name__)
print("DONE")
