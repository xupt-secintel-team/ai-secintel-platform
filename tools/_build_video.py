# -*- coding: utf-8 -*-
"""
操作演示视频合成
================================================================
把「技术讲解幻灯片」与「界面实录帧」合成一支带字幕的演示视频：

    幻灯片（讲解）    → 每页按字幕长度分配停留时长，页间交叉淡化
    界面实录（演示）  → 紧随相关讲解页出现，直观展示功能

输出：交付物/AI-SecIntel_2.0_操作演示.mp4   1920x1080 / 30fps / H.264

关于画面来源的说明（诚实声明）：
    界面帧的画面由 tools/_capture_ui.py 生成 —— 其中**所有数字、条数、
    质量分级、过滤原因、接口耗时都来自对本机 8848 端口服务的真实 HTTP 调用**
    （原始 JSON 已落盘 测试报告/_capture_raw.json 以备核对），
    只是按控制台配色重新排版绘制；本机无可用浏览器自动化内核，故未直接录制浏览器窗口。

    python tools/_build_video.py
"""
import os
import shutil
import subprocess
import sys

from PIL import Image, ImageDraw, ImageFont

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SLIDES = os.path.join(ROOT, "测试报告", "_video_frames")
UI = os.path.join(ROOT, "测试报告", "_video_frames_ui")
TMP = os.path.join(ROOT, "测试报告", "_video_build")
OUT = os.path.join(ROOT, "交付物", "AI-SecIntel_2.0_操作演示.mp4")

W, H, FPS = 1920, 1080, 30
XFADE = 0.45                       # 交叉淡化时长（秒）

SUB_FONT = r"C:\Windows\Fonts\msyh.ttc"
SUB_FONT_BD = r"C:\Windows\Fonts\msyhbd.ttc"


def rgb(c):
    return c


# (帧来源, 字幕, 停留秒数)   —— 幻灯片按页码取，UI 按文件名取
PLAN = [
    ("slide_00", "AI-SecIntel 2.0 —— AI 安全情报智能监测平台，下面演示完整能力链路", 5.5),
    ("slide_01", "演示分为八个部分：从架构与智能体方案，到监测、富化、问答三大模块", 5.0),
    ("slide_02", "先看设计目标：时效敏感、信噪比低、语义复杂、可信度差异大，这四条约束决定了全部技术选型", 7.0),
    ("slide_03", "系统采用五层架构，模块通过 module.json 声明式注册，新增模块无需改动主体代码", 7.0),
    ("slide_04", "写操作频率低、读多写少，因此引擎侧用一把可重入锁串行化写路径，读路径完全不加锁", 6.5),
    ("01_console", "这是控制台的真实运行状态：语料 10 万+ 条、48 个情报源，检索接口响应毫秒级", 7.0),
    ("slide_05", "智能体层解决「被动检索」的问题：感知、编排、富化执行、研判、决策、质疑六个智能体事件驱动协作", 7.0),
    ("slide_06", "多智能体最大的风险是黑箱，所以我们把「谁、何时、做了什么、成败、耗时」全部留痕可审计", 7.0),
    ("06_ops", "六智能体在列：决策智能体产出 P0/P1/P2 决策卡，质疑智能体红蓝自博弈修正，处置结果回填记忆库实现自我进化", 8.0),
    ("slide_07", "情报监测模块接入 48 个情报源，15 秒快车道轮询，并支持任意客户提交文章链接", 7.0),
    ("slide_08", "提交链接采用「先判定、后落盘」：抓取时不写盘，两道过滤都通过才落盘建索引，保证语料零污染", 7.5),
    ("02_submit_ok", "实测提交一条投稿：抓取、净化、查重、质量判定、收录、置顶，端到端远低于 1 小时的要求", 7.0),
    ("slide_09", "文章质量用四维模型打分：篇幅、结构、安全词密度、信息度，再叠加三类惩罚项，输出四级分类", 7.5),
    ("slide_10", "近重检测用标题相似度与正文包含率双通道判定，并加强候选召回，专治转载与洗稿", 7.5),
    ("03_submit_filter", "两道过滤的真实效果：广告软文判为质检不通过；同正文换链接的稿件标题相似度 1.0、正文包含率 1.0，被拦截", 8.0),
    ("slide_11", "富化模块为情报补全四个维度的上下文：关联论文、受影响资产、POC 搜集、CVSS 与影响评估", 7.0),
    ("04_enrich", "富化详情页展示真实数据：关联论文、受影响产品、POC 链接与 ATLAS 战术映射", 6.5),
    ("slide_12", "POC 不能一视同仁：我们做 A/B/C/D 四级可信度判定，避免使用者被不可靠的 POC 误导", 6.5),
    ("slide_13", "问答模块要解决的是理解复杂意图、跨文档语义检索与关联推理，而不是关键词匹配", 7.0),
    ("slide_14", "硬约束提取、条件链降噪、多轮指代消解、实体抽取，这四项是问答质量的地基", 7.0),
    ("05_qa", "真实问答演示：一次问清两个条件，系统给出结论、依据与来源；追问「第一个漏洞」也能正确消解指代", 8.0),
    ("slide_15", "工程优化第一部分：我们曾因异常被吞导致近重过滤静默失效，于是把它变成了一套工程能力——扫描 109 个文件、6 类缺陷模式，112 处静默异常全部治理", 9.0),
    ("slide_16", "工程优化第二部分：索引缓存改为三级判定，破解持续收录场景下「每次重启都全量重建」的死循环", 8.0),
    ("slide_17", "优化不能靠猜：我们做了 A/B 逐项比对，检索结果、倒排表、文档频次与长度全部一致", 7.5),
    ("slide_18", "性能实测：检索类接口 2.8 到 16.5 毫秒，带强筛选的查询仅 2.8 毫秒，验证了查询路由设计有效", 7.0),
    ("07_perf", "本次优化最直观的收益：冷启动从 355.5 秒降到 8.9 秒，提升约 40 倍", 7.0),
    ("slide_19", "所有结论都可复跑：80 项系统自测、27 项端到端用例、索引增量 A/B、静态缺陷扫描全部通过", 7.5),
    ("slide_20", "前三个创新点：把文章质量做成可计算指标，把静默失效变成工程能力，把索引缓存做成尾部增量", 7.5),
    ("slide_21", "另外三个：AI 安全深度专业化、六智能体从被动检索到「决策 + 进化」、处置闭环回填自我进化", 8.0),
    ("slide_22", "再三个：CTI 多跳图谱关联、溯源归因到威胁主体与 ATT&CK 战术链、可验证的工程严谨性", 8.0),
    ("slide_23", "以上就是全部交付物。谢谢观看，欢迎复跑验证。", 6.0),
]

SUBTITLE_BG = (12, 26, 48, 205)
SUB_TEXT = (255, 255, 255)
ACCENT = (61, 126, 232)


def fit_frame(src):
    im = Image.open(src).convert("RGB")
    canvas = Image.new("RGB", (W, H), (10, 22, 42))
    r = min(W / im.width, H / im.height)
    nw, nh = int(im.width * r), int(im.height * r)
    im = im.resize((nw, nh), Image.LANCZOS)
    canvas.paste(im, ((W - nw) // 2, (H - nh) // 2))
    return canvas


def wrap(draw, text, f, max_w):
    lines, cur = [], ""
    for ch in text:
        if draw.textlength(cur + ch, font=f) > max_w and cur:
            lines.append(cur)
            cur = ch
        else:
            cur += ch
    if cur:
        lines.append(cur)
    return lines


def with_subtitle(img, text):
    """底部字幕条：半透明底 + 左侧强调色竖条 + 居中文案。"""
    d = ImageDraw.Draw(img)
    f = ImageFont.truetype(SUB_FONT, 34)
    lines = wrap(d, text, f, 1620)[:2]
    lh = 50
    bh = 30 + lh * len(lines)
    y0 = H - bh - 26
    overlay = Image.new("RGBA", (W, bh), SUBTITLE_BG)
    img.paste(Image.alpha_composite(
        img.crop((0, y0, W, y0 + bh)).convert("RGBA"), overlay).convert("RGB"),
        (0, y0))
    d = ImageDraw.Draw(img)
    d.rectangle([0, y0, 8, y0 + bh], fill=ACCENT)
    y = y0 + 15
    for ln in lines:
        w = d.textlength(ln, font=f)
        # 描边提升可读性
        for dx, dy in ((-1, 0), (1, 0), (0, -1), (0, 1)):
            d.text(((W - w) / 2 + dx, y + dy), ln, font=f, fill=(0, 0, 0))
        d.text(((W - w) / 2, y), ln, font=f, fill=SUB_TEXT)
        y += lh
    return img


def fade(a, b, t):
    return Image.blend(a, b, t)


def main():
    ffmpeg = None
    try:
        import imageio_ffmpeg
        ffmpeg = imageio_ffmpeg.get_ffmpeg_exe()
    except Exception:
        ffmpeg = shutil.which("ffmpeg")
    if not ffmpeg:
        print("缺少 ffmpeg，无法合成视频")
        return 1

    os.makedirs(TMP, exist_ok=True)
    frames = []
    print("准备帧 ...")
    for key, text, dur in PLAN:
        p = os.path.join(SLIDES, key + ".png")
        if not os.path.isfile(p):
            p = os.path.join(UI, key + ".png")
        if not os.path.isfile(p):
            print("  !! 缺帧：%s" % key)
            continue
        frames.append((with_subtitle(fit_frame(p), text), int(dur * FPS)))

    total = sum(n for _, n in frames) + int(XFADE * FPS) * (len(frames) - 1)
    print("总帧数约 %d（约 %.1f 秒）" % (total, total / FPS))

    # 用管道把原始帧喂给 ffmpeg，避免落盘上万张 PNG
    cmd = [ffmpeg, "-y", "-f", "rawvideo", "-pix_fmt", "rgb24",
           "-s", "%dx%d" % (W, H), "-r", str(FPS), "-i", "-",
           "-an", "-c:v", "libx264", "-preset", "medium", "-crf", "20",
           "-pix_fmt", "yuv420p", "-movflags", "+faststart", OUT]
    proc = subprocess.Popen(cmd, stdin=subprocess.PIPE,
                            stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    hold = int(XFADE * FPS)
    try:
        for i, (img, n) in enumerate(frames):
            for _ in range(n):
                proc.stdin.write(img.tobytes())
            if i + 1 < len(frames):
                nxt = frames[i + 1][0]
                for k in range(hold):
                    proc.stdin.write(fade(img, nxt, (k + 1) / (hold + 1)).tobytes())
    finally:
        proc.stdin.close()
        err = proc.stderr.read().decode("utf-8", "ignore")
        proc.wait()
    if proc.returncode != 0:
        print("ffmpeg 失败：\n%s" % err[-1500:])
        return 1
    print("已生成：%s（%.1f MB）" % (OUT, os.path.getsize(OUT) / 1048576))
    return 0


if __name__ == "__main__":
    sys.exit(main())
