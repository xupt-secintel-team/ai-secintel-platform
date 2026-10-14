# -*- coding: utf-8 -*-
"""
配色重做 v2：AI 蓝 → 黑金（Obsidian & Champagne Gold）
------------------------------------------------------
修正 v1 的致命 bug：同一文件在任务表里出现多次时，v1 每次从磁盘重读、
各自生成一份结果，写入时后面的覆盖前面的 → 先写的改动被静默吞掉。
v2 改为「按文件分组：读一次 → 顺序替换 → 写一次」，并对已应用的条目
（old 不在但 new 已在）报 SKIP，可安全重跑。

用法： py _ui_recolor.py --check   # 只校验
       py _ui_recolor.py           # 校验通过才写入
"""
import glob
import io
import os
import sys

ROOT = r"C:\Users\丁\Desktop\aisec-D_2.0"
FE = os.path.join(ROOT, "frontend")

# ============================================================
# A. styles.css —— 深色主题令牌（黑曜石 + 香槟金）
# ============================================================
DARK_OLD = """  /* —— 画布：深空蓝黑。比 v5 更沉、色相更明确（冷蓝夜空）——
        底色越"有颜色"，上层的玻璃与辉光才立得住 —— */
  --bg:#04050d; --bg-2:#0b1021; --elev-1:#141b30; --elev-2:#1c2340;
  /* —— 亮度堆叠：表面统一带蓝调。"内容比底亮"是深色界面唯一的层次来源 —— */
  --surface-1:rgba(140,175,255,.062); --surface-2:rgba(140,175,255,.105);
  --surface-3:rgba(140,175,255,.148); --surface-4:rgba(140,175,255,.202);
  /* —— 发丝描边：比 v5 亮一档，卡片边缘才"切得出来" —— */
  --line:rgba(150,180,255,.145); --line-2:rgba(150,180,255,.23); --line-3:rgba(150,180,255,.38);
  /* —— 文本四级（对 --bg 全部 ≥ WCAG AA） —— */
  --txt:#eceffb; --txt-2:#b3bdd2; --txt-3:#838ea8; --txt-4:#757f9a;
  /* —— 主交互色：电光蓝，饱和抬高、辉光加强 —— */
  --accent:#4d8dff; --accent-2:#79a8ff; --accent-3:#b3ccff;
  --accent-soft:rgba(77,141,255,.15); --accent-line:rgba(77,141,255,.42);
  --accent-ink:#fff; --accent-glow:rgba(77,141,255,.5);
  /* —— 次交互色：赛博青。只用于"实时 / 在线 / 活数据"——本版新增的第二记忆点 —— */
  --cyan:#2ad4e6; --cyan-2:#5fe3f0; --cyan-soft:rgba(42,212,230,.14); --cyan-line:rgba(42,212,230,.38);
  /* —— iris：只用于「智能体/AI 推理」这一种语义，出现得越少越有力 —— */
  --iris:#9b8cff; --iris-soft:rgba(155,140,255,.15); --iris-line:rgba(155,140,255,.38);
  /* —— 语义色（严重度）：取更亮的取值域，深色下不糊 —— */
  --ok:#3ddc84; --warn:#ffc043; --danger:#ff5f6d;
  --crit:#ff5f6d; --high:#ff9a45; --med:#ffc043; --low:#3ddc84; --info:#4d8dff;
  /* —— 数据可视化专用色（只在图表里出现，界面不使用） —— */
  --viz-1:#4d8dff; --viz-2:#2ad4e6; --viz-3:#3ddc84; --viz-4:#ffc043; --viz-5:#ff9a45;
  --viz-6:#ff5f6d; --viz-7:#b39bff;"""

DARK_NEW = """  /* —— 画布：黑曜石（近黑、极弱暖调）。不用蓝——蓝紫渐变是最典型的"AI 生成感"，
        换成暖黑之后，金色主色与语义色之间的对比才干净 —— */
  --bg:#0b0906; --bg-2:#15110b; --elev-1:#1b160e; --elev-2:#26200f;
  /* —— 亮度堆叠：表面统一用暖白叠加（黑曜石上叠暖光）——
        "内容比底亮"是深色界面唯一的层次来源 —— */
  --surface-1:rgba(255,236,198,.055); --surface-2:rgba(255,236,198,.096);
  --surface-3:rgba(255,236,198,.142); --surface-4:rgba(255,236,198,.198);
  /* —— 发丝描边：暖金灰，卡片边缘才"切得出来" —— */
  --line:rgba(255,231,186,.125); --line-2:rgba(255,231,186,.215); --line-3:rgba(255,231,186,.36);
  /* —— 文本四级（对 --bg 全部 ≥ WCAG AA；暖白而非冷白，与金色同族） —— */
  --txt:#f5f0e2; --txt-2:#c5bda9; --txt-3:#968e79; --txt-4:#847c69;
  /* —— 主交互色：香槟金。金是"权威 / 贵重 / 指挥台"的语汇，且远离蓝紫 —— */
  --accent:#d9a441; --accent-2:#eec876; --accent-3:#f2dba6;
  --accent-soft:rgba(217,164,65,.15); --accent-line:rgba(217,164,65,.42);
  --accent-ink:#191204; --accent-glow:rgba(217,164,65,.46);
  /* —— 次交互色：青玉。只用于"实时 / 在线 / 活数据"——
        金玉并置是传统高级配色，与蓝紫无关，是黑金里唯一的冷色锚点 —— */
  --cyan:#2fbf9e; --cyan-2:#5edcbb; --cyan-soft:rgba(47,191,158,.13); --cyan-line:rgba(47,191,158,.36);
  /* —— iris：只用于「智能体/AI 推理」这一种语义，出现得越少越有力（古铜金） —— */
  --iris:#b8823a; --iris-soft:rgba(184,130,58,.15); --iris-line:rgba(184,130,58,.36);
  /* —— 语义色（严重度）：取更亮的取值域，深色下不糊；与主色靠色相/饱和度区分 —— */
  --ok:#4acc8a; --warn:#f0a72e; --danger:#ff5a52;
  --crit:#ff5a52; --high:#ff8a3d; --med:#f2c94c; --low:#4acc8a; --info:#d9a441;
  /* —— 数据可视化专用色（只在图表里出现，界面不使用）；整组暖金主导 —— */
  --viz-1:#d9a441; --viz-2:#2fbf9e; --viz-3:#e8913c; --viz-4:#f2c94c; --viz-5:#b8603c;
  --viz-6:#ff5a52; --viz-7:#b9a284;"""

# ============================================================
# B. styles.css —— 浅色主题令牌（象牙白 + 深金）
# ============================================================
LIGHT_OLD = """  --bg:#eceff8; --bg-2:#ffffff; --elev-1:#ffffff; --elev-2:#ffffff;
  --surface-1:rgba(22,30,60,.028); --surface-2:rgba(22,30,60,.055);
  --surface-3:rgba(22,30,60,.086); --surface-4:rgba(22,30,60,.122);
  --line:rgba(22,30,60,.115); --line-2:rgba(22,30,60,.175); --line-3:rgba(22,30,60,.28);
  --txt:#0b1220; --txt-2:#46536b; --txt-3:#5d6980; --txt-4:#6d7890;
  --accent:#2b5ce6; --accent-2:#2148cc; --accent-3:#1f42b8;
  --accent-soft:rgba(43,92,230,.10); --accent-line:rgba(43,92,230,.36);
  --accent-ink:#fff; --accent-glow:rgba(43,92,230,.24);
  --cyan:#0a8fa3; --cyan-2:#0a7d90; --cyan-soft:rgba(10,143,163,.10); --cyan-line:rgba(10,143,163,.32);
  --iris:#6a52e6; --iris-soft:rgba(106,82,230,.10); --iris-line:rgba(106,82,230,.32);
  --ok:#0f8a45; --warn:#8a5b00; --danger:#d32232;
  --crit:#d32232; --high:#b8500a; --med:#8a5b00; --low:#0f8a45; --info:#2b5ce6;
  --viz-1:#2b5ce6; --viz-2:#0a8fa3; --viz-3:#0f8a45; --viz-4:#8a5b00;
  --viz-5:#b8500a; --viz-6:#d32232; --viz-7:#6a52e6;"""

LIGHT_NEW = """  --bg:#f6f3eb; --bg-2:#ffffff; --elev-1:#ffffff; --elev-2:#ffffff;
  --surface-1:rgba(60,45,18,.030); --surface-2:rgba(60,45,18,.058);
  --surface-3:rgba(60,45,18,.090); --surface-4:rgba(60,45,18,.128);
  --line:rgba(60,45,18,.12); --line-2:rgba(60,45,18,.185); --line-3:rgba(60,45,18,.28);
  --txt:#1c1608; --txt-2:#4a4232; --txt-3:#605843; --txt-4:#6f6752;
  --accent:#8a6410; --accent-2:#a3760f; --accent-3:#7a5810;
  --accent-soft:rgba(138,100,16,.10); --accent-line:rgba(138,100,16,.34);
  --accent-ink:#ffffff; --accent-glow:rgba(138,100,16,.22);
  --cyan:#0d7a62; --cyan-2:#0a6653; --cyan-soft:rgba(13,122,98,.10); --cyan-line:rgba(13,122,98,.32);
  --iris:#8a5c1c; --iris-soft:rgba(138,92,28,.10); --iris-line:rgba(138,92,28,.32);
  --ok:#167a4a; --warn:#8a5b00; --danger:#c02b26;
  --crit:#c02b26; --high:#a84e0c; --med:#8a5b00; --low:#167a4a; --info:#8a6410;
  --viz-1:#8a6410; --viz-2:#0d7a62; --viz-3:#a8520c; --viz-4:#8a5b00;
  --viz-5:#8a3a1a; --viz-6:#c02b26; --viz-7:#6b5a3a;"""

# ============================================================
# C. styles.css —— 逐条替换
# ============================================================
CSS_PAIRS = [
    ("""  --sh-lip:inset 0 1px 0 rgba(184,208,255,.13),inset 0 0 0 1px rgba(184,208,255,.022);   /* 卡片顶边高光 + 极淡内描边 */""",
     """  --sh-lip:inset 0 1px 0 rgba(255,236,196,.20),inset 0 0 0 1px rgba(255,236,196,.024);   /* 卡片顶边高光 + 极淡内描边 */"""),
    ("""  --ring:0 0 0 1px var(--accent-line),0 0 0 5px rgba(77,141,255,.18);""",
     """  --ring:0 0 0 1px var(--accent-line),0 0 0 5px rgba(217,164,65,.18);"""),
    ("""  --ring:0 0 0 1px var(--accent-line),0 0 0 5px rgba(43,92,230,.16);""",
     """  --ring:0 0 0 1px var(--accent-line),0 0 0 5px rgba(138,100,16,.16);"""),
    ("""  background:
    radial-gradient(46% 44% at 12% 6%,var(--accent-soft),transparent 70%),
    radial-gradient(34% 40% at 88% 88%,var(--cyan-soft),transparent 72%),
    radial-gradient(30% 34% at 62% -2%,var(--iris-soft),transparent 74%);
  opacity:.9;""",
     """  background:
    radial-gradient(52% 46% at 14% 4%,var(--accent-soft),transparent 72%),
    radial-gradient(30% 36% at 92% 92%,var(--cyan-soft),transparent 76%);
  opacity:.9;"""),
    ("""/* 三层静态光：细网格（渐隐）+ 顶部冷光 + 底部极淡暖光 —— 制造"光从上下打来"的体积。""",
     """/* 两层静态光：细网格（渐隐）+ 左上金环境光 + 右下玉反光 —— 制造"光从哪来"的体积。"""),
    ("""box-shadow:0 0 0 2px var(--accent-soft,rgba(99,102,241,.18))}""",
     """box-shadow:0 0 0 2px var(--accent-soft,rgba(217,164,65,.18))}"""),
    (""".submsg.ok{color:var(--ok,#2fbf71)}""", """.submsg.ok{color:var(--ok,#4acc8a)}"""),
    (""".submsg.warn{color:var(--warn,#e0a83a)}""", """.submsg.warn{color:var(--warn,#f0a72e)}"""),
    (""".submsg.err{color:var(--danger,#ff6369)}""", """.submsg.err{color:var(--danger,#ff5a52)}"""),
    (""".badge.subb{color:var(--accent,#6366f1);border-color:rgba(99,102,241,.42);""",
     """.badge.subb{color:var(--accent,#d9a441);border-color:rgba(217,164,65,.42);"""),
    ("""  background:rgba(99,102,241,.12)}""", """  background:rgba(217,164,65,.12)}"""),
    (""".badge.q-优{color:#1f9d55;border-color:rgba(31,157,85,.4);background:rgba(31,157,85,.12)}""",
     """.badge.q-优{color:#3fbf7a;border-color:rgba(63,191,122,.45);background:rgba(63,191,122,.13)}"""),
    (""".badge.q-良{color:#3a7bd5;border-color:rgba(58,123,213,.4);background:rgba(58,123,213,.12)}""",
     """.badge.q-良{color:#2fbf9e;border-color:rgba(47,191,158,.42);background:rgba(47,191,158,.13)}"""),
    (""".badge.q-中{color:#c79a3a;border-color:rgba(199,154,58,.4);background:rgba(199,154,58,.12)}""",
     """.badge.q-中{color:#d9a441;border-color:rgba(217,164,65,.42);background:rgba(217,164,65,.13)}"""),
    (""".badge.q-差{color:#ff6369;border-color:rgba(255,99,105,.4);background:rgba(255,99,105,.12)}""",
     """.badge.q-差{color:#ff5a52;border-color:rgba(255,90,82,.42);background:rgba(255,90,82,.13)}"""),
    ("""  padding:0 4px; border-radius:999px; background:var(--crit,#e5484d); color:#fff;""",
     """  padding:0 4px; border-radius:999px; background:var(--crit,#ff5a52); color:#191204;"""),
    ("""  box-shadow:0 0 0 2px var(--bg,#101214);""", """  box-shadow:0 0 0 2px var(--bg,#0b0906);"""),
    ("""  background:linear-gradient(105deg,transparent 30%,rgba(255,255,255,.14) 50%,transparent 70%);""",
     """  background:linear-gradient(105deg,transparent 30%,rgba(255,240,205,.16) 50%,transparent 70%);"""),
    (""".btn.primary::after{background:linear-gradient(105deg,transparent 32%,rgba(255,255,255,.34) 50%,transparent 68%)}""",
     """.btn.primary::after{background:linear-gradient(105deg,transparent 32%,rgba(255,248,228,.40) 50%,transparent 68%)}"""),
    ("""  box-shadow:0 8px 20px -10px var(--accent-glow),inset 0 1px 0 rgba(255,255,255,.2);""",
     """  box-shadow:0 8px 20px -10px var(--accent-glow),inset 0 1px 0 rgba(255,248,228,.28);"""),
    ("""  box-shadow:inset 0 0 0 1px rgba(255,255,255,.2),0 4px 12px -6px var(--accent-glow);""",
     """  box-shadow:inset 0 0 0 1px rgba(255,248,228,.28),0 4px 12px -6px var(--accent-glow);"""),
    ("""inset 0 0 0 1px color-mix(in srgb,var(--accent-2) 55%,transparent),inset 0 1px 0 rgba(255,255,255,.32);""",
     """inset 0 0 0 1px color-mix(in srgb,var(--accent-2) 55%,transparent),inset 0 1px 0 rgba(255,248,228,.40);"""),
    ("""inset 0 0 0 1px color-mix(in srgb,var(--accent-2) 60%,transparent),inset 0 1px 0 rgba(255,255,255,.40);""",
     """inset 0 0 0 1px color-mix(in srgb,var(--accent-2) 60%,transparent),inset 0 1px 0 rgba(255,248,228,.50);"""),
    (""".btn.primary kbd{background:rgba(255,255,255,.16);border-color:rgba(255,255,255,.24);color:#fff}""",
     """.btn.primary kbd{background:rgba(25,18,4,.18);border-color:rgba(25,18,4,.28);color:var(--accent-ink)}"""),
    ("""   AI-SecIntel 控制台 · 设计系统 v7 —— frontend/styles.css
   ----------------------------------------------------------------------------
   v7 在 v6 之上做「材质与光」的第二跃迁（见第 22 节）：""",
     """   AI-SecIntel 控制台 · 设计系统 v8 · 配色「黑曜石 & 香槟金」—— frontend/styles.css
   ----------------------------------------------------------------------------
   v8 只做一件事：**换掉整套色彩**。v5~v7 的蓝紫青（电光蓝 + 赛博青 + iris 紫）
   是典型的"AI 生成感"配色；v8 改为黑金 —— 近黑暖调底色 + 香槟金主色，
   实时语义改用「青玉」（金玉并置），背景三色极光收敛为两层金/玉光。
   令牌名一字未改（--accent* / --line* / --surface* / --txt* 是模块公共 API），
   浅色主题同步换为「象牙白 + 深金」。语义色与图表色整组改为暖金主导。

   v7 在 v6 之上做「材质与光」的第二跃迁（见第 22 节）："""),
    ("""  animation:cmdflow 7.5s linear infinite;opacity:.8;""",
     """  animation:cmdflow 7.5s linear infinite;opacity:.55;"""),
    ("""/* —— 环境光：顶部一束冷色顶光 + 右下角一点青色地面反光。""",
     """/* —— 环境光：顶部一束金色顶光 + 右下角一点青玉地面反光。"""),
    ("""/* —— 左导航：底纹更明显的蓝调渐变；激活块更"实" —— */""",
     """/* —— 左导航：底纹更明显的金调渐变；激活块更"实" —— */"""),
    ("""   上缘一道蓝青细线 + 左上角光晕，标题落在这束光里，成为每屏的第一眼。 —— */""",
     """   上缘一道金玉细线 + 左上角光晕，标题落在这束光里，成为每屏的第一眼。 —— */"""),
    ("""/* —— 答复卡：顶部一道 蓝 → 青 → 紫 的三色线，是「AI 产出」的签名 —— */""",
     """/* —— 答复卡：顶部一道 金 → 玉 → 铜 的三色线，是「AI 产出」的签名 —— */"""),
    ("""/* —— 顶栏下缘：一道蓝→青的光沿边缓慢流过，暗示"数据在动"。""",
     """/* —— 顶栏下缘：一道金→玉的光沿边缓慢流过，暗示"数据在动"。"""),
    ("""/* —— 页头记号（蓝青竖条）轻微呼吸 —— */""",
     """/* —— 页头记号（金玉竖条）轻微呼吸 —— */"""),
]

# ============================================================
# D. app.js —— 分类徽章 / 实时徽章 / 图谱色 / 散落强调色 / theme-color
# ============================================================
JS_PAIRS = [
    ("""  knowledge: { label: 'ATLAS 知识', tag: '威胁技术', fg: '#93b1ff', bd: 'rgba(77,124,254,.48)', bg: 'rgba(77,124,254,.13)', idc: '#6b93ff' },
  advisory: { label: 'GitHub 供应链公告', tag: '供应链', fg: '#e0bd6a', bd: 'rgba(212,167,44,.5)', bg: 'rgba(212,167,44,.13)', idc: '#d4a72c' },
  repo: { label: 'GitHub 工具仓库', tag: '安全工具', fg: '#7fd894', bd: 'rgba(63,185,80,.45)', bg: 'rgba(63,185,80,.13)', idc: '#3fb950' },
  article: { label: 'CSDN 社区文章', tag: '社区文章', fg: '#b9c2cd', bd: 'rgba(255,255,255,.16)', bg: 'rgba(255,255,255,.05)', idc: '#8a929c' },
  paper: { label: '学术论文', tag: '论文', fg: '#ff9b9f', bd: 'rgba(240,85,93,.42)', bg: 'rgba(240,85,93,.13)', idc: '#f0555d' },""",
     """  knowledge: { label: 'ATLAS 知识', tag: '威胁技术', fg: '#e8c76e', bd: 'rgba(217,164,65,.48)', bg: 'rgba(217,164,65,.13)', idc: '#d9a441' },
  advisory: { label: 'GitHub 供应链公告', tag: '供应链', fg: '#5edcbb', bd: 'rgba(47,191,158,.48)', bg: 'rgba(47,191,158,.13)', idc: '#2fbf9e' },
  repo: { label: 'GitHub 工具仓库', tag: '安全工具', fg: '#ec9a52', bd: 'rgba(232,145,60,.45)', bg: 'rgba(232,145,60,.13)', idc: '#e8913c' },
  article: { label: 'CSDN 社区文章', tag: '社区文章', fg: '#c5bda9', bd: 'rgba(255,231,186,.20)', bg: 'rgba(255,231,186,.06)', idc: '#968e79' },
  paper: { label: '学术论文', tag: '论文', fg: '#ff9289', bd: 'rgba(255,90,82,.42)', bg: 'rgba(255,90,82,.13)', idc: '#ff5a52' },"""),
    ("""const LIVE_META = { fg: '#7fd894', bd: 'rgba(63,185,80,.45)', bg: 'rgba(63,185,80,.13)', idc: '#3fb950' };""",
     """const LIVE_META = { fg: '#5edcbb', bd: 'rgba(47,191,158,.45)', bg: 'rgba(47,191,158,.13)', idc: '#2fbf9e' };"""),
    ("""const GCAT = ['#4d7cfe', '#38bdf8', '#3fb950', '#d4a72c', '#f0883e', '#f0555d', '#a78bfa', '#8a929c', '#22c55e'];""",
     """const GCAT = ['#d9a441', '#2fbf9e', '#e8913c', '#f2c94c', '#ff5a52', '#b9a284', '#5edcbb', '#a8843c', '#cf8a6a'];"""),
    ("""  document.querySelector('meta[name=theme-color]')?.setAttribute('content', real === 'light' ? '#f5f6f8' : '#0a0b0c');""",
     """  document.querySelector('meta[name=theme-color]')?.setAttribute('content', real === 'light' ? '#f6f3eb' : '#0b0906');"""),
    ("""    const catColor = x.category_color || '#8a929c';""",
     """    const catColor = x.category_color || '#968e79';"""),
    ("""style="color:${tm ? tm.idc : '#6b93ff'}\"""", """style="color:${tm ? tm.idc : '#d9a441'}\""""),
    ("""v === 'AI安全' ? '#4d7cfe' : '#3fb950'""", """v === 'AI安全' ? '#d9a441' : '#4acc8a'"""),
    ("""  const catColor = (d.category || '').includes('①') ? '#6b93ff'
    : (d.category || '').includes('②') ? '#4d7cfe'
    : (d.category || '').includes('③') ? '#3fb950' : '#d4a72c';""",
     """  const catColor = (d.category || '').includes('①') ? '#eec876'
    : (d.category || '').includes('②') ? '#d9a441'
    : (d.category || '').includes('③') ? '#4acc8a' : '#f2c94c';"""),
    ("""style="background:linear-gradient(90deg,${c.color || '#4d7cfe'},color-mix(in srgb,${c.color || '#4d7cfe'} 60%,transparent))\"""",
     """style="background:linear-gradient(90deg,${c.color || '#d9a441'},color-mix(in srgb,${c.color || '#d9a441'} 60%,transparent))\""""),
]

# ============================================================
# E. index.html
# ============================================================
HTML_PAIRS = [
    ("""<meta name="theme-color" content="#0a0b0c">""", """<meta name="theme-color" content="#0b0906">"""),
    ("""fill='%230a0b0c'""", """fill='%230b0906'"""),
    ("""stroke='%234d7cfe'""", """stroke='%23d9a441'"""),
    ("""stroke='%236b93ff'""", """stroke='%23eec876'"""),
    ("""href="styles.css?v=14">""", """href="styles.css?v=15">"""),
    ("""href="styles.css?v=15">""", """href="styles.css?v=15">"""),
]

# ============================================================
# F. 模块面板 CSS —— 蓝紫 → 金玉
# ============================================================
MOD_PAIRS = [
    ("#4d7cfe", "#d9a441"), ("#5b8def", "#d9a441"),
    ("#4d9fff", "#eec876"), ("#6ea8fe", "#eec876"), ("#828fff", "#eec876"),
    ("#93b1ff", "#f2dba6"),
    ("#38bdf8", "#2fbf9e"), ("#56b6c2", "#2fbf9e"),
    ("#6a52e6", "#b8823a"), ("#a78bfa", "#b8823a"),
    ("#3fb950", "#4acc8a"), ("#2fbf71", "#4acc8a"), ("#36b37e", "#4acc8a"),
    ("#d4a72c", "#f2c94c"), ("#f5a524", "#f0a72e"),
    ("#f85149", "#ff5a52"), ("#ff6369", "#ff5a52"),
    ("#f0883e", "#ff8a3d"),
    ("rgba(77,124,254,", "rgba(217,164,65,"),
    ("rgba(77,159,255,", "rgba(217,164,65,"),
    ("rgba(113, 112, 255,", "rgba(217,164,65,"),
    ("rgba(113,112,255,", "rgba(217,164,65,"),
    ("rgba(56,189,248,", "rgba(47,191,158,"),
    ("rgba(56, 189, 248,", "rgba(47,191,158,"),
    ("rgba(63,185,80,", "rgba(74,204,138,"),
    ("rgba(63, 185, 80,", "rgba(74,204,138,"),
    ("rgba(48, 164, 108,", "rgba(74,204,138,"),
    ("rgba(48,164,108,", "rgba(74,204,138,"),
    ("rgba(212,167,44,", "rgba(242,201,76,"),
    ("rgba(212, 167, 44,", "rgba(242,201,76,"),
    ("rgba(240,85,93,", "rgba(255,90,82,"),
    ("rgba(240, 85, 93,", "rgba(255,90,82,"),
    ("rgba(255, 99, 105,", "rgba(255,90,82,"),
    ("rgba(106,82,230,", "rgba(184,130,58,"),
    ("rgba(106, 82, 230,", "rgba(184,130,58,"),
]


def read(p):
    with io.open(p, "r", encoding="utf-8", newline="") as f:
        return f.read()


def write(p, s):
    with io.open(p, "w", encoding="utf-8", newline="") as f:
        f.write(s)


def build_groups():
    """按文件分组：(path, [(label, old, new)])"""
    g = {}

    def add(p, label, old, new):
        g.setdefault(p, []).append((label, old, new))

    sp = os.path.join(FE, "styles.css")
    add(sp, "DARK-BLOCK", DARK_OLD, DARK_NEW)
    add(sp, "LIGHT-BLOCK", LIGHT_OLD, LIGHT_NEW)
    for i, (a, b) in enumerate(CSS_PAIRS):
        add(sp, f"CSS{i:02d}", a, b)

    ap = os.path.join(FE, "app.js")
    for i, (a, b) in enumerate(JS_PAIRS):
        add(ap, f"JS{i:02d}", a, b)

    hp = os.path.join(FE, "index.html")
    for i, (a, b) in enumerate(HTML_PAIRS):
        add(hp, f"HTML{i:02d}", a, b)

    # 模块 CSS：源 + 副本（glob 去重）
    mods = sorted(set(
        glob.glob(os.path.join(ROOT, "modules", "*", "web", "*.css")) +
        glob.glob(os.path.join(FE, "modules", "*", "*.css"))
    ))
    for p in mods:
        for i, (a, b) in enumerate(MOD_PAIRS):
            add(p, f"MOD{i:02d}", a, b)
    return g


def main():
    groups = build_groups()
    n_ok = n_skip = 0
    misses = []
    nongs = []
    plan = []

    for path, pairs in groups.items():
        txt = read(path)
        orig = txt
        applied = []
        skipped = []
        for label, old, new in pairs:
            if old == new:
                continue
            if old in txt:
                txt = txt.replace(old, new)
                applied.append(label)
                n_ok += 1
            elif new in txt:
                skipped.append(label)
                n_skip += 1
            elif label.startswith("MOD"):
                # 模块面板是硬编码色，某个色在该文件里本来就不存在 —— 无害
                nongs.append((path, label))
            else:
                misses.append((path, label))
        if txt != orig:
            plan.append((path, txt, applied, skipped))
        elif skipped:
            plan.append((path, txt, applied, skipped))

    print("=" * 76)
    for path, _, applied, skipped in plan:
        rel = os.path.relpath(path, ROOT)
        print(f"  {rel:<42} 应用 {len(applied):>3}  已就绪 {len(skipped):>3}")
    print("=" * 76)
    print(f"  本轮新应用 {n_ok} 条；已应用（跳过）{n_skip} 条；该文件无此色 {len(nongs)} 条；未命中 {len(misses)} 条")
    if misses:
        print("  !! 有未命中项 → 整体中止，不写入。")
        for p, label in misses:
            print(f"     - {os.path.relpath(p, ROOT)} :: {label}")
        return 1
    if "--check" in sys.argv:
        print("  (--check：不写入)")
        return 0
    written = 0
    for path, txt, applied, _ in plan:
        if applied:
            write(path, txt)
            written += 1
    print(f"  已写入 {written} 个文件。")
    return 0


if __name__ == "__main__":
    sys.exit(main())
