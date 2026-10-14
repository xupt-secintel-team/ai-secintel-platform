# -*- coding: utf-8 -*-
"""
配色精修 v8b：把「黑金」从"能用"推到"高级"
--------------------------------------------------
1) 深色底更中性（#0b0906 偏褐 → #0b0a08），网格/极光收敛（大面积的灰褐纹理最伤高级感）；
2) 表面亮度整体上提一档（卡片真正浮起来）；
3) 主色金提亮一档：#d9a441 → #e3b04b（原色偏暗，在大暗底上"闷"）；
4) 浅色主题去掉右下角青玉反光（白底上一片青色光斑很突兀）；
5) 后端分类色（taxonomy / daily_digest）从蓝紫青改为暖金调色板 ——
   它们在界面里是"色点 + 分布条"，不改就永远留着 AI 味。
"""
import glob
import io
import os
import sys

ROOT = r"C:\Users\丁\Desktop\aisec-D_2.0"
FE = os.path.join(ROOT, "frontend")

# ---------- A. styles.css 深色令牌精修 ----------
A_OLD = """  --bg:#0b0906; --bg-2:#15110b; --elev-1:#1b160e; --elev-2:#26200f;"""
A_NEW = """  --bg:#0b0a08; --bg-2:#16130f; --elev-1:#1d1913; --elev-2:#282218;"""

B_OLD = """  --surface-1:rgba(255,236,198,.055); --surface-2:rgba(255,236,198,.096);
  --surface-3:rgba(255,236,198,.142); --surface-4:rgba(255,236,198,.198);"""
B_NEW = """  --surface-1:rgba(255,236,198,.072); --surface-2:rgba(255,236,198,.118);
  --surface-3:rgba(255,236,198,.168); --surface-4:rgba(255,236,198,.228);"""

C_OLD = """  --line:rgba(255,231,186,.125); --line-2:rgba(255,231,186,.215); --line-3:rgba(255,231,186,.36);"""
C_NEW = """  --line:rgba(255,231,186,.145); --line-2:rgba(255,231,186,.245); --line-3:rgba(255,231,186,.40);"""

D_OLD = """  --txt:#f5f0e2; --txt-2:#c5bda9; --txt-3:#968e79; --txt-4:#847c69;"""
D_NEW = """  --txt:#f6f2e7; --txt-2:#c9c3b4; --txt-3:#9a927e; --txt-4:#877f6d;"""

E_OLD = """  --accent:#d9a441; --accent-2:#eec876; --accent-3:#f2dba6;
  --accent-soft:rgba(217,164,65,.15); --accent-line:rgba(217,164,65,.42);
  --accent-ink:#191204; --accent-glow:rgba(217,164,65,.46);"""
E_NEW = """  --accent:#e3b04b; --accent-2:#f0cd7a; --accent-3:#f6e3ae;
  --accent-soft:rgba(227,176,75,.16); --accent-line:rgba(227,176,75,.44);
  --accent-ink:#1a1305; --accent-glow:rgba(227,176,75,.48);"""

F_OLD = """  --ring:0 0 0 1px var(--accent-line),0 0 0 5px rgba(217,164,65,.18);"""
F_NEW = """  --ring:0 0 0 1px var(--accent-line),0 0 0 5px rgba(227,176,75,.18);"""

# ---------- B. 背衬强度收敛 ----------
G_OLD = """.backdrop::before{opacity:.92}   /* 网格再显一点 */
.backdrop::after{opacity:1}      /* 极光全亮 */"""
G_NEW = """.backdrop::before{opacity:.55}   /* 网格收敛：大面积细纹会"脏"，黑金要靠留白和光来说话 */
.backdrop::after{opacity:.78}    /* 极光不过曝 */"""

# ---------- C. 环境光：浅色主题去掉青色反光 ----------
H_OLD = """body{
  background-image:
    radial-gradient(124% 66% at 50% -14%,color-mix(in srgb,var(--accent) 14%,transparent),transparent 62%),
    radial-gradient(88% 58% at 102% 106%,color-mix(in srgb,var(--cyan) 10%,transparent),transparent 62%);
  background-attachment:fixed;
}"""
H_NEW = """body{
  background-image:
    radial-gradient(124% 66% at 50% -14%,color-mix(in srgb,var(--accent) 14%,transparent),transparent 62%),
    radial-gradient(88% 58% at 102% 106%,color-mix(in srgb,var(--cyan) 10%,transparent),transparent 62%);
  background-attachment:fixed;
}
/* 浅色主题只留一层极淡的金色顶光 —— 白底上一片青绿反光会显脏 */
:root[data-theme="light"] body{
  background-image:radial-gradient(120% 62% at 50% -12%,color-mix(in srgb,var(--accent) 6%,transparent),transparent 60%);
}"""

TK = [
    (os.path.join(FE, "styles.css"), [(A_OLD, A_NEW), (B_OLD, B_NEW), (C_OLD, C_NEW),
                                      (D_OLD, D_NEW), (E_OLD, E_NEW), (F_OLD, F_NEW),
                                      (G_OLD, G_NEW), (H_OLD, H_NEW)]),
]

# ---------- D. 主色统一提亮：全局色值同步 ----------
GLOBAL = [
    ("#d9a441", "#e3b04b"),
    ("#eec876", "#f0cd7a"),
    ("#f2dba6", "#f6e3ae"),
    ("rgba(217,164,65,", "rgba(227,176,75,"),
]

# ---------- E. 后端分类色 → 暖金调色板 ----------
TAXO = [
    ('"color": "#7c5cff"', '"color": "#e3b04b"'),   # ① AI基础设施与推理框架  紫 → 金
    ('"color": "#00b8d9"', '"color": "#2fbf9e"'),   # ② 模型与数据层          青 → 玉
    ('"color": "#36b37e"', '"color": "#e8913c"'),   # ③ AI应用与智能体        绿 → 橙
    ('"color": "#ffab00"', '"color": "#f2c94c"'),   # ④ AI供应链与平台        黄 → 亮黄
    ('"color": "#ff5630"', '"color": "#ff7a45"'),   # ⑤ Web应用与API安全      橙红 → 橙红(暖化)
    ('"color": "#6554c0"', '"color": "#b8823a"'),   # ⑥ 系统与二进制安全      紫 → 古铜
    ('"color": "#0065ff"', '"color": "#c8795a"'),   # ⑦ 网络与协议安全        宝蓝 → 陶土
    ('"color": "#00a3bf"', '"color": "#5edcbb"'),   # ⑧ 云原生与容器安全      青 → 浅玉
    ('"color": "#8777d9"', '"color": "#b9a284"'),   # ⑨ 身份与访问管理        紫 → 暖卡其
    ('"color": "#bf2600"', '"color": "#ff5a52"'),   # ⑩ 恶意代码与威胁活动    深红 → 红
    ('"color": "#00875a"', '"color": "#9fbf6f"'),   # ⑪ 数据安全与密码学      深绿 → 橄榄
]

DIGEST = [
    ('"dir_infra": "#7c5cff", "dir_model": "#00b8d9",',
     '"dir_infra": "#e3b04b", "dir_model": "#2fbf9e",'),
    ('"dir_appagent": "#36b37e", "dir_supply": "#ffab00",',
     '"dir_appagent": "#e8913c", "dir_supply": "#f2c94c",'),
    ('return _DIR_COLOR_FALLBACK.get(did, "#888780")',
     'return _DIR_COLOR_FALLBACK.get(did, "#b9a284")'),
]


def read(p):
    with io.open(p, "r", encoding="utf-8", newline="") as f:
        return f.read()


def write(p, s):
    with io.open(p, "w", encoding="utf-8", newline="") as f:
        f.write(s)


def apply(path, pairs, label):
    s = read(path)
    o = s
    miss = []
    n = 0
    for a, b in pairs:
        if a in s:
            n += s.count(a)
            s = s.replace(a, b)
        elif b in s:
            pass                      # 已应用
        else:
            miss.append(a[:60])
    if s != o:
        write(path, s)
    print(f"  [{label}] {os.path.relpath(path, ROOT)}  {n} 处" + (f"  MISS={miss}" if miss else ""))
    return miss


def main():
    allmiss = []
    for path, pairs in TK:
        allmiss += apply(path, pairs, "TK")

    # 全局主色同步（前端所有 css/js）
    files = sorted(set(
        glob.glob(os.path.join(FE, "**", "*.css"), recursive=True) +
        glob.glob(os.path.join(FE, "**", "*.js"), recursive=True) +
        glob.glob(os.path.join(ROOT, "modules", "*", "web", "*.css")) +
        glob.glob(os.path.join(ROOT, "modules", "*", "web", "*.js"))
    ))
    tot = 0
    for p in files:
        s = read(p)
        o = s
        for a, b in GLOBAL:
            if a in s:
                tot += s.count(a)
                s = s.replace(a, b)
        if s != o:
            write(p, s)
    print(f"  [GLOBAL] 主色同步 {tot} 处，涉及 {len(files)} 个文件")

    # 后端分类色
    allmiss += apply(os.path.join(ROOT, "core", "taxonomy.py"), TAXO, "TAXO")
    allmiss += apply(os.path.join(ROOT, "core", "daily_digest.py"), DIGEST, "DIGEST")

    print("=" * 70)
    if allmiss:
        print(f"  !! MISS {len(allmiss)} 条（见上）")
        return 1
    print("  全部命中 ✅")
    return 0


if __name__ == "__main__":
    sys.exit(main())
