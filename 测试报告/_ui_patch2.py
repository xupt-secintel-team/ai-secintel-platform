# -*- coding: utf-8 -*-
"""v6 第二轮：提高明暗分离度 + 再放大标题尺度。"""
import io

P = r"C:\Users\丁\Desktop\aisec-D_2.0\frontend\styles.css"
with io.open(P, "r", encoding="utf-8", newline="") as f:
    raw = f.read()
nl = "\r\n" if "\r\n" in raw else "\n"
t = raw

REPL = [
    # 深色：底色稍提，表面明显提亮 —— 内容要"浮"在底上
    ("""  --bg:#04050c; --bg-2:#070a13; --elev-1:#0b0f1c; --elev-2:#121728;
  /* —— 亮度堆叠：表面统一带蓝调，"发光玻璃"才成立 —— */
  --surface-1:rgba(138,172,255,.034); --surface-2:rgba(138,172,255,.062);
  --surface-3:rgba(138,172,255,.094); --surface-4:rgba(138,172,255,.132);
  /* —— 发丝描边：比 v5 亮一档，卡片边缘才"切得出来" —— */
  --line:rgba(146,176,255,.10); --line-2:rgba(146,176,255,.16); --line-3:rgba(146,176,255,.25);""",
     """  --bg:#05060e; --bg-2:#090c16; --elev-1:#0f1322; --elev-2:#171c2e;
  /* —— 亮度堆叠：表面统一带蓝调。"内容比底亮"是深色界面唯一的层次来源 —— */
  --surface-1:rgba(138,172,255,.046); --surface-2:rgba(138,172,255,.082);
  --surface-3:rgba(138,172,255,.116); --surface-4:rgba(138,172,255,.162);
  /* —— 发丝描边：比 v5 亮一档，卡片边缘才"切得出来" —— */
  --line:rgba(146,176,255,.115); --line-2:rgba(146,176,255,.185); --line-3:rgba(146,176,255,.30);""",
     "深色表面提亮"),

    # 浅色：同步提一档
    ("""  --surface-1:rgba(22,30,60,.022); --surface-2:rgba(22,30,60,.046);
  --surface-3:rgba(22,30,60,.074); --surface-4:rgba(22,30,60,.108);
  --line:rgba(22,30,60,.10); --line-2:rgba(22,30,60,.155); --line-3:rgba(22,30,60,.26);""",
     """  --surface-1:rgba(22,30,60,.028); --surface-2:rgba(22,30,60,.055);
  --surface-3:rgba(22,30,60,.086); --surface-4:rgba(22,30,60,.122);
  --line:rgba(22,30,60,.115); --line-2:rgba(22,30,60,.175); --line-3:rgba(22,30,60,.28);""",
     "浅色表面提亮"),

    # 标题再放大一档：30 -> 34（精读 36 -> 40）
    ("""  --fs-display:38px; --fs-h1:30px; --fs-h2:16px; --fs-h3:14px;""",
     """  --fs-display:42px; --fs-h1:34px; --fs-h2:16px; --fs-h3:14px;""",
     "h1 34"),
    ("""body.zl .viewhead h2{font-size:36px}""",
     """body.zl .viewhead h2{font-size:40px}""",
     "zl h1 40"),

    # 结果卡间距再拉开
    ("""#results{display:flex;flex-direction:column;gap:12px}""",
     """#results{display:flex;flex-direction:column;gap:15px}""",
     "results gap 15"),
    ("""  padding:19px 22px;border:1px solid var(--line-2);border-radius:var(--r-md);
  background:linear-gradient(180deg,var(--surface-2),var(--surface-1) 52%);""",
     """  padding:21px 24px;border:1px solid var(--line-2);border-radius:var(--r-md);
  background:linear-gradient(180deg,var(--surface-2),var(--surface-1) 52%);""",
     "res padding"),
    ("""  display:flex;flex-direction:column;gap:14px;
}
.side>*{flex:0 0 auto}""",
     """  display:flex;flex-direction:column;gap:16px;
}
.side>*{flex:0 0 auto}""",
     "side gap 16"),

    # 窄屏标题同步收
    ("""@media (max-width:1080px){
  .view[data-view="search"]{grid-template-columns:272px minmax(0,1fr)}
  .boardgrid{grid-template-columns:minmax(0,1fr)}
  .top-stat{display:none}
  /* 大标题在窄屏收一档，别把内容挤到换行 */
  .main{padding:28px 30px 80px}
  .viewhead h2{font-size:25px}""",
     """@media (max-width:1080px){
  .view[data-view="search"]{grid-template-columns:272px minmax(0,1fr)}
  .boardgrid{grid-template-columns:minmax(0,1fr)}
  .top-stat{display:none}
  /* 大标题在窄屏收一档，别把内容挤到换行 */
  .main{padding:28px 30px 80px}
  .viewhead h2{font-size:28px}""",
     "1080 标题"),
]

miss = []
for old, new, label in REPL:
    o, n = old.replace("\n", nl), new.replace("\n", nl)
    if o in t:
        t = t.replace(o, n, 1); print("  OK   ", label)
    elif n in t:
        print("  DONE ", label)
    else:
        print("  MISS ", label); miss.append(label)

if t != raw:
    with io.open(P, "w", encoding="utf-8", newline="") as f:
        f.write(t)
    print("\n已写回 bytes", len(t.encode()))
print("仍缺失:", miss if miss else "无")
