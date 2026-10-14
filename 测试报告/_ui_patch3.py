# -*- coding: utf-8 -*-
"""补齐响应式断点里丢失的几行。"""
import io

P = r"C:\Users\丁\Desktop\aisec-D_2.0\frontend\styles.css"
with io.open(P, "r", encoding="utf-8", newline="") as f:
    raw = f.read()
nl = "\r\n" if "\r\n" in raw else "\n"
t = raw

REPL = [
    # .side 间距 14 -> 16
    (""".side{
  flex:1;min-height:0;overflow-y:auto;overscroll-behavior:contain;padding:16px 14px 48px;
  display:flex;flex-direction:column;gap:14px;
}""",
     """.side{
  flex:1;min-height:0;overflow-y:auto;overscroll-behavior:contain;padding:16px 14px 48px;
  display:flex;flex-direction:column;gap:16px;
}""", "side gap16"),

    # 1080 断点
    ("""  .boardgrid{grid-template-columns:minmax(0,1fr)}
  .top-stat{display:none}
}""",
     """  .boardgrid{grid-template-columns:minmax(0,1fr)}
  .top-stat{display:none}
  .main{padding:28px 30px 80px}
  .viewhead h2{font-size:28px}
  .kpi b{font-size:30px}
}""", "1080 断点"),

    # 980 断点
    ("""  .main{overflow:visible;padding:18px 16px 48px;gap:20px}""",
     """  .main{overflow:visible;padding:18px 16px 48px;gap:20px}
  .viewhead h2{font-size:24px;margin-bottom:8px}
  .viewhead h2::before{width:4px}""", "980 断点"),

    # 620 断点
    ("""  .searchbar{flex-wrap:wrap}
  .searchbar input{flex-basis:100%;font-size:15px}""",
     """  .searchbar{flex-wrap:wrap;padding:13px 12px 13px 15px}
  .searchbar input{flex-basis:100%;font-size:15px}""", "620 searchbar"),
    ("""  .inspector{width:100vw}
  .main{padding:14px 12px 40px}
}""",
     """  .inspector{width:100vw}
  .main{padding:14px 12px 40px;gap:18px}
  .viewhead h2{font-size:20px}
  .kpi b{font-size:25px}
}""", "620 main"),
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
