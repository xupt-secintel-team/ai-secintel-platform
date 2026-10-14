# -*- coding: utf-8 -*-
"""对 frontend/styles.css 做一批精确替换（补齐并行编辑竞态丢失的改动）。
每个条目：old -> new；old 不存在时报 MISS，new 已存在时报 DONE。
"""
import io
import sys

P = r"C:\Users\丁\Desktop\aisec-D_2.0\frontend\styles.css"

with io.open(P, "r", encoding="utf-8", newline="") as f:
    raw = f.read()
nl = "\r\n" if "\r\n" in raw else "\n"
print("行尾:", repr(nl), "| CRLF 数:", raw.count("\r\n"), "| LF 数:", raw.count("\n"))

t = raw

REPL = [
    # ---------- 背衬 ----------
    ("""  background-size:64px 64px;background-position:-1px -1px;opacity:.55;
  mask-image:radial-gradient(120% 78% at 50% -8%,#000 0%,rgba(0,0,0,.42) 46%,transparent 92%);
  -webkit-mask-image:radial-gradient(120% 78% at 50% -8%,#000 0%,rgba(0,0,0,.42) 46%,transparent 92%);
}
.backdrop::after{
  content:"";position:absolute;left:50%;top:-40vh;width:135vw;height:72vh;transform:translateX(-50%);
  background:
    radial-gradient(40% 50% at 50% 100%,var(--accent-soft),transparent 72%),
    radial-gradient(30% 40% at 18% 100%,var(--iris-soft),transparent 78%);
  opacity:.8;
}""",
     """  background-size:48px 48px;background-position:-1px -1px;opacity:.75;
  mask-image:radial-gradient(132% 84% at 50% -6%,#000 0%,rgba(0,0,0,.5) 40%,transparent 88%);
  -webkit-mask-image:radial-gradient(132% 84% at 50% -6%,#000 0%,rgba(0,0,0,.5) 40%,transparent 88%);
}
.backdrop::after{
  content:"";position:absolute;inset:-20vh -10vw;
  background:
    radial-gradient(46% 44% at 12% 6%,var(--accent-soft),transparent 70%),
    radial-gradient(34% 40% at 88% 88%,var(--cyan-soft),transparent 72%),
    radial-gradient(30% 34% at 62% -2%,var(--iris-soft),transparent 74%);
  opacity:.9;
}""", "背衬"),

    # ---------- rail 品牌 ----------
    (""".rail-brand{
  width:33px;height:33px;flex:none;border-radius:10px;display:grid;place-items:center;
  color:var(--accent-2);background:linear-gradient(160deg,var(--surface-3),var(--surface-1));
  border:1px solid var(--line-2);
  box-shadow:var(--sh-lip);
  position:relative;overflow:hidden;""",
     """.rail-brand{
  width:40px;height:40px;flex:none;border-radius:13px;display:grid;place-items:center;
  color:var(--accent-2);
  background:linear-gradient(160deg,color-mix(in srgb,var(--accent) 20%,var(--elev-2)),var(--elev-1));
  border:1px solid var(--accent-line);
  box-shadow:var(--sh-lip),0 10px 26px -14px var(--accent-glow);
  position:relative;overflow:hidden;""", "rail-brand"),
    (""".rail-brand::after{ /* 徽标上的一道斜向高光，静态 */""",
     """.rail-brand svg{width:22px;height:22px}
.rail-brand::after{ /* 徽标上的一道斜向高光，静态 */""", "rail-brand svg"),

    # ---------- rail 导航项 ----------
    (""".rail-nav{position:relative;display:flex;flex-direction:column;gap:4px;margin-top:8px;width:100%;align-items:center}
.rail-item{
  position:relative;z-index:1;width:40px;height:40px;border:0;background:none;cursor:pointer;
  border-radius:11px;display:grid;place-items:center;gap:0;color:var(--txt-3);""",
     """.rail-nav{position:relative;display:flex;flex-direction:column;gap:6px;margin-top:14px;width:100%;align-items:center}
.rail-item{
  position:relative;z-index:1;width:44px;height:44px;border:0;background:none;cursor:pointer;
  border-radius:13px;display:grid;place-items:center;gap:0;color:var(--txt-3);""", "rail-nav/item"),
    (""".rail-item svg{width:19px;height:19px;transition:transform .3s var(--spring)}""",
     """.rail-item svg{width:21px;height:21px;transition:transform .3s var(--spring)}""", "rail-item svg"),

    # ---------- 顶栏 ----------
    (""".cmdbar{
  display:flex;align-items:center;gap:16px;padding:0 18px;height:54px;flex:none;
  min-width:0;overflow:hidden;
  border-bottom:1px solid var(--line);
  background:color-mix(in srgb,var(--bg-2) 86%,transparent);
  backdrop-filter:blur(16px) saturate(150%);
}
.cmd-left{display:flex;align-items:center;gap:14px;min-width:0;flex:0 1 auto;overflow:hidden}
.brandline{display:flex;flex-direction:column;line-height:1.14}
.brandline b{font-size:13.5px;font-weight:620;letter-spacing:var(--tk-tight);white-space:nowrap}
.brandline small{font-size:8.5px;letter-spacing:1.5px;color:var(--txt-4);text-transform:uppercase;white-space:nowrap;font-weight:520}""",
     """.cmdbar{
  position:relative;
  display:flex;align-items:center;gap:18px;padding:0 22px;height:66px;flex:none;
  min-width:0;overflow:hidden;
  border-bottom:1px solid var(--line);
  background:linear-gradient(180deg,color-mix(in srgb,var(--bg-2) 94%,transparent),color-mix(in srgb,var(--bg) 90%,transparent));
  backdrop-filter:blur(18px) saturate(160%);
}
/* 顶栏下缘：一道蓝→青的渐隐分割线，把"外壳"与"工作区"切开 */
.cmdbar::after{
  content:"";position:absolute;left:0;right:0;bottom:-1px;height:1px;pointer-events:none;
  background:linear-gradient(90deg,transparent,var(--accent-line) 20%,var(--cyan-line) 80%,transparent);
  opacity:.6;
}
.cmd-left{display:flex;align-items:center;gap:16px;min-width:0;flex:0 1 auto;overflow:hidden}
.brandline{display:flex;flex-direction:column;line-height:1.16}
.brandline b{font-size:16px;font-weight:660;letter-spacing:-.45px;white-space:nowrap}
.brandline small{font-size:8.5px;letter-spacing:2px;color:var(--txt-4);text-transform:uppercase;white-space:nowrap;font-weight:560}""", "cmdbar+品牌"),

    # ---------- 实时指示 ----------
    (""".livewrap{
  display:flex;align-items:center;gap:7px;flex:none;height:27px;padding:0 11px;border-radius:999px;
  border:1px solid var(--line);background:var(--surface-1);cursor:default;max-width:340px;
  transition:border-color .2s var(--ease),background .2s var(--ease);
}
.livewrap:hover{border-color:var(--line-2)}
.livedot{position:relative;width:6px;height:6px;flex:none;border-radius:50%;background:var(--ok)}""",
     """.livewrap{
  display:flex;align-items:center;gap:7px;flex:none;height:31px;padding:0 12px;border-radius:999px;
  border:1px solid var(--cyan-line);background:var(--cyan-soft);cursor:default;max-width:340px;
  transition:border-color .2s var(--ease),background .2s var(--ease);
}
.livewrap:hover{border-color:var(--cyan)}
.livedot{position:relative;width:6px;height:6px;flex:none;border-radius:50%;background:var(--cyan)}""", "livewrap"),

    # ---------- 读数胶囊 ----------
    (""".top-stat{
  display:flex;align-items:center;flex:0 1 auto;min-width:0;overflow:hidden;
  height:33px;padding:0 3px;border:1px solid var(--line-2);border-radius:var(--r-sm);background:var(--surface-2);
}
.top-stat .kv{padding:0 12px;border-left:1px solid var(--line);text-align:right;white-space:nowrap;line-height:1.12}""",
     """.top-stat{
  display:flex;align-items:center;flex:0 1 auto;min-width:0;overflow:hidden;
  height:41px;padding:0 4px;border:1px solid var(--line-2);border-radius:16px;background:var(--surface-1);
  box-shadow:var(--sh-lip);
}
.top-stat .kv{padding:0 13px;border-left:1px solid var(--line);text-align:right;white-space:nowrap;line-height:1.14}""", "top-stat"),
    ("""  background:linear-gradient(180deg,var(--txt),color-mix(in srgb,var(--txt) 70%,var(--txt-3)));-webkit-background-clip:text;background-clip:text;color:transparent}
.top-stat .kv span{display:block;font-size:9px;letter-spacing:1px;text-transform:uppercase;color:var(--txt-4)}""",
     """  background:linear-gradient(180deg,var(--txt),color-mix(in srgb,var(--txt) 62%,var(--accent-3)));-webkit-background-clip:text;background-clip:text;color:transparent}
.top-stat .kv span{display:block;font-size:9px;letter-spacing:1.1px;text-transform:uppercase;color:var(--txt-4)}""", "top-stat 数字"),
    ("""  font-size:13px;font-weight:500;letter-spacing:-.3px;font-variant-numeric:tabular-nums;
  background:linear-gradient(180deg,var(--txt),color-mix(in srgb,var(--txt) 62%""",
     """  font-size:15px;font-weight:520;letter-spacing:-.4px;font-variant-numeric:tabular-nums;
  background:linear-gradient(180deg,var(--txt),color-mix(in srgb,var(--txt) 62%""", "top-stat 字号"),

    # ---------- 翻译按钮 ----------
    (""".trbtn{
  height:29px;min-width:29px;flex:none;cursor:pointer;border-radius:var(--r-sm);font-size:12px;font-weight:560;padding:0 8px;""",
     """.trbtn{
  height:35px;min-width:35px;flex:none;cursor:pointer;border-radius:var(--r-sm);font-size:12.5px;font-weight:560;padding:0 9px;""", "trbtn"),

    # ---------- 侧栏卡片 ----------
    ("""  background:linear-gradient(180deg,var(--surface-2),var(--surface-1) 46%);
  border:1px solid var(--line);border-radius:var(--r-md);
  box-shadow:var(--sh-lip);
  overflow:hidden;transition:border-color .22s var(--ease),box-shadow .28s var(--ease),background .22s var(--ease);
  animation:cardIn .44s var(--ease-out) both;
}
.card:hover{border-color:var(--line-2);box-shadow:var(--sh-lip),0 10px 26px -18px rgba(0,0,0,.8)}""",
     """  background:linear-gradient(180deg,var(--surface-2),var(--surface-1) 46%);
  border:1px solid var(--line-2);border-radius:var(--r-md);
  box-shadow:var(--sh-lip),0 8px 22px -20px rgba(0,0,0,.7);
  overflow:hidden;transition:border-color .22s var(--ease),box-shadow .28s var(--ease),background .22s var(--ease);
  animation:cardIn .44s var(--ease-out) both;
}
.card:hover{border-color:var(--line-3);box-shadow:var(--sh-lip),0 18px 40px -22px rgba(0,0,0,.9)}""", "card 边"),

    # ---------- 侧栏内边距 ----------
    (""".side{
  flex:1;min-height:0;overflow-y:auto;overscroll-behavior:contain;padding:12px 12px 44px;
  display:flex;flex-direction:column;gap:10px;
}""",
     """.side{
  flex:1;min-height:0;overflow-y:auto;overscroll-behavior:contain;padding:16px 14px 48px;
  display:flex;flex-direction:column;gap:14px;
}""", "side 留白"),

    # ---------- 结果列表 ----------
    ("""#results{display:flex;flex-direction:column;gap:9px}""",
     """#results{display:flex;flex-direction:column;gap:12px}""", "results gap"),
    ("""  padding:14px 18px;border:1px solid var(--line);border-radius:var(--r-md);
  background:linear-gradient(180deg,var(--surface-2),var(--surface-1) 52%);
  box-shadow:var(--sh-lip);
  content-visibility:auto;contain-intrinsic-size:auto 120px;""",
     """  padding:19px 22px;border:1px solid var(--line-2);border-radius:var(--r-md);
  background:linear-gradient(180deg,var(--surface-2),var(--surface-1) 52%);
  box-shadow:var(--sh-lip),0 12px 28px -24px rgba(0,0,0,.75);
  content-visibility:auto;contain-intrinsic-size:auto 140px;""", "res 卡"),

    # ---------- 答复卡 ----------
    (""".answer{
  border:1px solid var(--line-2);border-radius:var(--r-lg);overflow:hidden;
  background:
    radial-gradient(130% 150% at 0% 0%,var(--accent-soft),transparent 58%),
    linear-gradient(180deg,var(--surface-2),var(--surface-1));
  box-shadow:var(--sh-lip);""",
     """.answer{
  border:1px solid var(--accent-line);border-radius:var(--r-lg);overflow:hidden;
  background:
    radial-gradient(130% 155% at 0% 0%,var(--accent-soft),transparent 56%),
    radial-gradient(90% 132% at 100% 100%,var(--iris-soft),transparent 62%),
    linear-gradient(180deg,var(--surface-2),var(--surface-1));
  box-shadow:var(--sh-lip),0 24px 58px -36px var(--accent-glow);""", "answer 卡"),

    # ---------- 检查器 ----------
    ("""  padding:14px 16px;border-bottom:1px solid var(--line);
  background:color-mix(in srgb,var(--bg-2) 84%,transparent);backdrop-filter:blur(14px) saturate(140%);z-index:3;
}
.insp-head h2{font-family:var(--mono);font-size:15px;font-weight:520;""",
     """  padding:17px 20px;border-bottom:1px solid var(--line);
  background:color-mix(in srgb,var(--bg-2) 88%,transparent);backdrop-filter:blur(14px) saturate(140%);z-index:3;
}
.insp-head h2{font-family:var(--mono);font-size:16px;font-weight:540;""", "insp-head"),
    (""".insp-body{flex:1;min-height:0;overflow-y:auto;overscroll-behavior:contain;padding:18px 18px 68px;contain:layout paint}""",
     """.insp-body{flex:1;min-height:0;overflow-y:auto;overscroll-behavior:contain;padding:22px 22px 76px;contain:layout paint}""", "insp-body"),

    # ---------- 监测台行 ----------
    (""".streamrow{
  display:flex;align-items:center;gap:9px;padding:9px 5px;border-bottom:1px solid var(--line);cursor:pointer;""",
     """.streamrow{
  display:flex;align-items:center;gap:11px;padding:11px 6px;border-bottom:1px solid var(--line);cursor:pointer;""", "streamrow"),
    (""".distrow{display:flex;align-items:center;gap:9px;margin-bottom:9px}
.distrow .dl{flex:none;width:84px;font-size:11.5px;color:var(--txt-3);overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.distrow .dbar{flex:1;height:16px;border-radius:var(--r-xs);background:var(--surface-2);overflow:hidden;position:relative}""",
     """.distrow{display:flex;align-items:center;gap:10px;margin-bottom:12px}
.distrow .dl{flex:none;width:92px;font-size:12px;color:var(--txt-3);overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.distrow .dbar{flex:1;height:20px;border-radius:var(--r-xs);background:var(--surface-2);overflow:hidden;position:relative}""", "distrow"),

    # ---------- 面板（确认） ----------
    (""".panel{
  border:1px solid var(--line);border-radius:var(--r-md);
  background:linear-gradient(180deg,var(--surface-2),var(--surface-1) 40%);
  box-shadow:var(--sh-lip);overflow:hidden;""",
     """.panel{
  border:1px solid var(--line-2);border-radius:var(--r-lg);
  background:linear-gradient(180deg,var(--surface-2),var(--surface-1) 40%);
  box-shadow:var(--sh-lip),0 18px 40px -32px rgba(0,0,0,.85);overflow:hidden;""", "panel"),

    # ---------- KPI 栅格（确认） ----------
    (""".kpirow{display:grid;grid-template-columns:repeat(auto-fit,minmax(138px,1fr));gap:10px}""",
     """.kpirow{display:grid;grid-template-columns:repeat(auto-fit,minmax(190px,1fr));gap:14px}""", "kpirow"),

    # ---------- 侧栏背景（确认） ----------
    ("""  background:color-mix(in srgb,var(--bg-2) 58%,transparent);
  border-right:1px solid var(--line);""",
     """  background:linear-gradient(180deg,color-mix(in srgb,var(--bg-2) 74%,transparent),color-mix(in srgb,var(--bg) 62%,transparent));
  border-right:1px solid var(--line);""", "sidepanel 背景"),
]

miss = []
for old, new, label in REPL:
    o = old.replace("\n", nl)
    n = new.replace("\n", nl)
    if o in t:
        t = t.replace(o, n, 1)
        print("  OK   ", label)
    elif n in t:
        print("  DONE ", label, "(已是目标值)")
    else:
        print("  MISS ", label)
        miss.append(label)

if t != raw:
    with io.open(P, "w", encoding="utf-8", newline="") as f:
        f.write(t)
    print("\n已写回。bytes", len(t.encode()))
else:
    print("\n无改动")

print("仍缺失:", miss if miss else "无")
sys.exit(0)
