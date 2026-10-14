# 阈值校准：用真实引擎索引测 similarity_to_existing 在「全新文章」与「转载/雷同」上的取值，
# 用于确定 过分相同 的过滤阈值（标题相似 0.9 / 正文包含率 0.6 是否合适）。
import sys, os, json, time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "core"))
from engine import SearchEngine

t0 = time.time()
eng = SearchEngine(os.path.join(ROOT, "data", "corpus.json"))
print("引擎加载 %.1fs，docs=%d" % (time.time() - t0, len(eng.docs)))


def mk(title, desc):
    return {"id": "CALIB", "title": title, "desc": desc, "category": "",
            "product": "", "vendor": "", "cwe": "", "tags": "", "kev": "", "atlas": ""}


# 1) 全新文章（Prompt Injection 实战），看它和现有语料的相似度（应较低）
rec_new = mk("Prompt Injection 实战：大模型越狱与防护",
             "本文梳理 Prompt Injection 在大模型应用中的典型攻击面，涵盖越狱、防御与检测，并给出安全护栏实践。")
sim_new = eng.similarity_to_existing(rec_new)
print("\n[全新文章] sim =", sim_new)

# 2) 取一篇真实已收录文档，用它的标题+正文构造 rec2（模拟同文转载）→ 应高度相似
d0 = eng.docs[0]
rec_dup = mk(d0.get("title", ""), (d0.get("desc") or "")[:1500])
sim_dup = eng.similarity_to_existing(rec_dup)
print("\n[转载/雷同(真实文档0)] sim =", sim_dup, "| 原标题=", d0.get("title", "")[:40])

# 3) 再取一篇，只复用标题（正文换成无关短句）→ 标题雷同但正文不同，应被标题相似抓住
rec_titledup = mk(d0.get("title", ""), "这是一段与原文无关的内容用于测试标题雷同触发。")
sim_td = eng.similarity_to_existing(rec_titledup)
print("\n[仅标题雷同] sim =", sim_td)

# 4) 一篇普通新安全文章（应较低）
rec_sec = mk("企业内网横向移动检测实践",
             "本文从实战角度总结内网横向移动的常见手法，包括凭据窃取、票据传递与远程服务利用，并给出检测与加固建议。")
sim_sec = eng.similarity_to_existing(rec_sec)
print("\n[普通新安全文章] sim =", sim_sec)
print("\n--- 参考：当前阈值 标题>=0.9 或 正文包含率>=0.6 触发过滤 ---")
