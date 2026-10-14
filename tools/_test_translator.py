# -*- coding: utf-8 -*-
"""modules/m3_qa/backend/qa/translator.py 的回归测试。

    py tools/_test_translator.py

不加载真实模型（一次加载 300MB + 首次推理十几秒），只测**纯逻辑**那几层：
长文本分块、术语表替换、worth_translating 判据、依赖探针。

为什么这几层要有测试 —— 都是实际踩过的：

1. MarianTokenizer 的 `truncation=True` 会**静默丢弃**超长文本的后半段。
   译文看着完整（前半段确实翻了），后半段直接没了，没有任何报错。
   所以必须自己分块，且要测"分块后能拼回原文"（除标点外不丢字）。
2. 术语表第一版写成 `out.replace(zh, zh)`，是个纯 no-op：翻译照旧，
   只是看起来"做了校准"。所以要有"错译形态 → 被替换成正确中文"的断言。
3. worth_translating 的上限曾卡在 2000 字符，正常的 NVD 描述直接
   超限不翻，用户看到"开了译但没翻"。

依赖探针（runtime_deps）单测里断言"ok 取决于本机装没装"，不断言
具体装了什么 —— 那会让测试在不同机器上假失败。
"""
from __future__ import annotations

import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "modules", "m3_qa", "backend"))

PASS, FAIL = [], []


def ck(name, cond, extra=""):
    (PASS if cond else FAIL).append(name)
    print(("  ok   " if cond else "  FAIL ") + name +
          (("  " + str(extra)) if extra and not cond else ""))


def main():
    from qa import translator as T

    print("\n[1] split_chunks 长文本分块")
    long_en = ("A buffer overflow in the GGUF parser allows an attacker to "
               "execute arbitrary code. " * 60).strip()
    ck("输入够长", len(long_en) > 1000, len(long_en))
    chunks = T.split_chunks(long_en)
    ck("确实被切成多块", len(chunks) > 1, len(chunks))
    ck("每块不超过上限",
       all(len(c) <= (T._CHUNK_CHARS + 80) for c in chunks),
       max(len(c) for c in chunks))
    ck("块数合理（不是一句一块的碎片）",
       all(len(c) > 50 for c in chunks), min(len(c) for c in chunks))
    # 关键：拼回去不能丢内容。去掉块间空白后应与原文一致。
    joined = re.sub(r"\s+", " ", " ".join(chunks)).strip()
    ck("分块后拼回原文不丢字",
       joined == re.sub(r"\s+", " ", long_en).strip(),
       "原文 %d 字 → 拼回 %d 字" % (len(long_en), len(joined)))

    print("\n[2] split_chunks 边界")
    ck("空串返回空列表", T.split_chunks("") == [] or T.split_chunks("") == [""])
    ck("None 不炸", T.split_chunks(None) == [] or T.split_chunks(None) == [""])
    ck("短文本原样返回一块", len(T.split_chunks("Hello world.")) == 1)
    # 超长无标点的单句（分句正则切不开）必须被硬切，不能原样返回
    no_space = "A" * 3000
    hard = T.split_chunks(no_space)
    ck("无标点超长句被硬切", len(hard) > 1, len(hard))
    ck("硬切后不超上限", all(len(c) <= T._CHUNK_CHARS + 80 for c in hard))
    # 中英混排（中文没有空格，句子正则要靠标点兜底）
    mixed = "这是一段中文说明。This is an English sentence. 接下来又一段中文。"
    ck("中英混排能切", isinstance(T.split_chunks(mixed), list))

    print("\n[3] 术语表 GLOSSARY")
    ck("术语表非空", len(getattr(T, "GLOSSARY", [])) > 0,
       len(getattr(T, "GLOSSARY", [])))
    ck("术语表三元组结构",
       all(len(x) == 3 for x in T.GLOSSARY),
       [x for x in T.GLOSSARY if len(x) != 3][:2])
    ck("每条都有英文源词",
       all(x[0] and str(x[0]).isascii() for x in T.GLOSSARY),
       [x[0] for x in T.GLOSSARY if not str(x[0]).isascii()][:3])

    # 核心回归：源文含英文术语、译文含错译形态 → 必须被换成正确中文
    src = "A buffer overflow in the parser leads to privilege escalation."
    wrong = "一个缓冲区溢出允许提权。"
    fixed = T.apply_glossary(src, wrong)
    ck("错译形态被纠正",
       "提权" not in fixed or "权限提升" in fixed, fixed)
    ck("正确的译文不被二次改写（no-op 回归）",
       T.apply_glossary(src, "一个缓冲区溢出允许远程代码执行。")
       == "一个缓冲区溢出允许远程代码执行。",
       T.apply_glossary(src, "一个缓冲区溢出允许远程代码执行。"))

    # 源文没有该术语时，绝不能动译文（这是第一版写成 no-op 的反面）
    ck("源文无术语则不动译文",
       T.apply_glossary("The vendor released a patch.",
                        "厂商发布了补丁。") == "厂商发布了补丁。")
    # 空输入
    ck("apply_glossary 空 src 安全", isinstance(T.apply_glossary("", "文本"), str))
    ck("apply_glossary 空 dst 安全", T.apply_glossary("some text", "") == "")

    print("\n[4] worth_translating 判据")
    ck("纯英文长句要翻", T.worth_translating(
        "This is a long enough English sentence to be worth translating.") is True)
    ck("纯中文不翻", T.worth_translating("这是一段纯中文的内容，不需要翻译。") is False)
    ck("短英文词不翻", T.worth_translating("OK") is False)
    ck("空串不翻", T.worth_translating("") is False)
    ck("None 不翻", T.worth_translating(None) is False)
    # 上限必须是 8000 —— 2000 会让正常 NVD 描述超限不翻
    long_desc = "Remote code execution flaw. " * 260   # ≈ 5980 字符
    ck("约 6000 字符的 NVD 描述仍要翻（上限不是 2000）",
       T.worth_translating(long_desc) is True, len(long_desc))
    # CVE / GHSA 标识符不算英文，不该触发翻译
    ck("纯标识符不翻", T.worth_translating("CVE-2026-97679") is False)
    ck("GHSA 标识符不翻", T.worth_translating("GHSA-jfh8-c2jp-5v3q") is False)

    print("\n[5] 依赖探针不抛异常")
    try:
        deps = T.runtime_deps()
        ck("runtime_deps 返回 dict", isinstance(deps, dict))
        ck("含 ok 字段", "ok" in deps)
        ck("missing 是 list", isinstance(deps.get("missing"), list))
        ck("缺依赖时给 hint",
           deps.get("ok") is True or bool(deps.get("hint")),
           deps.get("hint"))
    except Exception as e:  # noqa: BLE001
        ck("runtime_deps 不抛异常", False, e)

    try:
        d = T.find_local_dir()
        ck("find_local_dir 返回 str 或 None", d is None or isinstance(d, str), d)
        if d:
            ck("模型目录确实存在", os.path.isdir(d), d)
    except Exception as e:  # noqa: BLE001
        ck("find_local_dir 不抛异常", False, e)

    print("\n[6] _gen 的切块拼回逻辑（不加载真实模型）")
    if hasattr(T, "LocalTranslator"):
        ck("LocalTranslator 有 _gen 方法", hasattr(T.LocalTranslator, "_gen"))
        ck("LocalTranslator 有 translate 方法",
           callable(getattr(T.LocalTranslator, "translate", None)))
        # 直接测"切块 → owner 归属 → 拼回"这一层：把 generate 换成假的。
        # 不走 __init__（那会加载 300MB 模型），只借 _gen 的分块与拼回逻辑。
        try:
            obj = T.LocalTranslator.__new__(T.LocalTranslator)
            obj.maxlen = 512
            obj.beams = 1
            obj.no_repeat = 3.0
            obj.rep_pen = 1.2

            seen = []

            class FakeTok:
                def __call__(self, idx, **kw):
                    seen.append(list(idx))
                    return {"input_ids": [[1, 2]] * len(idx)}

                @staticmethod
                def decode(_msg, skip_special_tokens=True):
                    return "译文片段"

            class FakeModel:
                def generate(self, **kw):
                    n = len(kw["input_ids"])
                    return [[9, 9, 9]] * n

            obj._tok = FakeTok()
            obj._model = FakeModel()
            out = obj._gen([long_en])
            ck("_gen 返回与输入等长的列表", len(out) == 1, out)
            # 4 条（token,9,9,9）每块 3 个非特殊 token → 译文长度 ∝ 块数
            ck("_gen 分多批送进模型（证明切块生效）",
               sum(len(b) for b in seen) >= 2,
               [len(b) for b in seen])
            ck("_gen 产出了非空译文", bool(out[0].strip()), out[0][:40])
        except Exception as e:  # noqa: BLE001
            ck("_gen 可用假 tokenizer/model 跑通", False, e)

    print("\n[7] 标识符保护（新增判据）")
    for ident in ("CVE-2026-97679", "GHSA-jfh8-c2jp-5v3q",
                  "OSV-2024-1111", "CWE-200"):
        ck("纯 %-22s 不翻" % ident, T.worth_translating(ident) is False)
    ck("标识符 + 英文句子仍要翻（只剥标识符，不是全否）",
       T.worth_translating("CVE-2026-97679 affects Ollama and allows "
                           "remote code execution on the host.") is True)
    ck("剥掉标识符后无实质内容 → 不翻",
       T.worth_translating("CVE-2026-97679 GHSA-jfh8-c2jp-5v3q") is False)

    print("\n[8] strip_dangling 悬空截断尾巴（2026-10-07 用户截图的退化根因）")
    ck("', a...' 结尾 → 剥掉尾巴",
       T.strip_dangling("vulnerable in all versions up to, a...")
       == "vulnerable in all versions up to",
       T.strip_dangling("vulnerable in all versions up to, a..."))
    ck("', a' 结尾（无省略号，单个小写字母）→ 也剥",
       T.strip_dangling("affected versions up to, a")
       == "affected versions up to",
       T.strip_dangling("affected versions up to, a"))
    ck("', and including' 结尾（完整单词）→ 不动",
       T.strip_dangling("in all versions up to, and including")
       == "in all versions up to, and including")
    ck("', 6.3.1' 结尾（数字版本号）→ 不动",
       T.strip_dangling("up to, and including, 6.3.1")
       == "up to, and including, 6.3.1")
    ck("', IP' 结尾（大写缩写）→ 不动",
       T.strip_dangling("the request came from a trusted, IP")
       == "the request came from a trusted, IP")
    ck("正常句子不受影响",
       T.strip_dangling("Ollama allows RCE via crafted GGUF file.")
       == "Ollama allows RCE via crafted GGUF file.")
    # 2026-10-07 用户截图第二形态：截断点不在逗号后（空格 + 1~2 字母 + 省略号）
    ck("' an...' 结尾（无逗号，两字母残词）→ 也剥",
       T.strip_dangling("Ransomware Detection an...")
       == "Ransomware Detection",
       repr(T.strip_dangling("Ransomware Detection an...")))
    ck("'s...' 结尾（无逗号，单字母残词）→ 也剥",
       T.strip_dangling("crafted request s...")
       == "crafted request",
       repr(T.strip_dangling("crafted request s...")))
    ck("'file.' 结尾（完整单词 + 单句点）→ 不动",
       T.strip_dangling("crafted GGUF file.")
       == "crafted GGUF file.")
    ck("'U.S...' 结尾（省略号前不是空格）→ 不动",
       T.strip_dangling("deployed across the U.S...")
       == "deployed across the U.S...",
       repr(T.strip_dangling("deployed across the U.S...")))
    ck("多层尾巴最多剥 3 层",
       T.strip_dangling("bad case, a, b...") .endswith("bad case"),
       T.strip_dangling("bad case, a, b..."))

    print("\n[9] is_degenerate 重复退化检测（截图乱码必须被判退化）")
    # 真实乱码形态：柯基 - ... 后面一整段 a, a, a / e, e, e
    garbled = ("柯基 - 自由页面构建器 WordPress网站构建器和自定义插件,"
               "通过所有版本的注册元数据,很容易被存储跨线脚本, "
               + ", ".join(["a"] * 7) + ", " + ", ".join(["e"] * 12))
    ck("截图实测乱码 → 判退化", T.is_degenerate(garbled) is True, garbled[:60])
    ck("纯英文退化 a, a, a → 判退化",
       T.is_degenerate(", ".join(["a"] * 10)) is True)
    ck("正常中文译文 → 不判退化",
       T.is_degenerate("柯基 - 自由页面构建器、WordPress网站构建器和自定义插件,"
                       "在包括6.3.1之前的所有版本中,都很容易通过注册元数据进行"
                       "存储跨脚本的存储,因为没有足够地逃脱。") is False)
    ck("正常英文长句 → 不判退化",
       T.is_degenerate("This is due to insufficient escaping in the image "
                       "element, which concatenates attacker controlled data "
                       "into the page without sanitization.") is False)
    ck("重复的 normal 单词（长 token）不误伤",
       T.is_degenerate("very very very very very long description") is False)
    ck("短文本（<24字符）直接放行",
       T.is_degenerate("a, a, a, a, a") is False)
    # 2026-10-07 用户截图第二形态：连字符串成的短词重复（长 token 逃过前三判据）
    ck("连字符短词连重复「成本-成本-…」→ 判退化",
       T.is_degenerate("成本-成本-成本-成本-成本-成本 等级·多代理检测") is True,
       "成本-成本-成本-成本-成本-成本")
    ck("连字符正常词（multi-agent / Cross-Site）→ 不判退化",
       T.is_degenerate("Multi-Agent Ransomware Detection and Response "
                       "Using Machine Learning and Cross-Site Scripting "
                       "analysis for modern web applications") is False)

    print("\n[10] _gen 的退化兜底（假模型模拟：退化 → 重试 → 保原文）")
    if hasattr(T, "LocalTranslator"):
        try:
            obj2 = T.LocalTranslator.__new__(T.LocalTranslator)
            obj2.maxlen = 512
            obj2.beams = 1
            obj2.no_repeat = 3.0
            obj2.rep_pen = 1.2
            calls = []
            mode = {"strict": False}

            class FakeTok2:
                def __call__(self, idx, **kw):
                    return {"input_ids": [[1, 2]] * len(idx)}

                @staticmethod
                def decode(_msg, skip_special_tokens=True):
                    # strict（重试）时输出正常译文，否则输出退化文本 ——
                    # 用 decode 分叉模拟"重试修好了"这一路径
                    if mode.get("always"):
                        return "a, a, a, a, a, a, a, a, a, a, e, e, e, e, e, e"
                    if mode["strict"]:
                        return "正常译文文本，信息完整，攻击者可以控制页面内容。"
                    return "a, a, a, a, a, a, a, a, a, a, e, e, e, e, e, e"

            class FakeDegModel:
                """记录 generate 参数；第一次输出退化、strict 重试输出正常"""
                def generate(self, **kw):
                    calls.append(dict(kw))
                    mode["strict"] = kw.get("repetition_penalty", 0) >= 1.5
                    return [[9, 9, 9]]

            obj2._tok = FakeTok2()
            obj2._model = FakeDegModel()
            out = obj2._gen(["A truncated title in all versions up to, a..."])
            ck("退化输出被重试并替换成正常译文",
               out == ["正常译文文本，信息完整，攻击者可以控制页面内容。"], out)
            ck("确实发生了 strict 重试（repetition_penalty ≥ 1.5）",
               any(kw.get("repetition_penalty", 0) >= 1.5 for kw in calls),
               [kw.get("repetition_penalty") for kw in calls])
            ck("首推已带反重复参数（no_repeat_ngram_size ≥ 3）",
               calls and calls[0].get("no_repeat_ngram_size", 0) >= 3,
               calls[0].get("no_repeat_ngram_size") if calls else None)
            # 2026-10-07 实测：首推带 repetition_penalty 会把正常句子推到
            # 提前 EOS（截断后半句）——钉死它只出现在 strict 重试档
            ck("首推不带 repetition_penalty（防正常句被截断）",
               calls and calls[0].get("repetition_penalty") is None,
               calls[0].get("repetition_penalty") if calls else None)

            # 始终退化的模型 → 保原文
            calls.clear()
            mode["strict"] = False
            mode["always"] = True

            class FakeAlwaysDeg:
                def generate(self, **kw):
                    calls.append(dict(kw))
                    mode["strict"] = kw.get("repetition_penalty", 0) >= 1.5
                    return [[9, 9, 9]]

            obj3 = T.LocalTranslator.__new__(T.LocalTranslator)
            obj3.maxlen = 512
            obj3.beams = 1
            obj3.no_repeat = 3.0
            obj3.rep_pen = 1.2
            obj3._tok = FakeTok2()
            obj3._model = FakeAlwaysDeg()
            src_text = "A truncated title in all versions up to, a..."
            out3 = obj3._gen([src_text])
            ck("重试仍退化 → 该块保留原文（不输出噪音）",
               out3 == ["A truncated title in all versions up to"], out3)

            # 2026-10-07：句首编号（CVE/GHSA）先摘后拼 —— 编号不进模型
            #（实测带编号会让小模型提前 EOS 丢后半句），也不该被翻译
            calls.clear()
            mode["strict"] = False
            mode["always"] = True
            obj4 = T.LocalTranslator.__new__(T.LocalTranslator)
            obj4.maxlen = 512
            obj4.beams = 1
            obj4.no_repeat = 3.0
            obj4.rep_pen = 1.2
            obj4._tok = FakeTok2()
            obj4._model = FakeAlwaysDeg()
            out4 = obj4._gen(["CVE-2024-1234 A truncated title in all versions up to, a..."])
            ck("句首编号摘下后拼回（编号不进模型）",
               out4 == ["CVE-2024-1234 A truncated title in all versions up to"], out4)
        except Exception as e:  # noqa: BLE001
            ck("_gen 退化兜底可用假模型验证", False, e)

        # 静态钉死：generate 调用必须带反重复参数（防止将来被删）
        try:
            _src = open(os.path.join(ROOT, "modules", "m3_qa", "backend",
                                     "qa", "translator.py"),
                        encoding="utf-8").read()
            ck("generate 调用带 no_repeat_ngram_size",
               "no_repeat_ngram_size" in _src)
            ck("generate 调用带 repetition_penalty",
               "repetition_penalty" in _src)
            ck("is_degenerate 检测在 _gen 的输出路径上",
               re.search(r"def _gen\(.*?is_degenerate", _src, re.S) is not None)
            ck("strip_dangling 在切块前执行",
               re.search(r"split_chunks\(strip_dangling\(", _src) is not None)
        except Exception as e:  # noqa: BLE001
            ck("读 translator.py 源码做静态断言", False, e)

    print("\n[11] 术语表补条目（Kirki / 跨线脚本 / 连字符变体）")
    ck("Kirki → 不再翻成「柯基」",
       T.apply_glossary("The Kirki plugin for WordPress",
                        "柯基 - WordPress 的插件") == "Kirki - WordPress 的插件",
       T.apply_glossary("The Kirki plugin for WordPress",
                        "柯基 - WordPress 的插件"))
    ck("跨线脚本 → 跨站脚本",
       T.apply_glossary("Stored Cross-Site Scripting via metadata",
                        "通过注册元数据的存储跨线脚本").endswith("跨站脚本"),
       T.apply_glossary("Stored Cross-Site Scripting via metadata",
                        "通过注册元数据的存储跨线脚本"))
    # 2026-10-07 修的真 bug：词表英文源词只认空格，实际文本几乎全是
    # "Cross-Site" 连字符写法 → 整条校准失效
    ck("连字符写法 Cross-Site Scripting 也能命中词表",
       T.apply_glossary("Stored Cross-Site Scripting via metadata",
                        "存储跨站点脚本") == "存储跨站脚本",
       T.apply_glossary("Stored Cross-Site Scripting via metadata",
                        "存储跨站点脚本"))
    ck("use-after-free 连字符变体也能命中",
       T.apply_glossary("leads to use-after-free condition",
                        "使用后释放漏洞") == "释放后重用漏洞",
       T.apply_glossary("leads to use-after-free condition", "使用后释放漏洞"))
    # 2026-10-07 实测补录的错译形态
    ck("Kirki → 「基尔吉」也是坏形态",
       T.apply_glossary("The Kirki plugin", "基尔吉 - WordPress 插件")
       == "Kirki - WordPress 插件",
       T.apply_glossary("The Kirki plugin", "基尔吉 - WordPress 插件"))
    ck("ransomware → 「随机波段」纠成「勒索软件」",
       T.apply_glossary("Multi-Agent Ransomware Detection",
                        "多代理随机波段检测") == "多代理勒索软件检测",
       T.apply_glossary("Multi-Agent Ransomware Detection", "多代理随机波段检测"))
    ck("ransomware → 「随机软件」纠成「勒索软件」（同轮新形态）",
       T.apply_glossary("Multi-Agent Ransomware Detection",
                        "多代理随机软件探测") == "多代理勒索软件探测",
       T.apply_glossary("Multi-Agent Ransomware Detection", "多代理随机软件探测"))
    # ★ 结构性兜底：音译变体追不完（柯基/基基/基尔吉/基尔基…），
    #   src 提到 Kirki 而译文没保留时，句首音译段直接换 Kirki
    ck("Kirki 结构兜底：未知音译变体也被纠正",
       T.apply_glossary("The Kirki plugin for WordPress",
                        "基兹 - WordPress 的插件") == "Kirki - WordPress 的插件",
       T.apply_glossary("The Kirki plugin for WordPress", "基兹 - WordPress 的插件"))
    ck("Kirki 结构兜底：译文已保留 Kirki 时不乱动",
       T.apply_glossary("The Kirki plugin for WordPress",
                        "Kirki 插件更新修复了问题") == "Kirki 插件更新修复了问题")

    print("\n[12] _env_num 坏值回落（config 被填成文字的教训）")
    os.environ["AISEC_MT_NO_REPEAT"] = "not a number"
    ck("坏值 → 默认 3.0", T._env_num("AISEC_MT_NO_REPEAT", 3.0) == 3.0)
    os.environ["AISEC_MT_NO_REPEAT"] = "4.5"
    ck("合法值 → 4.5", T._env_num("AISEC_MT_NO_REPEAT", 3.0) == 4.5)
    os.environ["AISEC_MT_NO_REPEAT"] = ""
    ck("空串 → 默认", T._env_num("AISEC_MT_NO_REPEAT", 3.0) == 3.0)
    os.environ.pop("AISEC_MT_NO_REPEAT", None)
    ck("未设置 → 默认", T._env_num("AISEC_MT_NO_REPEAT", 3.0) == 3.0)

    print("\n" + "=" * 60)
    print("通过 %d / %d" % (len(PASS), len(PASS) + len(FAIL)))
    if FAIL:
        print("失败：")
        for f in FAIL:
            print("  - " + f)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
