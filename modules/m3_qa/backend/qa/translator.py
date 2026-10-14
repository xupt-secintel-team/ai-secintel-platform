# -*- coding: utf-8 -*-
"""translator.py —— 本地免费机器翻译（英文情报 → 中文）：零 token、零外部请求、离线可用。

为什么不用第三方云翻译（原实现在前端加载 SDK 把正文发到外部端点）：
  · 不花钱：模型下载一次（约 300 MB），之后完全在本机 CPU 推理，不消耗任何 API 额度；
  · 不外发：安全情报正文不出本机（对这类工具是硬要求）；
  · 离线可用：演示现场断网也能翻 —— 配合本地嵌入模型，整条栈都是本地的。

模型：`Helsinki-NLP/opus-mt-en-zh`（MarianMT，约 300 MB，速度快）。
想要更好质量可换 `Helsinki-NLP/opus-mt-tc-big-en-zh`（约 1 GB，慢约一倍）：
    AISEC_MT_MODEL=Helsinki-NLP/opus-mt-tc-big-en-zh

环境变量：
  AISEC_MT_MODEL_DIR  模型根目录（默认 <项目根>/data/models_mt）
  AISEC_MT_MODEL      模型名（默认 Helsinki-NLP/opus-mt-en-zh）
  AISEC_MT_THREADS    CPU 线程数（默认跟 AISEC_EMBED_THREADS，封顶 24）
  AISEC_MT_MAXLEN     单条最大 token（默认 512）

命令行自测（不需要起服务）：
  py -3 modules/m3_qa/backend/qa/translator.py --status
  py -3 modules/m3_qa/backend/qa/translator.py --download
  py -3 modules/m3_qa/backend/qa/translator.py --text "Ollama allows RCE via crafted GGUF file."
"""
import argparse
import importlib
import os
import re
import shutil
import subprocess
import threading
import time
from typing import Dict, List
try:  # aisec-swallow：静默异常统一登记（允许吞，但必须留痕）
    from errlog import swallow as _swallow
except Exception:  # pragma: no cover
    try:
        from core.errlog import swallow as _swallow
    except Exception:
        def _swallow(tag, exc=None):
            pass

_MODEL = os.environ.get("AISEC_MT_MODEL", "Helsinki-NLP/opus-mt-en-zh")


def _env_num(name: str, default: float) -> float:
    """读数值型环境变量；坏值（空串/文字）回落默认 —— 被填成说明文字的
    config 会让 int() 直接崩掉服务，这里不能重蹈覆辙。"""
    v = os.environ.get(name)
    try:
        return float(v) if v else default
    except (TypeError, ValueError):
        return default

# 项目根：translator.py 位于 <项目根>/modules/m3_qa/backend/qa/ 下，需向上 5 层。
# 此前只写了 4 层，算出来落在 <项目根>/modules/ ，内置的兜底目录
# <项目根>/data/models_mt 因此永远不生效（没有第二落脚点）。
_HERE = os.path.abspath(__file__)
_PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(
    os.path.dirname(os.path.dirname(_HERE)))))

_ROOTS = [
    os.environ.get("AISEC_MT_MODEL_DIR", ""),
    os.path.join(_PROJECT_ROOT, "data", "models_mt"),
]

# 已经是中文的不翻（只统计汉字占比，够用且不依赖分词）
_CJK = re.compile(r"[\u4e00-\u9fff]")
_HTML = re.compile(r"<[^>]+>")
_WS = re.compile(r"\s+")
# 句子边界（中英文标点 + 换行）。长文本按它切块后再送模型。
_SENT_SPLIT = re.compile(r"(?<=[.!?;。！？；])\s+|\n+")
# 纯标识符：GHSA-jfh8-c2jp-5v3q / CVE-2026-97679 / OSV-2024-111 / CWE-200
_ID_ONLY = re.compile(r"\b(?:CVE|CWEs?|GHSA|OSV|PYSEC|GMS|RUSTSEC|MAL|MS\d{2})-[\w.\-]+",
                      re.IGNORECASE)
# 悬空截断尾巴：前端列表的标题是截断显示的，常以 ", a..." / ", a" 结尾。
# 这种残句送进 Marian，解码器从悬空片段续写会陷入重复循环 ——
# 实测输出整段 "a, a, a, a, e, e, e, ..."（2026-10-07 用户截图）。
# 有省略号时允许剥 1~2 个字母；没有省略号时只剥单个**小写**字母
# （", a" 这类；两字母的大写缩写如 ", IP"、", OS" 是正常文本，不能动）。
# 2026-10-07 补第二种形态：空格 + 1~2 字母 + 省略号（"Detection an..."，
# 截断点不在逗号后）。完整单词/数字版本号不受影响；"U.S..." 因省略号前
# 不是空格而安全。
_DANGLING_TAIL = re.compile(
    r"(?:[,，、;；]\s*(?:[A-Za-z]{1,2}\s*(?:\.{2,}|…)|[a-z])"
    r"|\s+[A-Za-z]{1,2}\s*(?:\.{2,}|…))\s*$")
# 句首编号（CVE-2026-102173 / GHSA-xxxx-… 等）。编号**不该翻译**（翻了会
# 翻坏），且实测带编号进模型会让小模型玄学提前 EOS——后半句整段丢失
# （2026-10-07 实测：同句去掉编号即完整）。翻译前摘下、译文前拼回。
_LEADING_ID = re.compile(
    r"^\s*((?:CVE|GHSA|VU|MSRC)[-A-Za-z0-9]{3,40})\s+", re.I)
# 单块上限。MarianMT 的 max_length 默认 512 token，英文约 1 token ≈ 4 字符，
# 留足余量后取 400 字符/块 —— 超长会被**静默截断**（丢后半段），那是"翻了一半"。
_CHUNK_CHARS = 400


def strip_dangling(text: str) -> str:
    """去掉结尾的悬空截断尾巴（", a..." / ", a"），最多剥 3 层。

    为什么必须在送模型之前做：截断标题的尾巴（悬在逗号 + 半个词上）是
    解码器重复循环的强诱因。翻译层无法拿到完整原文（前端截断显示时
    传来的就是残句），只能把明显残缺的尾巴去掉 —— 少翻几个词无所谓，
    输出一整屏 "a, a, a" 才是真事故。
    """
    s = str(text or "").strip()
    for _ in range(3):
        s2 = _DANGLING_TAIL.sub("", s).strip()
        if s2 == s:
            break
        s = s2
    return s


def is_degenerate(text: str) -> bool:
    """检测译文是否"重复退化"（模型输出循环，如整段 a, a, a / e, e, e）。

    MarianMT 小模型在残句/异形输入上偶发解码循环，输出没有任何信息量，
    给用户看比不翻还糟。三个判据（命中任一即退化，纯逻辑、可离线测试）：
      1. 同一个短 token 连续出现 ≥ 5 次（", a, a, a, a, a"）；
      2. token 数 ≥ 20 且 ≤2 字符的超短 token 占比 > 50%；
      3. 单个非空白字符连续出现 ≥ 15 次（"。。。。。"）。
    """
    t = str(text or "").strip()
    if len(t) < 24:
        return False
    segs = [s for s in re.split(r"[,，、;；\s]+", t) if s]
    run, best = 1, 1
    for i in range(1, len(segs)):
        # 只有超短 token（≤3 字符，如 a / e / 100）的连续重复才算退化信号；
        # 长词的重复（"very very very..."）交给判据 2 按占比兜底，
        # 否则正常强调式重复会被误伤。
        if segs[i] == segs[i - 1] and len(segs[i]) <= 3:
            run += 1
            if run > best:
                best = run
        else:
            run = 1
    if best >= 5:
        return True
    if len(segs) >= 20:
        short = sum(1 for s in segs if len(s) <= 2)
        if short / len(segs) > 0.5:
            return True
    if re.search(r"(.)\1{14,}", t):
        return True
    # 判据 4（2026-10-07 实测新增）：同一个 ≤4 字符 token 被 "-"、"·" 等
    # 连接符串成 ≥5 连 —— "Cost-Aware" 类标题退化成
    # "成本-成本-成本-成本-成本"。主判据按空白/逗号切分时它是一个长
    # token，三个判据全部漏过（用户截图实测）。
    # ★ 只按连接符切、**不含空白**："very very very"（空格连接的强调
    #   重复）保持既有豁免，不被误伤。
    segs2 = [s for s in re.split(r"[\-·・—]+", t) if s]
    run, best2 = 1, 1
    for i in range(1, len(segs2)):
        if segs2[i] == segs2[i - 1] and len(segs2[i]) <= 4:
            run += 1
            if run > best2:
                best2 = run
        else:
            run = 1
    if best2 >= 5:
        return True
    return False


def split_chunks(text: str, limit: int = _CHUNK_CHARS):
    """把长文本切成不超过 `limit` 字符的块（尽量在句子边界断开）。

    为什么要切：MarianTokenizer 的 truncation=True 会把超出 max_length 的部分
    **直接丢掉**。一条 3000 字符的漏洞描述直接送进去，出来的译文只覆盖开头
    200 字 —— 用户看到"翻译了但后面没了"，比不翻译更难排查。
    单句本身就超长时按字符硬切，保证每块都进得去。
    """
    s = _WS.sub(" ", str(text or "")).strip()
    if not s:
        return []
    if len(s) <= limit:
        return [s]
    out, buf = [], ""
    for piece in _SENT_SPLIT.split(s):
        piece = (piece or "").strip()
        if not piece:
            continue
        while len(piece) > limit:                 # 超长句：硬切
            if buf:
                out.append(buf)
                buf = ""
            out.append(piece[:limit])
            piece = piece[limit:]
        if not piece:
            continue
        if buf and len(buf) + 1 + len(piece) <= limit:
            buf += " " + piece
        else:
            if buf:
                out.append(buf)
            buf = piece
    if buf:
        out.append(buf)
    return out


# --------------------------------------------------------------------------
# 安全术语校准表（MarianMT 直译后的人工校正）
# --------------------------------------------------------------------------
# 为什么需要：opus-mt-en-zh 是通用语料训练的，安全术语它并不认识 ——
# 实测 "buffer overflow" 会被翻成「缓冲溢出」，"exploit" 翻成「利用」还好，
# 但 "privilege escalation" 会出「特权升级」、"prompt injection" 出「提示注入」。
# 这种译文给安全人员看是不能接受的，而换大模型要 1GB+ 且慢一倍。
# 这里做**定向纠正**：只有当源文里确实出现了对应英文、且译文里确实出现了
# 错译形态时才替换，不动句子结构 —— 比换模型便宜得多、也快得多。
#
# 结构：(英文源词, 正确中文, 需要纠正的错译形态...)
GLOSSARY = [
    ("buffer overflow", "缓冲区溢出", ("缓冲溢出", "缓冲区溢出")),
    ("heap overflow", "堆溢出", ("堆溢出",)),
    ("stack overflow", "栈溢出", ("栈溢出",)),
    ("use after free", "释放后重用", ("使用后释放", "释放后免费")),
    ("remote code execution", "远程代码执行", ("远程代码执行", "远程代码执行")),
    ("arbitrary code execution", "任意代码执行", ("任意代码执行",)),
    ("command injection", "命令注入", ("命令注入",)),
    ("code injection", "代码注入", ("代码注入",)),
    ("cross site scripting", "跨站脚本", ("跨站点脚本", "跨线脚本", "跨站脚本")),
    ("cross site request forgery", "跨站请求伪造", ("跨站点请求伪造", "跨站请求伪造")),
    ("server side request forgery", "服务端请求伪造", ("服务器端请求伪造", "服务端请求伪造")),
    ("directory traversal", "目录遍历", ("目录遍历",)),
    ("path traversal", "路径穿越", ("路径遍历", "路径穿越")),
    ("prototype pollution", "原型链污染", ("原型污染", "原型链污染")),
    ("denial of service", "拒绝服务", ("拒绝服务",)),
    ("privilege escalation", "权限提升", ("特权升级", "提权", "权限提升")),
    ("authentication bypass", "认证绕过", ("身份验证绕过", "认证绕过")),
    ("unauthorized access", "越权访问", ("未经授权的访问", "越权访问")),
    ("brute force", "暴力破解", ("暴力破解", "残暴力量")),
    # ★ ransomware 的 bad 列表原来写成与正确词相同（等于没生效）——
    #   2026-10-07 实测 opus-mt 把 "Ransomware Detection" 翻成「随机波段 检测」，
    #   必须收录真实错译形态，否则这条词表是摆设。
    ("ransomware", "勒索软件", ("随机波段", "随机软件", "勒索软件")),
    ("botnet", "僵尸网络", ("僵尸网络",)),
    ("phishing", "钓鱼攻击", ("网络钓鱼", "钓鱼攻击")),
    ("social engineering", "社会工程", ("社会工程",)),
    ("supply chain attack", "供应链攻击", ("供应链攻击",)),
    ("threat intelligence", "威胁情报", ("威胁情报",)),
    ("active exploitation", "在野利用", ("主动利用", "在野利用")),
    ("prompt injection", "提示词注入", ("提示注入", "提示词注入")),
    ("jailbreak", "越狱", ("越狱",)),
    ("data poisoning", "数据投毒", ("数据中毒", "数据投毒")),
    ("model extraction", "模型窃取", ("模型提取", "模型窃取")),
    ("membership inference", "成员推断", ("成员推断",)),
    ("adversarial example", "对抗样本", ("对抗性例子", "对抗样本")),
    ("inference framework", "推理框架", ("推理框架",)),
    ("vector database", "向量数据库", ("向量数据库",)),
    ("zero day", "零日漏洞", ("零天", "零日漏洞")),
    ("intrusion detection", "入侵检测", ("入侵检测",)),
    ("honeypot", "蜜罐", ("蜜罐", "蜂蜜罐")),
    ("fuzzing", "模糊测试", ("模糊测试",)),
    # 产品名不翻：Kirki（WordPress 插件）实测被翻成「柯基」（犬种）甚至
    # 「Kiki」，必须纠正。bad 列表按实测出现过的形态积累
    # （2026-10-07 补「基尔吉」——反重复参数调整后的新错译形态）。
    ("kirki", "Kirki", ("柯基", "Kiki", "基基", "基尔吉", "基尔基")),
]
_GLOSS = []
for _en, _good, _bad in GLOSSARY:
    try:
        # 源词里的空格要能同时匹配 "cross site" / "Cross-Site"（连字符变体）——
        # 漏洞标题几乎全用连字符写法，实测 Cross-Site Scripting 因词表
        # 只认空格而整条失效（2026-10-07）。
        _pat = re.escape(_en).replace(r"\ ", r"[\s\-]+")
        _GLOSS.append((re.compile(r"(?<![a-z0-9])" + _pat + r"(?![a-z0-9])", re.I),
                       _good, tuple(_bad)))
    except Exception:  # pragma: no cover
        pass


def apply_glossary(src: str, dst: str) -> str:
    """按安全术语表纠正译文（源文命中英文 且 译文命中错译形态时才动）。"""
    s_l = str(src or "")
    out = str(dst or "")
    if not out:
        return out
    for pat, good, bad in _GLOSS:
        if not pat.search(s_l):
            continue
        for b in bad:
            if b != good and b in out:
                out = out.replace(b, good)
    # Kirki 类产品名兜底（2026-10-07）：音译变体层出不穷
    # （柯基/Kiki/基基/基尔吉/基尔基…），bad 列表追不完。规则：
    # src 确实提到 kirki、译文没保留 "Kirki" 时，把句首分隔符前的
    # CJK 音译段直接换成 Kirki —— 标题里产品名总在 " - " 前。
    if re.search(r"(?<![a-z0-9])kirki(?![a-z0-9])", s_l, re.I) \
            and not re.search(r"(?<![A-Za-z])Kirki(?![A-Za-z])", out):
        m = re.match(r"^([\u4e00-\u9fff]{1,6})(\s*[-–—]\s*)", out)
        if m:
            out = "Kirki" + m.group(2) + out[m.end():]
    return out


def candidate_dirs(model_name: str = "") -> List[str]:
    """该模型可能的本地目录（按优先级）"""
    short = (model_name or _MODEL).split("/")[-1]
    return [os.path.join(r, short) for r in _ROOTS if r]


# 判「齐」不能只看文件在不在：实测踩过坑 —— vocab.json 只下到 94 KB（应为 1.6 MB），
# 存在但残缺，加载时 transformers 5.x 只会抛一句很难懂的 TypeError（sentencepiece 拿到 None 路径）。
# 所以按「最小合理体积」判，宁可判为未就绪、让人重下，也不要假装可用。
_MIN_SIZE = {
    "config.json": 500,
    "vocab.json": 1_000_000,
    "source.spm": 500_000,
    "target.spm": 500_000,
    "pytorch_model.bin": 100_000_000,
    "model.safetensors": 100_000_000,
}


def missing_files(d: str) -> List[str]:
    """该目录还缺/残缺哪些关键文件（空 = 齐全）。用最小体积判定，残包也算缺。"""
    if not d or not os.path.isdir(d):
        return ["config.json", "vocab.json", "source.spm", "target.spm", "权重(pytorch_model.bin)"]
    miss = []
    for f, minsz in _MIN_SIZE.items():
        if f.startswith(("pytorch_model", "model.safetensors")):
            continue
        p = os.path.join(d, f)
        if not os.path.isfile(p) or os.path.getsize(p) < minsz:
            miss.append(f)
    if not any(os.path.isfile(os.path.join(d, w)) and os.path.getsize(os.path.join(d, w)) >= _MIN_SIZE[w]
               for w in ("pytorch_model.bin", "model.safetensors")):
        miss.append("权重(pytorch_model.bin)")
    return miss


def find_local_dir(model_name: str = "", strict: bool = True) -> str:
    """找到可用的本地模型目录。strict=True 时要求文件齐全（缺就视为不可用）。"""
    for d in candidate_dirs(model_name):
        if not os.path.isdir(d) or not os.path.exists(os.path.join(d, "config.json")):
            continue
        if strict and missing_files(d):
            continue
        return d
    return ""


def partial_dir(model_name: str = "") -> str:
    """有目录但没下全的情况（给用户一句准确的话，而不是让他猜）"""
    for d in candidate_dirs(model_name):
        if os.path.isdir(d) and os.path.exists(os.path.join(d, "config.json")) and missing_files(d):
            return d
    return ""


def runtime_deps() -> Dict:
    """翻译真正跑起来所需的运行时依赖。

    模型文件下齐了 ≠ 能用：MarianMT 的分词依赖 sentencepiece，缺了它会在
    from_pretrained 阶段抛 ImportError，界面只显示「翻译不可用」却不说缺什么，
    极易被误判成「模型没下载好」。这里单独查一次，把缺失项明确报出来。
    """
    need = (("torch", "torch"), ("transformers", "transformers"),
            ("sentencepiece", "sentencepiece"))
    miss = []
    for imp, pkg in need:
        try:
            importlib.import_module(imp)
        except Exception as _sw_e:  # noqa: BLE001
            _swallow("modules/m3_qa/backend/qa/translator.py:runtime_deps", _sw_e)
            miss.append(pkg)
    return {"ok": not miss, "missing": miss,
            "hint": ("pip install " + " ".join(miss)) if miss else ""}


def _threads() -> int:
    """翻译推理用的 CPU 线程数。

    踩过的坑：别写成 os.environ.get(k, "0") or ... —— 默认值 "0" 是**非空字符串**，
    在 Python 里属于 truthy，or 链会当场取到 "0" 而永远走不到 cpu_count()，
    结果 int("0")==0 → set_num_threads(max(1,min(0,24)))==1，推理被锁在单线程，
    状态接口还报 threads=0（看起来像没设置）。默认值必须给 None 才不会被误吞。
    """
    v = os.environ.get("AISEC_MT_THREADS") or os.environ.get("AISEC_EMBED_THREADS")
    try:
        n = int(v) if v else 0
    except (TypeError, ValueError) as _sw_e:  # noqa: BLE001
        _swallow("modules/m3_qa/backend/qa/translator.py:_threads", _sw_e)
        n = 0
    n = n or (os.cpu_count() or 4)
    try:                       # 性能档位：低配机器上推理线程压到 2
        from envprofile import T
        n = T.workers(min(n, 24))
    except Exception:
        n = min(n, 24)
    return max(1, n)


def _dir_size_mb(d: str) -> float:
    tot = 0
    for root, _dirs, files in os.walk(d):
        for f in files:
            try:
                tot += os.path.getsize(os.path.join(root, f))
            except OSError as _sw_e:
                _swallow("modules/m3_qa/backend/qa/translator.py:108", _sw_e)
    return round(tot / 1024 / 1024, 1)


def clean(text: str) -> str:
    """去标签、压空白。翻译层只关心纯文本。"""
    t = _HTML.sub(" ", str(text or ""))
    t = t.replace("&nbsp;", " ").replace("&amp;", "&").replace("&lt;", "<").replace("&gt;", ">")
    return _WS.sub(" ", t).strip()


def worth_translating(text: str) -> bool:
    """值得翻吗：太短/太长/已是中文/全是链接标识符 → 跳过（省时间，也避免把 CVE 号翻坏）

    上限从 2000 放宽到 8000（2026-10-07）：前端开启「译」后要自动覆盖整页，
    而情报正文（漏洞描述、博客摘要）动辄 2000~6000 字符 —— 旧上限会让
    「页面上大部分英文」里恰好最长、最该翻的那批直接不翻，用户看不出差别。
    超长文本由 `split_chunks()` 切块后逐块翻，不会被截断。
    """
    t = clean(text)
    if len(t) < 8 or len(t) > 8000:
        return False
    # 纯标识符（CVE-2026-97679 / GHSA-jfh8-c2jp-5v3q / OSV-2024-111）不翻。
    # 它们由大写字母 + 连字符 + 数字组成，字母占比高，会一路通过下面的
    # 「英文占比」判断 —— 翻出来必然是乱的，还会把 CVE 号翻坏。
    # 注意：**必须在英文占比判断之前**，否则拦不住。
    stripped = _ID_ONLY.sub("", t).strip()
    if not stripped:
        return False
    t = stripped
    if _CJK.search(t) and len(_CJK.findall(t)) / max(1, len(t)) > 0.12:
        return False
    letters = len(re.findall(r"[A-Za-z]", t))
    return letters / max(1, len(t)) > 0.5


class LocalTranslator:
    """本地翻译（线程安全，进程内单例，懒加载）"""

    def __init__(self):
        self.ok = False
        self._tok = None
        self._model = None
        self._lock = threading.Lock()
        self._loaded = False
        self._note = ""
        self.model_name = _MODEL
        self.model_dir = ""
        self.maxlen = int(os.environ.get("AISEC_MT_MAXLEN", "512"))
        self.beams = int(os.environ.get("AISEC_MT_BEAMS", "1"))
        # 反重复退化参数（2026-10-07 实测踩坑：截断标题令解码器输出
        # 整段 "a, a, a, e, e, e"）。no_repeat_ngram_size=3 对中文是安全的
        # —— 正常中文几乎不会有重复的 3-gram，但能掐断 ", a, a" 这类循环；
        # repetition_penalty=1.2 是温和档，不明显伤正常措辞。
        # 数值可被环境变量覆盖；坏值回落默认（config 被填成文字的教训同样适用）。
        self.no_repeat = _env_num("AISEC_MT_NO_REPEAT", 3.0)
        # rep_pen 只在 strict 重试档使用（首推带上会把正常句子截断，见 _gen_chunk）
        self.rep_pen = _env_num("AISEC_MT_REP_PEN", 1.2)

    # ---------------------------------------------------------------- 加载/状态
    def ensure(self) -> bool:
        """确保模型已加载；返回是否可用（失败不抛，调用方降级为「原文照抄」）"""
        if self._loaded:
            return self.ok
        with self._lock:
            if self._loaded:
                return self.ok
            self._loaded = True
            try:
                self._load()
            except Exception as e:  # noqa: BLE001
                self.ok = False
                self._note = f"{type(e).__name__}: {e}"
                print(f"[LocalTranslator] 加载失败，翻译不可用（其余功能不受影响）：{self._note}")
            return self.ok

    def _load(self) -> None:
        # 先查运行时依赖：缺 sentencepiece 时 transformers 只抛一句 ImportError，
        # 不说是哪个包，排查成本很高。这里直接给出可执行的安装命令。
        deps = runtime_deps()
        if not deps["ok"]:
            raise RuntimeError(
                f"缺少运行时依赖 {'、'.join(deps['missing'])}"
                f"（模型文件已就位，装上即可用）：{deps['hint']}")
        import torch
        from transformers import MarianMTModel, MarianTokenizer

        os.environ.setdefault("TOKENIZERS_PARALLELISM", "false")
        torch.set_num_threads(_threads())

        local = find_local_dir()
        target = local or self.model_name          # 本地有就直接用本地，绝不联网
        self._tok = MarianTokenizer.from_pretrained(target)
        self._model = MarianMTModel.from_pretrained(target)
        self._model.eval()
        self.model_dir = local
        self.ok = True
        print(f"[LocalTranslator] 已就绪（本地免费翻译）：{self.model_name} "
              f"目录={local or '（HF 缓存）'} 线程={torch.get_num_threads()}")

    def status(self) -> Dict:
        d = self.model_dir or find_local_dir()
        part = "" if d else partial_dir()
        miss = missing_files(part) if part else []
        deps = runtime_deps()
        if not d:
            hint = (f"已下部分文件，还缺 {'、'.join(miss)}：重新下载即可续传" if part else
                    "未下载：POST /api/qa/mt_download 或双击「下载翻译模型.bat」（约 300 MB 一次性，免费，之后离线可用）")
        elif not deps["ok"]:
            # 模型齐了但依赖不全 —— 不说清楚的话，用户只会看到「翻译不可用」，
            # 然后回头去反复重下那 300 MB，白等好几轮。
            hint = (f"模型已就位，但缺少运行时依赖 {'、'.join(deps['missing'])}：{deps['hint']}"
                    f"（装完无需重下模型）")
        else:
            hint = ""
        return {
            "ready": bool(d),
            "loaded": bool(self.ok),
            "model": self.model_name,
            "dir": d,
            "size_mb": _dir_size_mb(d or part) if (d or part) else 0,   # 没下全时也报「已下了多少」
            "threads": _threads(),
            "cost": "免费（本地 CPU 推理，不消耗任何 API 额度、不外发正文）",
            "note": self._note,
            "partial_dir": part,
            "missing": miss,
            "deps": deps,
            "hint": hint,
        }

    # ---------------------------------------------------------------- 下载
    def download(self, progress=None) -> Dict:
        """下载模型。返回 {ok, dir, size_mb, seconds, missing, error}

        本机实测的三条路（写在这里免得以后又踩）：
          1. huggingface_hub 的 snapshot_download：走代理时会卡在某个文件上反复
             "read operation timed out" —— 因为权重被重定向到 Xet CDN（us.aws.cdn.hf.co），
             Clash 转发该域会 SSL UNEXPECTED_EOF。
          2. huggingface.co 直连：本机直接超时（HTTP 000），必须挂代理。
          3. **ModelScope 镜像：直连可用（实测 780 KB/s），文件与原仓库一致（按体积核对）**。
        所以默认走 3（直连、不依赖代理，评委机器上只要能上网就行），失败再退回 1。
        已下好的文件按体积跳过；体积对不上（下了一半）就重下 —— 实测踩过 vocab.json 只下到 94 KB。
        """
        t0 = time.time()
        # 依次试建候选目录，取第一个成功的：换机器时首选盘符（E:）未必存在，
        # 硬写 [0] 会在 os.makedirs 阶段直接抛错，换成项目内目录就能继续。
        dest = ""
        for cand in candidate_dirs():
            try:
                os.makedirs(cand, exist_ok=True)
                dest = cand
                break
            except OSError as _sw_e:  # noqa: BLE001
                _swallow("modules/m3_qa/backend/qa/translator.py:download.dest", _sw_e)
        if not dest:
            return {"ok": False, "dir": "", "size_mb": 0,
                    "missing": ["目录"], "seconds": round(time.time() - t0, 1),
                    "source": "-", "log": [],
                    "error": f"所有候选目录都无法创建：{'、'.join(candidate_dirs())}"
                             f"（可设 AISEC_MT_MODEL_DIR 指定）"}
        files = ["config.json", "generation_config.json", "metadata.json",
                 "tokenizer_config.json", "vocab.json", "source.spm", "target.spm",
                 "pytorch_model.bin"]
        curl = shutil.which("curl")
        no_proxy_env = dict(os.environ)
        for k in ("HTTPS_PROXY", "HTTP_PROXY", "ALL_PROXY", "https_proxy", "http_proxy", "all_proxy"):
            no_proxy_env.pop(k, None)                 # ModelScope 直连：带上代理反而会绕远甚至失败
        no_proxy_env["NO_PROXY"] = "*"

        log: List[str] = []
        got_ms = False
        if curl:
            for i, f in enumerate(files, 1):
                path = os.path.join(dest, f)
                need = _MIN_SIZE.get(f, 1)
                if os.path.isfile(path) and os.path.getsize(path) >= need:
                    log.append(f"{f} 已有，跳过")
                    continue
                if os.path.isfile(path) and os.path.getsize(path) < need:
                    # 残包：优先删掉重下。但**删不掉也要能继续** —— 实测踩过：
                    # 文件还被上一个中断的 curl/杀软扫描占着时 os.remove 抛 WinError 32，
                    # 整个下载就带着 traceback 挂掉（难看且没必要）。截断的文件本来就是
                    # 远端文件的合法前缀，curl -C - 接着下没问题，最后按体积核对。
                    try:
                        os.remove(path)
                    except OSError as _sw_e:
                        _swallow("modules/m3_qa/backend/qa/translator.py:244", _sw_e)
                if progress:
                    progress(f"{i}/{len(files)} {f}", int(i * 100 / len(files)))
                url = f"https://modelscope.cn/models/{self.model_name}/resolve/master/{f}"
                for _attempt in range(1, 4):
                    try:
                        subprocess.run([curl, "-sL", "-C", "-", "--retry", "3", "--retry-delay", "5",
                                        "--retry-all-errors", "--speed-limit", "20000",
                                        "--speed-time", "45", "--max-time", "1800",
                                        "-o", path, url],
                                       timeout=1900, check=False, env=no_proxy_env)
                    except subprocess.TimeoutExpired as _sw_e:
                        _swallow("modules/m3_qa/backend/qa/translator.py:256", _sw_e)
                    if os.path.isfile(path) and os.path.getsize(path) >= need:
                        got_ms = True
                        break
                    time.sleep(2)
                sz = os.path.getsize(path) if os.path.isfile(path) else 0
                log.append(f"{f} → {sz/1048576:.1f} MB")

        miss = missing_files(dest)
        if miss and curl:                             # 镜像没下全 → 退回官方（走代理）
            proxy = os.environ.get("AISEC_PROXY") or os.environ.get("HTTPS_PROXY") or ""
            env2 = dict(os.environ)
            if proxy:
                env2["HTTPS_PROXY"] = proxy
                env2["HTTP_PROXY"] = proxy
            for f in files:
                path = os.path.join(dest, f)
                if os.path.getsize(path) >= _MIN_SIZE.get(f, 1) if os.path.isfile(path) else False:
                    continue
                try:
                    subprocess.run([curl, "-sL", "-C", "-", "--retry", "2", "--retry-delay", "4",
                                    "--max-time", "600", "-o", path,
                                    f"https://huggingface.co/{self.model_name}/resolve/main/{f}"],
                                   timeout=700, check=False, env=env2)
                except subprocess.TimeoutExpired as _sw_e:
                    _swallow("modules/m3_qa/backend/qa/translator.py:281", _sw_e)
            miss = missing_files(dest)

        return {"ok": not miss, "dir": dest, "size_mb": _dir_size_mb(dest),
                "missing": miss, "seconds": round(time.time() - t0, 1),
                "source": "modelscope（直连镜像）" if got_ms else "huggingface（代理）",
                "log": log[-4:],
                "error": None if not miss else f"缺少/残缺文件：{'、'.join(miss)}（重跑本命令会续传）"}

    # ---------------------------------------------------------------- 翻译
    def _gen_chunk(self, chunks, strict: bool = False):
        """一批块送模型生成。strict=True 时用更强的反重复参数重试。

        ★ 首推**不带** repetition_penalty（2026-10-07 实测教训）：
        它把 "WordPress" 这类合法重复词一起惩罚，实测把正常句子推到
        提前 EOS——"…is vulnerable to Stored Cross-Site Scripting via
        registration metadata in all versions up to" 只翻出前半句
        （隔离变量复现：加 rep_pen 即截断，去掉即完整）。
        均匀 token 死循环（"a, a, a"）由 no_repeat_ngram_size 单独挡住
        就够；rep_pen 只留在 strict 重试档——那时输出已经是退化重试，
        就算句子被压短也比 "a, a, a" 强。
        """
        import torch
        batch = self._tok(chunks, return_tensors="pt",
                          padding=True, truncation=True, max_length=self.maxlen)
        gen_kw = dict(max_length=self.maxlen, num_beams=self.beams,
                      no_repeat_ngram_size=int(self.no_repeat))
        if strict:
            # 重试档：n-gram 抑制更狠、重复惩罚更大、beam 拉到 2
            gen_kw.update(no_repeat_ngram_size=max(4, int(self.no_repeat) + 1),
                          repetition_penalty=max(1.5, self.rep_pen + 0.3),
                          num_beams=max(2, self.beams))
        with torch.no_grad():
            gen = self._model.generate(**batch, **gen_kw)
        return [self._tok.decode(g, skip_special_tokens=True).strip() for g in gen]

    def _gen(self, texts):
        """核心推理：摘句首编号 → 去悬空尾巴 → 切块 → 分批 generate →
        退化检测/重试 → 编号拼回。返回 [str]。
        退化的块宁可保留原文，绝不输出 "a, a, a" 这种噪音。"""
        # 句首编号（CVE-…/GHSA-…）先摘下来：①编号不该翻译（翻了会翻坏）；
        # ②实测带编号进模型会让小模型玄学提前 EOS——"CVE-2026-… The Kirki
        # … is vulnerable to …" 只翻出前半句，摘掉编号即完整（隔离复现）。
        prefixes, cores = [], []
        for t in texts:
            m = _LEADING_ID.match(t)
            if m:
                prefixes.append(m.group(1))
                cores.append(t[m.end():])
            else:
                prefixes.append("")
                cores.append(t)
        chunks, owner = [], []
        for i, t in enumerate(cores):
            for c in (split_chunks(strip_dangling(t)) or [t]):
                chunks.append(c)
                owner.append(i)
        res = [""] * len(texts)
        parts = [[] for _ in texts]
        for k in range(0, len(chunks), 8):            # 小批量，内存友好
            idx = chunks[k:k + 8]
            outs = self._gen_chunk(idx)
            for j, dst in enumerate(outs):
                c_src = idx[j]
                if is_degenerate(dst):
                    # 退化：换更保守的参数重试一次；仍退化 → 该块保原文。
                    # （翻错不如不翻：输出原文用户能看懂，"a, a, a" 只会被当成坏了。）
                    try:
                        d2 = self._gen_chunk([c_src], strict=True)[0]
                        if not is_degenerate(d2):
                            dst = d2
                        else:
                            dst = c_src
                    except Exception as _sw_e:  # noqa: BLE001
                        _swallow("modules/m3_qa/backend/qa/translator.py:_gen.retry", _sw_e)
                        dst = c_src
                parts[owner[k + j]].append(dst)
        for i, _t in enumerate(texts):
            body = " ".join(p for p in parts[i] if p).strip()
            res[i] = (prefixes[i] + " " + body).strip() if body else prefixes[i]
        return res

    def translate(self, texts: List[str], target_lang: str = "zh") -> Dict:
        """批量英译中。返回 {items:[{src,dst,skipped}], engine, minutes_saved, ms, ready}"""
        t0 = time.time()
        src = [clean(t) for t in (texts or [])]
        out = [{"src": s, "dst": s, "skipped": True} for s in src]
        todo = [i for i, s in enumerate(src) if worth_translating(s)]
        if not todo:
            return {"items": out, "engine": "local-marian", "ready": self.status()["ready"],
                    "ms": 0, "note": "没有需要翻译的文本（太短/已是中文/纯符号）"}
        if not self.ensure():
            return {"items": out, "engine": "local-marian", "ready": False, "ms": 0,
                    "error": f"翻译模型不可用：{self._note or '未下载'}"}
        try:
            dsts = self._gen([src[i] for i in todo])
            for i, dst in zip(todo, dsts):
                dst = apply_glossary(src[i], dst)
                out[i] = {"src": src[i], "dst": dst or src[i], "skipped": False}
            ms = int((time.time() - t0) * 1000)
            return {"items": out, "engine": "local-marian", "ready": True, "ms": ms,
                    "translated": len(todo), "skipped": len(src) - len(todo),
                    "note": "本地模型翻译：不花 token、正文不出本机（长文本已分块，不会截断）"}
        except Exception as e:  # noqa: BLE001
            self._note = f"{type(e).__name__}: {e}"
            return {"items": out, "engine": "local-marian", "ready": True, "ms": 0,
                    "error": f"翻译失败：{self._note}"}


translator = LocalTranslator()


def main() -> int:
    ap = argparse.ArgumentParser(description="本地免费翻译（英→中）自测")
    ap.add_argument("--status", action="store_true")
    ap.add_argument("--download", action="store_true")
    ap.add_argument("--text", default="")
    a = ap.parse_args()
    if a.status:
        import json
        print(json.dumps(translator.status(), ensure_ascii=False, indent=2))
        return 0
    if a.download:
        def prog(stage, pct):
            print(f"  [{stage}] {pct}%", flush=True)
        r = translator.download(prog)
        import json
        print(json.dumps(r, ensure_ascii=False, indent=2))
        return 0 if r.get("ok") else 1
    if a.text:
        r = translator.translate([a.text])
        for it in r["items"]:
            print("原文：", it["src"])
            print("译文：", it["dst"])
        print(f"引擎={r['engine']} 就绪={r['ready']} 耗时={r.get('ms')}ms "
              f"{r.get('error') or r.get('note') or ''}")
        return 0 if not r.get("error") else 1
    ap.print_help()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
