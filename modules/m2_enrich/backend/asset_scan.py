# -*- coding: utf-8 -*-
"""
asset_scan.py —— 公司互联网资产「上传 → 解析 → 风险体检」
============================================================================
负责人：成员B（情报富化模块新增能力）

用户需求（2026-10-03）
    「富化台内容严重不足：要能上传公司互联网资产（word / txt / excel），
      利用检测模块 1 的内容自动分析这些资产面临的风险。」

本模块做的事（一句话）：把一份《资产清单》文件变成一份「哪些资产、被哪些漏洞、
为什么受影响、先修哪个」的风险报告；判定依据全部来自模块 1 采集入库的真实情报，
不猜、不联网、不外发（文件只在本机解析）。

流水线
-----
    ① 解析文件      read_upload()      docx / xlsx / txt / csv / md / json / xml 为主，
                                       .doc / .xls（OLE 二进制）走「可打印串」尽力解析
    ② 抽取资产      extract_assets()   域名 / 子域 / URL / IPv4 / IPv6 / 邮箱 / 端口 /
                                       软件（产品+版本）/ 操作系统 / 文件里已写的 CVE
    ③ 关联上下文    ——                 同一行（或同一表格行）里出现的「主机 + 软件」互为
                                       承载关系：主机风险 = 其上软件风险的最大值
    ④ 精确匹配      AssetRiskScanner   用模块 1 语料里 NVD 原始 CPE 的版本区间做区间判定
                                       （versionStartIncluding / versionEndExcluding …），
                                       不是关键词命中；再叠加 KEV 在野利用 / CVSS / 可信度 /
                                       处置建议 / 官方补丁 / POC 线索
    ⑤ 出报告        build_report()     资产级 + 全局级；落盘 data/asset_scans.json（可回看）
                                       并可导出 Markdown

为什么用 CPE 区间而不是全文检索
--------------------------------
实测 `GET /api/search?q=nginx` 的前排结果是「描述里提到 nginx 的别的产品漏洞」
（如 roxy-wi），拿来做资产判定会大面积误报。模块 1 入库时保留了 NVD 的 `cpe` 结构
（vendor / product / version / start_incl / start_excl / end_incl / end_excl），
这里按「产品名 + 版本区间」做确定性判定，才谈得上"自动分析"而不是"似是而非"。

对外入口
--------
    read_upload(filename, data) -> DocText
    extract_assets(text) -> dict
    AssetRiskScanner(engine).scan(assets) -> list[dict]
    build_report(filename, data, engine, ...) -> dict     ← api.py 用这个
    report_to_markdown(report) -> str
"""

from __future__ import annotations

import html as _html
import io
import json
import os
import re
import threading
import time
import unicodedata
import zipfile
import xml.etree.ElementTree as ET
from collections import OrderedDict
from itertools import zip_longest
from typing import Dict, List, Optional, Sequence, Tuple

# —— 路径引导：既可被 api.py（core 已在 sys.path）加载，也可独立跑 ——
import sys as _sys
_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
for _p in (os.path.join(_ROOT, "core"), os.path.dirname(os.path.abspath(__file__))):
    if _p not in _sys.path:
        _sys.path.insert(0, _p)
try:
    import paths  # noqa: E402
    DATA_DIR = paths.DATA_DIR
except Exception:  # pragma: no cover - 独立运行时兜底
    DATA_DIR = os.path.join(_ROOT, "data")

SCAN_STORE = os.path.join(DATA_DIR, "asset_scans.json")      # 轻量索引（列表页用）
SCAN_REPORT_DIR = os.path.join(DATA_DIR, "asset_reports")    # 完整报告（按 id 一份）
STORE_MAX = 30                       # 只留最近 30 次体检（索引 + 报告文件一起裁剪）
_LOCK = threading.Lock()             # 落盘读-改-写串行化（并发提交会静默丢记录）

# ==========================================================================
# 0. 小工具
# ==========================================================================
_WS = re.compile(r"[ \t\u3000]+")


def _nz(s) -> str:
    return (s or "").strip() if isinstance(s, str) else (str(s) if s is not None else "")


def _sentence_clip(text: str, max_len: int) -> str:
    """按句号（或分号/换行）截断描述，避免按字符数切到半截单词（「over 」）。

    若前 max_len 字符内无句号，才退回字符截断并补省略号。
    """
    t = _nz(text)
    if len(t) <= max_len:
        return t
    head = t[:max_len]
    for ch in (". ", "。", "; ", "；", "\n", "! ", "? "):
        idx = head.rfind(ch)
        if idx > max_len * 0.4:
            return head[:idx + 1].rstrip() + "…"
    return head.rstrip() + "…"


def _uniq(seq: Sequence) -> list:
    seen, out = set(), []
    for x in seq:
        k = x if isinstance(x, str) else json.dumps(x, ensure_ascii=False, sort_keys=True)
        if k in seen:
            continue
        seen.add(k)
        out.append(x)
    return out


def _norm_text(s: str) -> str:
    """全角→半角、去零宽字符，避免「１.８」这种全角版本号漏抽。"""
    s = unicodedata.normalize("NFKC", s or "")
    return s.replace("\u200b", "").replace("\ufeff", "").replace("\xa0", " ")


# ==========================================================================
# 1. 文件解析（word / excel / txt …）
# ==========================================================================
class DocText:
    """解析结果：正文 + 元信息（供报告展示"这份文件是怎么读出来的"）。"""

    __slots__ = ("kind", "text", "chars", "warn", "rows")

    def __init__(self, kind: str, text: str, warn: str = "", rows: Optional[List[str]] = None):
        self.kind = kind
        self.text = text
        self.chars = len(text)
        self.warn = warn
        # rows：结构化行（表格一行 = 一个元素），用于「同一行/同一行表格」上下文关联
        self.rows = rows if rows is not None else text.splitlines()

    def to_dict(self) -> dict:
        return {"kind": self.kind, "chars": self.chars, "warn": self.warn}


_DECODE_ORDER = ("utf-8-sig", "utf-8", "gb18030", "utf-16", "latin-1")


def _decode(data: bytes) -> str:
    for enc in _DECODE_ORDER:
        try:
            s = data.decode(enc)
            # latin-1 永不失败，放最后；出现大量替换字符说明选错编码
            return s
        except (UnicodeDecodeError, LookupError):
            continue
    return data.decode("latin-1", "ignore")


def _zip_xml_text(zf: zipfile.ZipFile, name: str) -> str:
    try:
        return zf.read(name).decode("utf-8", "ignore")
    except (KeyError, OSError):
        return ""


_TAG = re.compile(r"<[^>]+>")


def _docx_text(data: bytes) -> DocText:
    """docx：按「段落 = 一行、表格一行 = 一行」还原。

    关键（踩过）：表格里**每个单元格本身是一个 <w:p>**。若只按 </w:p> 切行，
    "Apache HTTP Server" 与 "2.4.49" 会被切成两行 → 版本接不上产品 → 按"全版本"
    评估，命中数虚高一大截（实测 305 vs 203）。所以表格必须按 <w:tr> 聚合，
    单元格之间用 \\t 连接，和 xlsx / CSV 的行语义保持一致。
    """
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            if "word/document.xml" not in zf.namelist():
                return DocText("docx", "", "不是有效的 .docx（缺少 word/document.xml）")
            names = [n for n in zf.namelist()
                     if n == "word/document.xml"
                     or (n.startswith("word/header") and n.endswith(".xml"))
                     or (n.startswith("word/footer") and n.endswith(".xml"))]
            rows: List[str] = []
            for n in sorted(names, key=lambda x: (x != "word/document.xml", x)):
                try:
                    xml = zf.read(n).decode("utf-8", "ignore")
                except (KeyError, OSError):
                    continue
                rows.extend(_docx_rows(xml))
            return DocText("docx", "\n".join(rows), "", rows)
    except zipfile.BadZipFile:
        return _binary_fallback(data, "docx", "文件不是 zip 结构，可能是 .doc 改名")


def _docx_rows(xml: str) -> List[str]:
    """把一个 document.xml 拆成行：普通段落各占一行；表格按 <w:tr> 聚合成一行。"""
    out: List[str] = []
    pos = 0
    for tbl in re.finditer(r"<w:tbl[ >].*?</w:tbl>", xml, re.S):
        out.extend(_docx_paragraphs(xml[pos:tbl.start()]))
        for tr in re.findall(r"<w:tr[ >].*?</w:tr>", tbl.group(0), re.S):
            cells = []
            for tc in re.findall(r"<w:tc[ >].*?</w:tc>", tr, re.S):
                cells.append(" ".join(_docx_paragraphs(tc)).strip())
            line = "\t".join(cells).strip()
            if line.strip("\t"):
                out.append(line)
        pos = tbl.end()
    out.extend(_docx_paragraphs(xml[pos:]))
    return [r for r in out if r.strip()]


def _docx_paragraphs(seg: str) -> List[str]:
    """段落级文本：<w:p> 之间的内容各成一段（软换行 <w:br/> 视为空格）。"""
    out = []
    for para in re.split(r"</w:p\s*>", seg):
        txt = _w_t(para).replace("\n", " ").strip()
        if txt:
            out.append(txt)
    return out


def _w_t(para_xml: str) -> str:
    """把一段 <w:p> 的 XML 还原成可读文本（含 <w:tab/> 转 \\t、<w:br/> 转换行）。"""
    s = re.sub(r"<w:tab\s*/>", "\t", para_xml)
    s = re.sub(r"<w:br\s*/>", "\n", s)
    chunks = re.findall(r"<w:t(?:\s[^>]*)?>(.*?)</w:t>", s, re.S)
    return _unescape_xml("".join(chunks))


_NUMREF = re.compile(r"&#x([0-9a-fA-F]+);|&#(\d+);")


def _numref_sub(m: "re.Match") -> str:
    try:
        cp = int(m.group(1), 16) if m.group(1) else int(m.group(2))
        return chr(cp) if 0 <= cp <= 0x10FFFF else ""
    except ValueError:
        return ""


def _unescape_xml(s: str) -> str:
    """XML 反转义：数字字符引用（&#22791; / &#x5907;）+ 命名实体。

    ★ 数字引用必须处理：实测某些 CMDB 导出的 xlsx 把中文全部写成 &#NNNNN;
      （不处理则中文全是乱码，产品/主机名全部抽取失败）。

    ★ 性能（2026-10-05）：早先实现用 re.sub + 回调逐字符 chr() 转换——某 CMDB
      导出 129MB 的 sheet 里含 215 万个数字实体，逐单元格调用导致 ~90 万次
      回调、累计 6.4s。改为 html.unescape（C 实现，单次处理数字引用 + 命名实体）
      后热路径不再有 Python 级正则回调。
    """
    if "&" not in s:
        return s
    return _html.unescape(s)


_XLSX_PEEK_BYTES = 64 << 10          # sheet 表头预览窗口


def _xlsx_peek_rows(head: bytes, shared: List[str], max_rows: int = 3) -> List[List[str]]:
    """从 worksheet XML 开头片段解出前几个完整行的单元格（供表头预览判定）。

    只做判断用，不求全：64KB 窗口里切不出完整行就返回空（调用方按「不跳过」处理）。
    """
    if b"&#" in head:
        head = _XLSX_NUMREF.sub(_xlsx_numref_sub, head)
    out: List[List[str]] = []
    n_shared = len(shared)
    for piece in head.split(b"</row>")[:-1]:
        p0 = piece.find(b"<row")
        if p0 < 0:
            continue
        rowxml = piece[p0:]
        if (n_shared and b't="s"' in rowxml) or b"/>" in rowxml:
            cells: List[str] = []
            for cm in _XLSX_CELL.finditer(rowxml):
                if cm.group(1) is not None:
                    cells.append("")
                    continue
                attrs = cm.group(2) or b""
                inner = cm.group(3) or b""
                if n_shared and b't="s"' in attrs:
                    vm = _XLSX_V.search(inner)
                    idx = int(vm.group(1)) if (vm and vm.group(1).isdigit()) else -1
                    v = shared[idx] if 0 <= idx < n_shared else ""
                elif inner.startswith(b"<is"):
                    v = "".join(t.decode("utf-8", "ignore") for t in _XLSX_T.findall(inner))
                else:
                    vm = _XLSX_V.search(inner)
                    v = vm.group(1).decode("utf-8", "ignore") if vm else ""
                cells.append(v.strip())
        else:
            cells = [(m.group(1) or m.group(2)).decode("utf-8", "ignore").strip()
                     for m in _XLSX_TV.finditer(rowxml)]
        if any(c.strip() for c in cells):
            out.append(cells)
            if len(out) >= max_rows:
                break
    return out


def _xlsx_text(data: bytes, sheet_filter=None) -> DocText:
    """xlsx：字节级分块流式扫描 + sharedStrings 解引用，每个 worksheet 按行还原。

    资产清单基本都是以「一行一台主机」的形式存在，所以保留行列结构很重要——
    后面靠"同一行"把主机和它的组件关联起来。

    ★ 性能（2026-10-05）：最早实现把整个 worksheet XML 读进内存再正则抽行——
      25MB 的 xlsx 解压出 129MB 的 XML，整体解码 + 非贪婪正则要 ~12s 且峰值内存数百 MB；
      改成 ET.iterparse 实测更慢（1300 万个元素逐个触发 Python 回调，14.8s）。
      最终定为「整块读入 + 一次性实体解码 + 切行」：201MB XML 实测 ~4.5s，
      内存与单个 sheet 解压后大小成正比。

    ★ sheet 预览跳过（2026-10-05）：传入 sheet_filter(前几行单元格) -> bool 时，
      先用 64KB 预览窗口判表头——CMDB 大导出里的「关系拓扑/数据字典/变更单」等
      表没有产品/版本/主机字段，解析纯属浪费（实测 10 文件 2.8GB XML 里约 1.7GB
      是这类表）；判不出资产表头的 sheet 整个跳过，warn 里注明跳过数量。
    """
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            shared: List[str] = []
            try:
                with zf.open("xl/sharedStrings.xml") as fp:
                    sroot = ET.parse(fp)
                for si in sroot.getroot():
                    shared.append("".join(si.itertext()))
            except (KeyError, OSError):
                pass
            sheets = sorted(n for n in zf.namelist()
                            if re.match(r"xl/worksheets/sheet\d*\.xml$", n))
            if not sheets:
                return DocText("xlsx", "", "不是有效的 .xlsx（没有 worksheet）")
            rows: List[str] = []
            skipped = 0
            for sn in sheets:
                try:
                    fp = zf.open(sn)
                except (KeyError, OSError):
                    continue
                with fp:
                    if sheet_filter is not None:
                        # ★ 预览必须用独立流：在 fp 上 read 会把表头行吃掉，
                        #   后续 _xlsx_sheet_rows 从半截开始，整张表的列映射全毁
                        try:
                            with zf.open(sn) as pf:
                                head = pf.read(_XLSX_PEEK_BYTES)
                        except (KeyError, OSError):
                            head = b""
                        peek = _xlsx_peek_rows(head, shared) if head else []
                        try:
                            allowed = bool(sheet_filter(peek)) if peek else True
                        except Exception:            # noqa: BLE001  过滤器出错→保守解析
                            allowed = True
                        if not allowed:
                            skipped += 1
                            continue
                    rows.extend(_xlsx_sheet_rows(fp, shared))
            warn = ""
            if skipped:
                warn = "已跳过 %d 个不含软件资产字段的工作表（拓扑/字典/工单类）" % skipped
            return DocText("xlsx", "\n".join(rows), warn, rows)
    except zipfile.BadZipFile:
        return _binary_fallback(data, "xlsx", "文件不是 zip 结构，可能是 .xls 改名")


_XLSX_CELL = re.compile(rb"<c\b([^>]*?)/>|<c\b([^>]*?)>(.*?)</c>", re.S)
_XLSX_V = re.compile(rb"<v>(.*?)</v>", re.S)
_XLSX_T = re.compile(rb"<t(?:\s[^>]*)?>(.*?)</t>", re.S)
_XLSX_TV = re.compile(rb"<t(?:\s[^>]*)?>(.*?)</t>|<v>(.*?)</v>", re.S)
_XLSX_NUMREF = re.compile(rb"&#x([0-9a-fA-F]+);|&#(\d+);")
_XLSX_REF_CACHE: Dict[bytes, bytes] = {}    # 实体字节串 -> 解码结果（CMDB 导出实体高度重复：215 万个只有 ~851 种）


def _xlsx_numref_sub(m: "re.Match") -> bytes:
    """把数字字符引用 &#NNN; / &#xHH; 转回 UTF-8 字节（块级批量解码用）。

    ★ 性能（2026-10-05）：大导出里实体值高度重复（129MB sheet 215 万个实体仅 851 种），
      按整实体缓存后 int/chr/encode 只在首次出现时执行，重复实体一次 dict 查表搞定。
    """
    ent = m.group(0)
    hit = _XLSX_REF_CACHE.get(ent)
    if hit is not None:
        return hit
    try:
        if m.group(1) is not None:
            cp = int(m.group(1), 16)      # &#xHH;
        else:
            cp = int(m.group(2))          # &#NNN;（十进制）
        out = chr(cp).encode("utf-8") if 0 <= cp <= 0x10FFFF else b""
    except ValueError:
        out = b""
    if len(_XLSX_REF_CACHE) < 65536:
        _XLSX_REF_CACHE[ent] = out
    return out


def _xlsx_sheet_rows(fp, shared: List[str]) -> List[str]:
    """从一个 worksheet XML 流里扫描出所有行（TSV 文本）。

    用 </row> 切分（XML 文本里 <、> 会被转义，所以 <row / </row> 只可能是
    真实标签）；每行做一次单元格正则。自闭合空单元格 <c .../> 补空串保住列位，
    稀疏行不会错位。

    ★ 性能（2026-10-05）：CMDB 导出的 xlsx 把中文全部写成数字实体 &#NNNNN;
      （129MB sheet 里 215 万个）。实测「整块读入 + 一次性 re.sub 解码」比
      「8MB 分块滚动 + 逐行/逐块解码」快得多——纯解码 215 万实体仅 ~1.1s，
      而分块方案因跨块尾部重复扫描 + 逐行 sub，要 ~6s 且内存也没省多少。
      这里整块读入（129MB 可控）后做一次全局解码，再切行。
    """
    data = fp.read()
    if not data:
        return []
    # 一次性解码数字实体（含中文）——纯 bytes 正则，单次扫描
    if b"&#" in data:
        data = _XLSX_NUMREF.sub(_xlsx_numref_sub, data)
    out: List[str] = []
    n_shared = len(shared)
    for piece in data.split(b"</row>")[:-1]:
        p0 = piece.find(b"<row")
        if p0 < 0:
            continue
        rowxml = piece[p0:]
        # 行内有自闭合空单元格（<c .../>）或共享字符串引用时走逐格解析
        #（要补占位保列对齐 / 要解引用共享索引）；否则走快速取值路径
        if (n_shared and b't="s"' in rowxml) or b"/>" in rowxml:
            cells: List[str] = []
            for cm in _XLSX_CELL.finditer(rowxml):
                if cm.group(1) is not None:      # <c .../> 空单元格占位
                    cells.append("")
                    continue
                attrs = cm.group(2) or b""
                inner = cm.group(3) or b""
                if n_shared and b't="s"' in attrs:
                    vm = _XLSX_V.search(inner)
                    idx = int(vm.group(1)) if (vm and vm.group(1).isdigit()) else -1
                    v = shared[idx] if 0 <= idx < n_shared else ""
                elif inner.startswith(b"<is"):
                    v = "".join(t.decode("utf-8", "ignore") for t in _XLSX_T.findall(inner))
                else:
                    vm = _XLSX_V.search(inner)
                    v = vm.group(1).decode("utf-8", "ignore") if vm else ""
                cells.append(v.strip())
            line = "\t".join(cells).strip("\t")
        else:
            # 快速路径：行内 <t>（内联文本）与 <v>（数值/字符串）按文档序即列序
            cells = [(m.group(1) or m.group(2)).decode("utf-8", "ignore").strip()
                     for m in _XLSX_TV.finditer(rowxml)]
            line = "\t".join(cells).strip("\t")
        if line.strip():
            out.append(line)
    return out


_BIN_RUN = re.compile(rb"[\x20-\x7e]{4,}")
_BIN_RUN16 = re.compile(rb"(?:[\x20-\x7e]\x00){4,}")


def _binary_fallback(data: bytes, kind: str, warn: str) -> DocText:
    """老格式（.doc / .xls，OLE 复合文档）尽力解析：抽可打印串。

    说明：不引入 antiword / olefile 这类重依赖，也不联网。抽出来的文本足以覆盖
    「资产名 / 域名 / IP / 产品版本」这类纯 ASCII 内容；中文段落可能读不全，
    所以 warn 里会明确提示，供前端标注「建议另存为 docx/xlsx 后再分析」。
    """
    out: List[str] = []
    for enc, pat in (("ascii", _BIN_RUN), ("utf-16", _BIN_RUN16)):
        raw = pat.findall(data)
        if enc == "utf-16":
            chunks = [b.decode("utf-16-le", "ignore") for b in raw]
        else:
            chunks = [b.decode("latin-1", "ignore") for b in raw]
        for c in chunks:
            c = c.strip()
            # 过滤 OLE 结构噪声（名字里没有可读性、也不是资产形态的）
            if len(c) < 4:
                continue
            out.append(c)
    text = "\n".join(_uniq(out))
    return DocText(kind, text, warn or "老版二进制格式，采用可打印串尽力解析")


def read_upload(filename: str, data: bytes, sheet_filter=None) -> DocText:
    """按扩展名分派解析器。返回 DocText（含 kind / warn）。

    sheet_filter：xlsx 专用——传入 `函数(前几行单元格) -> bool`，返回 False 的
    工作表整个跳过不解析（CMDB 大导出里拓扑/字典类表占大头）。其余格式忽略。
    """
    name = _nz(filename).lower()
    ext = os.path.splitext(name)[1]
    data = data or b""
    if ext in (".docx", ".docm"):
        return _docx_text(data)
    if ext in (".xlsx", ".xlsm"):
        return _xlsx_text(data, sheet_filter)
    if ext == ".doc":
        txt = _decode(data)
        # 少数 .doc 其实是 docx 改名（zip 头 PK）
        if data[:2] == b"PK":
            return _docx_text(data)
        return _binary_fallback(data, "doc", "老版 .doc（OLE 二进制）：中文可能读不全，建议另存为 .docx")
    if ext == ".xls":
        if data[:2] == b"PK":
            return _xlsx_text(data, sheet_filter)
        return _binary_fallback(data, "xls", "老版 .xls（OLE 二进制）：中文可能读不全，建议另存为 .xlsx")
    if ext in (".txt", ".csv", ".tsv", ".md", ".json", ".xml", ".log", ".ini", ".conf",
               ".cfg", ".yaml", ".yml", ".html", ".htm", ""):
        return DocText("text", _decode(data))
    return DocText("text", _decode(data), "未识别扩展名，按纯文本解析：%s" % (ext or "无"))


# ==========================================================================
# 2. 资产抽取
# ==========================================================================
# 产品词典：alias(小写) -> (标准产品名 / 即 NVD CPE 的 product, 展示名, 厂商)
#   · 标准名必须与语料 CPE 的 product 字段可归一化对应（见 _canon）
#   · alias 覆盖常见书写变体（中英文、带空格/下划线/连字符）
_PRODUCT_DICT: Dict[str, Tuple[str, str, str]] = {}
_ALIASES: List[Tuple[re.Pattern, str, str, str, str]] = []   # (正则, prod, 展示名, vendor, 别名归一键)


def _alias_re(alias: str) -> re.Pattern:
    """把别名编译成「容错分隔符」正则：apache tomcat ≈ apache_tomcat ≈ apache-tomcat。

    为什么不能在原文里直接 find(别名)：别名归一化后（见 _canon_key）分隔符已被去掉，
    而用户文件里写的是 "Apache Tomcat"，带空格的别名会永远匹配不上。
    """
    toks = [t for t in re.split(r"[\s_\-./]+", _nz(alias).lower()) if t]
    body = r"[\s_\-./]{0,2}".join(re.escape(t) for t in toks)
    return re.compile(r"(?<![a-z0-9_\-])" + body + r"(?![a-z0-9_\-])", re.I)


def _pd(prod: str, disp: str, vendor: str, *aliases: str) -> None:
    for a in (prod,) + aliases:
        key = _canon_key(a)
        _PRODUCT_DICT[key] = (prod, disp, vendor)
        _ALIASES.append((_alias_re(a), prod, disp, vendor, key))


def _canon_key(s: str) -> str:
    """产品名归一化键：小写 + 去空格/下划线/连字符/点（用于别名匹配）。"""
    return re.sub(r"[\s_\-./]+", "", _nz(s).lower())


# —— Web / 中间件 ——
_pd("nginx", "Nginx", "f5", "nginx")
_pd("http_server", "Apache HTTP Server", "apache", "apache", "apache httpd", "apache http server",
    "httpd", "http server")
_pd("tomcat", "Apache Tomcat", "apache", "tomcat", "apache tomcat")
_pd("iis", "Microsoft IIS", "microsoft", "iis", "internet information services")
_pd("weblogic", "Oracle WebLogic", "oracle", "weblogic", "weblogic server")
_pd("websphere_application_server", "IBM WebSphere", "ibm", "websphere")
_pd("jboss_eap", "JBoss EAP", "redhat", "jboss", "jboss eap", "wildfly")
_pd("jetty", "Jetty", "eclipse", "jetty")
_pd("undertow", "Undertow", "redhat", "undertow")
_pd("openssl", "OpenSSL", "openssl", "openssl")
_pd("openssh", "OpenSSH", "openbsd", "openssh", "ssh")
# —— 开发框架 / 组件 ——
# 注意：log4j2 / struts2 / apache http server 这类写法一律归一到语料里真实存在的
# CPE product（log4j / struts / http_server）；别名重复定义会互相覆盖，改词典时
# 务必确认产品名在语料 products 里真的存在（见 tools/_probe_products.py）。
_pd("log4j", "Apache Log4j", "apache", "log4j", "log4j2", "log4j-core", "apache log4j")
_pd("struts", "Apache Struts", "apache", "struts", "struts2", "apache struts")
_pd("spring_framework", "Spring Framework", "vmware", "spring", "spring framework", "springframework")
_pd("spring_boot", "Spring Boot", "vmware", "spring boot", "springboot")
_pd("spring_security", "Spring Security", "vmware", "spring security")
_pd("shiro", "Apache Shiro", "apache", "shiro", "apache shiro")
_pd("fastjson", "Fastjson", "alibaba", "fastjson")
_pd("jackson-databind", "Jackson Databind", "fasterxml", "jackson", "jackson-databind")
_pd("xstream", "XStream", "xstream", "xstream")
_pd("dubbo", "Apache Dubbo", "apache", "dubbo")
_pd("nacos", "Alibaba Nacos", "alibaba", "nacos")
_pd("rocketmq", "Apache RocketMQ", "apache", "rocketmq")
_pd("zookeeper", "Apache ZooKeeper", "apache", "zookeeper")
_pd("druid", "Alibaba Druid", "alibaba", "druid")
_pd("xxl-job", "XXL-JOB", "xuxueli", "xxl-job", "xxljob")
_pd("activemq", "Apache ActiveMQ", "apache", "activemq")
_pd("rabbitmq", "RabbitMQ", "pivotal", "rabbitmq")
_pd("kafka", "Apache Kafka", "apache", "kafka")
_pd("grafana", "Grafana", "grafana", "grafana")
_pd("prometheus", "Prometheus", "prometheus", "prometheus")
_pd("jenkins", "Jenkins", "jenkins", "jenkins")
_pd("gitlab", "GitLab", "gitlab", "gitlab")
_pd("gitea", "Gitea", "gitea", "gitea")
_pd("harbor", "Harbor", "linuxfoundation", "harbor")
_pd("sonarqube", "SonarQube", "sonarsource", "sonarqube")
_pd("confluence", "Atlassian Confluence", "atlassian", "confluence")
_pd("jira", "Atlassian Jira", "atlassian", "jira")
_pd("bitbucket", "Atlassian Bitbucket", "atlassian", "bitbucket")
_pd("zabbix", "Zabbix", "zabbix", "zabbix")
_pd("nagios", "Nagios", "nagios", "nagios")
# —— 数据库 / 缓存 / 检索 ——
_pd("mysql", "MySQL", "oracle", "mysql")
_pd("mariadb", "MariaDB", "mariadb", "mariadb")
_pd("postgresql", "PostgreSQL", "postgresql", "postgresql", "postgres", "pgsql")
_pd("redis", "Redis", "redis", "redis")
_pd("mongodb", "MongoDB", "mongodb", "mongodb", "mongo")
_pd("elasticsearch", "Elasticsearch", "elastic", "elasticsearch")
_pd("kibana", "Kibana", "elastic", "kibana")
_pd("logstash", "Logstash", "elastic", "logstash")
_pd("sqlserver", "Microsoft SQL Server", "microsoft", "sql server", "mssql", "sqlserver")
_pd("oracle_database", "Oracle Database", "oracle", "oracle database", "oracle db")
_pd("clickhouse", "ClickHouse", "clickhouse", "clickhouse")
_pd("memcached", "Memcached", "memcached", "memcached")
# —— 容器 / 云原生 / 虚拟化 ——
_pd("kubernetes", "Kubernetes", "kubernetes", "kubernetes", "k8s")
_pd("docker", "Docker", "docker", "docker", "docker engine")
_pd("containerd", "containerd", "linuxfoundation", "containerd")
_pd("kubelet", "kubelet", "kubernetes", "kubelet")
_pd("istio", "Istio", "istio", "istio")
_pd("vmware_esxi", "VMware ESXi", "vmware", "esxi", "vmware esxi")
_pd("vcenter_server", "VMware vCenter", "vmware", "vcenter", "vcenter server")
_pd("citrix_adc", "Citrix ADC", "citrix", "citrix adc", "netscaler")
# —— CMS / 建站 / 协同 ——
_pd("wordpress", "WordPress", "wordpress", "wordpress", "wp")
_pd("drupal", "Drupal", "drupal", "drupal")
_pd("joomla", "Joomla", "joomla", "joomla")
_pd("discuz", "Discuz!", "comsenz", "discuz", "discuz!")
_pd("phpmyadmin", "phpMyAdmin", "phpmyadmin", "phpmyadmin")
_pd("php", "PHP", "php", "php")
_pd("dokuwiki", "DokuWiki", "dokuwiki", "dokuwiki")
_pd("nextcloud", "Nextcloud", "nextcloud", "nextcloud")
_pd("owncloud", "ownCloud", "owncloud", "owncloud")
_pd("exchange_server", "Microsoft Exchange", "microsoft", "exchange", "exchange server", "owa")
_pd("sharepoint", "Microsoft SharePoint", "microsoft", "sharepoint")
_pd("coremail", "Coremail", "coremail", "coremail")
# —— 网络 / 安全设备 / 应用 ——
_pd("fortios", "Fortinet FortiOS", "fortinet", "fortios", "fortigate", "fortinet")
_pd("fortiproxy", "Fortinet FortiProxy", "fortinet", "fortiproxy")
_pd("pan-os", "Palo Alto PAN-OS", "paloaltonetworks", "pan-os", "panos", "palo alto")
_pd("sonicwall", "SonicWall", "sonicwall", "sonicwall")
_pd("citrix_gateway", "Citrix Gateway", "citrix", "citrix gateway")
_pd("ivanti", "Ivanti", "ivanti", "ivanti", "pulse secure")
_pd("vsftpd", "vsftpd", "vsftpd", "vsftpd")
# —— 语言运行时 / 框架（资产清单里常见）——
_pd("openjdk", "OpenJDK", "oracle", "openjdk", "jdk", "java")
_pd("node.js", "Node.js", "nodejs", "node.js", "nodejs", "node")
_pd("python", "Python", "python", "python", "python3")
_pd("gunicorn", "Gunicorn", "gunicorn", "gunicorn")
_pd("uwsgi", "uWSGI", "unbit", "uwsgi")
_pd("flask", "Flask", "pallets", "flask")
_pd("django", "Django", "djangoproject", "django")
_pd("laravel", "Laravel", "laravel", "laravel")
_pd("thinkphp", "ThinkPHP", "thinkphp", "thinkphp")

# 别名按长度倒序（先长后短，避免 struts2 被 struts 抢、apache tomcat 被 apache 抢）
_ALIAS_SORTED = sorted(_ALIASES, key=lambda x: -len(x[0].pattern))

# 「弱别名」：本身是通用词/会出现在技术叙述里（Apache、Java、Node…），
# 只有在后面明确跟了版本号时才认；否则 "Java 业务系统" 这种描述会被当成一个资产。
_WEAK_ALIASES = {"apache", "java", "node", "nodejs", "php", "python", "python3", "ssh",
                 "es", "wp", "postgres", "sonar", "was", "jdk", "logstash", "spring"}

# 域名 TLD 白名单（避免把 report.docx / v1.2.3 当域名）
_TLDS = set("""com cn net org gov edu mil com.cn net.cn org.cn gov.cn edu.cn
ac uk de fr jp kr ru io ai app dev top xyz site online tech store cloud info biz tv me cc
co com.hk com.tw com.sg com.au co.jp co.uk com.br in id th vn my ph hk tw mo
asia mobi name pro int museum travel club shop win vip ltd group work live life world today
""".split())

_IPV4 = re.compile(r"(?<![\d.])(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}"
                   r"(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?![\d.])")
_IPV6 = re.compile(r"(?<![:.\w])(?:[A-Fa-f0-9]{1,4}:){2,7}[A-Fa-f0-9]{0,4}(?![:.\w])")
_URL = re.compile(r"\b(?:https?|ftp)://[^\s\"'<>()\[\]{},；;，]+", re.I)
_EMAIL = re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,24}\b")
_DOMAIN = re.compile(r"(?<![@\w.\-/])((?:[A-Za-z0-9](?:[A-Za-z0-9\-]{0,61}[A-Za-z0-9])?\.)+"
                     r"[A-Za-z]{2,24})(?![\w.\-])")
_CVE_IN_DOC = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.I)
_PORT_SVC = re.compile(r"(?<![\d.])(\d{1,5})\s*/\s*(tcp|udp)\b", re.I)
_PORT_PAIR = re.compile(r"(?<![\d.\-/])(\d{1,5})\s*/\s*(\d{1,5})(?![\d.\-])")
_PORT_KW = re.compile(r"\bport\s*[:=]?\s*(\d{1,5})\b", re.I)


def _valid_port(x: str) -> bool:
    return x.isdigit() and 0 < int(x) <= 65535
_VER_RE = r"v?(\d+(?:\.\d+){0,3}(?:[a-z]\d*)?(?:[-_.]?(?:rc|beta|alpha|p|r)\d*)?)"
_OS_PATTERNS = [
    (r"windows\s+server\s+(\d{4}(?:\s*r2)?)", "Windows Server"),
    (r"windows\s+(11|10|8\.1|8|7|xp|vista)", "Windows"),
    (r"centos\s*(?:linux)?\s*(\d+(?:\.\d+)?)", "CentOS"),
    (r"(ubuntu)\s*(\d+(?:\.\d+)?(?:\.\d+)?)?", "Ubuntu"),
    (r"debian\s*(\d+(?:\.\d+)?)?", "Debian"),
    (r"red\s*hat\s*(?:enterprise\s*linux)?\s*(\d+(?:\.\d+)?)?", "Red Hat"),
    (r"(?:rocky|almalinux)\s*(\d+(?:\.\d+)?)?", "Rocky/Alma"),
    (r"opensuse\s*(\d+(?:\.\d+)?)?", "openSUSE"),
    (r"kylin|银河麒麟", "银河麒麟"),
    (r"uos|统信", "统信 UOS"),
    (r"aix\s*(\d+(?:\.\d+)?)?", "AIX"),
    (r"solaris\s*(\d+(?:\.\d+)?)?", "Solaris"),
    (r"android\s*(\d+(?:\.\d+)?)?", "Android"),
]
_FILE_EXT_NOISE = re.compile(r"\.(docx?|xlsx?|pptx?|pdf|txt|csv|md|json|xml|zip|rar|7z|png|jpg|jpeg|gif|"
                             r"exe|dll|so|log|conf|ini|ya?ml|bat|sh|py|js|css|html?|mp4|mp3)$", re.I)


def _clean_host(h: str) -> str:
    h = _nz(h).lower().strip(".")
    if h.startswith("www.") and h.count(".") >= 2:
        return h
    return h


def _local_ip(ip: str) -> bool:
    try:
        a, b = (int(x) for x in ip.split(".")[:2])
    except (ValueError, IndexError):
        return False
    return a == 10 or a == 127 or (a == 172 and 16 <= b <= 31) or (a == 192 and b == 168) or a == 0


def extract_assets(text: str, rows: Optional[Sequence[str]] = None) -> dict:
    """从文本中抽取资产。返回结构化字典（hosts / products / other）。

    ★ 性能（2026-10-05）：rows 传入时（xlsx/docx 表格行）不再对整个 text 做
      _norm_text——每行在第 529 行已单独规范化，56MB 大文本的整体规范化是纯浪费；
      CMDB 导出的 8 万行清单实测可省 ~2-4s。
    """
    if rows:
        lines = list(rows)
    else:
        lines = _norm_text(text or "").splitlines()

    domains: "OrderedDict[str, int]" = OrderedDict()   # 值 -> 首次出现的行号
    ips: "OrderedDict[str, int]" = OrderedDict()
    ipv6: "OrderedDict[str, int]" = OrderedDict()
    urls: "OrderedDict[str, int]" = OrderedDict()
    emails: "OrderedDict[str, int]" = OrderedDict()
    products: "OrderedDict[str, dict]" = OrderedDict()  # key: canon|version
    ports: "OrderedDict[str, int]" = OrderedDict()
    oses: "OrderedDict[str, int]" = OrderedDict()
    cves_in_doc: "OrderedDict[str, int]" = OrderedDict()

    for i, raw in enumerate(lines):
        line = _norm_text(raw)
        if not line.strip():
            continue
        low = line.lower()

        # --- URL（先抽，避免把 URL 路径当域名）---
        for m in _URL.finditer(line):
            u = m.group(0).rstrip(".,；;、")
            urls.setdefault(u, i)
            try:
                host = re.sub(r"^[a-z]+://", "", u, flags=re.I).split("/")[0].split(":")[0]
                if host and not _IPV4.fullmatch(host) and "." in host:
                    domains.setdefault(_clean_host(host), i)
            except Exception:  # noqa: BLE001
                pass
        # --- 邮箱 ---
        for m in _EMAIL.finditer(line):
            emails.setdefault(m.group(0).lower(), i)
        # --- IP ---
        for m in _IPV4.finditer(line):
            ips.setdefault(m.group(0), i)
        for m in _IPV6.finditer(line):
            v6 = m.group(0)
            if v6.count(":") >= 2 and not v6.startswith("::"):
                ipv6.setdefault(v6.lower(), i)
        # --- 域名 ---
        for m in _DOMAIN.finditer(line):
            d = m.group(1).lower()
            if _FILE_EXT_NOISE.search(d):
                continue
            if d in oses:            # centos / ubuntu 之类被 OS 规则吃掉
                continue
            tld = d.rsplit(".", 1)[-1]
            if tld not in _TLDS and not d.endswith(tuple("." + t for t in _TLDS)):
                continue
            if re.fullmatch(r"\d+(\.\d+)+", d):
                continue
            domains.setdefault(_clean_host(d), i)
        # --- 端口 ---
        for m in _PORT_SVC.finditer(line):
            if _valid_port(m.group(1)):
                ports.setdefault(m.group(1) + "/" + m.group(2).lower(), i)
        for m in _PORT_PAIR.finditer(line):
            a, b = m.group(1), m.group(2)
            # 排除 "2024/10"、"1/2" 这类日期与比例写法
            if _valid_port(a) and _valid_port(b) and not (1900 <= int(a) <= 2099 and int(b) <= 12):
                ports.setdefault(a, i)
                ports.setdefault(b, i)
        for m in _PORT_KW.finditer(low):
            if _valid_port(m.group(1)):
                ports.setdefault(m.group(1), i)
        # --- 操作系统 ---
        for pat, label in _OS_PATTERNS:
            m = re.search(pat, low)
            if m:
                ver = next((g for g in m.groups() if g and re.search(r"\d", str(g))), "")
                oses.setdefault((label + " " + ver).strip(), i)
        # --- 文档里已写的 CVE ---
        for m in _CVE_IN_DOC.finditer(line):
            cves_in_doc.setdefault(m.group(0).upper(), i)
        # --- 软件：产品 + 可选版本 ---
        _extract_products_line(line, i, products)

    hosts: List[dict] = []
    for name, ln in list(domains.items()):
        hosts.append({"name": name, "type": "domain", "line": ln, "scope": "公网"})
    for name, ln in list(ips.items()):
        hosts.append({"name": name, "type": "ip", "line": ln,
                      "scope": "内网" if _local_ip(name) else "公网"})
    for name, ln in list(ipv6.items()):
        hosts.append({"name": name, "type": "ipv6", "line": ln, "scope": "公网"})

    return {
        "hosts": hosts,
        "products": list(products.values()),
        "urls": [{"url": u, "line": l} for u, l in urls.items()],
        "emails": list(emails.keys()),
        "ports": list(ports.keys()),
        "os": list(oses.keys()),
        "cves_in_doc": list(cves_in_doc.keys()),
    }


def _extract_products_line(line: str, line_no: int, out: "OrderedDict[str, dict]") -> None:
    """在一行里找「产品名 + 可选版本」。命中词典别名即认；无版本时按要求登记。

    两遍：先收集全部候选，再把「同一产品在同一行已经有带版本命中」的无版本条目丢掉
    （否则 "Apache HTTP Server 2.4.49" 会因为别名 apache 多出一条"版本未知"的重复资产）。
    """
    hits: List[Tuple[str, str, str, str]] = []          # (prod, disp, vendor, version)
    for pat, prod, disp, vendor, akey in _ALIAS_SORTED:
        m = pat.search(line)
        if not m:
            continue
        # 紧跟在后面的版本： 名称 [空格/斜杠/冒号/连字符] vX.Y.Z
        tail = line[m.end(): m.end() + 28]
        # 分隔符要覆盖真实清单里的各种写法：空格 / 制表 / 冒号 / 等号 / 竖线 / 逗号
        vm = re.match(r"\s*(?:version\s*|版本\s*[:：]?)?[\s/:=\-–—|｜,，;；]{0,4}" + _VER_RE, tail, re.I)
        version = ""
        if vm:
            cand = vm.group(1)
            matched = vm.group(0)
            # 排除明显不是版本的数字：纯 4 位数（年份）且后面没有点号延续
            if not (re.fullmatch(r"\d{4}", cand) and "." not in matched):
                version = cand
        if not version and akey in _WEAK_ALIASES:
            continue                                     # 弱别名无版本 → 不认（防幻觉资产）
        hits.append((prod, disp, vendor, version))

    versioned = {p for p, _d, _v, ver in hits if ver}
    for prod, disp, vendor, version in hits:
        if not version and prod in versioned:
            continue                                     # 同行已有带版本命中 → 不重复登记
        k = _canon_key(prod) + "|" + version
        if k in out:
            continue
        out[k] = {"name": prod, "display": disp, "vendor": vendor,
                  "version": version, "line": line_no,
                  "raw": line.strip()[:160]}


# ==========================================================================
# 3. 版本比较（CPE 区间判定）
# ==========================================================================
_PRERELEASE = ("rc", "beta", "alpha", "pre", "dev", "snapshot", "m")


def _suf_rank(s: str) -> int:
    """字母后缀语义：''=正式版；rc/beta/alpha/M=预发布（更早）；g/k/u/p=补丁字母（更晚）。

    这一步很关键：OpenSSL 1.1.1g 是 1.1.1 之后的补丁版（应更大），
    而 1.0.0rc1 早于 1.0.0（应更小）—— 同一个"字母后缀"位置，方向相反。
    """
    s = (s or "").lower()
    if s == "":
        return 0
    if s.startswith(_PRERELEASE):
        return -1
    return 1


def _vparts(s: str) -> List[Tuple[int, int, str]]:
    s = _nz(s).lower().lstrip("v")
    out: List[Tuple[int, int, str]] = []
    for p in re.split(r"[._\-+~ ]", s):
        if not p:
            continue
        m = re.match(r"^(\d+)([a-z]*)$", p)
        if m:
            out.append((0, int(m.group(1)), m.group(2)))
        else:
            m2 = re.match(r"^(\d+)", p)
            if m2:
                out.append((0, int(m2.group(1)), p[m2.end():]))
            else:
                out.append((1, 0, p))
    return out or [(0, 0, "")]


def _vcmp(a: str, b: str) -> int:
    """版本比较：a<b → -1；==0；a>b → 1。数字段按数值比，字母段按 'a<b<r<正式' 排。"""
    A, B = _vparts(a), _vparts(b)
    for x, y in zip_longest(A, B, fillvalue=(0, 0, "")):
        if x[0] != y[0]:
            return 1 if x[0] < y[0] else -1          # 数字段 > 字母段
        if x[1] != y[1]:
            return 1 if x[1] > y[1] else -1
        if x[2] != y[2]:
            rx, ry = _suf_rank(x[2]), _suf_rank(y[2])
            if rx != ry:
                return 1 if rx > ry else -1
            return 1 if x[2] > y[2] else -1
    return 0


def _same_version(asset_v: str, cpe_v: str) -> bool:
    """资产版本是否等于 CPE 精确版本（允许补丁位延伸：1.2.3.4 ≈ 1.2.3）。"""
    a, c = _nz(asset_v), _nz(cpe_v)
    if not a or not c or c in ("*", "-"):
        return False
    if _vcmp(a, c) == 0:
        return True
    return a.startswith(c + ".")


def in_range(asset_v: str, e: dict) -> Optional[bool]:
    """资产版本是否落在某条 CPE 的受影响区间内。

    返回 True/False；`None` 表示「该 CPE 条目没有版本信息可判」（视为全版本），
    调用方按「版本未知」降级置信度。
    """
    a = _nz(asset_v)
    if not a:
        return None
    v = _nz(e.get("version"))
    si, se = _nz(e.get("start_incl")), _nz(e.get("start_excl"))
    ei, ee = _nz(e.get("end_incl")), _nz(e.get("end_excl"))
    has_bound = bool(si or se or ei or ee)
    if v and v not in ("*", "-") and not has_bound:
        return _same_version(a, v)
    if si and _vcmp(a, si) < 0:
        return False
    if se and _vcmp(a, se) <= 0:
        return False
    if ei and _vcmp(a, ei) > 0:
        return False
    if ee and _vcmp(a, ee) >= 0:
        return False
    return True if has_bound else None


# ==========================================================================
# 4. 风险匹配（用模块 1 语料的 CPE 区间做确定性判定）
# ==========================================================================
_SEV_RANK = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "UNKNOWN": 0}
_INDEX_CACHE: dict = {}          # (engine_id, N) -> {canon_product: [doc_idx, ...]}
_PREFIX_CACHE: dict = {}         # (engine_id, N) -> {prefix: [doc_idx, ...]} 宽松回退用
_MIN_PREFIX = 4                  # 词根最小长度（与 _candidates 的 len(k) < 4 判据一致）
_MATCH_CACHE: dict = {}          # (engine_id, name, version) -> [finding, ...] 匹配结果缓存
_MATCH_CACHE_MAX = 8192          # 匹配缓存上限（FIFO 淘汰，防止无界增长）


def _MATCH_CACHE_set(key: tuple, val: List[dict]) -> None:
    """写入匹配缓存；超限时按 FIFO 淘汰一半（dict 在 CPython 3.7+ 保持插入序）。"""
    _MATCH_CACHE[key] = val
    if len(_MATCH_CACHE) > _MATCH_CACHE_MAX:
        over = len(_MATCH_CACHE) - (_MATCH_CACHE_MAX // 2)
        for k in list(_MATCH_CACHE)[:over]:
            _MATCH_CACHE.pop(k, None)


def _canon(s: str) -> str:
    return re.sub(r"[\s_\-./]+", "", _nz(s).lower())


class AssetRiskScanner:
    """把「产品 + 版本」映射到模块 1 库里的 CVE 集合。"""

    def __init__(self, engine, max_per_asset: int = 40):
        self.engine = engine
        self.docs = getattr(engine, "docs", []) or []
        self.max_per_asset = max_per_asset

    # ---- 产品倒排索引（按引擎代际缓存；只在需要时构建一次）----
    def _index(self) -> Dict[str, List[int]]:
        eid, n = id(self.engine), len(self.docs)
        key = (eid, n)
        hit = _INDEX_CACHE.get(key)
        if hit is not None:
            return hit
        with _LOCK:
            hit = _INDEX_CACHE.get(key)
            if hit is not None:
                return hit
            idx: Dict[str, List[int]] = {}
            for i, d in enumerate(self.docs):
                if not str(d.get("id", "")).upper().startswith("CVE-"):
                    continue
                seen = set()
                for c in (d.get("cpe") or []):
                    if not isinstance(c, dict):
                        continue
                    p = _canon(c.get("product") or "")
                    if p and p not in seen:
                        seen.add(p)
                        idx.setdefault(p, []).append(i)
                for p in (d.get("products") or []):
                    p = _canon(p)
                    if p and p not in seen:
                        seen.add(p)
                        idx.setdefault(p, []).append(i)
            # 只保留一份索引（引擎换代会重新构建），防止内存随热切换累积
            _INDEX_CACHE.clear()
            _INDEX_CACHE[key] = idx
            return idx

    # ---- 前缀倒排索引（宽松回退用；把 O(idx) 线性扫描降为 O(1) 查表）----
    def _prefix_index(self) -> Dict[str, List[int]]:
        eid, n = id(self.engine), len(self.docs)
        key = (eid, n)
        hit = _PREFIX_CACHE.get(key)
        if hit is not None:
            return hit
        with _LOCK:
            hit = _PREFIX_CACHE.get(key)
            if hit is not None:
                return hit
            base = self._index()
            pfx: Dict[str, List[int]] = {}
            for pk, lst in base.items():
                if len(pk) < _MIN_PREFIX:
                    continue
                # 前缀（词根在前，如 "tomcat" 命中 "tomcat9"）
                for i in range(_MIN_PREFIX, len(pk) + 1):
                    pfx.setdefault(pk[:i], []).extend(lst)
                # 后缀（词根在后，如 "log4j" 命中 "apachelog4j"）
                for i in range(_MIN_PREFIX, len(pk) + 1):
                    pfx.setdefault(pk[-i:], []).extend(lst)
            _PREFIX_CACHE.clear()
            _PREFIX_CACHE[key] = pfx
            return pfx

    def _candidates(self, product: str) -> List[int]:
        idx = self._index()
        keys = [_canon(product)]
        # 别名回退：词典里登记过的产品名可能和 CPE product 不一致
        mapped = _PRODUCT_DICT.get(_canon_key(product))
        if mapped:
            keys.append(_canon(mapped[0]))
        out: List[int] = []
        seen = set()
        for k in keys:
            for i in idx.get(k, ()):                # 精确命中
                if i not in seen:
                    seen.add(i)
                    out.append(i)
        if not out:
            # 宽松回退：产品名作为词根（≥4 字符）出现在 CPE product 里
            # 前缀索引同时收录了「前缀」与「后缀」两种 key，直接查词根本身即可
            pfx = self._prefix_index()
            for k in keys:
                if len(k) < _MIN_PREFIX:
                    continue
                for i in pfx.get(k, ()):
                    if i not in seen:
                        seen.add(i)
                        out.append(i)
        return out

    def match(self, product: dict) -> List[dict]:
        """匹配单个软件资产 → 命中列表（已按风险排序、截断）。

        ★ 性能：产品名去重后大量重复（同一软件出现在成百上千台主机上），
          按 (engine_id, name, version) 缓存匹配结果，重复产品直接复用，
          避免对同一产品反复走候选索引 + CPE 版本区间判定。
        """
        name = product.get("name") or ""
        ver = _nz(product.get("version"))
        cache_key = (id(self.engine), name, ver)
        hit = _MATCH_CACHE.get(cache_key)
        if hit is not None:
            return hit
        # 该资产在语料里可能对应的所有 CPE 产品名（含词典别名归一）
        want = {_canon(name)}
        mapped = _PRODUCT_DICT.get(_canon_key(name))
        if mapped:
            want.add(_canon(mapped[0]))
        out: List[dict] = []
        for i in self._candidates(name):
            if i >= len(self.docs):
                continue
            d = self.docs[i]
            entries = [c for c in (d.get("cpe") or [])
                       if isinstance(c, dict) and _canon(c.get("product") or "") in want]
            if entries:
                if ver:
                    hits = [e for e in entries if in_range(ver, e) is True]
                    if not hits:
                        continue                       # 版本不在受影响区间 → 不计入
                    conf = "高"
                    ev = "; ".join(self._range_text(e) for e in hits[:3])
                else:
                    conf = "低"
                    ev = "未提供版本，按产品全版本区间评估"
            else:
                conf = "中"
                ev = "由 NVD 产品字段匹配（无 CPE 版本区间，建议人工确认）"
            out.append(self._finding(d, conf, ev))
        out.sort(key=lambda f: (int(bool(f.get("exploited"))), _SEV_RANK.get(f["severity"], 0),
                                float(f.get("score") or 0)), reverse=True)
        out = out[:self.max_per_asset]
        _MATCH_CACHE_set(cache_key, out)
        return out

    @staticmethod
    def _range_text(e: dict) -> str:
        si, se = _nz(e.get("start_incl")), _nz(e.get("start_excl"))
        ei, ee = _nz(e.get("end_incl")), _nz(e.get("end_excl"))
        v = _nz(e.get("version"))
        parts = []
        if si:
            parts.append(">= " + si)
        if se:
            parts.append("> " + se)
        if ei:
            parts.append("<= " + ei)
        if ee:
            parts.append("< " + ee)
        if not parts:
            parts.append("= " + v if v and v not in ("*", "-") else "全部版本")
        return " ".join(parts)

    @staticmethod
    def _finding(d: dict, conf: str, ev: str) -> dict:
        cvss = d.get("cvss") or {}
        kev = d.get("kev") or {}
        rem = [r for r in (d.get("remediation") or []) if isinstance(r, str) and r.strip()]
        cwe = [(c.get("id") or "") for c in (d.get("cwe") or []) if isinstance(c, dict)]
        f = {
            "id": d.get("id") or "",
            "title": _sentence_clip(d.get("title") or d.get("desc") or "", 180),
            # ★ 严重度以 CVSS 分值按 v3.1 区间推导，避免「分值 10.0 却标 HIGH」
            #   这种自相矛盾（分值缺失时才回退语料标签）
            "severity": _sev_from_cvss(cvss.get("score"), cvss.get("severity") or "UNKNOWN"),
            "score": cvss.get("score"),
            "label_severity": (cvss.get("severity") or ""),
            "vector": cvss.get("vector") or "",
            "published": (d.get("published") or "")[:10],
            "modified": (d.get("modified") or "")[:10],
            "status": d.get("status") or "",
            "exploited": bool(kev.get("exploited")),
            "kev_added": (kev.get("date_added") or "")[:10],
            "sources": [s for s in (d.get("sources") or []) if isinstance(s, str)][:4],
            "risk_tags": [t for t in (d.get("risk_tags") or []) if isinstance(t, str)][:4],
            "cwe": [c for c in cwe if c][:3],
            "category": d.get("category") or "",
            "papers": len(d.get("papers") or []),
            "poc": len(d.get("poc_links") or []),
            "patch": len(d.get("patch_links") or []),
            "remediation": rem[:2],
            "confidence": conf,
            "evidence": ev,
        }
        # AI 对抗技术（ATLAS）——模块 1 的富化结果，AI 安全类资产会用到
        atlas = d.get("atlas")
        if isinstance(atlas, dict):
            f["atlas"] = (atlas.get("technique_name") or atlas.get("name") or "")[:60]
        elif isinstance(atlas, str) and atlas:
            f["atlas"] = atlas[:60]
        if d.get("trust_label"):
            f["trust_label"] = d["trust_label"]
        if d.get("exploit_label"):
            f["exploit_label"] = d["exploit_label"]
        return f


def _sev_from_cvss(score, fallback: str = "UNKNOWN") -> str:
    """按 CVSS 分值推导严重度（CVSS v3.1 官方区间，以分值为准）。

    ★ 为什么必须以分值推导、不能直接用语料里的 severity 标签：
      语料标签是人工填的，会和分值矛盾——例如 CVE-2004-0888 分值 10.0
      却标了 HIGH。报告里出现「CVSS 10.0 / 严重度 HIGH」这种自相矛盾的行，
      评审会直接判定报告不可信。CVSS v3.1 规定：
        9.0-10.0 CRITICAL / 7.0-8.9 HIGH / 4.0-6.9 MEDIUM / 0.1-3.9 LOW / 0 NONE
      分值缺失或非数值时，才回退到原标签。
    """
    try:
        s = float(score)
    except (TypeError, ValueError):
        return (fallback or "UNKNOWN").upper()
    if s >= 9.0:
        return "CRITICAL"
    if s >= 7.0:
        return "HIGH"
    if s >= 4.0:
        return "MEDIUM"
    if s > 0.0:
        return "LOW"
    return "NONE"


def _risk_of(findings: Sequence[dict], version_known: bool) -> Tuple[str, int, int]:
    """资产风险级别 / 在野利用数 / 命中数。"""
    if not findings:
        return ("无已知风险" if version_known else "待确认", 0, 0)
    crit = sum(1 for f in findings if f["severity"] == "CRITICAL")
    high = sum(1 for f in findings if f["severity"] == "HIGH")
    kev = sum(1 for f in findings if f["exploited"])
    if kev:
        level = "严重"
    elif crit:
        level = "严重"
    elif high:
        level = "高"
    elif any(f["severity"] == "MEDIUM" for f in findings):
        level = "中"
    else:
        level = "低"
    return (level, kev, len(findings))


def scan_assets(engine, assets: dict) -> dict:
    """核心：把抽取出的资产跑一遍风险匹配，产出资产级结论。"""
    sc = AssetRiskScanner(engine)
    hosts = assets.get("hosts") or []
    products = assets.get("products") or []

    findings_by_line: Dict[int, List[dict]] = {}
    prod_results: List[dict] = []
    for p in products:
        fs = sc.match(p)
        level, kev, cnt = _risk_of(fs, bool(p.get("version")))
        item = dict(p)
        item.update({"risk_level": level, "kev_count": kev, "cve_count": cnt,
                     "findings": fs,
                     "top": fs[0]["id"] if fs else "",
                     "max_score": max([f.get("score") or 0 for f in fs], default=0)})
        prod_results.append(item)
        findings_by_line.setdefault(int(p.get("line") or 0), []).append(item)

    # 主机风险 = 同一行（表格同一行 / 同一文本行）出现的软件风险的最大值
    host_results: List[dict] = []
    for h in hosts:
        ln = int(h.get("line") or 0)
        near = findings_by_line.get(ln) or []
        lv, kev, cnt = "无已知风险", 0, 0
        order = {"严重": 4, "高": 3, "中": 2, "低": 1, "无已知风险": 0, "待确认": 0}
        if near:
            lv = max((x["risk_level"] for x in near), key=lambda x: order.get(x, 0))
            kev = sum(int(x.get("kev_count") or 0) for x in near)
            cnt = sum(int(x.get("cve_count") or 0) for x in near)
        item = dict(h)
        item.update({"risk_level": lv, "kev_count": kev, "cve_count": cnt,
                     "components": [{"name": x.get("display") or x.get("name"),
                                     "version": x.get("version") or "",
                                     "risk_level": x["risk_level"],
                                     "cve_count": x["cve_count"]} for x in near]})
        host_results.append(item)

    all_f = [f for x in prod_results for f in x["findings"]]
    order = {"严重": 4, "高": 3, "中": 2, "低": 1, "无已知风险": 0, "待确认": 0}
    host_results.sort(key=lambda h: (order.get(h["risk_level"], 0), h["kev_count"], h["cve_count"]),
                      reverse=True)
    prod_results.sort(key=lambda p: (order.get(p["risk_level"], 0), p["kev_count"], p["max_score"]),
                      reverse=True)
    kev_ids = [f["id"] for f in all_f if f["exploited"]]
    return {
        "hosts": host_results,
        "products": prod_results,
        "summary": {
            "hosts": len(host_results),
            "products": len(prod_results),
            "products_no_version": sum(1 for p in prod_results if not p.get("version")),
            "cve_hits": len({f["id"] for f in all_f}),
            "critical": len({f["id"] for f in all_f if f["severity"] == "CRITICAL"}),
            "high": len({f["id"] for f in all_f if f["severity"] == "HIGH"}),
            "exploited": len(set(kev_ids)),
            "kev_ids": _uniq(kev_ids)[:20],
            "risk_hosts": sum(1 for h in host_results if h["risk_level"] in ("严重", "高")),
            "risk_products": sum(1 for p in prod_results if p["risk_level"] in ("严重", "高")),
            # 参与比对的情报库规模（放进 summary，列表页/报告/前端都直接可用）
            "scanned_docs": len(sc.docs),
        },
    }


# ==========================================================================
# 5. 报告构建 / 持久化 / 导出
# ==========================================================================
def _load_store() -> List[dict]:
    if not os.path.isfile(SCAN_STORE):
        return []
    try:
        with open(SCAN_STORE, "r", encoding="utf-8") as f:
            data = json.load(f)
        return data if isinstance(data, list) else []
    except (OSError, ValueError):
        return []


def _save_store(items: List[dict]) -> None:
    os.makedirs(os.path.dirname(SCAN_STORE), exist_ok=True)
    tmp = "%s.%d.%d.tmp" % (SCAN_STORE, os.getpid(), threading.get_ident())
    try:
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(items[:STORE_MAX], f, ensure_ascii=False, separators=(",", ":"))
        os.replace(tmp, SCAN_STORE)
    except OSError:
        try:
            os.remove(tmp)
        except OSError:
            pass


def _report_fp(scan_id: str) -> str:
    safe = re.sub(r"[^A-Za-z0-9\-]", "", scan_id or "")[:40]
    return os.path.join(SCAN_REPORT_DIR, safe + ".json")


def _save_report(rep: dict) -> None:
    """完整报告单独存一份：索引保持轻量（列表页秒开），报告按 id 取。

    为什么拆开：一次体检的报告可能上百 KB，若全塞进 asset_scans.json，
    每次体检都要重写整个文件（越来越慢），列表页也要传一堆用不上的明细。
    """
    os.makedirs(SCAN_REPORT_DIR, exist_ok=True)
    fp = _report_fp(rep.get("id") or "")
    tmp = "%s.%d.tmp" % (fp, os.getpid())
    try:
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(rep, f, ensure_ascii=False, separators=(",", ":"))
        os.replace(tmp, fp)
    except OSError:
        try:
            os.remove(tmp)
        except OSError:
            pass
    # 裁剪过期报告文件（保留索引里还在的那些）
    keep = {os.path.basename(_report_fp(it.get("id") or ""))
            for it in _load_store()}
    try:
        for fn in os.listdir(SCAN_REPORT_DIR):
            if fn.endswith(".json") and fn not in keep:
                try:
                    os.remove(os.path.join(SCAN_REPORT_DIR, fn))
                except OSError:
                    pass
    except OSError:
        pass


def load_report(scan_id: str) -> Optional[dict]:
    fp = _report_fp(scan_id or "")
    if not os.path.isfile(fp):
        with _LOCK:
            for it in _load_store():
                if it.get("id") == scan_id and it.get("full"):
                    return it["full"]
        return None
    try:
        with open(fp, "r", encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return None


def _new_id() -> str:
    # 秒级 + 3 位随机后缀：同一秒内连续体检（示例 → 换文件重跑）不会撞 id
    return "AS-%s-%s" % (time.strftime("%Y%m%d-%H%M%S"), os.urandom(2).hex())


SAMPLE_ASSETS = """# 示例：某公司互联网资产清单（脱敏演示）
资产名称\t域名 / IP\t组件\t版本\t端口\t备注
官网门户\twww.example-corp.cn\tNginx\t1.16.1\t80/443\t对外门户，公网
官网门户\twww.example-corp.cn\tOpenSSL\t1.1.1g\t443\t
客户中心\tcrm.example-corp.cn\tApache Tomcat\t9.0.30\t8080/tcp\tJava 业务系统
客户中心\tcrm.example-corp.cn\tApache Log4j\t2.14.0\t\t日志组件
文件服务\tfile.example-corp.cn\tApache HTTP Server\t2.4.49\t80/tcp\t
运维门户\tops.example-corp.cn\tJenkins\t2.289.1\t8080\tCI/CD
运维门户\t10.10.20.31\tRedis\t5.0.7\t6379/tcp\t内网缓存
数据平台\tdata.example-corp.cn\tElasticsearch\t7.10.0\t9200\t
工单系统\tticket.example-corp.cn\tAtlassian Jira\t8.5.0\t8080/tcp\t
代码仓库\tgit.example-corp.cn\tGitLab\t13.10.0\t\t
统一认证\tsso.example-corp.cn\tSpring Boot\t2.3.0\t\t
堡垒机\t10.10.20.40\tCentOS 7\t7.9\t22/tcp\t
出口网关\t203.0.113.10\tFortinet FortiOS\t6.4.2\t443\t
内部 Wiki\twiki.example-corp.cn\tConfluence\t7.4.0\t\t
安全联系人\tsecurity@example-corp.cn\t\t\t\t
"""


def build_report(filename: str, data: bytes, engine,
                 text: Optional[str] = None, doc: Optional[DocText] = None,
                 persist: bool = True) -> dict:
    """完整流水线：解析 → 抽取 → 匹配 → 报告。"""
    t0 = time.time()
    if doc is None:
        doc = read_upload(filename, data) if data is not None else DocText("text", text or "")
    if text is not None:
        doc = DocText(doc.kind, _norm_text(text), doc.warn,
                      text.splitlines() if not doc.rows else doc.rows)
    assets = extract_assets(doc.text, doc.rows)
    risk = scan_assets(engine, assets)
    report = {
        "id": _new_id(),
        "filename": _nz(filename) or "（未命名）",
        "created_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        "file": {"kind": doc.kind, "chars": doc.chars, "warn": doc.warn,
                 "size": len(data or b"")},
        "assets": {
            "hosts": assets["hosts"][:200],
            "products": assets["products"][:200],
            "urls": assets["urls"][:100],
            "emails": assets["emails"][:50],
            "ports": assets["ports"][:80],
            "os": assets["os"][:20],
            "cves_in_doc": assets["cves_in_doc"][:80],
        },
        "risk": risk,
        "elapsed_ms": int((time.time() - t0) * 1000),
        "basis": "模块 1 情报库（NVD CPE 版本区间 / CISA KEV 在野利用 / CVSS / 官方补丁 / 处置建议）",
    }
    if persist:
        with _LOCK:
            items = [x for x in _load_store() if x.get("id") != report["id"]]
            items.insert(0, _summary_of(report))
            _save_store(items)
        _save_report(report)
    return report


def _summary_of(rep: dict) -> dict:
    """列表页用的轻量摘要（不带逐条命中，避免 store 膨胀）。"""
    s = rep.get("risk", {}).get("summary", {})
    return {
        "id": rep.get("id"), "filename": rep.get("filename"),
        "created_at": rep.get("created_at"), "file": rep.get("file"),
        "summary": s,
        "top_hosts": [{"name": h.get("name"), "risk_level": h.get("risk_level"),
                       "cve_count": h.get("cve_count")}
                      for h in (rep.get("risk", {}).get("hosts") or [])[:6]],
        "top_products": [{"name": p.get("display") or p.get("name"),
                          "version": p.get("version"), "risk_level": p.get("risk_level"),
                          "cve_count": p.get("cve_count"), "top": p.get("top")}
                         for p in (rep.get("risk", {}).get("products") or [])[:8]],
    }


def list_scans() -> List[dict]:
    with _LOCK:
        return _load_store()


def clear_scans() -> int:
    with _LOCK:
        n = len(_load_store())
        _save_store([])
        try:
            for fn in os.listdir(SCAN_REPORT_DIR):
                if fn.endswith(".json"):
                    try:
                        os.remove(os.path.join(SCAN_REPORT_DIR, fn))
                    except OSError:
                        pass
        except OSError:
            pass
        return n


def report_to_markdown(rep: dict) -> str:
    """把报告导出成可交付的 Markdown。"""
    r = rep.get("risk", {})
    s = r.get("summary", {})
    L: List[str] = []
    L.append("# 公司互联网资产风险体检报告")
    L.append("")
    L.append("- **报告编号**：%s" % rep.get("id"))
    L.append("- **资产文件**：%s（%s，%s 字符）" % (
        rep.get("filename"), (rep.get("file") or {}).get("kind"), (rep.get("file") or {}).get("chars")))
    L.append("- **生成时间**：%s" % rep.get("created_at"))
    L.append("- **判定依据**：%s" % rep.get("basis"))
    L.append("- **情报库规模**：%s 条文档参与匹配" % s.get("scanned_docs"))
    L.append("")
    L.append("## 一、体检结论")
    L.append("")
    L.append("| 资产主机 | 软件组件 | 命中 CVE | 严重 | 高危 | 在野利用 | 高风险资产 |")
    L.append("| --- | --- | --- | --- | --- | --- | --- |")
    L.append("| %s | %s | %s | %s | %s | %s | %s |" % (
        s.get("hosts"), s.get("products"), s.get("cve_hits"), s.get("critical"),
        s.get("high"), s.get("exploited"), s.get("risk_hosts")))
    L.append("")
    if s.get("kev_ids"):
        L.append("> ⚠️ **已被在野利用（CISA KEV）**：%s" % "、".join(s["kev_ids"]))
        L.append("")
    L.append("## 二、资产风险清单（按风险排序）")
    L.append("")
    for h in (r.get("hosts") or []):
        comp = "、".join("%s %s" % (c.get("name"), c.get("version") or "") for c in h.get("components") or [])
        L.append("### %s —— %s" % (h.get("name"), h.get("risk_level")))
        L.append("")
        L.append("- 类型：%s（%s）" % (h.get("type"), h.get("scope")))
        if comp:
            L.append("- 承载组件：%s" % comp)
        L.append("- 命中漏洞：%s 条，其中在野利用 %s 条" % (h.get("cve_count"), h.get("kev_count")))
        L.append("")
    L.append("## 三、软件组件命中明细")
    L.append("")
    for p in (r.get("products") or []):
        if not p.get("findings"):
            continue
        L.append("#### %s %s（风险：%s，命中 %s 条）" % (
            p.get("display") or p.get("name"), p.get("version") or "版本未知",
            p.get("risk_level"), p.get("cve_count")))
        L.append("")
        L.append("| CVE | 严重度 | CVSS | 在野利用 | 依据 |")
        L.append("| --- | --- | --- | --- | --- |")
        for f in p["findings"][:20]:
            L.append("| %s | %s | %s | %s | %s |" % (
                f["id"], f["severity"], f.get("score"), "是" if f.get("exploited") else "—",
                f.get("evidence", "")))
        L.append("")
        rem = [x for f in p["findings"][:5] for x in (f.get("remediation") or [])]
        if rem:
            L.append("**处置建议**：")
            for x in _uniq(rem)[:4]:
                L.append("- %s" % x)
            L.append("")
    L.append("## 四、说明")
    L.append("")
    L.append("- 判定采用 NVD 原始 CPE 版本区间（含 versionStartIncluding / versionEndExcluding），"
             "不是关键词命中；仅当资产版本落在受影响区间内才计入。")
    L.append("- 老版 .doc / .xls（OLE 二进制）为尽力解析，建议另存为 .docx / .xlsx 后重新体检。")
    L.append("- 全部解析与匹配在本机完成，资产文件不外发、不联网。")
    return "\n".join(L)


def markdown_of(scan_id: str) -> Optional[str]:
    """按报告编号取 Markdown（导出用）。"""
    rep = load_report(scan_id)
    return report_to_markdown(rep) if rep else None


# ==========================================================================
# 6. 自测入口
# ==========================================================================
if __name__ == "__main__":
    import sys
    sys.path.insert(0, os.path.join(_ROOT, "core"))
    from engine import SearchEngine  # noqa: E402
    try:
        eng = SearchEngine(os.path.join(DATA_DIR, "corpus.json"))
    except Exception as e:  # noqa: BLE001
        print("无法加载引擎：%s" % e)
        raise SystemExit(1)
    d = DocText("text", SAMPLE_ASSETS, "", SAMPLE_ASSETS.splitlines())
    assets = extract_assets(d.text, d.rows)
    print("抽取：主机 %d / 软件 %d / 端口 %s / OS %s" % (
        len(assets["hosts"]), len(assets["products"]), assets["ports"], assets["os"]))
    rep = build_report("示例.txt", SAMPLE_ASSETS.encode("utf-8"), eng, persist=False)
    print(json.dumps(rep["risk"]["summary"], ensure_ascii=False, indent=1))
    for p in rep["risk"]["products"][:12]:
        print("  %-22s %-9s %-4s 命中 %-3s top=%s" % (
            (p.get("display") or p["name"]), p.get("version") or "-", p["risk_level"],
            p["cve_count"], p["top"]))
