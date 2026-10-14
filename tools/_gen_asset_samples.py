# -*- coding: utf-8 -*-
"""
_gen_asset_samples.py —— 生成「公司互联网资产清单」样例文件（docx / xlsx / txt）
================================================================================
用途：给「富化台 · 资产风险体检」提供可直接上传的演示文件，同时当解析器的回归语料。

为什么手写 OOXML 而不是用 python-docx / openpyxl：
  · 本机是隔离运行环境，不额外装第三方库；
  · 生成的是**标准最小包**（[Content_Types] + rels + document.xml / workbook.xml + sharedStrings），
    Word / Excel / WPS 都能正常打开，不是"只对我自己解析器有效"的假文件。

用法： py tools/_gen_asset_samples.py
"""
from __future__ import annotations

import os
import zipfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT = os.path.join(ROOT, "data", "asset_samples")

# 资产清单内容：一行一台主机/一组组件（与 asset_scan.SAMPLE_ASSETS 同源，便于对齐验证）
HEADERS = ["资产名称", "域名 / IP", "组件", "版本", "端口", "备注"]
ROWS = [
    ["官网门户", "www.example-corp.cn", "Nginx", "1.16.1", "80/443", "对外门户，公网"],
    ["官网门户", "www.example-corp.cn", "OpenSSL", "1.1.1g", "443", ""],
    ["客户中心", "crm.example-corp.cn", "Apache Tomcat", "9.0.30", "8080/tcp", "Java 业务系统"],
    ["客户中心", "crm.example-corp.cn", "Apache Log4j", "2.14.0", "", "日志组件"],
    ["文件服务", "file.example-corp.cn", "Apache HTTP Server", "2.4.49", "80/tcp", ""],
    ["运维门户", "ops.example-corp.cn", "Jenkins", "2.289.1", "8080", "CI/CD"],
    ["运维门户", "10.10.20.31", "Redis", "5.0.7", "6379/tcp", "内网缓存"],
    ["数据平台", "data.example-corp.cn", "Elasticsearch", "7.10.0", "9200", ""],
    ["工单系统", "ticket.example-corp.cn", "Atlassian Jira", "8.5.0", "8080/tcp", ""],
    ["代码仓库", "git.example-corp.cn", "GitLab", "13.10.0", "", ""],
    ["统一认证", "sso.example-corp.cn", "Spring Boot", "2.3.0", "", ""],
    ["堡垒机", "10.10.20.40", "CentOS 7", "7.9", "22/tcp", ""],
    ["出口网关", "203.0.113.10", "Fortinet FortiOS", "6.4.2", "443", ""],
    ["内部 Wiki", "wiki.example-corp.cn", "Confluence", "7.4.0", "", ""],
    ["安全联系人", "security@example-corp.cn", "", "", "", ""],
]

CT = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
<Default Extension="xml" ContentType="application/xml"/>
<Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>
<Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>
<Override PartName="/xl/worksheets/sheet1.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>
<Override PartName="/xl/sharedStrings.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sharedStrings+xml"/>
</Types>"""

RELS = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/>
<Relationship Id="rId2" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/>
</Relationships>"""


def esc(s: str) -> str:
    return (s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;"))


def docx_bytes() -> bytes:
    paras = ["公司互联网资产清单（样例 · 脱敏）", "资产总数：15　填报人：安全运营组　填报日期：2026-10-03", ""]
    rows_xml = []
    for r in [HEADERS] + ROWS:
        cells = "".join(
            '<w:tc><w:p><w:r><w:t xml:space="preserve">%s</w:t></w:r></w:p></w:tc>' % esc(c)
            for c in r)
        rows_xml.append("<w:tr>%s</w:tr>" % cells)
    body = "".join('<w:p><w:r><w:t xml:space="preserve">%s</w:t></w:r></w:p>' % esc(p) for p in paras)
    body += ("<w:tbl>" + "".join(rows_xml) + "</w:tbl>")
    doc = ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
           '<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">'
           '<w:body>' + body + '</w:body></w:document>')
    import io
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("[Content_Types].xml", CT)
        z.writestr("_rels/.rels", RELS)
        z.writestr("word/document.xml", doc)
    return buf.getvalue()


def xlsx_bytes() -> bytes:
    # sharedStrings：所有单元格文本去重后编号（Excel 的标准做法）
    allc = [HEADERS] + ROWS
    flat, idx = [], {}
    for r in allc:
        for c in r:
            if c not in idx:
                idx[c] = len(flat)
                flat.append(c)
    sst = ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
           '<sst xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" count="%d" uniqueCount="%d">'
           % (len(allc) * len(HEADERS), len(flat))
           + "".join('<si><t xml:space="preserve">%s</t></si>' % esc(s) for s in flat) + "</sst>")

    def col(i):  # 0->A, 1->B ...
        s = ""
        i += 1
        while i:
            i, rem = divmod(i - 1, 26)
            s = chr(65 + rem) + s
        return s

    rows_xml = []
    for ri, r in enumerate(allc, start=1):
        cells = "".join(
            '<c r="%s%d" t="s"><v>%d</v></c>' % (col(ci), ri, idx[c]) if c else ""
            for ci, c in enumerate(r))
        rows_xml.append('<row r="%d">%s</row>' % (ri, cells))
    sheet = ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
             '<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">'
             '<sheetData>' + "".join(rows_xml) + '</sheetData></worksheet>')
    wb = ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
          '<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" '
          'xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">'
          '<sheets><sheet name="资产清单" sheetId="1" r:id="rId1"/></sheets></workbook>')
    wbrels = ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
              '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
              '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet1.xml"/>'
              '<Relationship Id="rId2" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/sharedStrings" Target="sharedStrings.xml"/>'
              '</Relationships>')
    import io
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("[Content_Types].xml", CT)
        z.writestr("_rels/.rels", RELS)
        z.writestr("xl/workbook.xml", wb)
        z.writestr("xl/_rels/workbook.xml.rels", wbrels)
        z.writestr("xl/worksheets/sheet1.xml", sheet)
        z.writestr("xl/sharedStrings.xml", sst)
    return buf.getvalue()


def txt_bytes() -> bytes:
    out = ["# 公司互联网资产清单（样例 · 脱敏）", "# 格式：资产名称 | 域名/IP | 组件 | 版本 | 端口 | 备注"]
    out.append(" | ".join(HEADERS))
    for r in ROWS:
        out.append(" | ".join(r))
    return ("\n".join(out) + "\n").encode("utf-8")


def main() -> None:
    os.makedirs(OUT, exist_ok=True)
    files = {
        "示例-某公司互联网资产清单.docx": docx_bytes(),
        "示例-某公司互联网资产清单.xlsx": xlsx_bytes(),
        "示例-某公司互联网资产清单.txt": txt_bytes(),
    }
    for name, data in files.items():
        fp = os.path.join(OUT, name)
        with open(fp, "wb") as f:
            f.write(data)
        print("已生成 %s（%d 字节）" % (fp, len(data)))


if __name__ == "__main__":
    main()
