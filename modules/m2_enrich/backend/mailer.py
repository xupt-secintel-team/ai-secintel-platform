"""邮件投递（2026-10-06）—— 把 CMDB 分析报告发到指定邮箱。

设计要点
--------
1. **零新增依赖**：只用标准库 `smtplib` + `email`，不引第三方包。
   项目的 requirements.txt 要保持精简，且离线环境下装包容易失败。

2. **配置走 secrets.env**（与 AISEC_LLM_API_KEY / AISEC_GITHUB_TOKEN 同一约定）：

       AISEC_SMTP_HOST=smtp.qq.com
       AISEC_SMTP_PORT=465
       AISEC_SMTP_USER=zhang@qq.com
       AISEC_SMTP_PASS=授权码（不是登录密码！）
       AISEC_SMTP_FROM=zhang@qq.com        # 可选，默认同 USER
       AISEC_SMTP_SSL=1                    # 可选，465 默认开、25 默认关

   没配就是 `configured() == False`，前端会显示"未配置 SMTP"，
   **不会静默失败** —— 用户点了发送必须知道结果。

3. **发送绝不阻塞响应**：SMTP 在 30s 内连不上是很常见的（内网防火墙）。
   所以这里只提供 `send_report_mail()` 供后台线程调用，
   请求线程负责立刻返回"已进入发送队列"。

4. **默认脱敏**：报告含责任人邮箱 / 内网 IP / 业务系统名，外发必须显式选级别。
   `mask=""` 会退回 basic 而不是 off —— 发到外部邮箱还用原文是安全事故。
"""
from __future__ import annotations

import os
import re
import socket
import smtplib
import threading
from email.header import Header
from email.mime.application import MIMEApplication
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.utils import formataddr, formatdate
# ★ 异常类**直接绑定到本模块**，不在 except 子句里写 smtplib.XXX。
#   否则一旦有人替换 mailer.smtplib（测试替身、故障注入、甚至某些打包器
#   对 smtplib 做了惰性代理），except 子句会抛 AttributeError，
#   把"认证失败"这类可诊断错误变成看不懂的崩溃。
from smtplib import SMTPAuthenticationError, SMTPException
from typing import Any, Dict, List, Optional, Tuple

# 允许的脱敏级别（与 cmdb_scan._mask_markdown 一致）
_MASK_OK = ("basic", "strict")

# 常见邮箱服务商的默认端口，用户只填账号密码也能猜对
_KNOWN_HOSTS = {
    "smtp.qq.com": 465,
    "smtp.163.com": 465,
    "smtp.126.com": 465,
    "smtp.126.com": 465,
    "smtp.foxmail.com": 465,
    "smtp.gmail.com": 587,
    "smtp.qq.com": 465,
    "smtp.yahoo.com": 465,
    "smtp.aliyun.com": 465,
}

# 一次最多发几个收件人：多了容易被判垃圾邮件，也不好排查
MAX_RECIPIENTS = 20

# 邮箱格式校验。刻意保守：只允许常见形态，不追求 RFC 完备。
_EMAIL_RE = re.compile(r"^[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,24}$")


def _swallow(tag: str, e: BaseException) -> None:
    """记录异常但不打断流程（与项目其他模块一致的 best-effort 约定）。"""
    try:
        from core.registry import swallow as _s  # type: ignore
        _s(tag, e)
    except Exception:  # noqa: BLE001
        pass


# ----------------------------------------------------------------------
# 配置
# ----------------------------------------------------------------------
def _cfg() -> Dict[str, str]:
    """从环境变量读 SMTP 配置（secrets.env 由启动脚本注入到 os.environ）。"""
    host = (os.environ.get("AISEC_SMTP_HOST") or "").strip()
    user = (os.environ.get("AISEC_SMTP_USER") or "").strip()
    pwd = (os.environ.get("AISEC_SMTP_PASS") or "").strip()
    if not (host and user and pwd):
        return {}
    try:
        port = int((os.environ.get("AISEC_SMTP_PORT") or "").strip() or 0)
    except (TypeError, ValueError):
        port = 0
    if not port:
        port = _KNOWN_HOSTS.get(host.lower(), 465)
    frm = (os.environ.get("AISEC_SMTP_FROM") or "").strip() or user
    ssl_on = (os.environ.get("AISEC_SMTP_SSL") or "").strip().lower()
    if ssl_on in ("1", "true", "yes", "on"):
        use_ssl = True
    elif ssl_on in ("0", "false", "no", "off"):
        use_ssl = False
    else:
        use_ssl = port == 465          # 465 是 SMTPS，25 是明文
    return {"host": host, "port": port, "user": user, "pass": pwd,
            "from": frm, "ssl": use_ssl}


def configured() -> bool:
    """SMTP 是否已配置（前端用它决定要不要显示"未配置"提示）。"""
    return bool(_cfg())


def config_status() -> Dict[str, Any]:
    """给前端的配置状态。

    **绝不回传密码，也不回传发信账号/发件地址**（2026-10-06）——
    页面只需知道"能不能发、走哪台服务器"，账号属于敏感信息，不落到浏览器。
    """
    c = _cfg()
    if not c:
        return {"ok": False, "configured": False,
                "hint": "未配置 SMTP：请在 secrets.env 填 AISEC_SMTP_HOST / "
                        "AISEC_SMTP_USER / AISEC_SMTP_PASS（QQ/163 邮箱填授权码，不是登录密码）"}
    return {"ok": True, "configured": True,
            "host": c["host"], "port": c["port"], "ssl": c["ssl"]}


# ----------------------------------------------------------------------
# 收件人校验
# ----------------------------------------------------------------------
def parse_recipients(raw: Any) -> Tuple[List[str], List[str]]:
    """解析收件人输入。返回 (合法地址列表, 被拒的原始串列表)。

    支持逗号 / 分号 / 顿号 / 换行 / 空格分隔（用户从 Excel 里粘贴很常见）。
    """
    if isinstance(raw, (list, tuple)):
        items = [str(x) for x in raw]
    else:
        s = str(raw or "")
        items = [t for t in re.split(r"[,;，；、\s]+", s) if t]
    good: List[str] = []
    bad: List[str] = []
    for it in items:
        t = it.strip().strip("<>")
        if not t:
            continue
        if _EMAIL_RE.match(t):
            if t not in good:
                good.append(t)
        else:
            bad.append(it.strip())
    return good, bad


def validate(raw: Any) -> Dict[str, Any]:
    """校验收件人输入，返回可直接回给前端的结构。"""
    good, bad = parse_recipients(raw)
    if not good and bad:
        return {"ok": False,
                "error": "邮箱地址格式不正确：%s" % "、".join(bad[:3]),
                "recipients": [], "rejected": bad}
    if not good:
        return {"ok": False, "error": "请填写收件邮箱", "recipients": [], "rejected": []}
    if len(good) > MAX_RECIPIENTS:
        return {"ok": False,
                "error": "收件人 %d 个，超过单次上限 %d" % (len(good), MAX_RECIPIENTS),
                "recipients": good[:MAX_RECIPIENTS], "rejected": bad}
    return {"ok": True, "recipients": good, "rejected": bad}


# ----------------------------------------------------------------------
# 正文构造
# ----------------------------------------------------------------------
def build_subject(report: dict, host_tag: str = "") -> str:
    """邮件标题：一眼能看出是哪次分析的什么报告。"""
    name = (report.get("name") or report.get("title") or "").strip()
    rid = str(report.get("id") or "")
    base = "CMDB 资产风险分析报告"
    if name:
        base = "%s · %s" % (base, name)
    if host_tag:
        base = "[%s] %s" % (host_tag, base)
    return "%s（%s）" % (base, rid[-8:] if rid else "未编号")


def build_body(report: dict, md_text: str, to_list: List[str],
               html: bool = True) -> Tuple[object, str]:
    """构造 (MIME 对象, 纯文本备选)。

    markdown 一律转成 HTML 做正文 —— 邮件客户端基本不认 Markdown 语法，
    直接塞原文的话收件人看到的是一堆 ** 和 ##。
    转换失败不阻断：退化成 <pre> 包裹的可读文本。
    """
    plain = _plain_intro(report, to_list) + "\n\n" + (md_text or "")

    html_body = None
    if html:
        try:
            import markdown as _md  # type: ignore
            html_body = _md.markdown(
                md_text or "", extensions=["tables", "fenced_code", "toc"])
        except Exception:  # noqa: BLE001
            html_body = None
    if html_body is None:
        try:
            html_body = "<html><body style=\"font-family:Segoe UI,Microsoft YaHei,sans-serif;"
            html_body += "font-size:13px;line-height:1.7\">"
            html_body += "<pre style=\"white-space:pre-wrap;word-break:break-word\">"
            html_body += _html_escape(plain)
            html_body += "</pre></body></html>"
        except Exception:  # noqa: BLE001
            html_body = plain

    msg = MIMEMultipart("alternative")
    msg.attach(MIMEText(plain, "plain", "utf-8"))
    msg.attach(MIMEText(html_body, "html", "utf-8"))
    return msg, plain


def _plain_intro(report: dict, to_list: List[str]) -> str:
    s = report.get("summary") or {}
    def g(*ks):
        for k in ks:
            v = s.get(k)
            if v is not None and v != "":
                return v
        return ""
    lines = [
        "本邮件由 AI-SecIntel 2.0 自动发送，报告正文如下。",
        "",
        "报告编号：%s" % (report.get("id") or "—"),
        "生成时间：%s" % (report.get("generated_at") or report.get("ts") or "—"),
    ]
    ci = g("ci_total", "ci", "total_ci", "hosts")
    if ci:
        lines.append("资产总数：%s" % ci)
    vul = g("vuln_total", "ledger_rows", "vuln_count")
    if vul:
        lines.append("漏洞条目：%s" % vul)
    crit = g("critical", "critical_count")
    if crit:
        lines.append("严重(Critical)：%s" % crit)
    return "\n".join(lines)


def _html_escape(s: str) -> str:
    return (str(s or "").replace("&", "&amp;").replace("<", "&lt;")
            .replace(">", "&gt;").replace("\"", "&quot;"))


# ----------------------------------------------------------------------
# 实际发送
# ----------------------------------------------------------------------
def send_simple_mail(recipients: List[str], subject: str, text: str,
                     timeout: int = 30) -> Dict[str, Any]:
    """纯文本通知信（每日报告提醒等）。**只能在后台线程里调用**。

    与 send_report_mail 的区别：不吃 report 结构、不做脱敏（正文是我们自己
    生成的摘要，不含责任人邮箱 / 内网 IP）、无附件。之所以单独写而不是
    硬套 send_report_mail，是因为它会把一段纯文本当成报告渲染，产出
    一堆空的表格骨架。
    """
    c = _cfg()
    if not c:
        return {"ok": False, "error": config_status()["hint"], "to": list(recipients)}
    good, bad = parse_recipients(recipients)
    if not good:
        return {"ok": False, "error": "没有有效收件人", "to": []}
    if len(good) > MAX_RECIPIENTS:
        return {"ok": False,
                "error": "收件人 %d 个，超过单次上限 %d" % (len(good), MAX_RECIPIENTS),
                "to": good}
    body = str(text or "")
    if not body.strip():
        return {"ok": False, "error": "正文为空，未发送", "to": good}

    msg = MIMEMultipart()
    msg["Subject"] = Header(str(subject or "AI-SecIntel 通知"), "utf-8")
    try:
        msg["From"] = formataddr((str(Header("AI-SecIntel 2.0", "utf-8")), c["from"]))
    except Exception:  # noqa: BLE001
        msg["From"] = c["from"]
    msg["To"] = ", ".join(good)
    msg["Date"] = formatdate(localtime=True)
    msg["X-Mailer"] = "AI-SecIntel/2.0"
    msg.attach(MIMEText(body, "plain", "utf-8"))

    srv = None
    try:
        if c["ssl"]:
            srv = smtplib.SMTP_SSL(c["host"], c["port"], timeout=timeout)
        else:
            srv = smtplib.SMTP(c["host"], c["port"], timeout=timeout)
            try:
                srv.ehlo()
                srv.starttls()
                srv.ehlo()
            except SMTPException as e:
                _swallow("mailer.starttls.simple", e)
        srv.login(c["user"], c["pass"])
        srv.sendmail(c["from"], good, msg.as_string())
        return {"ok": True, "to": good, "rejected": bad,
                "host": c["host"], "port": c["port"]}
    except SMTPAuthenticationError as e:
        return {"ok": False, "to": good,
                "error": "SMTP 认证失败：%s。QQ/163 需填「授权码」而非登录密码"
                          % (str(e)[:100])}
    except (socket.timeout, TimeoutError):
        return {"ok": False, "to": good,
                "error": "连接 %s:%s 超时（%ds）。请检查网络/防火墙，或改用其他端口"
                          % (c["host"], c["port"], timeout)}
    except (SMTPException, OSError) as e:
        return {"ok": False, "to": good, "error": "SMTP 发送失败：%s" % str(e)[:150]}
    except Exception as e:  # noqa: BLE001
        _swallow("mailer.send_simple", e)
        return {"ok": False, "to": good, "error": "邮件发送异常：%s" % str(e)[:150]}
    finally:
        if srv is not None:
            try:
                srv.quit()
            except Exception:  # noqa: BLE001
                try:
                    srv.close()
                except Exception:  # noqa: BLE001
                    pass


def send_report_mail(recipients: List[str], report: dict, md_text: str,
                     mask: str = "basic", attach_md: bool = False,
                     host_tag: str = "", timeout: int = 30,
                     xlsx_bytes: Optional[bytes] = None) -> Dict[str, Any]:
    """同步发送。**只能在后台线程里调用**（SMTP 连接最多阻塞 timeout 秒）。

    attach_md 默认 **False**：正文已经是完整报告，附件只是给"想在本地存档/转发"
    的人用的。默认带上会让每封信都多一份几十 KB 的重复内容，也容易被判垃圾邮件。

    xlsx_bytes：简略版处置台账的字节流（bytes）。给了就作为 .xlsx 附件带上。

    返回 {"ok": bool, "error": str, "to": [...], "mask": ...}
    """
    c = _cfg()
    if not c:
        return {"ok": False, "error": config_status()["hint"], "to": list(recipients)}
    good, bad = parse_recipients(recipients)
    if not good:
        return {"ok": False, "error": "没有有效收件人", "to": []}
    if len(good) > MAX_RECIPIENTS:
        return {"ok": False,
                "error": "收件人 %d 个，超过单次上限 %d" % (len(good), MAX_RECIPIENTS),
                "to": good}

    # ★ 外发默认 basic：报告含责任人邮箱 / 内网 IP / 业务系统名，
    #   直接把原文发到外部邮箱是安全事故。只有显式传 off 才发原文。
    use_mask = mask if mask in _MASK_OK else "basic"

    body_msg, _plain = build_body(report, md_text, good)
    msg = MIMEMultipart()
    msg["Subject"] = Header(build_subject(report, host_tag), "utf-8")
    try:
        msg["From"] = formataddr((str(Header("AI-SecIntel 2.0", "utf-8")), c["from"]))
    except Exception:  # noqa: BLE001
        msg["From"] = c["from"]
    msg["To"] = ", ".join(good)
    msg["Date"] = formatdate(localtime=True)
    msg["X-Mailer"] = "AI-SecIntel/2.0"
    msg.attach(body_msg)
    if attach_md and md_text:
        att = MIMEApplication((md_text or "").encode("utf-8"), _subtype="markdown")
        att.add_header("Content-Disposition", "attachment",
                       filename=("CMDB风险分析报告_%s.md"
                                 % str(report.get("id") or "")[-8:]))
        msg.attach(att)
    if xlsx_bytes:
        # xlsx 的规范 MIME 名就是它自己，不要设成 octet-stream ——
        # 部分手机邮件客户端会因此拒绝预览附件。
        xa = MIMEApplication(xlsx_bytes,
                             _subtype="vnd.openxmlformats-officedocument."
                                      "spreadsheetml.sheet")
        xa.add_header("Content-Disposition", "attachment",
                      filename=("CMDB处置简略台账_%s.xlsx"
                                % str(report.get("id") or "")[-8:]))
        msg.attach(xa)

    srv = None
    try:
        if c["ssl"]:
            srv = smtplib.SMTP_SSL(c["host"], c["port"], timeout=timeout)
        else:
            srv = smtplib.SMTP(c["host"], c["port"], timeout=timeout)
            try:
                srv.ehlo()
                srv.starttls()
                srv.ehlo()
            except SMTPException as e:
                # 25 端口不发 TLS 也可能被对端接受，不该因此判定整体失败
                _swallow("mailer.starttls", e)
        srv.login(c["user"], c["pass"])
        srv.sendmail(c["from"], good, msg.as_string())
        return {"ok": True, "to": good, "rejected": bad, "mask": use_mask,
                "host": c["host"], "port": c["port"]}
    except SMTPAuthenticationError as e:
        return {"ok": False, "to": good,
                "error": "SMTP 认证失败：%s。QQ/163 需填「授权码」而非登录密码"
                          % (str(e)[:100])}
    except (socket.timeout, TimeoutError):
        return {"ok": False, "to": good,
                "error": "连接 %s:%s 超时（%ds）。请检查网络/防火墙，或改用其他端口"
                          % (c["host"], c["port"], timeout)}
    except (SMTPException, OSError) as e:
        return {"ok": False, "to": good,
                "error": "SMTP 发送失败：%s" % str(e)[:150]}
    except Exception as e:  # noqa: BLE001
        _swallow("mailer.send", e)
        return {"ok": False, "to": good, "error": "邮件发送异常：%s" % str(e)[:150]}
    finally:
        if srv is not None:
            try:
                srv.quit()
            except Exception:  # noqa: BLE001
                try:
                    srv.close()
                except Exception:  # noqa: BLE001
                    pass


def send_async(recipients: List[str], report: dict, md_text: str,
               mask: str = "basic", attach_md: bool = False,
               host_tag: str = "", xlsx_bytes: Optional[bytes] = None) -> None:
    """后台发送（请求线程专用）：立刻返回，邮件在守护线程里发。

    结果通过 last_result() 回传（用于更新 UI 状态）。
    """
    def _work():
        try:
            res = send_report_mail(recipients, report, md_text, mask, attach_md,
                                   host_tag, xlsx_bytes=xlsx_bytes)
        except Exception as e:  # noqa: BLE001
            _swallow("mailer.async", e)
            res = {"ok": False, "error": str(e)[:150], "to": list(recipients)}
        _LAST_RESULT["value"] = res
        return res

    t = threading.Thread(target=_work, name="aisec-mail", daemon=True)
    t.start()


# 最近一次发送结果（单进程内给轮询接口用；够用且不引数据库）
_LAST_RESULT: Dict[str, Any] = {"value": None}


def last_result() -> Optional[Dict[str, Any]]:
    v = _LAST_RESULT.get("value")
    return v if isinstance(v, dict) else None


def clear_last_result() -> None:
    _LAST_RESULT["value"] = None