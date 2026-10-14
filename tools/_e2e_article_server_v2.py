# -*- coding: utf-8 -*-
"""端到端测试用的假文章服务器（v2）：在 127.0.0.1:8892 提供可控正文。
  · 默认（/ 或任意 ?r= 路径）          → 按 r 派生的「特定安全主题」文章（质量高，应正常收录并给分级）
  · /spam                              → 短 + 重度广告（应被「质量极差」过滤）
  · /dup_a 与 /dup_b（不同 URL 同正文）→ DUP_HTML（dup_b 应被「过分相同」过滤）
设计要点：默认文章按 r 取不同主题，避免并发提交时彼此被判「过分相同」，也让正文明显区别于语料库。
"""
import hashlib
import random
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

# 12 个高度具体的攻防主题（标题 + 2 段专属正文），彼此词项重叠低，且明显区别于语料库（CVE/公告类）。
TOPICS = [
    ("Prompt Injection 实战：大模型越狱与防护",
     "本文梳理提示词注入在大模型应用中的攻击面，涵盖直接注入、间接注入与多轮越狱。攻击者可借 RAG 检索增强与 MCP 协议暴露面构造恶意指令，诱导 Agent 越权调用工具。",
     "防御侧给出输入清洗、权限最小化、护栏与输出审计的组合方案，并结合模型投毒与模型窃取风险，建议从供应链审计与异常行为监控两方面加固。"),
    ("Log4j 供应链漏洞：从 JNDI 注入到内网沦陷",
     "Log4Shell 暴露了日志组件加载远程 LDAP 类的安全缺陷，攻击者可借 JNDI 注入在目标主机执行任意代码，进而植入后门实现持久化。",
     "治理要点是升级受影响的日志依赖、关闭 lookup 功能，并在 WAF 与边界处过滤恶意类名，配合资产盘点完成闭环修复。"),
    ("Kubernetes 容器逃逸：挂载与特权滥用",
     "容器逃逸常利用特权容器、危险挂载（如宿主机根文件系统）或内核漏洞突破隔离边界，获取节点控制权。",
     "加固方向包括禁止特权容器、启用 seccomp 与 AppArmor、使用只读根文件系统，并以准入控制拦截高风险 Pod 配置。"),
    ("JWT 伪造与算法混淆攻击",
     "JSON Web Token 在 alg=none 或公私钥混淆场景下可被伪造，攻击者在未掌握密钥的情况下篡改声明实现越权。",
     "防护要求服务端显式指定签名算法、校验密钥来源，并对敏感接口的令牌做短期失效与绑定校验。"),
    ("XXE 外部实体注入利用与防御",
     "XML 外部实体注入可读取本地文件、探测内网或触发拒绝服务，常见于遗留的 XML 解析组件与文档导入接口。",
     "修复需禁用 DTD 与外部实体解析，或在解析器中关闭相关特性，并对上传的 XML 做严格白名单校验。"),
    ("钓鱼邮件演练：社工与凭据窃取",
     "钓鱼演练通过仿冒登录页与紧迫话术诱导员工提交凭据，是检验安全意识与邮件网关拦截率的有效手段。",
     "结合 DMARC、反向 DNS 校验与附件沙箱，并将演练结果纳入红蓝对抗复盘，可显著降低凭据泄露风险。"),
    ("勒索软件溯源：加密行为与横向移动",
     "勒索软件多在入侵后期加密关键数据并窃取信息，常借助弱口令爆破与内网横向移动扩大影响面。",
     "溯源依赖日志关联、流量取证与内存马检测，配合离线备份与最小权限原则构建纵深防御。"),
    ("零信任架构落地：身份与微隔离",
     "零信任以身份为中心，要求每次访问都经过显式校验，不再默认信任网络位置。",
     "落地重点是统一身份目录、细粒度授权、持续信任评估，以及基于微隔离的工作负载分段。"),
    ("云原生安全加固：IAM 与最小权限",
     "云上风险多源于过度授权的 IAM 策略与公开存储桶，攻击者可借被盗凭证横向访问更多资源。",
     "治理需收敛角色权限、开启访问日志审计，并对敏感存储启用加密与私有访问端点。"),
    ("SOC 检测规则调优：误报治理",
     "安全运营中心在海量告警中易被误报淹没，规则调优需结合真实攻击链与上下文 enrichment 降低噪音。",
     "通过关联多源遥测、引入威胁情报与用户行为基线，可提升高保真告警比例，缩短响应时间。"),
    ("恶意 Office 宏分析与沙箱逃逸",
     "恶意宏常借社会工程诱导启用，下载二阶段载荷并建立持久化，部分样本会探测沙箱环境以规避分析。",
     "检测应结合宏行为静态特征、AMSI 扫描与内存取证，并在隔离环境中动态执行以捕获逃逸变种。"),
    ("SSRF 内网探测：从元数据到凭证泄露",
     "服务端请求伪造可让攻击者借应用出网能力访问内网与云元数据接口，窃取临时凭证进而横向移动。",
     "修复需对请求目标做白名单与 DNS 重绑定防护，并禁止实例元数据接口被任意内部请求访问。"),
]
SHARED_P = ("本文面向安全研究与防护实践，强调在合规框架下开展授权测试，所有技术细节仅用于防御能力提升，"
            "不涉及任何未授权入侵。相关结论已在护网演练与红蓝对抗中验证，可供团队参考落地。")


# 随机化用的字表：刻意选用「非安全领域」的中性汉字。
# 原因：content_containment 统计的是「新文章词项权重被已收录文档覆盖的比例」，
# 若随机串由安全词汇的汉字拼成，其 CJK 2-gram 会命中已有安全文档的词项，
# 覆盖率压不下来；用中性字可让这部分词项几乎不可能被覆盖，从而把跨轮重叠
# 真正降到阈值（0.6）以下。
_CHARS = ("山水风雨花草树木天空海洋城市乡村道路桥梁春夏秋冬日月星云江河湖海"
          "田园村庄庭院楼台琴棋书画诗词歌赋笔墨纸砚梅兰竹菊松柏杨柳晨昏暮晓")


def _seed(tok):
    return int(hashlib.md5(("seed|" + str(tok)).encode("utf-8")).hexdigest()[:12], 16)


def short(r):
    """由 token 派生的标题标记（4 个随机汉字）。

    为什么不用 hex 短串：查重是模糊判定（title_sim ≥ 0.9 或 正文包含率 ≥ 0.6
    即命中），hex 的字符集只有 0-9a-f，两轮后缀的字符集重叠极高，实测
    title_sim 仍达 0.95。改用大字符集汉字，才能真正拉开距离。
    """
    if not r:
        return ""
    rnd = random.Random(_seed(r))
    return "".join(rnd.choice(_CHARS) for _ in range(4))


def _rand_body(tok, n=260):
    """由 token 确定性派生的随机正文（同 token → 同文本，不同 token → 差异大）。

    必要性：仅有标题不同不够——正文完全相同会让 content_containment≈0.99，
    照样触发「过分相同」过滤。随机正文把跨轮重叠率压到阈值以下。
    """
    if not tok:
        return ""
    rnd = random.Random(_seed(tok) ^ 0x5A5A)
    n = rnd.randint(n - 40, n + 40)
    buf = []
    for i in range(n):
        buf.append(rnd.choice(_CHARS))
        if (i + 1) % rnd.randint(14, 22) == 0:
            buf.append("。")
    return "".join(buf).rstrip("。") + "。"


def make_good(r, tok=""):
    idx = 0
    if r:
        h = hashlib.md5(r.encode("utf-8")).digest()
        idx = (h[0] | (h[1] << 8)) % len(TOPICS)
    title, p1, p2 = TOPICS[idx]
    title = _uniq(title, tok or r)
    # 随机正文插在主题正文之间：既稀释跨轮文本重叠（压低包含率），
    # 又保留主题安全词以维持正常的质量分级。
    noise = _rand_body(tok or r)
    paras = [p1, noise, p2, SHARED_P] if noise else [p1, p2, SHARED_P]
    body = "".join("<p>%s</p>" % x for x in paras)
    html = ("<!DOCTYPE html><html><head>"
            '<meta property="og:title" content="%s">'
            '<meta property="article:published_time" content="2026-09-30T08:30:00Z">'
            '<meta name="author" content="Lolcat">'
            "<title>%s</title></head><body>"
            "<h1>%s</h1>%s</body></html>"
            % (title, title, title, body))
    return html


def _uniq(title, tok):
    """给标题追加轮次标记；无 token 时保持原标题（向后兼容旧调用方）。"""
    s = short(tok)
    return "%s · %s" % (title, s) if s else title


SPAM_HTML = """<!DOCTYPE html><html><head>
<meta property="og:title" content="限时优惠活动">
<title>限时优惠活动</title>
</head><body>
<h1>限时优惠活动</h1>
<p>扫码加微信领优惠券，加好友免费领取，推广返利返利，代写包过。</p>
</body></html>"""

DUP_TITLE = "供应链攻击溯源实战：从依赖投毒到内网横向移动"


def make_dup(tok=""):
    """生成「过分相同」测试对：dup_a / dup_b 必须传同一个 token，
    两者标题与正文完全一致才能触发近重过滤；token 每轮换新的目的同上。"""
    title = _uniq(DUP_TITLE, tok)
    noise = _rand_body(tok)
    mid = "<p>%s</p>" % noise if noise else ""
    return """<!DOCTYPE html><html><head>
<meta property="og:title" content="{t}">
<meta property="article:published_time" content="2026-09-29T12:00:00Z">
<meta name="author" content="Lolcat">
<title>{t}</title>
</head><body>
<h1>{t}</h1>
<p>供应链攻击已成为高级威胁的主要入口。攻击者通过在开源依赖中植入后门或投毒，借用可信构建链将恶意代码送入目标内网，实现隐蔽的权限提升与持久化。</p>
{mid}
<p>本文结合真实入侵案例，梳理从依赖投毒、钓鱼社工到内网横向移动的完整攻击链，并给出基于零信任与微隔离的纵深防御思路。</p>
<p>溯源环节强调日志关联、流量取证与内存马检测，配合红蓝对抗演练持续打磨检测规则，提升对 APT 组织供应链作战手法的识别与响应能力。</p>
</body></html>""".format(t=title, mid=mid)


DUP_HTML = make_dup("")   # 向后兼容：无 token 时使用原标题


class H(BaseHTTPRequestHandler):
    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path
        qs = parse_qs(parsed.query)
        r = (qs.get("r") or [""])[0]
        # t = 标题轮次 token；缺省回落到 r，保证旧调用方行为不变
        tok = (qs.get("t") or [r])[0]
        if path.startswith("/spam"):
            body = SPAM_HTML
        elif path.startswith("/dup_a") or path.startswith("/dup_b"):
            body = make_dup(tok)
        else:
            body = make_good(r, tok)
        data = body.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, *a):
        pass


if __name__ == "__main__":
    srv = ThreadingHTTPServer(("127.0.0.1", 8892), H)
    print("e2e fake article server v2 on http://127.0.0.1:8892", flush=True)
    srv.serve_forever()
