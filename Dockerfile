# AI-SecIntel（aisec-D）容器镜像
# =====================================================================
# 零依赖也能跑主体：这里只装「核心档」依赖（requests/bs4/numpy），
# torch / transformers 等重依赖按需在扩展镜像里加（缺失时系统自动降级，
# 语义检索退回关键词检索，功能不中断 —— 见 requirements.txt 分档说明）。
#
# 构建并启动：
#   docker compose up -d --build
# 查看健康与日志：
#   docker compose ps
#   docker compose logs -f aisec
# 数据（语料/索引/情报库）全部落在宿主机 ./data，重建镜像不丢数据。
# =====================================================================
FROM python:3.13-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    TZ=Asia/Shanghai

WORKDIR /app

# 先装依赖（利用 Docker 层缓存：代码改动不触发重装）
# openpyxl / markdown 是「报告导出」必需：缺了 .xlsx 台账导不出来（直接报错），
# 邮件正文也会退化成纯文本。这两个包很小，一并在核心档装掉。
COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir requests urllib3 beautifulsoup4 numpy openpyxl markdown

# 再拷代码（data/ 由卷挂载提供，不打进镜像）
COPY core/ /app/core/
COPY modules/ /app/modules/
COPY frontend/ /app/frontend/
COPY tools/ /app/tools/
COPY config.json /app/

# ── 非 root 运行（容器安全基线，2026-10-06 补）──
# 之前整段 Dockerfile 没有任何 USER 指令，容器以 root 跑 —— 一旦服务出现
# 可被外部触发的执行漏洞，攻击面直接是宿主机的 root。
# uid 固定 10001（非 root 可写范围的常规起点），nologin 禁止交互登录。
RUN useradd --system --uid 10001 --home-dir /app --shell /usr/sbin/nologin aisec \
    && mkdir -p /app/data \
    && chown -R aisec:aisec /app
# 注意：./data 是宿主机卷挂载，**挂上去之后属主由宿主机决定**。
# 若宿主机上 ./data 属 root，容器内 aisec 会写不进去（表现为归档落盘失败）。
# 一次性修复：`sudo chown -R 10001:10001 ./data`（部署文档里也写了这一条）。
USER aisec

EXPOSE 8848

# 健康检查：/api/health 不依赖引擎冷加载，秒回
HEALTHCHECK --interval=30s --timeout=5s --start-period=90s --retries=3 \
    CMD python -c "import urllib.request,sys; r=urllib.request.urlopen('http://127.0.0.1:8848/api/health', timeout=4); sys.exit(0 if r.status==200 else 1)"

CMD ["python", "core/server.py", "8848"]
