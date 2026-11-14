```
# AI-SecIntel Platform
本地运行的国内公开漏洞自动同步与智能问答防御类安全工具

---

## 免责声明（强制阅读）
**本工具仅用于企业安全运维、授权渗透测试、网络安全研究与学习，禁止用于任何未授权访问、攻击破坏、非法数据获取等违法活动。使用本工具产生的所有风险、法律责任，均由使用者自行承担，项目开发者与贡献者不承担任何法律责任。请严格遵守《网络安全法》《数据安全法》《个人信息保护法》。**

本工具所有数据默认仅存储于用户本地，不主动上传任何用户隐私数据，无默认远程遥测、数据上报功能。本项目开源许可证为GPLv3，二次开发需遵循相同开源协议。

---

## 核心功能
1. 多源公开漏洞情报自动同步，覆盖国内厂商专属漏洞，支持定时增量更新
2. 本地漏洞知识库构建，支持资产指纹匹配、信息富化与授权范围内POC本地验证
3. 可选本地LLM智能体问答，检索增强生成漏洞分析与修复建议，无API密钥自动降级为模板问答
4. 漏洞日报/周报一键导出，支持Excel、PDF格式，适配企业运维流程

---

## 环境要求
1. 系统：Windows 10/11（优先适配）、Linux/macOS，支持Docker部署
2. Python版本：**3.10 ~ 3.12（推荐3.11，依赖兼容性最好）**，不支持3.9以下、3.13以上版本
3. 硬件：最低8GB内存，2GB磁盘剩余空间；全功能本地模型推荐16GB以上内存
4. 路径要求：项目必须放在全英文路径，禁止中文、空格、特殊字符，避免依赖解析报错

---

## 核心部署模块（Windows新手专属，全程无需敲命令）
仓库根目录内置三个标准化部署脚本，按顺序双击即可完成全流程，脚本自动切换国内镜像，单源失败自动重试。

| 模块脚本 | 核心能力 | 执行时机 |
|---|---|---|
| **install_venv.bat** | 1. 自动检测合规Python版本<br>2. 创建独立虚拟环境，不污染系统配置<br>3. 多镜像自动切换安装核心依赖<br>4. 自动创建运行目录、生成空配置模板<br>支持`--full`参数安装全量本地模型 | 首次部署第一步 |
| **初始化语料.bat** | 1. 自动拉取公开漏洞语料<br>2. 本地构建检索索引<br>3. 失败自动重试，无需手动干预 | 环境安装完成后第二步 |
| **start_service.bat** | 1. 自动加载本地密钥配置<br>2. 启动Web后端服务<br>3. 支持自定义端口传入<br>默认端口8848 | 语料初始化完成后第三步 |

---

### 完整部署流程
1. **第一步：环境安装**
双击`install_venv.bat`，等待核心依赖安装完成；需要本地语义模型，在终端执行`install_venv.bat --full`即可。
2. **第二步：语料初始化**
联网直接双击`初始化语料.bat`，普通宽带预计15~30分钟，后台运行即可；网络较差可下载Release离线语料包，解压覆盖`data`目录跳过下载。
3. **第三步：启动服务**
打开自动生成的`secrets.env`，可选填写API密钥与代理，留空不影响核心功能；双击`start_service.bat`，浏览器访问`http://127.0.0.1:8848`打开控制台。端口被占用执行`start_service.bat 8899`更换端口。

---

## 进阶部署方式
### 手动命令行部署（PowerShell）
```powershell
# 进入项目目录
Set-LiteralPath "你的全英文项目路径"
# 创建并激活虚拟环境
python -m venv .venv
.\.venv\Scripts\Activate.ps1
# 安装核心依赖（阿里云镜像）
pip install requests urllib3 beautifulsoup4 numpy openpyxl markdown -i https://mirrors.aliyun.com/pypi/simple/
# 初始化语料
python -u core/fetch_corpus.py
# 启动服务
python -u core/server.py 8848
```

### Linux/macOS 部署

项目自带`安装.sh`、`start.sh`，添加执行权限后直接运行：

```
chmod +x 安装.sh start.sh
./安装.sh
./start.sh
```

### Docker 部署

项目自带 Dockerfile 与 docker-compose.yml，执行：

```
docker compose up -d
docker compose logs -f
```

启动后访问服务器 IP+8848 端口即可。

---

## 团队分工

表格

| GitHub 账号 | 负责模块 | 核心职责 |
| --- | --- | --- |
| 666duyi | 基础架构、爬虫模块 | 项目框架、多源漏洞爬虫、定时同步、本地存储、部署脚本、前端基础页面 |
| 队友 1 账号（待补充最终 ID） | POC 框架、资产富化模块 | 漏洞验证 POC、资产指纹匹配、漏洞富化、误报校验、本地验证逻辑 |
| 队友 2 账号（待补充最终 ID） | 智能体编排、问答模块 | 本地知识库、LLM Agent 编排、检索增强、智能问答、交互逻辑 |

> 
> 所有贡献自动通过 Git 提交记录统计，仓库 Insights 页面可查看完整贡献数据，禁止代他人提交代码。

---

## 启动参数说明

表格

| 参数 | 作用 |
| --- | --- |
| `--low` | 低性能模式，适配低配电脑，关闭高频调度 |
| `--mid` | 默认平衡模式 |
| `--high` | 高性能模式，全开模块，适配 16GB 以上内存设备 |
| `--no-live` | 关闭实时同步，仅使用本地缓存数据 |
| `--full` | 安装全量本地模型依赖 |

---

## 常见问题排查

1. 提示`python not found`：重装 Python3.11，安装时勾选「Add Python to PATH」，重启终端后重试
2. 镜像源 403 报错：脚本自动切换备用源，若仍失败关闭代理后重试，不要反复请求单一镜像
3. 提示语料缺失：先运行`初始化语料.bat`，或导入离线 data 目录，不要直接启动服务
4. 端口被占用：启动时传入其他端口，例如`start_service.bat 8899`
5. 中文乱码：脚本默认开启 UTF8 编码，不要手动修改系统编码，不要放在中文路径下
6. LLM 功能未启用：属于正常降级，填写`AISEC_LLM_API_KEY`后重启即可，不影响离线核心功能
7. 模块导入错误：确认虚拟环境已激活，依赖安装完整，不要直接使用系统 Python 启动

---

## 根目录结构

```
├── install_venv.bat   # 环境安装核心模块
├── 初始化语料.bat      # 语料初始化核心模块
├── start_service.bat  # 服务启动核心模块
├── core/              # 核心服务、基础能力
├── modules/           # 分模块功能（监控/富化/问答）
├── frontend/          # Web前端页面
├── tools/             # 工具脚本
├── data/              # 本地语料缓存（不入库，自动生成）
├── logs/              # 运行日志（不入库，自动生成）
├── .venv/             # 本地虚拟环境（不入库，自动生成）
└── requirements.txt   # 依赖清单
```

---

## 附录：三个部署脚本完整源码

### 1. `install_venv.bat`

```
@echo off
chcp 65001 >nul
cd /d "%~dp0"
setlocal enabledelayedexpansion
set PYTHONUTF8=1

echo ============================================================
echo  AI-SecIntel v2.0 - One Click Environment Installation
echo ============================================================

REM Detect valid Python 3.10-3.12
set "PYTHON_CMD="
where python >nul 2>&1
if %errorlevel% equ 0 (
    for /f "delims=" %%v in ('python -c "import sys; print(1 if (3,10) <= sys.version_info[:2] <= (3,12) else 0)"') do set "PY_VER_VALID=%%v"
    if "!PY_VER_VALID!"=="1" set "PYTHON_CMD=python"
)
if not defined PYTHON_CMD (
    where py >nul 2>&1
    if %errorlevel% equ 0 (
        for /f "delims=" %%v in ('py -3.11 -c "import sys; print(1 if (3,10) <= sys.version_info[:2] <= (3,12) else 0)"') do set "PY_VER_VALID=%%v"
        if "!PY_VER_VALID!"=="1" set "PYTHON_CMD=py -3.11"
    )
)
if not defined PYTHON_CMD (
    echo [ERROR] Python 3.10-3.12 not found.
    echo Please install Python 3.11 and check "Add Python to PATH".
    pause
    exit /b 1
)
echo [INFO] Using Python: !PYTHON_CMD!

REM Create clean virtual environment
if exist ".venv\Scripts\python.exe" (
    echo [INFO] Reuse existing virtual environment.
) else (
    echo [INFO] Creating virtual environment...
    !PYTHON_CMD! -m venv .venv
    if errorlevel 1 (
        echo [ERROR] Failed to create venv.
        pause
        exit /b 1
    )
)

call .\.venv\Scripts\activate.bat

REM Create runtime directories
if not exist "data" mkdir data
if not exist "logs" mkdir logs

REM Create empty secrets template if not exist
if not exist "secrets.env" (
    echo # AI-SecIntel configuration template > secrets.env
    echo AISEC_LLM_API_KEY= >> secrets.env
    echo AISEC_LLM_BASE_URL= >> secrets.env
    echo AISEC_PROXY= >> secrets.env
    echo [INFO] Empty secrets.env template created.
)

REM Install core dependencies, auto fallback mirrors
echo [INFO] Installing core dependencies...
set "MIRROR_LIST=https://mirrors.aliyun.com/pypi/simple/ https://pypi.mirrors.ustc.edu.cn/simple/ https://pypi.org/simple/"
set "INSTALL_SUCCESS=0"
for %%M in (%MIRROR_LIST%) do (
    if "!INSTALL_SUCCESS!"=="0" (
        echo [INFO] Trying mirror: %%M
        pip install requests urllib3 beautifulsoup4 numpy openpyxl markdown -i %%M
        if not errorlevel 1 set "INSTALL_SUCCESS=1"
    )
)
if "!INSTALL_SUCCESS!"=="0" (
    echo [ERROR] Core dependencies install failed, check network.
    pause
    exit /b 1
)

REM Optional full install with local LLM models
if /i "%1"=="--full" (
    echo [INFO] Installing full dependencies with local embedding models...
    set "FULL_SUCCESS=0"
    for %%M in (%MIRROR_LIST%) do (
        if "!FULL_SUCCESS!"=="0" (
            pip install openai torch transformers sentencepiece -i %%M
            if not errorlevel 1 set "FULL_SUCCESS=1"
        )
    )
)

echo ============================================================
echo  Installation completed.
echo  1. Edit secrets.env to fill your API keys if needed
echo  2. Run 初始化语料.bat to download vulnerability corpus
echo  3. Run start_service.bat to launch the service
echo  Optional full model install: install_venv.bat --full
echo ============================================================
pause
exit /b 0
```

### 2. `初始化语料.bat`

```
@echo off
chcp 65001 >nul
cd /d "%~dp0"
setlocal enabledelayedexpansion
set PYTHONUTF8=1

if not exist ".venv\Scripts\python.exe" (
    echo [ERROR] Virtual environment not found, please run install_venv.bat first.
    pause
    exit /b 1
)

call .\.venv\Scripts\activate.bat
echo [INFO] Start downloading public vulnerability corpus...
echo [INFO] This process may take 15-30 minutes, do not close the window.
python -u core/fetch_corpus.py

if not errorlevel 1 (
    echo ============================================================
    echo  Corpus initialization finished.
    echo  Now you can run start_service.bat to launch the service.
    echo ============================================================
) else (
    echo [ERROR] Corpus download failed, check network or use offline data package.
)
pause
```

### 3. `start_service.bat`

```
@echo off
chcp 65001 >nul
cd /d "%~dp0"
setlocal enabledelayedexpansion
set PYTHONUTF8=1
set NO_PROXY=127.0.0.1,localhost
set no_proxy=127.0.0.1,localhost

if not exist ".venv\Scripts\python.exe" (
    echo [ERROR] Virtual environment not found, run install_venv.bat first.
    pause
    exit /b 1
)

call .\.venv\Scripts\activate.bat
echo [INFO] Loading configuration from secrets.env...
if exist "secrets.env" (
    for /f "usebackq tokens=1,* delims==" %%A in (`findstr /v /b "#" secrets.env`) do (
        if not "%%A"=="" if not "%%B"=="" set "%%A=%%B"
    )
) else (
    echo [WARN] secrets.env not found, offline features only.
)

set "PORT=8848"
if not "%1"=="" set "PORT=%1"
echo [INFO] Starting service on port %PORT%
echo [INFO] Web access: http://127.0.0.1:%PORT%
python -u core\server.py %PORT%
pause
```
