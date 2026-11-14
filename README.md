# AI-SecIntel Platform
本地运行的国内漏洞自动同步与智能问答安全工具

## 免责声明
**本工具仅用于企业安全运维、授权渗透测试、网络安全研究与学习，禁止用于任何未授权访问、攻击破坏、非法数据获取等违法活动。使用本工具产生的所有风险、法律责任，均由使用者自行承担，项目开发者与贡献者不承担任何法律责任。请严格遵守《网络安全法》《数据安全法》《个人信息保护法》。**

本工具所有数据默认仅存储于用户本地，不主动上传任何用户隐私数据，无默认远程遥测、数据上报功能。

## 核心功能
1. 多源公开漏洞情报自动同步，覆盖国内厂商专属漏洞
2. 本地漏洞知识库构建，支持资产富化与POC本地验证
3. 本地LLM智能体问答，检索增强生成漏洞分析与修复建议

## 团队分工
| GitHub账号 | 负责模块 | 核心职责 |
|---|---|---|
| waterkingmemory| 基础架构、爬虫模块 | 项目框架、多源漏洞爬虫、定时同步、本地存储、部署脚本、前端基础页面 |
| 666duyi | POC框架、资产富化模块 | 漏洞验证POC、资产指纹匹配、漏洞富化、误报校验、本地验证逻辑 |
| Showthesky | 智能体编排、问答模块 | 本地知识库、LLM Agent编排、检索增强、智能问答、交互逻辑 |

# AI-SecIntel v2.0 操作流程手册

## 前置说明

### 合规免责

本工具仅用于授权安全测试、企业安全运维、安全研究学习，禁止用于未授权访问、攻击破坏等违法活动，使用风险由使用者自行承担。所有数据默认存储在本地，不强制上传用户隐私数据。

### 环境要求

1. 系统：Windows 10/11（优先适配）、Linux/macOS
2. Python 版本：**3.10 ~ 3.12（推荐 3.11，依赖兼容性最好）**，禁止使用 3.7 以下、3.13 以上版本
3. 硬件：内存≥8GB，磁盘剩余空间≥2GB
4. 路径要求：项目必须放在**全英文路径**，禁止中文、空格、特殊字符，避免依赖解析报错。

---

## 一、Windows 一键部署（新手优先，全程不用敲命令）

### 1.1 获取项目

- 方式 1：Git 克隆仓库：`git clone git@github.com:xupt-secintel-team/ai-secintel-platform.git`
- 方式 2：解压发布的压缩包，进入项目根目录。

### 1.2 初始化虚拟环境（新加标准脚本）

1. 将下面提供的`install_venv.bat`保存到项目根目录
2. 双击运行，脚本自动完成：
   - 检测合规 Python 版本
   - 创建独立`.venv`虚拟环境，不污染系统 Python
   - 自动使用清华镜像源安装全部依赖，解决国内网络超时
   - 自动创建`data`、`logs`运行目录
3. 看到「Installation completed successfully」即安装成功。

### 1.3 配置密钥

1. 双击`设置密钥.bat`，或手动打开`secrets.env`
2. 按注释填写自己的 API Key、代理等配置，保存关闭；无外部 API 需求可以留空，仅使用离线功能。
3. 禁止将填好真实密钥的`secrets.env`提交到公开仓库。

### 1.4 下载本地模型（可选）

需要本地语义检索、智能问答功能，依次双击：

- `下载嵌入模型.bat`
- `下载翻译模型.bat`
脚本自动下载模型到本地，无需手动配置。

### 1.5 启动服务

1. 将下面提供的`start_service.bat`保存到项目根目录
2. 双击启动，默认端口为 8848；如果端口被占用，在终端执行`start_service.bat 8899`即可更换端口。
3. 浏览器访问 `http://127.0.0.1:8848` 即可打开 Web 控制台。

---

## 二、手动命令行部署（进阶用户）

### 2.1 Windows PowerShell

```
# 1. 进入项目目录
Set-Location -LiteralPath "你的全英文项目路径"
# 2. 创建虚拟环境
python -m venv .venv
# 3. 激活虚拟环境
.\.venv\Scripts\Activate.ps1
# 如果提示执行权限错误，先执行：
Set-ExecutionPolicy RemoteSigned -Scope CurrentUser
# 4. 升级pip，安装依赖（清华源）
python -m pip install --upgrade pip -i https://pypi.tuna.tsinghua.edu.cn/simple
pip install -r requirements.txt -i https://pypi.tuna.tsinghua.edu.cn/simple
# 5. 创建运行目录
New-Item -ItemType Directory -Force data,logs
# 6. 启动服务
python -u core/server.py 8848
```

### 2.2 Linux/macOS

项目自带`安装.sh`、`start.sh`，直接执行：

```
chmod +x 安装.sh start.sh
./安装.sh
./start.sh
```

---

## 三、Docker 部署（可选，适配服务器）

项目已自带 Dockerfile 和 docker-compose.yml，执行：

```
# 构建并启动
docker compose up -d
# 查看日志
docker compose logs -f
```

启动后访问服务器 IP+8848 端口即可。

---

## 四、核心功能操作流程

1. **漏洞情报同步**：控制台点「立即同步」，自动拉取 CNVD、CNNVD、厂商公开漏洞，数据保存在本地 data 目录。
2. **资产富化与 POC 验证**：录入资产信息，自动匹配指纹、关联漏洞，仅在授权前提下执行本地 POC 验证，禁止对公网无授权目标发起请求。
3. **智能问答**：在问答页面输入漏洞编号、产品名称，本地知识库自动检索，生成漏洞分析、修复建议。
4. **报告导出**：选择时间范围、漏洞等级，一键导出日报 / 周报，支持 Excel、PDF 格式。

### 启动参数说明

- `--low`：低性能模式，适配低配电脑，关闭高频调度
- `--mid`：默认平衡模式
- `--high`：高性能模式，全开模块，适合 16GB 以上内存设备
- `--no-live`：关闭实时同步，仅使用本地缓存数据

---

## 五、常见问题排查

1. 提示`python not found`：重装 Python，安装时必须勾选「Add Python to PATH」，推荐 3.11 版本。
2. 依赖安装超时 / 失败：脚本已内置清华源，若仍失败检查网络，不要手动中断安装。
3. 端口被占用：启动时传入其他端口，例如`start_service.bat 8899`。
4. 模型加载失败：先执行模型下载脚本，确认网络正常，模型文件完整。
5. 中文乱码：脚本已自动开启 UTF8 编码，不要手动修改系统编码。
6. 导入模块报错：确认虚拟环境已激活，依赖全部安装完成，不要使用系统 Python 直接启动。

---

## 六、标准新增脚本（直接复制保存）

### 脚本 1：`install_venv.bat`（放项目根目录）

```
@echo off
chcp 65001 >nul
cd /d "%~dp0"
setlocal enabledelayedexpansion

echo ============================================================
echo  AI-SecIntel v2.0 - Virtual Environment Installation
echo ============================================================

REM Detect valid Python
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
    echo [ERROR] Valid Python 3.10-3.12 not found.
    echo Please install Python 3.11 and check "Add Python to PATH".
    pause
    exit /b 1
)
echo [INFO] Using Python: !PYTHON_CMD!

REM Create virtual environment
if exist ".venv\Scripts\python.exe" (
    echo [INFO] Virtual environment already exists, skip creation.
) else (
    echo [INFO] Creating virtual environment...
    !PYTHON_CMD! -m venv .venv
    if errorlevel 1 (
        echo [ERROR] Failed to create virtual environment.
        pause
        exit /b 1
    )
)

REM Install dependencies
call .\.venv\Scripts\activate.bat
echo [INFO] Upgrading pip...
python -m pip install --upgrade pip -i https://pypi.tuna.tsinghua.edu.cn/simple
echo [INFO] Installing dependencies...
pip install -r requirements.txt -i https://pypi.tuna.tsinghua.edu.cn/simple
if errorlevel 1 (
    echo [ERROR] Dependencies installation failed, check network.
    pause
    exit /b 1
)

REM Create runtime directories
if not exist "data" mkdir data
if not exist "logs" mkdir logs

echo ============================================================
echo  Installation completed. Edit secrets.env then run start_service.bat
echo ============================================================
pause
exit /b 0
```

### 脚本 2：`start_service.bat`（放项目根目录）

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
echo [INFO] Loading secrets.env...
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
python -u core\server.py %PORT% %*
pause
```

原有自带的`安装.bat`、`启动服务.bat`可以保留不用删除，新脚本作为新手推荐入口，避免旧脚本乱码、逻辑复杂的问题，写完后把两个脚本提交推送到仓库即可。
