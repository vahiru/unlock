# Arch-Logic: ABL Vulnerability Automated Research Agent

Arch-Logic 是一个针对高通 ABL (Android Bootloader) 固件的自动化漏洞挖掘 Agent，它集成了 Ghidra Headless 反汇编能力、大模型 (如 GPT-4o) 伪代码审计能力以及 Angr 符号执行验证能力。

## 部署先决条件 (Prerequisites)

1. **Linux (Ubuntu/Debian 推荐) 或 macOS/Windows**
2. **Python 3.10+** (建议在 Linux 下使用 `python3-venv` 或 `conda`)
3. **Java JDK 17+** (Ghidra 运行强依赖，如 `sudo apt install openjdk-17-jdk`)
4. **Ghidra**: 建议下载 [Ghidra 11.x+](https://github.com/NationalSecurityAgency/ghidra/releases) 

## 部署步骤 (Deployment Steps)

### 1. 安装 Python 依赖库 (推荐使用 uv)
使用 `uv` 可以极大地加速虚拟环境创建和依赖安装。在终端中进入项目根目录：
```bash
cd arch_logic
# 创建虚拟环境
uv venv
# 激活虚拟环境 (Linux/macOS)
source .venv/bin/activate
# 如果是 Windows 用户，请使用: .venv\Scripts\activate

# 安装依赖
uv pip install -r requirements.txt
```

### 2. 配置环境变量 (.env)
为了方便跨平台部署和配置第三方 API 服务，Agent 引入了 `.env` 支持。
1. 复制配置示例文件：
   ```bash
   cp .env.example .env
   ```
2. 编辑 `.env` 文件，填入你的专属配置：
   ```dotenv
   # 配置第三方代理或兼容节点（如 Claude 转发、DeepSeek 等）
   OPENAI_API_KEY=sk-xxxx...
   OPENAI_BASE_URL=https://api.your-provider.com/v1
   MODEL_NAME=claude-3-5-sonnet-20240620
   
   # 修改为实际的 Ghidra 解压路径 (Linux 下常见如 /opt/ghidra_11.x)
   GHIDRA_HOME=/opt/ghidra
   ```

### 3. 配置 Ghidra (Linux 示例)
在 Debian/Ubuntu 上，Ghidra 12.x 需要 **JDK 17 或 21**。
1. **安装 JDK**:
   ```bash
   sudo apt update
   sudo apt install openjdk-17-jdk
   ```
2. **解压 Ghidra**: 
   假设你的压缩包名为 `ghidra_12.0.4_PUBLIC_20260303.zip`：
   ```bash
   sudo unzip ghidra_12.0.4_PUBLIC_20260303.zip -d /opt/
   # 创建软链接方便引用
   sudo ln -s /opt/ghidra_12.0.4_PUBLIC /opt/ghidra
   ```
3. **验证**: 确保 `/opt/ghidra/support/analyzeHeadless` 文件存在并具有执行权限。

### 4. 准备目标固件
将 `body.bin` 放置在项目目录下（你已经完成了这一步）。然后在 `.env` 中确认路径：
```dotenv
BINARY_PATH=body.bin
GHIDRA_HOME=/opt/ghidra
```

### 5. 运行 Agent
首次运行时，需要取消 `main.py` 中 `decompiler.import_binary(...)` 的注释以完成 Ghidra 初始化。

```bash
python main.py
```
