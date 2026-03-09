# Arch-Logic: ABL Vulnerability Automated Research Agent

Arch-Logic 是一个针对高通 ABL (Android Bootloader) 固件的自动化漏洞挖掘 Agent，它集成了 Ghidra Headless 反汇编能力、大模型 (如 GPT-4o) 伪代码审计能力以及 Angr 符号执行验证能力。

## 部署先决条件 (Prerequisites)

1. **Python 3.10+**
2. **Java JDK 17+** (Ghidra 运行强依赖)
3. **Ghidra**: 建议下载 [Ghidra 11.x+](https://github.com/NationalSecurityAgency/ghidra/releases) 

## 部署步骤 (Deployment Steps)

### 1. 安装 Python 依赖库
在终端中进入项目根目录：
```cmd
cd arch_logic
pip install -r requirements.txt
```

### 2. 配置 Ghidra
1. 将下载的 Ghidra 解压至电脑的任意目录（例如 `C:\ghidra`）。
2. 确保系统环境变量中配置好了 JDK 的 `JAVA_HOME`。
3. 打开 `main.py`，并将 `ghidra_home` 变量修改为你的实际 Ghidra 安装路径：
```python
# main.py
ghidra_home = "C:/ghidra" # 修改为你真实的 Ghidra 路径
```

### 3. 配置 OpenAI API Key
为 AI 审计模块配置环境变量：
- **Windows (CMD):**
  ```cmd
  set OPENAI_API_KEY=sk-xxxx...
  ```
- **Windows (PowerShell):**
  ```powershell
  $env:OPENAI_API_KEY="sk-xxxx..."
  ```
> **注**: 如果你使用其他提供商（如代理转发或本地模型），可以在 `auditor.py` 中修改 `OpenAI(base_url="...", api_key="...")` 的初始化。

### 4. 准备目标固件
将你要分析的固件 `body.bin` (SD865 ABL 镜像) 放置到 `arch_logic/` 同级目录下。

### 5. 运行 Agent
首次运行时，需要取消 `main.py` 中 `decompiler.import_binary` 的注释以完成 Ghidra 初始化。

```cmd
python main.py
```
