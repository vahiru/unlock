# Arch-Logic v2: ABL Vulnerability Automated Research Agent

基于 **IDA Pro + IDAPython** 的高通 ABL 固件自动化漏洞挖掘 Agent。

## 工作流程

```
body.bin → IDA Pro 无头分析 → 字符串提取 → 交叉引用定位函数 → Hex-Rays 反编译 → AI 审计 → AI 自验证
```

## 部署 (Windows)

### 1. 安装依赖
```bash
cd arch_logic
pip install -r requirements.txt
```

### 2. 配置 .env
```bash
cp .env.example .env
```
编辑 `.env`：
```dotenv
OPENAI_API_KEY=sk-xxxx...
OPENAI_BASE_URL=https://api.your-provider.com/v1
MODEL_NAME=claude-3-5-sonnet-20240620

# IDA Pro 的 idat64.exe 路径
IDA_PATH=C:\IDA\idat64.exe

BINARY_PATH=body.bin
```

### 3. 运行
```bash
python main.py
```

## 模块说明

| 模块 | 功能 |
|:---|:---|
| `ida_scripts/ida_export.py` | IDAPython 脚本，自动分析 + 导出伪代码 |
| `decompiler.py` | IDA 无头模式封装 |
| `auditor.py` | AI 漏洞审计 + 可行性自验证 |
| `main.py` | 5 阶段主流程 |
