import os
import asyncio
from typing import List
from dotenv import load_dotenv

from ingestor import Ingestor
from decompiler import GhidraWrapper
from auditor import Auditor
from verifier import Verifier

# 加载 .env 环境变量
load_dotenv()

def ask_llm(pseudocode: str) -> str:
    """
    独立封装的快捷分析函数：将伪代码发给 AI 并返回漏洞分析报告。
    """
    # 优先使用环境变量中的 API Key，如果没配则降级为 mock 用于演示
    api_key = os.getenv("OPENAI_API_KEY", "mock")
    model = os.getenv("MODEL_NAME", "gpt-4o")
    auditor = Auditor(api_key=api_key, model=model)
    return auditor.analyze(pseudocode)

async def main():
    print("="*50)
    print(" Arch-Logic: ABL Vulnerability Automated Research Agent")
    print("="*50)
    
    # --- 环境变量配置 ---
    binary_path = os.getenv("BINARY_PATH", "body.bin")
    binary_name = os.path.basename(binary_path)
    base_addr = int(os.getenv("BASE_ADDR", "0x9FA00000"), 16)
    ghidra_home = os.getenv("GHIDRA_HOME", "/opt/ghidra")
    project_dir = os.getenv("PROJECT_DIR", "./ghidra_proj")
    project_name = os.getenv("PROJECT_NAME", "abl_analysis")
    script_dir = os.getenv("SCRIPT_DIR", "./ghidra_scripts")
    
    # 0. 感知提取 (Ingestion)
    print("\n[Phase 0] 感知二进制提取特征...")
    if os.path.exists(binary_path):
        ingestor = Ingestor(binary_path, base_addr)
        seeds = ingestor.extract_sensitive_strings()
        print(f"[+] 找到 {len(seeds)} 个关键字符串线索。")
    
    # 1. 自动初始化 Ghidra 项目并导入 body.bin
    print("\n[Phase 1] 初始化 Ghidra 逆向辅助...")
    decompiler = GhidraWrapper(ghidra_home, project_dir, project_name, script_dir)
    # decompiler.import_binary(binary_path, hex(base_addr)) # 第一次运行时取消注释导入固件
    
    # 2. 定位到 LinuxLoader.dll 入口，并导出前 5 个最相关的命令处理函数
    print("\n[Phase 2] 定位核心分发逻辑与导出伪代码...")
    handlers = decompiler.locate_linuxloader_handlers(binary_name, max_count=5)
    
    pseudo_codes = {}
    for handler in handlers:
        code = decompiler.export_pseudocode(binary_name, handler)
        pseudo_codes[handler] = code
        print(f"  -> 成功提取 {handler} 的伪代码 (长度: {len(code) if code else 0})")
        
    # 3. 将伪代码发给 AI 并返回漏洞分析报告
    print("\n[Phase 3] AI 漏洞审计...")
    for handler, code in pseudo_codes.items():
        if code:
            print(f"\n[*] 正在审计目标函数: {handler} ...")
            report = ask_llm(code)
            print("-" * 40)
            print(f"[{handler} 审计报告]:\n{report}")
            print("-" * 40)

    # 4. 可选：针对发现的分支调用 angr 验证
    print("\n[Phase 4] 开始使用 Angr 对高危路径进行可达性验证...")
    # 假设 GPT 认为 CmdOemUnlock 的地址 0x9fa01234 触发了 Bypass，目标到达 0x9fa02000
    verifier = Verifier(binary_path, base_addr)
    # verifier.verify_path(start_addr=0x9FA01234, target_addrs=[0x9FA02000], avoid_addrs=[0x9FA01FFF])
    print("[+] 流程执行完毕。")

if __name__ == "__main__":
    asyncio.run(main())
