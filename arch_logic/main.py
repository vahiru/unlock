import os
import asyncio
from typing import List

from ingestor import Ingestor
from decompiler import GhidraWrapper
from auditor import Auditor
from verifier import Verifier

def ask_llm(pseudocode: str) -> str:
    """
    独立封装的快捷分析函数：将伪代码发给 AI 并返回漏洞分析报告。
    """
    auditor = Auditor(api_key="mock")  # 替换为真实的 os.getenv("OPENAI_API_KEY")
    return auditor.analyze(pseudocode)

async def main():
    print("="*50)
    print(" Arch-Logic: ABL Vulnerability Automated Research Agent")
    print("="*50)
    
    # --- 环境变量配置 ---
    binary_path = "body.bin"        # 目标 ABL 固件
    binary_name = "body.bin"
    base_addr = 0x9FA00000          # SD865 ABL 默认基址
    ghidra_home = "C:/ghidra"       # 修改为实际的 Ghidra 安装路径
    project_dir = "./ghidra_proj"   # Ghidra 项目路径
    project_name = "abl_analysis"   # Ghidra 项目名
    script_dir = "./ghidra_scripts" # 自定义脚本路径
    
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
