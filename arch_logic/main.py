import os
import json
import asyncio
from dotenv import load_dotenv

from decompiler import IDAWrapper
from auditor import Auditor

# 加载 .env 环境变量
load_dotenv()

def ask_llm(pseudocode: str, context: dict = None) -> str:
    """独立封装的快捷分析函数"""
    api_key = os.getenv("OPENAI_API_KEY", "mock")
    model = os.getenv("MODEL_NAME", "gpt-4o")
    auditor = Auditor(api_key=api_key, model=model)
    return auditor.analyze(pseudocode, context)

async def main():
    print("=" * 60)
    print("  Arch-Logic v2: ABL Vulnerability Research Agent (IDA Pro)")
    print("=" * 60)
    
    # --- 配置 ---
    binary_path = os.getenv("BINARY_PATH", "body.bin")
    ida_path = os.getenv("IDA_PATH", r"C:\Program Files\IDA Pro\idat64.exe")
    script_dir = os.path.join(os.path.dirname(__file__), "ida_scripts")
    output_dir = os.getenv("IDA_OUTPUT_DIR", "./ida_output")
    
    # 检查 IDA 路径
    if not os.path.exists(ida_path):
        print(f"[!] IDA Pro 未找到: {ida_path}")
        print("    请在 .env 中设置 IDA_PATH 为你的 idat64.exe 完整路径")
        print("    例如: IDA_PATH=C:\\IDA\\idat64.exe")
        return
    
    if not os.path.exists(binary_path):
        print(f"[!] 固件文件未找到: {binary_path}")
        return
    
    # ============================================================
    # Phase 0 + 1: IDA 自动分析 + 函数发现 + 反编译导出
    # ============================================================
    print("\n[Phase 0-1] IDA Pro 自动分析与反编译导出...")
    print(f"  目标文件: {binary_path}")
    print(f"  IDA 路径: {ida_path}")
    
    ida = IDAWrapper(ida_path, script_dir, output_dir)
    export_data = ida.analyze_and_export(binary_path)
    
    if not export_data:
        print("[-] IDA 分析失败，请检查 IDA Pro 配置")
        return
    
    # 打印发现的字符串
    strings = export_data.get("strings", [])
    print(f"\n[+] 感知结果: 找到 {len(strings)} 个关键字符串")
    for s in strings[:10]:
        print(f"    {s['address']}: \"{s['string']}\"")
    if len(strings) > 10:
        print(f"    ... 还有 {len(strings) - 10} 个")
    
    # 打印定位到的函数
    targets = export_data.get("target_functions", [])
    print(f"\n[+] 函数发现: 通过交叉引用定位到 {len(targets)} 个目标函数")
    for t in targets:
        print(f"    {t['address']}: {t['name']}  (引用: {', '.join(t['references'][:3])})")
    
    # ============================================================
    # Phase 2: 获取反编译/反汇编代码
    # ============================================================
    decompiled = export_data.get("decompiled", [])
    print(f"\n[Phase 2] 已获取 {len(decompiled)} 个函数的代码")
    for d in decompiled:
        code_len = len(d.get("code", "")) if d.get("code") else 0
        print(f"    {d['name']} @ {d['address']} [{d['code_type']}] ({code_len} chars)")
    
    # ============================================================
    # Phase 3: AI 漏洞审计
    # ============================================================
    print("\n[Phase 3] AI 漏洞审计...")
    
    api_key = os.getenv("OPENAI_API_KEY", "mock")
    model = os.getenv("MODEL_NAME", "gpt-4o")
    auditor = Auditor(api_key=api_key, model=model)
    
    audit_results = []
    
    for i, func_data in enumerate(decompiled):
        code = func_data.get("code", "")
        if not code:
            continue
            
        name = func_data["name"]
        print(f"\n{'='*50}")
        print(f"[*] 审计函数 [{i+1}/{len(decompiled)}]: {name} @ {func_data['address']}")
        print(f"{'='*50}")
        
        # 构建完整的伪代码 (带上下文)
        pseudocode = ida.get_pseudocode(export_data, i)
        
        # 第一轮：漏洞审计
        context = {
            "name": name,
            "address": func_data["address"],
            "string_refs": func_data.get("string_refs", [])
        }
        report = auditor.analyze(pseudocode, context)
        print(f"\n[审计报告]:\n{report}")
        
        audit_results.append({
            "function": name,
            "address": func_data["address"],
            "report": report,
            "pseudocode": pseudocode
        })

    # ============================================================
    # Phase 4: AI 自验证
    # ============================================================
    print("\n" + "=" * 60)
    print("[Phase 4] AI 漏洞可行性自验证...")
    print("=" * 60)
    
    for result in audit_results:
        name = result["function"]
        print(f"\n[*] 验证 {name} 的漏洞报告...")
        
        verification = auditor.verify_feasibility(
            audit_report=result["report"],
            pseudocode=result["pseudocode"]
        )
        print(f"\n[验证结果]:\n{verification}")
        result["verification"] = verification

    # ============================================================
    # 保存完整报告
    # ============================================================
    report_path = os.path.join(output_dir, "full_report.json")
    with open(report_path, "w", encoding="utf-8") as f:
        json.dump(audit_results, f, indent=2, ensure_ascii=False)
    print(f"\n[+] 完整报告已保存到: {report_path}")
    print("[+] 流程执行完毕。")

if __name__ == "__main__":
    asyncio.run(main())
