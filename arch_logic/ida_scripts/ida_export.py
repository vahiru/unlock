# IDA Pro IDAPython Script: ida_export.py
# 该脚本由 Arch-Logic Agent 通过 IDA 无头模式自动调用
# 功能: 自动分析 ABL 固件、提取函数列表、导出反编译伪代码

import ida_auto
import ida_funcs
import ida_hexrays
import ida_name
import ida_bytes
import idautils
import idaapi
import idc
import json
import os
import sys

OUTPUT_DIR = os.environ.get("IDA_OUTPUT_DIR", ".")

def wait_for_analysis():
    """等待 IDA 自动分析完成"""
    ida_auto.auto_wait()

def export_strings(keywords=None):
    """导出包含关键字的字符串列表"""
    if keywords is None:
        keywords = ["unlock", "verify", "scm", "fastboot", "flash", "token", "oem"]
    
    results = []
    sc = idautils.Strings()
    for s in sc:
        val = str(s).lower()
        if any(kw.lower() in val for kw in keywords):
            results.append({
                "address": hex(s.ea),
                "string": str(s),
                "length": s.length
            })
    return results

def export_functions(keywords=None):
    """导出带关键字过滤的函数列表"""
    if keywords is None:
        keywords = []
    
    results = []
    for ea in idautils.Functions():
        name = ida_funcs.get_func_name(ea)
        if not name:
            continue
        if keywords:
            if not any(kw.lower() in name.lower() for kw in keywords):
                continue
        results.append({
            "address": hex(ea),
            "name": name,
            "size": ida_funcs.get_func(ea).size()
        })
    return results

def get_xrefs_to_string(string_ea):
    """获取所有引用某字符串地址的函数"""
    refs = []
    for xref in idautils.XrefsTo(string_ea):
        func = ida_funcs.get_func(xref.frm)
        if func:
            refs.append({
                "caller_addr": hex(func.start_ea),
                "caller_name": ida_funcs.get_func_name(func.start_ea),
                "xref_addr": hex(xref.frm)
            })
    return refs

def decompile_function(ea):
    """反编译指定地址的函数，返回 C 伪代码"""
    try:
        cfunc = ida_hexrays.decompile(ea)
        if cfunc:
            return str(cfunc)
    except ida_hexrays.DecompilationFailure as e:
        return f"// Decompilation failed: {e}"
    except Exception as e:
        return f"// Error: {e}"
    return None

def disassemble_function(ea, max_insns=200):
    """反汇编指定地址的函数"""
    func = ida_funcs.get_func(ea)
    if not func:
        return f"// No function at {hex(ea)}"
    
    lines = []
    lines.append(f"// Function: {ida_funcs.get_func_name(ea)} @ {hex(ea)}")
    lines.append(f"// Size: {func.size()} bytes")
    
    current = func.start_ea
    count = 0
    while current < func.end_ea and count < max_insns:
        disasm = idc.generate_disasm_line(current, 0)
        lines.append(f"  {hex(current)}:  {disasm}")
        current = idc.next_head(current, func.end_ea)
        count += 1
    return "\n".join(lines)


def main():
    """主导出逻辑 - 由 Agent 自动调用"""
    wait_for_analysis()
    
    output = {}
    
    # 1. 导出敏感字符串
    print("[IDA] Exporting sensitive strings...")
    strings = export_strings()
    output["strings"] = strings
    print(f"[IDA] Found {len(strings)} sensitive strings")
    
    # 2. 通过字符串交叉引用定位关键函数
    print("[IDA] Finding functions via string xrefs...")
    target_funcs = {}  # addr -> {name, reason}
    
    for s in strings:
        s_ea = int(s["address"], 16)
        xrefs = get_xrefs_to_string(s_ea)
        for xref in xrefs:
            addr = xref["caller_addr"]
            if addr not in target_funcs:
                target_funcs[addr] = {
                    "name": xref["caller_name"],
                    "references": [],
                    "address": addr
                }
            target_funcs[addr]["references"].append(s["string"])
    
    # 按引用数量排序，取 top 函数
    sorted_funcs = sorted(target_funcs.values(), key=lambda x: len(x["references"]), reverse=True)
    top_funcs = sorted_funcs[:10]
    output["target_functions"] = top_funcs
    print(f"[IDA] Found {len(top_funcs)} target functions via xrefs")
    
    # 3. 对每个目标函数导出反编译/反汇编
    print("[IDA] Decompiling target functions...")
    decomp_results = []
    
    for func_info in top_funcs:
        ea = int(func_info["address"], 16)
        name = func_info["name"]
        refs = func_info["references"][:5]  # 最多显示5个引用字符串
        
        print(f"  -> Decompiling {name} @ {func_info['address']}...")
        
        # 先尝试反编译，失败则反汇编
        code = decompile_function(ea)
        code_type = "decompiled"
        if not code or code.startswith("//"):
            code = disassemble_function(ea)
            code_type = "disassembly"
        
        decomp_results.append({
            "address": func_info["address"],
            "name": name,
            "code_type": code_type,
            "code": code,
            "string_refs": refs
        })
    
    output["decompiled"] = decomp_results
    
    # 4. 写入结果到 JSON 文件
    output_path = os.path.join(OUTPUT_DIR, "ida_export.json")
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(output, f, indent=2, ensure_ascii=False)
    print(f"[IDA] Results saved to: {output_path}")

    # 退出 IDA
    idc.qexit(0)

if __name__ == "__main__":
    main()
