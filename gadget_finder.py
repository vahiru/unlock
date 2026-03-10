#!/usr/bin/env python3
"""
gadget_finder.py — ARM64 Alphanumeric Gadget Scanner

目标：在高通 ABL 固件中寻找其机器码完全落在 16 进制 ASCII 表示字符集内的
      短跳转/分支跳板指令。
      
限制字符集： '0'-'9' (0x30-0x39), 'A'-'F' (0x41-0x46), 'a'-'f' (0x61-0x66)
由于 ARM64 指令是 4 字节（32-bit）小端序，我们需要在这 4 个字节的每一个字节的
二进制表示中，确认哪些指令（如 B, BR, BLR 等）符合条件。
"""

import sys
import os

# 允许的字节值集（ASCII Hex 字符）
HEX_CHARS_SET = set(
    list(range(0x30, 0x3A)) +  # '0'-'9'
    list(range(0x41, 0x47)) +  # 'A'-'F'
    list(range(0x61, 0x67))    # 'a'-'f'
)

def is_alphanumeric_hex(data: bytes):
    for b in data:
        if b not in HEX_CHARS_SET:
            return False
    return True

def scan_file(filepath, base_addr=0x9FA00000):
    try:
        with open(filepath, 'rb') as f:
            data = f.read()
    except FileNotFoundError:
        print(f"[-] 找不到文件 {filepath}")
        return

    print(f"[*] 扫描文件: {filepath} ({len(data)} 字节)")
    print(f"[*] 约束条件: 机器码必须完全由 0-9, A-F, a-f 的 ASCII 字节组成")
    
    matches = []
    # ARM64 指令 4 字节对齐
    for i in range(0, len(data) - 3, 4):
        insn_bytes = data[i:i+4]
        if is_alphanumeric_hex(insn_bytes):
            matches.append((base_addr + i, insn_bytes))
            
    print(f"[+] 找到 {len(matches)} 个符合约束条件的 4 字节块。")
    if matches:
        print("\n[>] 正在保存反汇编请求记录到 matches.txt，需要使用 IDA 或 capstone 检查这些块是否是有效的跳板指令...")
        with open("matches.txt", "w") as f:
            for addr, b in matches:
                hex_str = " ".join([f"{x:02x}" for x in b])
                f.write(f"Address: 0x{addr:X} | Bytes: {hex_str} | Ascii: {b.decode('ascii', errors='replace')}\n")
        print("[+] 记录已保存到 matches.txt。")
        
        # 如果安装了 capstone，尝试解析
        try:
            from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM
            md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
            print("\n[>] 使用 Capstone 解码验证分支指令...")
            valid_branches = 0
            for addr, b in matches:
                for insn in md.disasm(b, addr):
                    # 我们寻找 Branch 指令 (b, br, bl, blr, cbz 等)
                    if insn.mnemonic.startswith('b') or insn.mnemonic.startswith('c'):
                        print(f"  [!] 绝佳 Gadget! 0x{addr:X}: {insn.mnemonic}\t{insn.op_str} (Bytes: {b.hex()})")
                        valid_branches += 1
            print(f"[+] 解码完成，共发现 {valid_branches} 个纯 Hex-ASCII 分支转移跳板！")
        except ImportError:
            print("[-] 未安装 capstone，跳过自动反汇编关联匹配。 (pip install capstone)")
            
if __name__ == "__main__":
    target = "body.bin"
    if len(sys.argv) > 1:
        target = sys.argv[1]
    scan_file(target)
