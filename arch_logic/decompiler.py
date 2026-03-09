import os
import subprocess
from typing import Optional

class GhidraWrapper:
    """
    逆向抽象层 (The Decompiler Wrapper)
    负责调用 Ghidra Headless 导出伪代码等。
    当 Native Decompiler 不可用时（如 ARM64 Linux），自动降级为反汇编。
    """
    def __init__(self, ghidra_home: str, project_dir: str, project_name: str, script_dir: str):
        self.ghidra_home = ghidra_home
        self.project_dir = project_dir
        self.project_name = project_name
        self.script_dir = script_dir
        if os.name == 'nt':
            self.headless_bat = os.path.join(ghidra_home, "support", "analyzeHeadless.bat")
        else:
            self.headless_bat = os.path.join(ghidra_home, "support", "analyzeHeadless")

    def import_binary(self, binary_path: str, base_addr: str = "0x9FA00000"):
        """
        初始化项目并导入 body.bin，指定特定的架构和基址
        """
        # Ghidra Headless 要求项目目录必须事先存在
        os.makedirs(self.project_dir, exist_ok=True)
        cmd = [
            self.headless_bat,
            self.project_dir,
            self.project_name,
            "-import", binary_path,
            "-loader", "BinaryLoader",
            "-loader-imagebase", base_addr,
            "-processor", "AARCH64:LE:64:v8A", # 高通 SD865 为 ARM64 (Ghidra 12)
            "-overwrite" 
        ]
        print(f"[*] 执行导入并分析: {' '.join(cmd)}")
        subprocess.run(cmd, check=True)
        print("[+] Ghidra 导入分析完成。")

    def _run_script(self, binary_name: str, script_name: str, *script_args: str) -> str:
        """
        通用方法：在已导入的项目上执行 Ghidra Script 并返回标准输出。
        """
        cmd = [
            self.headless_bat,
            self.project_dir,
            self.project_name,
            "-process", binary_name,
            "-noanalysis",
            "-scriptPath", self.script_dir,
            "-postScript", script_name, *script_args
        ]
        result = subprocess.run(cmd, capture_output=True, text=True, errors='ignore')
        return result.stdout

    def export_pseudocode(self, binary_name: str, target_func_or_addr: str) -> Optional[str]:
        """
        使用自定义 Ghidra Script 将指定函数反编译为 C 伪代码。
        在 ARM64 Linux 等环境下 native decompiler 不可用时，将自动降级为反汇编列表。
        """
        print(f"[*] 正在从 {target_func_or_addr} 导出伪代码...")
        out = self._run_script(binary_name, "ExportDecompile.java", target_func_or_addr)
        
        # 解析标准输出获取反编译/反汇编代码
        if "---DECOMP_START---" in out and "---DECOMP_END---" in out:
            return out.split("---DECOMP_START---")[1].split("---DECOMP_END---")[0].strip()
            
        print(f"[-] Ghidra 执行可能有误，未找到反编译标记。输出长度: {len(out)}")
        # 输出 Ghidra 的错误信息用于 debug
        for line in out.split('\n'):
            if 'ERROR' in line or 'error' in line.lower() or 'not found' in line.lower():
                print(f"    {line.strip()}")
        return None

    def locate_linuxloader_handlers(self, binary_name: str, max_count: int = 5) -> list[str]:
        """
        通过 Ghidra 的 ListFunctions 脚本自动发现固件中与 fastboot/unlock 相关的函数。
        使用关键字过滤，返回地址列表。
        """
        print("[*] 正在通过 Ghidra 扫描固件中的函数列表...")
        keywords = "fastboot,unlock,flash,verify,scm,oem,cmd,boot,token"
        out = self._run_script(binary_name, "ListFunctions.java", keywords)

        handlers = []
        if "---FUNC_LIST_START---" in out and "---FUNC_LIST_END---" in out:
            block = out.split("---FUNC_LIST_START---")[1].split("---FUNC_LIST_END---")[0].strip()
            for line in block.split('\n'):
                line = line.strip()
                if not line:
                    continue
                parts = line.split(None, 1)
                if len(parts) == 2:
                    addr, name = parts
                    handlers.append(addr)  # 使用地址来做后续反编译
                    print(f"    [+] 发现函数: {name} @ 0x{addr}")
                    if len(handlers) >= max_count:
                        break

        if not handlers:
            print("[!] 未通过过滤找到函数，回退使用 Ingestor 种子地址...")
            # 回退策略：从感知模块的种子中提取参考地址
            # 这些地址附近很可能有相关的处理逻辑
            
        print(f"[+] 共定位到 {len(handlers)} 个目标函数地址。")
        return handlers
