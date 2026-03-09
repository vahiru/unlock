import os
import subprocess
from typing import Optional

class GhidraWrapper:
    """
    逆向抽象层 (The Decompiler Wrapper)
    负责调用 Ghidra Headless 导出伪代码等。
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
        cmd = [
            self.headless_bat,
            self.project_dir,
            self.project_name,
            "-import", binary_path,
            "-loader", "RawBinaryLoader",
            "-loader-imagebase", base_addr,
            "-processor", "AARCH64:LE:v8A:default", # 高通 SD865 为 ARM64
            "-overwrite" 
        ]
        print(f"[*] 执行导入并分析: {' '.join(cmd)}")
        subprocess.run(cmd, check=True)
        print("[+] Ghidra 导入分析完成。")

    def export_pseudocode(self, binary_name: str, target_func_or_addr: str) -> Optional[str]:
        """
        使用自定义 Ghidra Script 将指定函数反编译为 C 伪代码。
        """
        script_name = "ExportDecompile.java" # 假设我们要写的脚本名
        
        cmd = [
            self.headless_bat,
            self.project_dir,
            self.project_name,
            "-process", binary_name,
            "-noanalysis",
            "-scriptPath", self.script_dir,
            "-postScript", script_name, target_func_or_addr
        ]
        print(f"[*] 正在从 {target_func_or_addr} 导出伪代码...")
        result = subprocess.run(cmd, capture_output=True, text=True, errors='ignore')
        out = result.stdout
        
        # 解析标准输出获取真正的反编译代码
        if "---DECOMP_START---" in out and "---DECOMP_END---" in out:
            return out.split("---DECOMP_START---")[1].split("---DECOMP_END---")[0].strip()
            
        print(f"[-] Ghidra 执行可能有误，未找到反编译标记。输出长度: {len(out)}")
        return None

    def locate_linuxloader_handlers(self, binary_name: str, max_count: int = 5) -> list[str]:
        """
        查找 LinuxLoader.dll 相关的最核心初始化与命令分发函数
        这里可以内部调用另一个 headless 脚本来实现扫描，或者使用预定义特征
        """
        # Mock logic
        return ["FastbootMain", "CmdOemUnlock", "CmdFlashingUnlock", "CmdScmCall", "VerifyImageSignature"]
