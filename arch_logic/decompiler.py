import os
import subprocess
import json
from typing import Optional

class IDAWrapper:
    """
    逆向抽象层 (The Decompiler Wrapper)
    使用 IDA Pro 无头模式 (Batch Mode) 进行自动化反编译。
    """
    def __init__(self, ida_path: str, script_dir: str, output_dir: str = "./ida_output"):
        """
        ida_path: IDA Pro 可执行文件路径 (如 idat64.exe 或 ida64.exe)
        script_dir: IDAPython 脚本所在路径
        output_dir: 导出结果存放目录
        """
        self.ida_path = ida_path
        self.script_dir = script_dir
        self.output_dir = output_dir
        os.makedirs(output_dir, exist_ok=True)
        
        # 检测 IDA 可执行文件
        if not os.path.exists(ida_path):
            raise FileNotFoundError(f"IDA Pro not found at: {ida_path}")
    
    def analyze_and_export(self, binary_path: str) -> Optional[dict]:
        """
        使用 IDA 无头模式分析固件并导出所有结果到 JSON。
        返回解析后的 JSON 字典。
        """
        script_path = os.path.join(self.script_dir, "ida_export.py")
        export_json = os.path.join(self.output_dir, "ida_export.json")
        
        # 设置环境变量传递 output 目录路径给 IDAPython 脚本
        env = os.environ.copy()
        env["IDA_OUTPUT_DIR"] = os.path.abspath(self.output_dir)
        
        # IDA 无头模式命令
        # -A: 自主模式 (无 GUI 交互)
        # -S: 运行指定脚本
        # -P+: 激活 ARM 处理器
        cmd = [
            self.ida_path,
            "-A",                           # 自主模式
            f"-S{script_path}",             # 运行 IDAPython 脚本
            "-P+",                          # ARM 处理器包
            "-o" + os.path.join(self.output_dir, "body.idb"),  # 数据库输出路径
            binary_path
        ]
        
        print(f"[*] 启动 IDA Pro 无头分析: {os.path.basename(binary_path)}")
        print(f"    命令: {' '.join(cmd)}")
        
        try:
            result = subprocess.run(
                cmd, 
                env=env, 
                capture_output=True, 
                text=True, 
                errors='ignore',
                timeout=600  # 10 分钟超时
            )
            
            # 打印 IDA 输出中的关键信息
            for line in result.stdout.split('\n'):
                if line.startswith("[IDA]"):
                    print(f"    {line}")
                    
        except subprocess.TimeoutExpired:
            print("[-] IDA 分析超时（10分钟）")
            return None
        except Exception as e:
            print(f"[-] IDA 执行失败: {e}")
            return None
        
        # 读取导出的 JSON 结果
        if os.path.exists(export_json):
            with open(export_json, "r", encoding="utf-8") as f:
                data = json.load(f)
            print(f"[+] IDA 分析完成，成功导出 {len(data.get('decompiled', []))} 个函数")
            return data
        else:
            print("[-] 未找到导出文件，IDA 可能执行异常")
            # 如果有 stderr 输出，打印出来帮助调试
            if result.stderr:
                for line in result.stderr.split('\n')[:10]:
                    print(f"    [stderr] {line}")
            return None

    def get_pseudocode(self, export_data: dict, index: int = 0) -> Optional[str]:
        """
        从已有的导出数据中获取第 N 个函数的伪代码。
        """
        funcs = export_data.get("decompiled", [])
        if index >= len(funcs):
            return None
        
        func = funcs[index]
        header = f"// Function: {func['name']} @ {func['address']}\n"
        header += f"// Code type: {func['code_type']}\n"
        header += f"// Related strings: {', '.join(func.get('string_refs', []))}\n\n"
        return header + func.get("code", "// No code available")
