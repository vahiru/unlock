import angr
import archinfo

class Verifier:
    """
    自动验证模块 (The Verifier)
    使用 angr 符号执行引擎进行可达性验证
    """
    def __init__(self, binary_path: str, base_addr: int = 0x9FA00000):
        self.binary_path = binary_path
        self.base_addr = base_addr
        self.project = None

    def load_project(self):
        """
        初始化 Angr Project
        为 ABL (ARM64) 指定架构与入口地址参数
        """
        print(f"[*] 初始化 angr 引擎加载固件: {self.binary_path}")
        self.project = angr.Project(
            self.binary_path, 
            main_opts={'custom_base_addr': self.base_addr},
            arch=archinfo.ArchAArch64(),
            auto_load_libs=False
        )

    def verify_path(self, start_addr: int, target_addrs: list[int], avoid_addrs: list[int] = None) -> bool:
        """
        验证从 start_addr 是否存在能够到达目标地址列表其中之一的路径
        并尽力避开 avoid_addrs (如报错退出路径)
        """
        if not self.project:
            self.load_project()
            
        print(f"[*] 正在使用 Angr 寻找从 {hex(start_addr)} 到 {list(map(hex, target_addrs))} 的可达路径...")
        
        initial_state = self.project.factory.blank_state(addr=start_addr)
        simulation = self.project.factory.simgr(initial_state)
        
        # 启动探索
        avoid_targets = avoid_addrs if avoid_addrs else []
        simulation.explore(find=target_addrs, avoid=avoid_targets)
        
        if simulation.found:
            found_state = simulation.found[0]
            print(f"[+] 找到可达路径！所需输入条件约束如下:")
            # 输出路径对应的约束，以复现执行
            print(found_state.solver.constraints)
            return True
        else:
            print("[-] 未能找到满足条件的可达路径。")
            return False
