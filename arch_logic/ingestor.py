import re
from typing import List, Dict

class Ingestor:
    """
    感知模块 (The Ingestor)
    负责解析固件、提取敏感特征和基地址信息。
    """
    def __init__(self, binary_path: str, base_addr: int = 0x9FA00000):
        self.binary_path = binary_path
        self.base_addr = base_addr

    def extract_sensitive_strings(self) -> List[Dict[str, any]]:
        """
        提取包含目标关键字的字符串及其内存地址信息
        """
        target_keywords = [b"Unlock", b"Verify", b"Scm"]
        results = []
        
        # 简单模拟 strings 工具的逻辑提取二进制中的 ASCII 字符串
        with open(self.binary_path, 'rb') as f:
            content = f.read()
            
        # 匹配长度至少为 4 的 ASCII 连续可打印字符
        pattern = re.compile(b'[ -~]{4,}')
        for match in pattern.finditer(content):
            matched_bytes = match.group()
            if any(keyword.lower() in matched_bytes.lower() for keyword in target_keywords):
                offset = match.start()
                vaddr = self.base_addr + offset
                results.append({
                    "offset": offset,
                    "address": hex(vaddr),
                    "string": matched_bytes.decode('ascii', errors='ignore')
                })
                
        return results
