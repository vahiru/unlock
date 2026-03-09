import os
from openai import OpenAI

class Auditor:
    """
    推理与审计模块 (The Auditor)
    将伪代码与漏洞模式通过 CoT 结合，发送给大模型进行审计。
    """
    def __init__(self, api_key: str = None, model: str = "gpt-4o"):
        self.api_key = api_key or os.environ.get("OPENAI_API_KEY")
        self.model = model
        self.client = OpenAI(api_key=self.api_key)

    def build_cot_prompt(self, pseudocode: str) -> str:
        """
        构建针对 ABL 的思维链 Prompt
        """
        return f"""
        你是一个专门审计 UEFI/ABL 固件漏洞的高级安全工程师。
        请仔细分析以下 ABL 伪代码，并根据以下常见漏洞模式进行检查：
        1. 缓冲区溢出（如 AsciiStrCpy、MemCpy 无边界检查导致的溢出）。
        2. UnlockToken 或特定结构体验证逻辑绕过（如长度截断、时间竞争等）。
        3. 状态认证位的覆盖与非预期控制流跳转。

        请用以下思维链 (CoT) 格式进行作答：
        【伪代码逻辑梳理】: (简述该函数做什么)
        【数据流与约束分析】: (输入受控制程度，验证条件是什么)
        【潜在漏洞点】: (漏洞类型和触发原因)
        【触发条件/路径】: (使得该漏洞被触发，所需的预期输入和内存状态)

        待分析伪代码如下：
        {pseudocode}
        """

    def analyze(self, pseudocode: str) -> str:
        """
        向大模型发送请求并获取审计报告。
        """
        prompt = self.build_cot_prompt(pseudocode)
        
        # 演示环境如未配置 KEY，返回 Mock
        if not self.api_key or self.api_key == "mock":
            return "[+] Mock Report: Found potential UnlockToken bypass in `if (token_len > 0) ...`"

        try:
            response = self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": "You are a specialized security researcher."},
                    {"role": "user", "content": prompt}
                ],
                temperature=0.2
            )
            return response.choices[0].message.content
        except Exception as e:
            return f"[-] LLM Error: {str(e)}"
