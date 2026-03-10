import os
from openai import OpenAI

class Auditor:
    """
    推理与审计模块 (The Auditor)
    将伪代码与漏洞模式通过 CoT 结合，发送给大模型进行审计。
    支持 AI 自验证：对每个漏洞点进行二次可行性评估。
    """
    def __init__(self, api_key: str = None, model: str = "gpt-4o"):
        self.api_key = api_key or os.environ.get("OPENAI_API_KEY")
        self.base_url = os.environ.get("OPENAI_BASE_URL")
        self.model = model
        
        client_kwargs = {"api_key": self.api_key}
        if self.base_url:
            client_kwargs["base_url"] = self.base_url
        self.client = OpenAI(**client_kwargs)

    def _call_llm(self, system_prompt: str, user_prompt: str) -> str:
        """统一的 LLM 调用接口"""
        if not self.api_key or self.api_key == "mock":
            return "[Mock Mode] 请配置 .env 中的 OPENAI_API_KEY 以启用真实 AI 审计。"

        try:
            response = self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt}
                ],
                temperature=0.2,
                max_tokens=4096
            )
            return response.choices[0].message.content
        except Exception as e:
            return f"[-] LLM Error: {str(e)}"

    def analyze(self, pseudocode: str, context: dict = None) -> str:
        """
        第一轮审计：分析伪代码中的潜在漏洞。
        context 可以包含 string_refs 等辅助信息。
        """
        ctx_info = ""
        if context:
            if "string_refs" in context:
                ctx_info += f"\n该函数引用了以下关键字符串: {', '.join(context['string_refs'])}"
            if "name" in context:
                ctx_info += f"\n函数名: {context['name']}"
            if "address" in context:
                ctx_info += f"\n地址: {context['address']}"

        system_prompt = "你是一个专门审计 UEFI/ABL 固件漏洞的高级安全工程师。请用中文回答。"
        
        user_prompt = f"""请仔细分析以下 ABL (Android Bootloader) 代码，检查以下常见漏洞模式：
1. 缓冲区溢出（如 AsciiStrCpy、MemCpy 无边界检查）
2. UnlockToken / 签名验证逻辑绕过（长度截断、时间竞争等）
3. 状态认证位的覆盖与非预期控制流跳转
4. 整数溢出导致的内存安全问题
{ctx_info}

请按以下格式输出：
## 函数逻辑概述
(简述该函数做什么)

## 数据流分析
(输入来源、受控程度、验证条件)

## 发现的漏洞点
对每个漏洞点：
- **漏洞类型**: 
- **严重程度**: 高/中/低
- **位置**: 具体的代码行或地址
- **触发条件**: 

## 利用路径
(如何实际触发该漏洞)

---
待分析代码：
```
{pseudocode}
```"""

        return self._call_llm(system_prompt, user_prompt)

    def verify_feasibility(self, audit_report: str, pseudocode: str, 
                           additional_context: str = "") -> str:
        """
        第二轮验证：AI 自行验证漏洞的可行性。
        基于初始审计报告 + 原始代码 + 额外上下文，输出可行性评估。
        """
        system_prompt = """你是一个严谨的漏洞验证专家。你的任务是对初始审计报告中的每个漏洞点进行二次验证。
你必须：
1. 逐条审查每个漏洞，判断它是否为 **真阳性（实际可利用）** 还是 **误报（理论漏洞但实际不可触发）**
2. 给出明确的可行性评分 (0-10)
3. 如果可行，给出具体的 PoC 思路
请用中文回答。不要重复初始报告的内容，只做验证和判断。"""

        user_prompt = f"""## 初始审计报告
{audit_report}

## 原始代码
```
{pseudocode}
```

{f"## 额外上下文（调用链/交叉引用）{chr(10)}{additional_context}" if additional_context else ""}

请对报告中的每个漏洞点进行二次验证，输出格式：

### 漏洞 #N: [漏洞名称]
- **初始判定**: [来自报告的原始判定]
- **验证结论**: 真阳性 / 误报 / 需进一步确认
- **可行性评分**: X/10
- **理由**: [为什么你认为它可行/不可行]
- **PoC 思路**: [如果可行，如何构造输入触发]

### 总结
- 真阳性数量: X
- 最有价值的攻击路径: [描述]
"""

        return self._call_llm(system_prompt, user_prompt)
