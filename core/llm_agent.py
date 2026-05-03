import os
import aiohttp
import json

class LLMAgent:
    def __init__(self, model="gpt-4o-mini"):
        self.key = os.getenv("OPENAI_API_KEY")
        self.model = model

    async def analyze(self, finding):
        if not self.key:
            return {"note": "LLM disabled (no API key)", "severity": "Unknown", "recommendation": "Set OPENAI_API_KEY to enable detailed analysis."}

        prompt = f"""
Analyze this security finding as a vulnerability report:
{finding}

Produce JSON with the following fields:
- severity
- impact
- exploitability
- recommendation
- owasp_category
- cvss_estimate
"""

        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    "https://api.openai.com/v1/chat/completions",
                    headers={"Authorization": f"Bearer {self.key}"},
                    json={
                        "model": self.model,
                        "messages": [{"role": "user", "content": prompt}],
                        "temperature": 0.2,
                    },
                    timeout=30,
                ) as resp:
                    data = await resp.json()
                    message = data.get("choices", [{}])[0].get("message", {}).get("content", "")
                    try:
                        parsed = json.loads(message)
                        return parsed
                    except json.JSONDecodeError:
                        return {"analysis": message.strip(), "severity": "Unknown"}
        except Exception as e:
            return {"error": str(e), "severity": "Unknown"}