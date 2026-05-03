from core.llm_agent import LLMAgent
from core.exploit_chain import ExploitChainEngine
from core.ml_engine import AnomalyDetector
import asyncio

class Agent:
    def __init__(self):
        self.llm = LLMAgent()
        self.chain = ExploitChainEngine()
        self.anomaly_detector = AnomalyDetector()

    async def process(self, finding, interactsh_client=None):
        self.chain.add(finding)
        analysis = await self.llm.analyze(finding)

        # Anomaly detection on response data
        if 'response' in finding:
            anomaly_score = self.anomaly_detector.detect([finding['response']])
            analysis['anomaly'] = anomaly_score

        # OAST interaction
        if interactsh_client and 'oast' in finding.get('type', '').lower():
            oast_data = await interactsh_client.poll()
            analysis['oast_interactions'] = oast_data

        return {
            "finding": finding,
            "analysis": analysis,
            "severity": self._calculate_severity(analysis),
            "exploitability": self._assess_exploitability(finding)
        }

    def plan(self):
        return self.chain.correlate()

    def _calculate_severity(self, analysis):
        # Simple severity calculation based on LLM output
        if 'high' in analysis.get('severity', '').lower():
            return 'High'
        elif 'medium' in analysis.get('severity', '').lower():
            return 'Medium'
        return 'Low'

    def _assess_exploitability(self, finding):
        # Assess based on finding type
        exploit_map = {
            'SQL Injection': 'High',
            'XSS': 'Medium',
            'IDOR': 'High',
            'JWT': 'Medium'
        }
        return exploit_map.get(finding.get('type'), 'Low')