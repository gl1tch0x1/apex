import json
import os
from datetime import datetime

class ReportGenerator:
    def __init__(self, output_dir='reports'):
        self.output_dir = output_dir
        os.makedirs(self.output_dir, exist_ok=True)

    def build(self, target, findings, exploit_chains, tools, config):
        timestamp = datetime.utcnow().isoformat() + 'Z'
        report = {
            'target': target,
            'timestamp': timestamp,
            'summary': self._summarize(findings),
            'findings': findings,
            'exploit_chains': exploit_chains,
            'tools': tools,
            'configuration': config,
            'recommendations': self._recommendations(findings)
        }
        return report

    def save_json(self, report, filename=None):
        filename = filename or f'report_{datetime.utcnow().strftime("%Y%m%d_%H%M%S")}.json'
        path = os.path.join(self.output_dir, filename)
        with open(path, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2)
        return path

    def _summarize(self, findings):
        counts = {}
        for item in findings:
            severity = item.get('severity', 'Unknown')
            counts[severity] = counts.get(severity, 0) + 1
        return {'counts': counts, 'total_findings': len(findings)}

    def _recommendations(self, findings):
        recommendations = []
        for item in findings:
            analysis = item.get('analysis')
            rec = None
            if isinstance(analysis, dict):
                rec = analysis.get('recommendation')
            if rec:
                recommendations.append({'type': item.get('type'), 'recommendation': rec})
        if not recommendations:
            recommendations.append({'general': 'Review findings and implement OWASP Top 10 remediation guidance for each issue.'})
        return recommendations
