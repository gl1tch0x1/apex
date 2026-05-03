import re

class AnomalyDetector:
    SUSPICIOUS_PATTERNS = [
        r"sql syntax", r"syntax error", r"exception", r"stack trace", r"traceback",
        r"warning", r"failed to parse", r"onerror", r"<script", r"javascript:", r"alert\(",
    ]

    def detect(self, responses):
        anomalies = []
        for index, response in enumerate(responses):
            text = response if isinstance(response, str) else str(response)
            score = 0
            if len(text) > 5000:
                score += 1
            if len(text) > 1000 and any(token in text.lower() for token in ['sql', 'error', 'exception']):
                score += 1
            for pattern in self.SUSPICIOUS_PATTERNS:
                if re.search(pattern, text, re.IGNORECASE):
                    score += 1
            anomalies.append({
                'index': index,
                'score': score,
                'suspicious': score >= 2,
            })
        return anomalies