import re
from core.http import fetch

SENSITIVE_PATTERNS = [
    r'\b\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}\b',
    r'\b\d{3}[-.]?\d{3}[-.]?\d{4}\b',
    r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b',
    r'\b\d{10}\b',
    r'password\s*[:=]\s*\S+',
    r'api[_-]?key\s*[:=]\s*\S+',
    r'private[_-]?key',
    r'secret[_-]?key',
    r'authorization\s*[:=]\s*\S+',
]

ENDPOINTS = ['/', '/api/users', '/admin', '/config', '/.env', '/.git/config']

def generate_tasks(url, config):
    tasks = []
    base = url.rstrip('/')
    for ep in ENDPOINTS:
        tasks.append({
            'url': base + ep,
            'method': 'GET',
            'type': 'Sensitive Data Exposure',
            'executor': test_sensitive_data,
        })
    return tasks

async def test_sensitive_data(session, task):
    try:
        text, resp = await fetch(session, task['url'])
        if resp and resp.status == 200 and text:
            found_patterns = []
            for pattern in SENSITIVE_PATTERNS:
                matches = re.findall(pattern, text, re.IGNORECASE)
                if matches:
                    found_patterns.extend(matches[:5])
            vulnerable = len(found_patterns) > 0
            return {
                'type': 'Sensitive Data Exposure',
                'url': task['url'],
                'vulnerable': vulnerable,
                'data_found': found_patterns,
                'response': text[:1000],
            }
    except Exception as exc:
        return {'type': 'Sensitive Data Exposure', 'url': task['url'], 'error': str(exc), 'vulnerable': False}
    return {'type': 'Sensitive Data Exposure', 'url': task['url'], 'vulnerable': False}