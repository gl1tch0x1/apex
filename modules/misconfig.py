from core.http import fetch

MISCONFIG_ENDPOINTS = [
    {'path': '/.git/config', 'check': 'Git Exposure'},
    {'path': '/.env', 'check': 'Env File Exposure'},
    {'path': '/.well-known/security.txt', 'check': 'Security TXT Exposure'},
    {'path': '/backup.sql', 'check': 'Backup File Exposure'},
    {'path': '/phpinfo.php', 'check': 'PHP Info Exposure'},
    {'path': '/.htpasswd', 'check': 'htpasswd Exposure'},
]

def generate_tasks(url, config):
    tasks = []
    base = url.rstrip('/')
    for entry in MISCONFIG_ENDPOINTS:
        tasks.append({
            'url': base + entry['path'],
            'method': 'GET',
            'type': 'Security Misconfiguration',
            'check': entry['check'],
            'executor': test_misconfig,
        })
    return tasks

async def test_misconfig(session, task):
    try:
        text, resp = await fetch(session, task['url'])
        if resp and resp.status == 200 and text:
            markers = ['gitdir:', 'DB_PASSWORD', 'DATABASE_URL', 'phpinfo()', 'AuthType', 'AllowOverride']
            vulnerable = any(marker.lower() in text.lower() for marker in markers)
            return {
                'type': 'Security Misconfiguration',
                'url': task['url'],
                'vulnerable': vulnerable,
                'check': task['check'],
                'response': text[:1000],
            }
    except Exception as exc:
        return {'type': 'Security Misconfiguration', 'url': task['url'], 'error': str(exc), 'vulnerable': False}
    return {'type': 'Security Misconfiguration', 'url': task['url'], 'vulnerable': False}