from core.http import fetch

PROTECTED_PATHS = [
    '/admin',
    '/user/1',
    '/user/2',
    '/dashboard',
    '/settings',
    '/api/admin',
]

def generate_tasks(url, config):
    tasks = []
    base = url.rstrip('/')
    for path in PROTECTED_PATHS:
        tasks.append({
            'url': base + path,
            'method': 'GET',
            'type': 'Broken Access Control',
            'executor': test_broken_access,
        })
    return tasks

async def test_broken_access(session, task):
    try:
        text, resp = await fetch(session, task['url'])
        if resp:
            restricted_indicators = ['admin', 'manager', 'dashboard', 'settings', 'user profile']
            visible = any(term in text.lower() for term in restricted_indicators)
            vulnerable = resp.status == 200 and visible
            return {
                'type': 'Broken Access Control',
                'url': task['url'],
                'vulnerable': vulnerable,
                'status': resp.status,
                'response': text[:1000],
            }
    except Exception as exc:
        return {'type': 'Broken Access Control', 'url': task['url'], 'error': str(exc), 'vulnerable': False}
    return {'type': 'Broken Access Control', 'url': task['url'], 'vulnerable': False}