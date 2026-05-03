from core.http import fetch

DEFAULT_CREDS = [
    {'username': 'admin', 'password': 'admin'},
    {'username': 'admin', 'password': 'password'},
    {'username': 'admin', 'password': '123456'},
    {'username': 'admin', 'password': 'admin123'},
    {'username': 'user', 'password': 'user'},
    {'username': 'root', 'password': 'root'},
    {'username': 'test', 'password': 'test'},
]

BYPASS_HEADERS = [
    {"X-Forwarded-For": "127.0.0.1"},
    {"X-Real-IP": "127.0.0.1"},
    {"X-Originating-IP": "127.0.0.1"},
]

def generate_tasks(url, config):
    tasks = []
    login_path = config.get('broken_auth', {}).get('login_path', '/login')
    target_url = url.rstrip('/') + login_path
    
    for cred in DEFAULT_CREDS:
        tasks.append({
            'url': target_url,
            'method': 'POST',
            'data': cred,
            'type': 'Broken Authentication',
            'executor': test_broken_auth,
        })
        
        # Test rate limit bypass via headers
        for bypass in BYPASS_HEADERS:
             tasks.append({
                'url': target_url,
                'method': 'POST',
                'data': cred,
                'headers': bypass,
                'type': 'Broken Authentication',
                'executor': test_broken_auth,
             })
             
    return tasks

async def test_broken_auth(session, task):
    try:
        text, resp = await fetch(session, task['url'], method='POST', data=task['data'], headers=task.get('headers', {}))
        if resp:
            login_page = 'login' in text.lower() or 'invalid' in text.lower() or 'incorrect' in text.lower()
            vulnerable = (resp.status in [200, 301, 302]) and not login_page
            
            # Simple check if bypass header was used
            bypass_used = 'headers' in task
            
            if vulnerable:
                return {
                    'type': 'Broken Authentication',
                    'url': task['url'],
                    'data': task['data'],
                    'vulnerable': vulnerable,
                    'severity': 'Critical',
                    'response': text[:1000],
                    'status': resp.status,
                    'bypass_used': bypass_used,
                    'owasp_category': "A07:2021 – Identification and Authentication Failures"
                }
    except Exception as exc:
        return {'type': 'Broken Authentication', 'url': task['url'], 'error': str(exc), 'vulnerable': False}
    return {'type': 'Broken Authentication', 'url': task['url'], 'vulnerable': False}