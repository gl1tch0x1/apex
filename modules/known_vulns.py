from core.http import fetch

KNOWN_VULNS = [
    {'pattern': 'Apache/2.4.49', 'vuln': 'CVE-2021-41773'},
    {'pattern': 'nginx/1.20.0', 'vuln': 'CVE-2021-23017'},
    {'pattern': 'PHP/7.4.0', 'vuln': 'CVE-2020-7070'},
    {'pattern': 'OpenSSH_7.2', 'vuln': 'CVE-2016-0777'},
    {'pattern': 'IIS/10.0', 'vuln': 'CVE-2017-11774'},
]

def generate_tasks(url, config):
    return [{
        'url': url,
        'method': 'HEAD',
        'type': 'Known Vulnerabilities',
        'executor': test_known_vulns,
    }]

async def test_known_vulns(session, task):
    try:
        text, resp = await fetch(session, task['url'], method='HEAD')
        if resp:
            server = resp.headers.get('Server', '')
            found_vuln = next((kv['vuln'] for kv in KNOWN_VULNS if kv['pattern'] in server), None)
            return {
                'type': 'Known Vulnerabilities',
                'url': task['url'],
                'vulnerable': found_vuln is not None,
                'server': server,
                'cve': found_vuln,
            }
    except Exception as exc:
        return {'type': 'Known Vulnerabilities', 'url': task['url'], 'error': str(exc), 'vulnerable': False}
    return {'type': 'Known Vulnerabilities', 'url': task['url'], 'vulnerable': False}