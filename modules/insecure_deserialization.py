import pickle
import base64
from core.http import fetch

DESERIAL_PAYLOADS = [
    base64.b64encode(pickle.dumps({'exploit': 'test'})).decode(),
    base64.b64encode(pickle.dumps({'__class__': 'os.system', '__args__': ['echo deserialized']})).decode(),
]

def generate_tasks(url, config):
    tasks = []
    for payload in DESERIAL_PAYLOADS:
        tasks.append({
            'url': url,
            'method': 'POST',
            'data': {'data': payload},
            'type': 'Insecure Deserialization',
            'executor': test_insecure_deserialization,
        })
    return tasks

async def test_insecure_deserialization(session, task):
    try:
        text, resp = await fetch(session, task['url'], method='POST', data=task['data'])
        if resp and text:
            lower = text.lower()
            vulnerable = any(marker in lower for marker in ['exploit', 'deserialized', 'traceback', 'pickle'])
            return {
                'type': 'Insecure Deserialization',
                'url': task['url'],
                'vulnerable': vulnerable,
                'response': text[:1000],
            }
    except Exception as exc:
        return {'type': 'Insecure Deserialization', 'url': task['url'], 'error': str(exc), 'vulnerable': False}
    return {'type': 'Insecure Deserialization', 'url': task['url'], 'vulnerable': False}