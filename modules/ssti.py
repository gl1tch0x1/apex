"""Server-Side Template Injection (SSTI) detection.

A03:2021 – Injection
Probes Jinja2, Twig, Mako, Freemarker, and generic math-based canaries.
"""

from core.http import fetch

# Each entry: (payload, expected_response_contains, engine_hint)
SSTI_PROBES = [
    # Jinja2 / Flask / Python
    ("{{7*7}}", "49", "Jinja2"),
    ("{{7*'7'}}", "7777777", "Jinja2"),
    ("${7*7}", "49", "Mako/Freemarker"),
    # Twig (PHP)
    ("{{7*7}}", "49", "Twig"),
    # ERB (Ruby)
    ("<%= 7*7 %>", "49", "ERB"),
    # Freemarker (Java)
    ("${7*7}", "49", "Freemarker"),
    # Smarty (PHP)
    ("{7*7}", "49", "Smarty"),
    # Velocity (Java)
    ("#set($x=7*7)${x}", "49", "Velocity"),
    # Generic math canary
    ("[[7*7]]", "49", "Pebble/Thymeleaf"),
    ("#{7*7}", "49", "Groovy/Spring"),
]

# Parameters commonly rendered in templates
SSTI_PARAMS = ("q", "search", "name", "message", "title", "content", "query", "input", "text", "template")


def generate_tasks(url: str, config: dict) -> list:
    tasks = []
    
    default_params = config.get("ssti", {}).get("params", list(SSTI_PARAMS))
    discovered = config.get("discovered_params", [])
    all_params = list(dict.fromkeys(default_params + discovered))
    
    probe_limit = config.get("ssti", {}).get("probe_limit", len(SSTI_PROBES))
    for param in all_params:
        for payload, expected, engine in SSTI_PROBES[:probe_limit]:
            tasks.append(
                {
                    "url": url,
                    "method": "GET",
                    "params": {param: payload},
                    "type": "SSTI",
                    "expected": expected,
                    "engine_hint": engine,
                    "ssti_param": param,
                    "executor": test_ssti,
                }
            )
    return tasks


async def test_ssti(session, task):
    try:
        text, resp = await fetch(session, task["url"], params=task["params"])
        if not resp or not text:
            return {"type": "SSTI", "url": task["url"], "vulnerable": False}

        expected = task.get("expected", "49")
        payload = next(iter(task["params"].values()))
        param = task.get("ssti_param")
        engine = task.get("engine_hint", "Unknown")

        # Confirm the expression was evaluated (not just reflected verbatim)
        evaluated = expected in text and payload not in text
        # Secondary signal: payload reflected but expected value also present (partial eval)
        partial = expected in text

        vulnerable = evaluated or partial

        return {
            "type": "SSTI",
            "url": task["url"],
            "params": task["params"],
            "vulnerable": vulnerable,
            "engine_hint": engine,
            "param": param,
            "evaluated": evaluated,
            "expected_found": partial,
            "response": text[:800],
            "confidence": "high" if evaluated else ("medium" if partial else "none"),
        }
    except Exception as exc:
        return {"type": "SSTI", "url": task["url"], "error": str(exc), "vulnerable": False}
