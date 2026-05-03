"""OWASP Top 10 (2021) mapping for findings — used by scanners and reports."""

OWASP_MAP = {
    "SQL Injection": "A03:2021 – Injection",
    "Reflected XSS": "A03:2021 – Injection",
    "DOM XSS": "A03:2021 – Injection",
    "GraphQL Introspection": "A05:2021 – Security Misconfiguration",
    "GraphQL Injection": "A03:2021 – Injection",
    "JWT Vulnerability": "A07:2021 – Identification and Authentication Failures",
    "Broken Authentication": "A07:2021 – Identification and Authentication Failures",
    "IDOR": "A01:2021 – Broken Access Control",
    "Broken Access Control": "A01:2021 – Broken Access Control",
    "Sensitive Data Exposure": "A02:2021 – Cryptographic Failures",
    "XXE": "A03:2021 – Injection",
    "Security Misconfiguration": "A05:2021 – Security Misconfiguration",
    "Insecure Deserialization": "A08:2021 – Software and Data Integrity Failures",
    "Known Vulnerable Components": "A06:2021 – Vulnerable and Outdated Components",
    "SSRF": "A10:2021 – Server-Side Request Forgery",
    "Open Redirect": "A01:2021 – Broken Access Control",
    "CSRF": "A01:2021 – Broken Access Control",
    "Path Traversal": "A01:2021 – Broken Access Control",
    "File Upload": "A04:2021 – Insecure Design",
}


def owasp_category(finding_type: str) -> str:
    return OWASP_MAP.get(finding_type, "A09:2021 – Security Logging and Monitoring Failures")


def infer_severity(result: dict) -> str:
    """Assign severity from module result; never hard-fail on shape."""
    t = result.get("type", "")
    if result.get("severity"):
        return result["severity"]
    if "SQL" in t or "SSRF" in t or t == "JWT Vulnerability" and _jwt_high(result):
        return "High"
    if "XSS" in t or t == "IDOR" or t == "Path Traversal" or t == "File Upload":
        return "Medium"
    if t in ("GraphQL Introspection", "Security Misconfiguration", "Sensitive Data Exposure"):
        return "Medium"
    if t == "CSRF":
        return "Medium"
    if t == "Known Vulnerable Components":
        return "High"
    return "Low"


def _jwt_high(result: dict) -> bool:
    h = result.get("header") or {}
    return (h.get("alg") or "").lower() == "none"


def enrich_finding(result: dict) -> dict:
    out = {**result}
    t = out.get("type", "Unknown")
    out.setdefault("owasp_category", owasp_category(t))
    out.setdefault("severity", infer_severity(out))
    return out
