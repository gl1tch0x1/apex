"""JWT structural checks on canonical weak samples (offline lab indicators)."""

import jwt as pyjwt

# Minimal valid three-segment samples; alg=none style tokens for parser regression checks.
JWT_TEST_TOKENS = [
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
    "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxIn0.",
]


def generate_tasks(url, config):
    tasks = []
    limit = min(len(JWT_TEST_TOKENS), config.get("payloads", {}).get("jwt", len(JWT_TEST_TOKENS)))
    for token in JWT_TEST_TOKENS[:limit]:
        tasks.append(
            {
                "token": token,
                "type": "JWT Vulnerability",
                "executor": test_jwt,
            }
        )
    return tasks


async def test_jwt(session, task):
    del session  # offline structural analysis
    try:
        token = task["token"]
        header = pyjwt.get_unverified_header(token)
        alg = (header.get("alg") or "").lower()
        decoded = pyjwt.decode(token, options={"verify_signature": False})

        weak_alg_none = alg == "none"
        missing_alg = not alg

        vulnerable = weak_alg_none or missing_alg
        issues = []
        if weak_alg_none:
            issues.append("algorithm none — unsigned token acceptance risk if server trusts alg header")
        if missing_alg:
            issues.append("missing alg in header")

        return {
            "type": "JWT Vulnerability",
            "token_preview": (task["token"][:48] + "…") if len(task["token"]) > 48 else task["token"],
            "vulnerable": vulnerable,
            "issues": issues,
            "header": header,
            "decoded": decoded,
        }
    except Exception as exc:
        return {"type": "JWT Vulnerability", "error": str(exc), "vulnerable": False}
