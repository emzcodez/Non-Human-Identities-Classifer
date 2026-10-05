"""Shared helpers for reading IAM policy documents."""


def as_list(value):
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def statements(doc):
    return [s for s in as_list((doc or {}).get("Statement")) if isinstance(s, dict)]


def identity_statements(identity):
    """Yield (policy_name, statement) for every statement attached to an identity."""
    for pol in identity.get("policies", []):
        for st in statements(pol.get("document")):
            yield pol.get("name", "?"), st


def trust_principals(trust_stmt):
    """Return list of (kind, value) from a trust statement Principal."""
    p = trust_stmt.get("Principal", {})
    if p == "*":
        return [("AWS", "*")]
    out = []
    if isinstance(p, dict):
        for kind, vals in p.items():
            out.extend((kind, v) for v in as_list(vals))
    return out
