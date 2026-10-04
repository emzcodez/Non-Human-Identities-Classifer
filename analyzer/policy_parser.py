"""IAM policy parsing and normalisation.

Turns raw IAM policy documents (as returned by boto3) into a flat list of
normalised statements so that the risk rules never have to deal with the
string-or-list quirks of the IAM policy grammar.
"""
import json
from fnmatch import fnmatchcase


class PolicyParseError(ValueError):
    """Raised when a policy document is structurally invalid."""


# ---------------------------------------------------------------- basics
def as_list(value):
    """IAM allows a scalar or a list almost everywhere. Always return a list."""
    if value is None:
        return []
    if isinstance(value, (list, tuple, set)):
        return list(value)
    return [value]


def _normalise_principal(raw):
    """'*' -> {'AWS': ['*']}; {'AWS': 'x'} -> {'AWS': ['x']}."""
    if raw is None:
        return {}
    if isinstance(raw, str):
        return {"AWS": [raw]}
    if isinstance(raw, dict):
        return {kind: [str(v) for v in as_list(vals)] for kind, vals in raw.items()}
    raise PolicyParseError(f"Unsupported Principal format: {raw!r}")


def normalize_policy(doc):
    """Return one normalised dict per statement.

    Each record: index, sid, effect, actions, not_actions, resources,
    not_resources, principals, not_principals, conditions.
    An empty / missing policy returns [].
    """
    if isinstance(doc, str):
        try:
            doc = json.loads(doc)
        except json.JSONDecodeError as exc:
            raise PolicyParseError(f"Policy is not valid JSON: {exc}") from exc
    if not doc:
        return []
    if not isinstance(doc, dict):
        raise PolicyParseError("Policy document must be a JSON object")

    statements = []
    for i, st in enumerate(as_list(doc.get("Statement"))):
        if not isinstance(st, dict):
            raise PolicyParseError(f"Statement {i} is not an object")
        effect = st.get("Effect")
        if effect not in ("Allow", "Deny"):
            raise PolicyParseError(f"Statement {i} has invalid Effect: {effect!r}")
        conditions = st.get("Condition") or {}
        if not isinstance(conditions, dict):
            raise PolicyParseError(f"Statement {i} has invalid Condition")
        statements.append({
            "index": i,
            "sid": st.get("Sid"),
            "effect": effect,
            "actions": [str(a) for a in as_list(st.get("Action"))],
            "not_actions": [str(a) for a in as_list(st.get("NotAction"))],
            "resources": [str(r) for r in as_list(st.get("Resource"))],
            "not_resources": [str(r) for r in as_list(st.get("NotResource"))],
            "principals": _normalise_principal(st.get("Principal")),
            "not_principals": _normalise_principal(st.get("NotPrincipal")),
            "conditions": conditions,
        })
    return statements


# ------------------------------------------------------------- matching
def action_matches(pattern, action):
    """Case-insensitive IAM wildcard match: action_matches('s3:Get*', 's3:GetObject')."""
    return fnmatchcase(action.lower(), pattern.lower())


def actions_overlap(a, b):
    """True if either string, treated as a pattern, matches the other."""
    return action_matches(a, b) or action_matches(b, a)


def condition_keys(conditions):
    """Lower-cased set of all condition keys used, ignoring the operator."""
    keys = set()
    for block in (conditions or {}).values():
        if isinstance(block, dict):
            keys.update(k.lower() for k in block)
    return keys


# ---------------------------------------------------- action power level
LEVEL_RANK = {"list": 0, "read": 1, "write": 2, "permission": 3, "admin": 4}

# Actions that change who can do what (permission management / escalation).
PERMISSION_ACTIONS = [
    "iam:Attach*", "iam:Detach*", "iam:Put*Policy", "iam:CreatePolicyVersion",
    "iam:SetDefaultPolicyVersion", "iam:UpdateAssumeRolePolicy", "iam:PassRole",
    "iam:CreateAccessKey", "iam:CreateLoginProfile", "iam:UpdateLoginProfile",
    "iam:AddUserToGroup", "s3:PutBucketPolicy", "s3:PutBucketAcl",
    "s3:PutObjectAcl", "s3:PutAccessPointPolicy", "kms:PutKeyPolicy",
    "kms:CreateGrant", "lambda:AddPermission", "sts:AssumeRole",
]


def action_level(action):
    """Classify an action (possibly containing wildcards) as
    list < read < write < permission < admin."""
    action = action.strip()
    if action == "*" or action.endswith(":*"):
        return "admin"
    for pattern in PERMISSION_ACTIONS:
        if actions_overlap(pattern, action):
            return "permission"
    name = action.split(":", 1)[-1].lower()
    if name.startswith(("list", "describe")):
        return "list"
    if name.startswith(("get", "batchget", "view", "lookup", "search", "head", "select", "read")):
        return "read"
    return "write"  # unknown verbs are treated conservatively


def max_level(actions):
    if not actions:
        return "list"
    return max((action_level(a) for a in actions), key=LEVEL_RANK.get)
