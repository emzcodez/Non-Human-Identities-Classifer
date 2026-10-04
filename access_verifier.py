"""
Access-path verification (MVP).

Scenario supported:
    principal --sts:AssumeRole--> IAM role --<action>--> S3 resource

Two checks are combined:
  1. Trust-policy evaluation (done locally, with a limited set of condition operators).
  2. Permission evaluation via IAM Policy Simulator (simulate_principal_policy).

IMPORTANT: an "allowed" result means *policy evaluation* allowed the path. It is NOT
proof that the access works at runtime (see docs/VERIFICATION_SCOPE.md).
"""
from __future__ import annotations

import fnmatch
from typing import Any, Dict, List, Optional

ALLOWED, BLOCKED, INCONCLUSIVE = "allowed", "blocked", "inconclusive"

# Tri-state used internally for statement matching
MATCH, NO_MATCH, UNKNOWN = "match", "no_match", "unknown"

SUPPORTED_CONDITION_OPS = {
    "StringEquals", "StringNotEquals", "StringLike",
    "ArnEquals", "ArnLike",
}
ASSUME_ACTIONS = {"sts:assumerole"}


# ----------------------------------------------------------------- helpers
def _as_list(value) -> list:
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def _account_of(arn: str) -> Optional[str]:
    parts = arn.split(":")
    return parts[4] if len(parts) > 4 and parts[4] else None


def _normalize_principal(principal) -> Dict[str, str]:
    """Accepts 'ec2.amazonaws.com', an ARN, or {'type': 'Service', 'value': '...'}."""
    if isinstance(principal, dict):
        return {"type": principal.get("type", "AWS"), "value": principal["value"]}
    if principal.endswith(".amazonaws.com") or principal.endswith(".amazonaws.com.cn"):
        return {"type": "Service", "value": principal}
    return {"type": "AWS", "value": principal}


def _match_action(patterns, action: str) -> bool:
    return any(fnmatch.fnmatchcase(action.lower(), p.lower()) for p in _as_list(patterns))


# -------------------------------------------------------- trust-policy logic
def _principal_match(stmt: dict, principal: Dict[str, str]) -> (str, str):
    if "NotPrincipal" in stmt:
        return UNKNOWN, "NotPrincipal is not supported by this verifier"
    block = stmt.get("Principal")
    if block == "*":
        return MATCH, "Principal is '*'"
    if not isinstance(block, dict):
        return NO_MATCH, "No usable Principal element"

    for entry in _as_list(block.get(principal["type"])):
        if entry == "*" or entry == principal["value"]:
            return MATCH, f"{principal['type']} principal '{entry}' matches"
        # Account-root trust: any principal of that account is *eligible*
        if (principal["type"] == "AWS" and entry.endswith(":root")
                and _account_of(entry) == _account_of(principal["value"])):
            return MATCH, (f"Trust delegates to account {_account_of(entry)} root; "
                           "the principal's own IAM policy must also allow sts:AssumeRole "
                           "(NOT checked here)")
    return NO_MATCH, f"{principal['value']} not listed in {principal['type']} principals"


def _condition_match(stmt: dict, context: Dict[str, str]) -> (str, List[str]):
    notes: List[str] = []
    ctx = {k.lower(): v for k, v in (context or {}).items()}
    result = MATCH
    for op, kv in (stmt.get("Condition") or {}).items():
        if op not in SUPPORTED_CONDITION_OPS:
            return UNKNOWN, [f"Unsupported condition operator '{op}'"]
        for key, expected in kv.items():
            if key.lower() not in ctx:
                result = UNKNOWN
                notes.append(f"Context value for '{key}' not provided")
                continue
            actual, exp = str(ctx[key.lower()]), [str(e) for e in _as_list(expected)]
            if op in ("StringEquals", "ArnEquals"):
                ok = actual in exp
            elif op in ("StringLike", "ArnLike"):
                ok = any(fnmatch.fnmatchcase(actual, e) for e in exp)
            else:  # StringNotEquals
                ok = actual not in exp
            notes.append(f"{op} {key}: actual='{actual}' expected={exp} -> {'ok' if ok else 'FAIL'}")
            if not ok:
                return NO_MATCH, notes
    return result, notes


def check_trust_policy(trust_policy: dict, principal, context=None) -> dict:
    """Return {'status': allowed|blocked|inconclusive, 'evidence': [...], 'unresolved': [...]}."""
    principal = _normalize_principal(principal)
    evidence, unresolved = [], []
    allow_match = allow_unknown = deny_match = deny_unknown = False

    for i, stmt in enumerate(_as_list(trust_policy.get("Statement"))):
        sid = stmt.get("Sid", f"#{i}")
        if "NotAction" in stmt:
            unresolved.append(f"Statement {sid}: NotAction unsupported")
            if stmt.get("Effect") == "Deny":
                deny_unknown = True
            else:
                allow_unknown = True
            continue
        if not _match_action(stmt.get("Action"), "sts:AssumeRole"):
            continue
        p_res, p_note = _principal_match(stmt, principal)
        if p_res == NO_MATCH:
            continue
        c_res, c_notes = _condition_match(stmt, context)
        res = UNKNOWN if UNKNOWN in (p_res, c_res) else (MATCH if c_res == MATCH else NO_MATCH)
        effect = stmt.get("Effect")
        evidence.append(f"Trust statement {sid} ({effect}): {p_note}; conditions={c_res}")
        evidence.extend(f"  {n}" for n in c_notes)

        if res == MATCH:
            if effect == "Deny":
                deny_match = True
            else:
                allow_match = True
        elif res == UNKNOWN:
            unresolved.extend(n for n in ([p_note] if p_res == UNKNOWN else []) + c_notes
                              if "FAIL" not in n and "ok" not in n.split("->")[-1])
            if effect == "Deny":
                deny_unknown = True
            else:
                allow_unknown = True

    if deny_match:
        return {"status": BLOCKED, "evidence": evidence + ["Explicit Deny in trust policy"], "unresolved": unresolved}
    if deny_unknown:
        return {"status": INCONCLUSIVE, "evidence": evidence, "unresolved": unresolved}
    if allow_match:
        return {"status": ALLOWED, "evidence": evidence, "unresolved": unresolved}
    if allow_unknown:
        return {"status": INCONCLUSIVE, "evidence": evidence, "unresolved": unresolved}
    return {"status": BLOCKED,
            "evidence": evidence + ["No trust statement allows this principal (implicit deny)"],
            "unresolved": unresolved}


# --------------------------------------------------------- permission check
def check_permission(iam_client, role_arn: str, action: str, resource: str,
                     context_entries: Optional[List[dict]] = None) -> dict:
    kwargs: Dict[str, Any] = dict(PolicySourceArn=role_arn, ActionNames=[action], ResourceArns=[resource])
    if context_entries:
        kwargs["ContextEntries"] = context_entries
    try:
        resp = iam_client.simulate_principal_policy(**kwargs)
    except Exception as exc:  # botocore ClientError, throttling, missing perms...
        return {"status": INCONCLUSIVE, "evidence": [],
                "unresolved": [f"IAM Policy Simulator call failed: {exc}"]}

    results = resp.get("EvaluationResults", [])
    if not results:
        return {"status": INCONCLUSIVE, "evidence": [], "unresolved": ["Simulator returned no results"]}

    r = results[0]
    decision = r.get("EvalDecision")
    matched = [m.get("SourcePolicyId", "?") for m in r.get("MatchedStatements", [])]
    evidence = [f"Policy Simulator: {action} on {resource} -> {decision}",
                f"Matched policies: {matched or 'none'}"]
    if r.get("MissingContextValues"):
        return {"status": INCONCLUSIVE, "evidence": evidence,
                "unresolved": [f"Missing context values: {r['MissingContextValues']}"]}
    if decision == "allowed":
        return {"status": ALLOWED, "evidence": evidence, "unresolved": []}
    if decision in ("explicitDeny", "implicitDeny"):
        kind = "explicit deny" if decision == "explicitDeny" else "no allow (implicit deny)"
        return {"status": BLOCKED, "evidence": evidence + [f"Blocked by {kind}"], "unresolved": []}
    return {"status": INCONCLUSIVE, "evidence": evidence, "unresolved": [f"Unknown decision '{decision}'"]}


# ------------------------------------------------------------- entry point
def verify_access(identity: dict, principal, resource: str,
                  action: str = "s3:GetObject",
                  iam_client=None,
                  trust_context: Optional[Dict[str, str]] = None,
                  context_entries: Optional[List[dict]] = None) -> dict:
    """
    identity : the target role, e.g. {"name": "AppRole", "arn": "arn:aws:iam::123:role/AppRole",
               "trust_policy": {...}}   (trust_policy fetched via iam_client.get_role if absent)
    principal: who tries to assume it: 'ec2.amazonaws.com' | role/user ARN | {'type','value'}
    resource : target ARN, e.g. 'arn:aws:s3:::my-bucket/*' or '.../key'
    """
    role_arn = identity.get("arn")
    result = {
        "status": INCONCLUSIVE,
        "principal": principal if isinstance(principal, str) else principal.get("value"),
        "role": role_arn or identity.get("name"),
        "resource": resource,
        "action": action,
        "evidence": [],
        "unresolved": [],
        "verification_level": "policy_evaluation_only",
        "disclaimer": ("Policy-level result only. Not proof of runtime access: SCPs, S3 Block Public "
                       "Access, bucket policies, VPC endpoint policies, KMS and network paths are "
                       "not fully evaluated."),
    }
    if not role_arn:
        result["unresolved"].append("identity has no 'arn'")
        return result

    trust_policy = identity.get("trust_policy")
    if trust_policy is None and iam_client is not None:
        try:
            trust_policy = iam_client.get_role(RoleName=role_arn.split("/")[-1])["Role"]["AssumeRolePolicyDocument"]
        except Exception as exc:
            result["unresolved"].append(f"Could not fetch trust policy: {exc}")
            return result
    if trust_policy is None:
        result["unresolved"].append("No trust policy supplied and no iam_client available")
        return result

    # Step 1: role assumption
    trust = check_trust_policy(trust_policy, principal, trust_context)
    result["evidence"].append(f"[Trust] status={trust['status']}")
    result["evidence"] += trust["evidence"]
    result["unresolved"] += trust["unresolved"]
    if trust["status"] == BLOCKED:
        result["status"] = BLOCKED
        result["explanation"] = "Principal cannot assume the role (trust policy blocks it); permissions not tested."
        return result

    # Step 2: permissions
    if iam_client is None:
        result["unresolved"].append("No iam_client: permission check skipped")
        return result
    perm = check_permission(iam_client, role_arn, action, resource, context_entries)
    result["evidence"].append(f"[Permission] status={perm['status']}")
    result["evidence"] += perm["evidence"]
    result["unresolved"] += perm["unresolved"]

    if perm["status"] == BLOCKED:
        result["status"] = BLOCKED
        result["explanation"] = "Role cannot perform the action on the resource (deny or no allow)."
    elif trust["status"] == ALLOWED and perm["status"] == ALLOWED:
        result["status"] = ALLOWED
        result["explanation"] = "Principal may assume the role and the role's policies allow the action (policy evaluation only)."
    else:
        result["status"] = INCONCLUSIVE
        result["explanation"] = "One or more checks could not be resolved; see 'unresolved'."
    return result
