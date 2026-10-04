"""Risk detection engine for AWS IAM identities.

Entry point: detect_risks(data) -> list of findings (JSON-compatible dicts).

Finding format (required keys first, extras for the dashboard / verifier):
    identity, risk, reason, resource, rule, policy, evidence
"""
import json
import re
import sys
from fnmatch import fnmatchcase

from analyzer.policy_parser import (
    LEVEL_RANK, PolicyParseError, action_level, action_matches,
    actions_overlap, condition_keys, max_level, normalize_policy,
)

# ------------------------------------------------------------- severity
LEVELS = ["Low", "Medium", "High", "Critical"]
SEVERITY_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}


def shift(severity, steps):
    """Move a severity up (+) or down (-) by steps, clamped to Low..Critical."""
    return LEVELS[max(0, min(len(LEVELS) - 1, LEVELS.index(severity) + steps))]


# Conditions that genuinely narrow who/where/how a permission can be used.
MITIGATING_KEYS = {
    "aws:sourceip", "aws:principalorgid", "aws:principalorgpaths",
    "aws:requestedregion", "aws:sourcevpc", "aws:sourcevpce",
    "aws:principalarn", "aws:sourceaccount", "aws:sourcearn",
    "aws:multifactorauthpresent", "aws:resourceorgid", "sts:externalid",
}
MITIGATING_PREFIXES = ("aws:principaltag/", "aws:resourcetag/", "s3:prefix")
# Strong conditions for trust policies.
STRONG_TRUST_KEYS = {
    "sts:externalid", "aws:principalorgid", "aws:principalorgpaths",
    "aws:sourcearn", "aws:sourceaccount", "aws:principalarn",
}


def has_mitigating_conditions(conditions):
    keys = condition_keys(conditions)
    return any(k in MITIGATING_KEYS or k.startswith(MITIGATING_PREFIXES) for k in keys)


# Services where "service:*" is dangerous even on a single resource.
HIGH_RISK_SERVICES = {
    "s3", "ec2", "lambda", "kms", "secretsmanager", "ssm", "sts", "cloudformation",
    "rds", "dynamodb", "ecr", "eks", "cloudtrail", "config", "organizations",
}
FULL_CONTROL_SERVICES = {"iam", "organizations"}

# Actions that legitimately need Resource "*" -> no unrestricted-resource noise.
STAR_RESOURCE_ALLOWLIST = [
    "s3:ListAllMyBuckets", "sts:GetCallerIdentity", "ec2:Describe*",
    "iam:ListAccountAliases", "cloudwatch:PutMetricData", "logs:CreateLogGroup",
    "logs:CreateLogStream", "logs:PutLogEvents", "xray:PutTraceSegments",
    "xray:PutTelemetryRecords",
]


# -------------------------------------------------------------- helpers
def make_finding(identity, risk, rule, reason, policy, resource, **evidence):
    return {
        "identity": identity.get("name", "<unknown>"),
        "risk": risk,
        "rule": rule,
        "reason": reason,
        "policy": policy,
        "resource": resource,
        "evidence": evidence,
    }


def _is_wildcard_action(action):
    a = action.strip()
    return a == "*" or a.endswith(":*")


def _res_str(st):
    if st["not_resources"]:
        return "NotResource: " + ", ".join(st["not_resources"])
    return ", ".join(st["resources"]) or "*"


def _unrestricted(st):
    """Resource '*' or a NotResource (which covers everything else)."""
    return "*" in st["resources"] or bool(st["not_resources"])


def _allow_statements(parsed):
    for pol in parsed:
        for st in pol["statements"]:
            if st["effect"] == "Allow":
                yield pol, st


def _overlapping_denies(parsed, actions):
    """Explicit Deny statements that touch these actions (noted, not evaluated)."""
    out = []
    for pol in parsed:
        for st in pol["statements"]:
            if st["effect"] == "Deny" and any(
                actions_overlap(d, a) for d in st["actions"] for a in actions
            ):
                out.append({"policy": pol["policy"], "statement_index": st["index"],
                            "actions": st["actions"]})
    return out


def collect_policies(identity):
    """All policy documents attached to an identity: managed, inline, group."""
    out = []
    for p in identity.get("attached_policies") or []:
        out.append((p.get("name", "<unnamed>"), "attached", p.get("document")))
    for p in identity.get("inline_policies") or []:
        out.append((p.get("name", "<unnamed>"), "inline", p.get("document")))
    for p in identity.get("group_policies") or []:
        out.append((p.get("name", "<unnamed>"), f"group:{p.get('group', '?')}", p.get("document")))
    return out


def parse_identity_policies(identity):
    parsed, errors = [], []
    for name, source, doc in collect_policies(identity):
        try:
            parsed.append({"policy": name, "source": source,
                           "statements": normalize_policy(doc)})
        except PolicyParseError as exc:
            errors.append(make_finding(
                identity, "Low", "POLICY_PARSE_ERROR",
                f"Policy {name} could not be parsed and was not analysed: {exc}",
                name, "N/A", source=source))
    return parsed, errors


def _canon_s3(resource):
    r = resource.lower()
    return r[len("arn:aws:s3:::"):] if r.startswith("arn:aws:s3:::") else r


def matches_sensitive(resource, sensitive):
    """Return the first sensitive pattern the resource overlaps with, else None."""
    if resource == "*":
        return None  # handled explicitly by the caller
    rc = _canon_s3(resource)
    for s in sensitive:
        sc = _canon_s3(s)
        if (fnmatchcase(rc, sc) or fnmatchcase(sc, rc)
                or fnmatchcase(rc.split("/")[0], sc.split("/")[0])
                or fnmatchcase(sc.split("/")[0], rc.split("/")[0])):
            return s
    return None


# ------------------------------------------------- Rule 1: wildcard actions
def check_wildcards(identity, parsed, ctx):
    findings = []
    sensitive = ctx["sensitive"]
    for pol, st in _allow_statements(parsed):
        star_res = _unrestricted(st)
        mitigated = has_mitigating_conditions(st["conditions"])
        sens_hit = any(matches_sensitive(r, sensitive) for r in st["resources"])

        if st["not_actions"]:  # Allow + NotAction = everything except a short list
            sev = "Critical" if star_res else "High"
            sev = shift(sev, -1) if mitigated else sev
            findings.append(make_finding(
                identity, sev, "ALLOW_NOT_ACTION",
                f"Policy {pol['policy']} allows everything except {st['not_actions']}"
                f" on {_res_str(st)}; this is effectively near-admin access",
                pol["policy"], _res_str(st),
                statement_index=st["index"], not_actions=st["not_actions"],
                source=pol["source"], mitigating_conditions=mitigated))

        for action in st["actions"]:
            if not _is_wildcard_action(action):
                continue
            svc = action.split(":")[0].lower()
            if action.strip() == "*":
                sev = "Critical" if star_res else "High"
                desc = "all actions in all services, i.e. full admin"
            elif svc in FULL_CONTROL_SERVICES:
                sev = "Critical" if star_res else "High"
                desc = f"full control of {svc.upper()}, usable for privilege escalation"
            elif svc in HIGH_RISK_SERVICES:
                sev = "High" if (star_res or sens_hit) else "Medium"
                desc = f"all {svc} actions"
            else:
                sev = "Medium" if star_res else "Low"
                desc = f"all {svc} actions"
            if mitigated:
                sev = shift(sev, -1)
            scope = "all resources" if star_res else (
                "a sensitive resource" if sens_hit else "scoped resources")
            ev = dict(statement_index=st["index"], actions=[action], source=pol["source"],
                      resource_scope="all" if star_res else "restricted",
                      touches_sensitive=sens_hit, mitigating_conditions=mitigated)
            denies = _overlapping_denies(parsed, [action])
            if denies:
                ev["explicit_denies"] = denies
            findings.append(make_finding(
                identity, sev, "WILDCARD_ACTION",
                f"Policy {pol['policy']} grants {action}: {desc}, on {scope}"
                + (" with mitigating conditions" if mitigated else ""),
                pol["policy"], _res_str(st), **ev))
    return findings


# ----------------------------------------- Rule 2: unrestricted resources
_LEVEL_TO_SEVERITY = {"list": "Low", "read": "Medium", "write": "High",
                      "permission": "High", "admin": "High"}


def check_unrestricted_resources(identity, parsed, ctx):
    findings = []
    for pol, st in _allow_statements(parsed):
        if not _unrestricted(st):
            continue
        # wildcard actions are already reported by rule 1
        actions = [a for a in st["actions"]
                   if not _is_wildcard_action(a)
                   and not any(action_matches(allowed, a) for allowed in STAR_RESOURCE_ALLOWLIST)]
        if not actions:
            continue
        level = max_level(actions)
        sev = _LEVEL_TO_SEVERITY[level]
        mitigated = has_mitigating_conditions(st["conditions"])
        if mitigated:
            sev = shift(sev, -1)
        ev = dict(statement_index=st["index"], actions=actions, highest_action_level=level,
                  source=pol["source"], mitigating_conditions=mitigated,
                  conditions=sorted(condition_keys(st["conditions"])))
        denies = _overlapping_denies(parsed, actions)
        if denies:
            ev["explicit_denies"] = denies
        findings.append(make_finding(
            identity, sev, "UNRESTRICTED_RESOURCE",
            f"Policy {pol['policy']} grants {level}-level actions {actions} on every resource (*)"
            + (" but is limited by conditions" if mitigated else " with no restricting condition"),
            pol["policy"], _res_str(st), **ev))
    return findings


# ----------------------------------------------- Rule 3: trust relationships
def _account_of(principal):
    if re.fullmatch(r"\d{12}", principal):
        return principal
    parts = principal.split(":")
    if principal.startswith("arn:") and len(parts) > 4 and re.fullmatch(r"\d{12}", parts[4]):
        return parts[4]
    return None


def _is_account_root(principal):
    return re.fullmatch(r"\d{12}", principal) is not None or principal.endswith(":root")


def check_trust_policy(identity, parsed, ctx):
    trust = identity.get("trust_policy")
    if not trust:
        return []
    try:
        statements = normalize_policy(trust)
    except PolicyParseError as exc:
        return [make_finding(identity, "Low", "POLICY_PARSE_ERROR",
                             f"Trust policy could not be parsed: {exc}", "TrustPolicy", "N/A")]
    findings = []
    own = ctx.get("account_id")

    for st in statements:
        if st["effect"] != "Allow":
            continue
        keys = condition_keys(st["conditions"])
        strong = bool(keys & STRONG_TRUST_KEYS)
        weak = bool(keys) and not strong
        actions_l = [a.lower() for a in st["actions"]]

        def add(sev, rule, reason, who):
            findings.append(make_finding(
                identity, sev, rule, reason, "TrustPolicy", str(who),
                statement_index=st["index"], principal=who, actions=st["actions"],
                condition_keys=sorted(keys)))

        for kind, values in st["principals"].items():
            for who in values:
                if kind == "AWS" and who == "*":
                    sev = "Critical" if not keys else ("Medium" if strong else "High")
                    add(sev, "TRUST_PUBLIC_PRINCIPAL",
                        "Trust policy allows ANY AWS principal to assume this role"
                        + ("" if not keys else " (restricted only by conditions)"), who)
                elif kind == "AWS":
                    acct = _account_of(who)
                    if acct is None:
                        continue
                    if own and acct == own:
                        if _is_account_root(who):
                            add("Low", "TRUST_SAME_ACCOUNT_ROOT",
                                "Trusts the whole account root: any principal in this account "
                                "with sts:AssumeRole permission can assume the role", who)
                    else:
                        if own is None:
                            sev, note = "Medium", "account ownership could not be determined"
                        elif strong:
                            sev, note = "Low", "restricted by ExternalId / org / ARN condition"
                        else:
                            sev = "High" if _is_account_root(who) else "Medium"
                            note = "no sts:ExternalId or aws:PrincipalOrgID condition"
                        add(sev, "TRUST_EXTERNAL_ACCOUNT",
                            f"Role is assumable from external account {acct} ({note})", who)
                elif kind == "Federated":
                    is_saml = "saml" in who.lower()
                    if is_saml:
                        if not any(k.endswith("saml:aud") for k in keys):
                            add("Medium", "TRUST_FEDERATED_NO_AUDIENCE",
                                "SAML trust has no saml:aud condition", who)
                    else:
                        if not any(k.endswith(":sub") or k.endswith(":aud") for k in keys):
                            add("High", "TRUST_FEDERATED_NO_SUBJECT",
                                "Web-identity trust has no sub/aud condition, so any identity "
                                "from this provider can assume the role", who)
                # Service / CanonicalUser principals are expected and skipped.
    return findings


# ------------------------------------------ Rule 4: sensitive resource access
_ACCESS_TO_SEVERITY = {"list": "Low", "read": "Medium", "write": "High",
                       "permission": "Critical", "admin": "Critical"}


def check_sensitive_access(identity, parsed, ctx):
    sensitive = ctx["sensitive"]
    if not sensitive:
        return []
    findings = []
    for pol, st in _allow_statements(parsed):
        s3_actions = [a for a in st["actions"] if a == "*" or a.lower().startswith("s3:")]
        if not s3_actions:
            continue
        matched, via_star = [], False
        if _unrestricted(st):
            matched, via_star = list(sensitive), True
        else:
            for r in st["resources"]:
                hit = matches_sensitive(r, sensitive)
                if hit and hit not in matched:
                    matched.append(hit)
        if not matched:
            continue
        level = max_level(s3_actions)
        sev = _ACCESS_TO_SEVERITY[level]
        if via_star:
            sev = shift(sev, +1)
        mitigated = has_mitigating_conditions(st["conditions"])
        if mitigated:
            sev = shift(sev, -1)
        ev = dict(statement_index=st["index"], actions=s3_actions, access_level=level,
                  via_resource_wildcard=via_star, source=pol["source"],
                  mitigating_conditions=mitigated)
        denies = _overlapping_denies(parsed, s3_actions)
        if denies:
            ev["explicit_denies"] = denies
        findings.append(make_finding(
            identity, sev, "SENSITIVE_RESOURCE_ACCESS",
            f"Policy {pol['policy']} grants {level}-level S3 access to sensitive resource(s) "
            f"{matched}" + (" through Resource '*'" if via_star else ""),
            pol["policy"], ", ".join(matched), **ev))
    return findings


# ------------------------------------- Rule 5: dangerous action combinations
# 'groups' = AND of groups; each group is an OR of alternative actions.
DANGEROUS_COMBOS = [
    {"id": "PASSROLE_EC2", "severity": "High", "scope_action": "iam:PassRole",
     "groups": [["iam:PassRole"], ["ec2:RunInstances"]],
     "why": "can launch an EC2 instance with a more privileged role and use its credentials"},
    {"id": "PASSROLE_LAMBDA", "severity": "High", "scope_action": "iam:PassRole",
     "groups": [["iam:PassRole"], ["lambda:CreateFunction"],
                ["lambda:InvokeFunction", "lambda:CreateEventSourceMapping"]],
     "why": "can create and run a Lambda function under a more privileged role"},
    {"id": "CREATE_POLICY_VERSION", "severity": "Critical", "scope_action": None,
     "groups": [["iam:CreatePolicyVersion"]],
     "why": "can publish a new default policy version granting itself admin rights"},
    {"id": "SET_DEFAULT_POLICY_VERSION", "severity": "High", "scope_action": None,
     "groups": [["iam:SetDefaultPolicyVersion"]],
     "why": "can re-activate an older, more permissive policy version"},
    {"id": "ATTACH_OR_PUT_POLICY", "severity": "Critical", "scope_action": None,
     "groups": [["iam:AttachUserPolicy", "iam:AttachRolePolicy", "iam:AttachGroupPolicy",
                 "iam:PutUserPolicy", "iam:PutRolePolicy", "iam:PutGroupPolicy"]],
     "why": "can attach or write policies to itself or others, granting arbitrary permissions"},
    {"id": "CREDENTIAL_TAKEOVER", "severity": "High", "scope_action": None,
     "groups": [["iam:CreateAccessKey", "iam:CreateLoginProfile", "iam:UpdateLoginProfile"]],
     "why": "can create credentials or reset passwords for other IAM users"},
    {"id": "UPDATE_ASSUME_ROLE_POLICY", "severity": "Critical", "scope_action": None,
     "groups": [["iam:UpdateAssumeRolePolicy"]],
     "why": "can rewrite a role's trust policy and then assume that role"},
    {"id": "S3_POLICY_TAMPERING", "severity": "High", "scope_action": None,
     "groups": [["s3:PutBucketPolicy"],
                ["s3:PutBucketPublicAccessBlock", "s3:PutAccountPublicAccessBlock",
                 "s3:DeleteBucketPublicAccessBlock"]],
     "why": "can change a bucket policy and disable Block Public Access, enabling public exposure"},
]


def _grants(parsed, required):
    """(policy, statement) pairs of Allow statements granting a concrete action.

    Service-level wildcards ('s3:*', '*') are ignored here because rule 1 already
    reports them; partial wildcards such as 'iam:Put*' still count."""
    return [(pol, st) for pol, st in _allow_statements(parsed)
            if any(action_matches(a, required) and not _is_wildcard_action(a)
                   for a in st["actions"])]


def check_dangerous_combos(identity, parsed, ctx):
    # Identities with Action:"*" are already Critical via rule 1; skip to avoid noise.
    if any("*" in [a.strip() for a in st["actions"]] for _, st in _allow_statements(parsed)):
        return []
    findings = []
    for combo in DANGEROUS_COMBOS:
        matched, contributing, ok = [], [], True
        for group in combo["groups"]:
            hits = [(a, _grants(parsed, a)) for a in group]
            hits = [(a, g) for a, g in hits if g]
            if not hits:
                ok = False
                break
            matched += [a for a, _ in hits]
            contributing += [pair for _, g in hits for pair in g]
        if not ok:
            continue
        sev = combo["severity"]
        notes = []
        if all(has_mitigating_conditions(st["conditions"]) for _, st in contributing):
            sev = shift(sev, -1)
            notes.append("all granting statements have mitigating conditions")
        scope = combo["scope_action"]
        if scope and not any(_unrestricted(st) for _, st in _grants(parsed, scope)):
            sev = shift(sev, -1)
            notes.append(f"{scope} is limited to specific resources")
        policies = sorted({p["policy"] for p, _ in contributing})
        resources = sorted({r for _, st in contributing
                            for r in (st["resources"] or ["*"])})
        ev = dict(combo=combo["id"], matched_actions=sorted(set(matched)),
                  statement_indexes=sorted({st["index"] for _, st in contributing}),
                  context_notes=notes)
        denies = _overlapping_denies(parsed, matched)
        if denies:
            ev["explicit_denies"] = denies
        findings.append(make_finding(
            identity, sev, "PRIVILEGE_ESCALATION",
            f"Permission combination {sorted(set(matched))} {combo['why']}",
            ", ".join(policies), ", ".join(resources), **ev))
    return findings


# --------------------------------------------------------------- entry point
RULES = [check_wildcards, check_unrestricted_resources, check_trust_policy,
         check_sensitive_access, check_dangerous_combos]


def _account_from_arn(arn):
    parts = (arn or "").split(":")
    return parts[4] if len(parts) > 4 and re.fullmatch(r"\d{12}", parts[4]) else None


def detect_risks(data):
    """Analyse collected IAM data and return a sorted list of findings.

    data = {"identities": [...], "sensitive_resources": [...], "account_id": "..."}
    """
    if not isinstance(data, dict) or not isinstance(data.get("identities", []), list):
        raise ValueError("data must be a dict with an 'identities' list")
    sensitive = data.get("sensitive_resources") or []
    findings = []
    for identity in data.get("identities", []):
        parsed, errors = parse_identity_policies(identity)
        ctx = {"sensitive": sensitive,
               "account_id": data.get("account_id") or _account_from_arn(identity.get("arn"))}
        findings += errors
        for rule in RULES:
            findings += rule(identity, parsed, ctx)

    seen, unique = set(), []
    for f in findings:  # drop exact duplicates
        key = json.dumps(f, sort_keys=True, default=str)
        if key not in seen:
            seen.add(key)
            unique.append(f)
    return sorted(unique, key=lambda f: (SEVERITY_ORDER[f["risk"]], f["identity"]))


if __name__ == "__main__":
    path = sys.argv[1] if len(sys.argv) > 1 else "data/sample_input.json"
    with open(path) as fh:
        print(json.dumps(detect_risks(json.load(fh)), indent=2))
