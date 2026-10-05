"""
classifier.py
Rule-based, score-driven classification of IAM identities as human / non_human / uncertain.

Each rule adds points toward 'human' or 'non_human' and records a readable signal,
so the dashboard can show WHY an identity was classified the way it was.
An IAM user is NOT assumed human and a role is NOT assumed non-human.
"""
import re

NON_HUMAN_NAME = re.compile(
    r"(^|[-_.])(svc|service|bot|app|ci|cd|cicd|jenkins|github|gitlab|terraform|automation|"
    r"lambda|ec2|ecs|eks|pipeline|deploy|backup|etl|batch|cron|worker|scanner|monitor)([-_.]|$)", re.I)
HUMAN_ROLE_NAME = re.compile(r"AWSReservedSSO_|admin-?role|breakglass|developer|engineer|analyst", re.I)
HUMAN_TAG_VALUES = {"human", "employee", "person", "user", "staff", "contractor"}
NON_HUMAN_TAG_VALUES = {"service", "application", "app", "automation", "bot", "workload", "machine", "ci"}
TAG_KEYS = ("type", "identitytype", "identity-type", "identity_type", "kind", "owner-type")

SERVICE_PRINCIPAL_SUFFIX = ".amazonaws.com"
CONFIDENCE_THRESHOLD = 2  # minimum score difference to commit to a category


def _principals(trust_policy):
    """Yield (principal_kind, value) from a trust policy."""
    for stmt in (trust_policy or {}).get("Statement", []):
        if stmt.get("Effect") != "Allow":
            continue
        princ = stmt.get("Principal", {})
        if princ == "*":
            yield "Wildcard", "*"
            continue
        for kind, vals in princ.items():
            for v in ([vals] if isinstance(vals, str) else vals):
                yield kind, v


def _score(identity):
    human, non_human, signals = 0, 0, []

    def add(side, pts, text):
        nonlocal human, non_human
        if side == "human":
            human += pts
        else:
            non_human += pts
        signals.append(f"{side}:{text}")

    name, tags = identity["name"], {k.lower(): str(v).lower() for k, v in identity.get("tags", {}).items()}

    # --- tags (strongest, explicit signal) ---
    for k in TAG_KEYS:
        v = tags.get(k)
        if v in HUMAN_TAG_VALUES:
            add("human", 4, f"tag {k}={v}")
        elif v in NON_HUMAN_TAG_VALUES:
            add("non_human", 4, f"tag {k}={v}")

    # --- naming convention ---
    if NON_HUMAN_NAME.search(name):
        add("non_human", 2, "service-style name")
    if re.fullmatch(r"[a-z]+[._-][a-z]+", name, re.I) and identity["type"] == "user" \
            and not NON_HUMAN_NAME.search(name):
        add("human", 1, "firstname.lastname-style name")

    if identity["type"] == "user":
        if identity.get("has_console_access"):
            add("human", 3, "console password enabled")
        if identity.get("mfa_enabled"):
            add("human", 2, "MFA device attached")
        if identity.get("access_keys") and not identity.get("has_console_access"):
            add("non_human", 1, "access keys but no console login")
        if not identity.get("has_console_access") and not identity.get("access_keys"):
            signals.append("neutral:user with no credentials")
    else:  # role
        kinds = list(_principals(identity.get("trust_policy")))
        if any(k == "Service" for k, _ in kinds):
            add("non_human", 4, "trusted by AWS service principal")
        for k, v in kinds:
            if k != "Federated":
                continue
            if "saml" in str(v).lower() or "sso" in identity["path"].lower():
                add("human", 3, "assumed via SAML/SSO federation")
            else:
                add("non_human", 1, "OIDC/web federation (often CI/CD)")
            break
        if "AWSReservedSSO_" in name or "/aws-reserved/sso.amazonaws.com/" in identity["path"]:
            add("human", 4, "AWS IAM Identity Center (SSO) role")
        elif HUMAN_ROLE_NAME.search(name):
            add("human", 1, "human-style role name")
        if any(k == "AWS" for k, _ in kinds) and not any(k in ("Service", "Federated") for k, _ in kinds):
            signals.append("neutral:assumable by AWS principals (could be human or workload)")

    return human, non_human, signals


def classify_identity(identity):
    human, non_human, signals = _score(identity)
    diff = human - non_human
    if diff >= CONFIDENCE_THRESHOLD:
        category = "human"
    elif -diff >= CONFIDENCE_THRESHOLD:
        category = "non_human"
    else:
        category = "uncertain"
    total = human + non_human
    confidence = round(abs(diff) / total, 2) if total else 0.0
    return {"category": category, "confidence": confidence,
            "human_score": human, "non_human_score": non_human, "signals": signals,
            "needs_review": category == "uncertain"}


def classify_identities(identities):
    for ident in identities:
        ident["classification"] = classify_identity(ident)
    return identities
