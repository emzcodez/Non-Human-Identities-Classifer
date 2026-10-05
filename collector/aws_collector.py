"""
aws_collector.py
Collects IAM users, roles, policies, trust policies and S3 bucket data,
and returns them in the team's common schema.

Credentials: never hardcode. boto3 reads them from (in order) environment
variables, ~/.aws/credentials profiles (set AWS_PROFILE), or an SSO/role session.
Use a dedicated read-only identity (e.g. SecurityAudit + ViewOnlyAccess) in a TEST account.
"""
import json
import logging
import os
from datetime import datetime, timezone
from urllib.parse import unquote

import boto3
from botocore.exceptions import BotoCoreError, ClientError

from collector.classifier import classify_identities

log = logging.getLogger(__name__)


def _safe(fn, default=None, what=""):
    """Run an AWS call; on failure log it and return a default instead of crashing."""
    try:
        return fn()
    except (ClientError, BotoCoreError) as e:
        log.warning("Could not retrieve %s: %s", what, e)
        return default


def _decode_doc(doc):
    """Policy documents are sometimes URL-encoded strings; normalise to dict."""
    if isinstance(doc, str):
        try:
            return json.loads(unquote(doc))
        except json.JSONDecodeError:
            return {}
    return doc or {}


def _tags(tag_list):
    return {t["Key"]: t["Value"] for t in (tag_list or [])}


def _iso(dt):
    return dt.isoformat() if isinstance(dt, datetime) else None


# ---------- policies ----------
_policy_cache = {}


def _managed_policy_doc(iam, arn):
    if arn in _policy_cache:
        return _policy_cache[arn]
    meta = _safe(lambda: iam.get_policy(PolicyArn=arn)["Policy"], None, f"policy {arn}")
    doc = {}
    if meta:
        ver = _safe(
            lambda: iam.get_policy_version(PolicyArn=arn, VersionId=meta["DefaultVersionId"])["PolicyVersion"],
            None, f"policy version {arn}")
        doc = _decode_doc(ver["Document"]) if ver else {}
    _policy_cache[arn] = doc
    return doc


def _attached(iam, lister, **kwargs):
    out = []
    pages = _safe(lambda: list(iam.get_paginator(lister).paginate(**kwargs)), [], lister)
    for page in pages:
        for p in page.get("AttachedPolicies", []):
            out.append({"name": p["PolicyName"], "arn": p["PolicyArn"],
                        "document": _managed_policy_doc(iam, p["PolicyArn"])})
    return out


def _inline(iam, list_fn, get_fn, name_key, entity_name):
    out = []
    names = _safe(lambda: list_fn(**{name_key: entity_name})["PolicyNames"], [], "inline policy names")
    for n in names:
        res = _safe(lambda: get_fn(**{name_key: entity_name, "PolicyName": n}), None, f"inline policy {n}")
        if res:
            out.append({"name": n, "document": _decode_doc(res["PolicyDocument"])})
    return out


# ---------- IAM ----------
def _collect_groups(iam):
    groups = {}
    pages = _safe(lambda: list(iam.get_paginator("list_groups").paginate()), [], "groups")
    for page in pages:
        for g in page["Groups"]:
            gn = g["GroupName"]
            groups[gn] = {
                "attached_policies": _attached(iam, "list_attached_group_policies", GroupName=gn),
                "inline_policies": _inline(iam, iam.list_group_policies, iam.get_group_policy, "GroupName", gn),
            }
    return groups


def _collect_users(iam, groups):
    users = []
    pages = _safe(lambda: list(iam.get_paginator("list_users").paginate()), [], "users")
    for page in pages:
        for u in page["Users"]:
            name = u["UserName"]
            tags = _safe(lambda: _tags(iam.list_user_tags(UserName=name)["Tags"]), {}, f"tags of {name}")
            has_console = _login_profile_exists(iam, name)
            keys = _safe(lambda: iam.list_access_keys(UserName=name)["AccessKeyMetadata"], [], f"keys of {name}")
            mfa = _safe(lambda: iam.list_mfa_devices(UserName=name)["MFADevices"], [], f"MFA of {name}")
            grp_names = _safe(lambda: [g["GroupName"] for g in iam.list_groups_for_user(UserName=name)["Groups"]],
                              [], f"groups of {name}")
            users.append({
                "id": u["Arn"], "arn": u["Arn"], "name": name, "type": "user", "path": u["Path"],
                "created": _iso(u["CreateDate"]),
                "last_used": _iso(u.get("PasswordLastUsed")),
                "tags": tags,
                "has_console_access": has_console,
                "mfa_enabled": bool(mfa),
                "access_keys": [{"id": k["AccessKeyId"], "status": k["Status"], "created": _iso(k["CreateDate"])}
                                for k in keys],
                "groups": grp_names,
                "attached_policies": _attached(iam, "list_attached_user_policies", UserName=name),
                "inline_policies": _inline(iam, iam.list_user_policies, iam.get_user_policy, "UserName", name),
                "group_policies": [p for g in grp_names for p in
                                   groups.get(g, {}).get("attached_policies", []) +
                                   groups.get(g, {}).get("inline_policies", [])],
                "trust_policy": None,
            })
    return users


def _login_profile_exists(iam, name):
    try:
        iam.get_login_profile(UserName=name)
        return True
    except iam.exceptions.NoSuchEntityException:
        return False
    except (ClientError, BotoCoreError) as e:
        log.warning("login profile check failed for %s: %s", name, e)
        return False


def _collect_roles(iam):
    roles = []
    pages = _safe(lambda: list(iam.get_paginator("list_roles").paginate()), [], "roles")
    for page in pages:
        for r in page["Roles"]:
            name = r["RoleName"]
            # Skip AWS service-linked roles (not customer-managed, noisy)
            if r["Path"].startswith("/aws-service-role/"):
                continue
            tags = _safe(lambda: _tags(iam.list_role_tags(RoleName=name)["Tags"]), {}, f"tags of {name}")
            last = (r.get("RoleLastUsed") or {}).get("LastUsedDate")
            roles.append({
                "id": r["Arn"], "arn": r["Arn"], "name": name, "type": "role", "path": r["Path"],
                "created": _iso(r["CreateDate"]), "last_used": _iso(last), "tags": tags,
                "max_session_duration": r.get("MaxSessionDuration"),
                "attached_policies": _attached(iam, "list_attached_role_policies", RoleName=name),
                "inline_policies": _inline(iam, iam.list_role_policies, iam.get_role_policy, "RoleName", name),
                "group_policies": [],
                "trust_policy": _decode_doc(r.get("AssumeRolePolicyDocument")),
            })
    return roles


# ---------- S3 ----------
def _collect_buckets(s3):
    buckets = []
    resp = _safe(lambda: s3.list_buckets()["Buckets"], [], "S3 buckets")
    for b in resp:
        name = b["Name"]

        def _policy():
            try:
                return json.loads(s3.get_bucket_policy(Bucket=name)["Policy"])
            except ClientError as e:
                if e.response["Error"]["Code"] == "NoSuchBucketPolicy":
                    return None
                raise

        def _pab():
            try:
                return s3.get_public_access_block(Bucket=name)["PublicAccessBlockConfiguration"]
            except ClientError as e:
                if e.response["Error"]["Code"] == "NoSuchPublicAccessBlockConfiguration":
                    return None
                raise

        buckets.append({
            "id": f"arn:aws:s3:::{name}", "arn": f"arn:aws:s3:::{name}", "name": name, "type": "s3_bucket",
            "created": _iso(b.get("CreationDate")),
            "bucket_policy": _safe(_policy, None, f"policy of {name}"),
            "public_access_block": _safe(_pab, None, f"public access block of {name}"),
            "tags": _safe(lambda: _tags(s3.get_bucket_tagging(Bucket=name)["TagSet"]), {}, f"tags of {name}"),
        })
    return buckets


# ---------- public API ----------
def collect_aws_data(profile=None, region=None):
    """Collect IAM + S3 data and return {'metadata', 'identities', 'resources'}."""
    session = boto3.Session(profile_name=profile or os.getenv("AWS_PROFILE"),
                            region_name=region or os.getenv("AWS_REGION", "us-east-1"))
    iam, s3, sts = session.client("iam"), session.client("s3"), session.client("sts")

    account = _safe(lambda: sts.get_caller_identity()["Account"], "unknown", "caller identity")
    groups = _collect_groups(iam)
    identities = _collect_users(iam, groups) + _collect_roles(iam)
    identities = classify_identities(identities)

    return {
        "metadata": {"account_id": account,
                     "collected_at": datetime.now(timezone.utc).isoformat(),
                     "schema_version": "1.0"},
        "identities": identities,
        "resources": _collect_buckets(s3),
    }


def save_to_json(data, path="data/collected_data.json"):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        json.dump(data, f, indent=2, default=str)
    return path


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    out = save_to_json(collect_aws_data())
    print(f"Saved to {out}")
