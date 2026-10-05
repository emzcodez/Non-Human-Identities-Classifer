import json
import pathlib

import pytest

from analyzer.policy_parser import (
    PolicyParseError, action_level, action_matches, normalize_policy,
)
from analyzer.risk_detector import detect_risks

TESTS = pathlib.Path(__file__).resolve().parent
REPO = TESTS.parent
FIXTURES = TESTS / "fixtures"
ACCOUNT = "123456789012"
REQUIRED_KEYS = {"identity", "risk", "reason", "resource", "rule", "policy", "evidence"}
VALID_SEVERITIES = {"Critical", "High", "Medium", "Low"}


def fx(name):
    return json.loads((FIXTURES / f"{name}.json").read_text())


def identity(policy=None, trust=None, name="TestRole", **extra):
    ident = {"name": name, "type": "role", "arn": f"arn:aws:iam::{ACCOUNT}:role/{name}",
             "attached_policies": [{"name": "TestPolicy", "document": policy}] if policy is not None else [],
             "inline_policies": []}
    if trust is not None:
        ident["trust_policy"] = trust
    ident.update(extra)
    return ident


def run(ident, sensitive=None):
    return detect_risks({"account_id": ACCOUNT, "identities": [ident],
                         "sensitive_resources": sensitive or []})


def by_rule(findings, rule):
    return [f for f in findings if f["rule"] == rule]


# ------------------------------------------------------------- parser
def test_single_dict_statement_and_string_action_are_normalised():
    stmts = normalize_policy(fx("edge_single_dict_statement_string_action"))
    assert len(stmts) == 1
    assert stmts[0]["actions"] == ["S3:GetObject"]
    assert stmts[0]["resources"] == ["arn:aws:s3:::reports-bucket/*"]


def test_empty_policy_returns_no_statements_and_no_findings():
    assert normalize_policy(fx("edge_empty_policy")) == []
    assert run(identity(fx("edge_empty_policy"))) == []


def test_action_matching_is_case_insensitive_and_supports_wildcards():
    assert action_matches("s3:Get*", "S3:GETOBJECT")
    assert action_matches("*", "iam:CreateUser")
    assert not action_matches("s3:Get*", "s3:PutObject")


def test_deny_statement_is_parsed():
    doc = {"Statement": [{"Effect": "Deny", "Action": "s3:*", "Resource": "*"}]}
    assert normalize_policy(doc)[0]["effect"] == "Deny"


def test_invalid_effect_raises():
    with pytest.raises(PolicyParseError):
        normalize_policy({"Statement": [{"Effect": "Maybe", "Action": "s3:*", "Resource": "*"}]})


def test_action_levels():
    assert action_level("*") == "admin"
    assert action_level("iam:PassRole") == "permission"
    assert action_level("s3:DeleteObject") == "write"
    assert action_level("s3:GetObject") == "read"
    assert action_level("ec2:DescribeInstances") == "list"


# ------------------------------------------------------- safe policies
@pytest.mark.parametrize("name", ["safe_readonly_one_bucket", "safe_lambda_basic_logging"])
def test_safe_permission_policies_produce_no_findings(name):
    assert run(identity(fx(name))) == []


def test_service_trust_policy_is_safe():
    assert run(identity(trust=fx("safe_lambda_trust"))) == []


# --------------------------------------------------- rule 1: wildcards
def test_full_admin_is_critical():
    f = by_rule(run(identity(fx("risky_admin_star"))), "WILDCARD_ACTION")
    assert len(f) == 1 and f[0]["risk"] == "Critical"


def test_s3_star_on_all_resources_is_high():
    f = by_rule(run(identity(fx("risky_s3_star_all"))), "WILDCARD_ACTION")
    assert f[0]["risk"] == "High"


def test_iam_star_is_critical():
    f = by_rule(run(identity(fx("risky_iam_star"))), "WILDCARD_ACTION")
    assert f[0]["risk"] == "Critical"


def test_s3_star_on_single_non_sensitive_bucket_is_only_medium():
    findings = run(identity(fx("context_s3_star_single_bucket")))
    assert [f["rule"] for f in findings] == ["WILDCARD_ACTION"]
    assert findings[0]["risk"] == "Medium"


def test_s3_star_on_sensitive_bucket_is_high():
    doc = {"Statement": [{"Effect": "Allow", "Action": "s3:*",
                          "Resource": "arn:aws:s3:::prod-customer-data/*"}]}
    f = by_rule(run(identity(doc), ["prod-customer-data"]), "WILDCARD_ACTION")
    assert f[0]["risk"] == "High"


def test_partial_service_wildcard_is_not_a_wildcard_finding():
    doc = {"Statement": [{"Effect": "Allow", "Action": "ec2:Describe*", "Resource": "*"}]}
    assert run(identity(doc)) == []


def test_allow_not_action_is_flagged():
    doc = {"Statement": [{"Effect": "Allow", "NotAction": "iam:*", "Resource": "*"}]}
    f = by_rule(run(identity(doc)), "ALLOW_NOT_ACTION")
    assert f and f[0]["risk"] == "Critical"


# ----------------------------------------- rule 2: unrestricted resources
def test_write_on_star_is_high():
    f = by_rule(run(identity(fx("risky_delete_on_star"))), "UNRESTRICTED_RESOURCE")
    assert f[0]["risk"] == "High"


def test_restricting_condition_downgrades_severity():
    f = by_rule(run(identity(fx("context_star_resource_with_condition"))), "UNRESTRICTED_RESOURCE")
    assert f[0]["risk"] == "Medium"
    assert f[0]["evidence"]["mitigating_conditions"] is True


def test_read_on_star_is_medium_and_list_on_star_is_low():
    read = {"Statement": [{"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"}]}
    lst = {"Statement": [{"Effect": "Allow", "Action": "s3:ListBucket", "Resource": "*"}]}
    assert by_rule(run(identity(read)), "UNRESTRICTED_RESOURCE")[0]["risk"] == "Medium"
    assert by_rule(run(identity(lst)), "UNRESTRICTED_RESOURCE")[0]["risk"] == "Low"


# ------------------------------------------------------ rule 3: trust
def test_public_principal_trust_is_critical():
    f = by_rule(run(identity(trust=fx("risky_trust_public_principal"))), "TRUST_PUBLIC_PRINCIPAL")
    assert f[0]["risk"] == "Critical"


def test_external_account_without_externalid_is_high():
    f = by_rule(run(identity(trust=fx("risky_trust_external_no_externalid"))), "TRUST_EXTERNAL_ACCOUNT")
    assert f[0]["risk"] == "High"


def test_external_account_with_externalid_is_low():
    f = by_rule(run(identity(trust=fx("context_trust_external_with_externalid"))), "TRUST_EXTERNAL_ACCOUNT")
    assert f[0]["risk"] == "Low"


def test_same_account_root_trust_is_low():
    trust = {"Statement": [{"Effect": "Allow", "Principal": {"AWS": f"arn:aws:iam::{ACCOUNT}:root"},
                            "Action": "sts:AssumeRole"}]}
    f = by_rule(run(identity(trust=trust)), "TRUST_SAME_ACCOUNT_ROOT")
    assert f[0]["risk"] == "Low"


def test_web_identity_trust_without_sub_is_high_and_with_sub_is_clean():
    bad = run(identity(trust=fx("risky_trust_web_identity_no_sub")))
    good = run(identity(trust=fx("context_trust_web_identity_with_sub")))
    assert by_rule(bad, "TRUST_FEDERATED_NO_SUBJECT")[0]["risk"] == "High"
    assert good == []


# --------------------------------------- rule 4: sensitive resource access
def test_write_to_sensitive_bucket_is_high():
    f = by_rule(run(identity(fx("risky_sensitive_bucket_write")), ["arn:aws:s3:::finance-*"]),
                "SENSITIVE_RESOURCE_ACCESS")
    assert f[0]["risk"] == "High"
    assert f[0]["resource"] == "arn:aws:s3:::finance-*"


def test_read_of_sensitive_bucket_is_medium_but_star_resource_raises_it():
    scoped = {"Statement": [{"Effect": "Allow", "Action": "s3:GetObject",
                             "Resource": "arn:aws:s3:::prod-customer-data/*"}]}
    star = {"Statement": [{"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"}]}
    assert by_rule(run(identity(scoped), ["prod-customer-data"]), "SENSITIVE_RESOURCE_ACCESS")[0]["risk"] == "Medium"
    assert by_rule(run(identity(star), ["prod-customer-data"]), "SENSITIVE_RESOURCE_ACCESS")[0]["risk"] == "High"


def test_no_sensitive_finding_without_sensitive_config_or_match():
    assert by_rule(run(identity(fx("risky_sensitive_bucket_write"))), "SENSITIVE_RESOURCE_ACCESS") == []
    assert by_rule(run(identity(fx("safe_readonly_one_bucket")), ["prod-customer-data"]),
                   "SENSITIVE_RESOURCE_ACCESS") == []


# ----------------------------------------------- rule 5: combinations
def test_passrole_plus_runinstances_is_escalation():
    f = by_rule(run(identity(fx("risky_passrole_runinstances"))), "PRIVILEGE_ESCALATION")
    assert len(f) == 1 and f[0]["risk"] == "High"
    assert f[0]["evidence"]["combo"] == "PASSROLE_EC2"


def test_passrole_alone_is_not_a_combo():
    doc = {"Statement": [{"Effect": "Allow", "Action": "iam:PassRole", "Resource": "*"}]}
    assert by_rule(run(identity(doc)), "PRIVILEGE_ESCALATION") == []


def test_passrole_scoped_to_one_role_downgrades_combo():
    doc = {"Statement": [
        {"Effect": "Allow", "Action": "iam:PassRole", "Resource": f"arn:aws:iam::{ACCOUNT}:role/AppRole"},
        {"Effect": "Allow", "Action": "ec2:RunInstances", "Resource": "*"}]}
    assert by_rule(run(identity(doc)), "PRIVILEGE_ESCALATION")[0]["risk"] == "Medium"


def test_combination_across_two_policies_is_detected():
    ident = identity(
        {"Statement": [{"Effect": "Allow", "Action": "iam:PassRole", "Resource": "*"}]},
        inline_policies=[{"name": "Launch", "document":
                          {"Statement": [{"Effect": "Allow", "Action": "ec2:RunInstances", "Resource": "*"}]}}])
    f = by_rule(run(ident), "PRIVILEGE_ESCALATION")
    assert f and "Launch" in f[0]["policy"] and "TestPolicy" in f[0]["policy"]


def test_create_policy_version_is_critical():
    f = by_rule(run(identity(fx("risky_policy_version"))), "PRIVILEGE_ESCALATION")
    assert f[0]["risk"] == "Critical"


def test_s3_policy_tampering_combo():
    doc = {"Statement": [{"Effect": "Allow",
                          "Action": ["s3:PutBucketPolicy", "s3:PutBucketPublicAccessBlock"],
                          "Resource": "arn:aws:s3:::reports-bucket"}]}
    assert by_rule(run(identity(doc)), "PRIVILEGE_ESCALATION")[0]["evidence"]["combo"] == "S3_POLICY_TAMPERING"


def test_full_admin_does_not_generate_combo_noise():
    assert by_rule(run(identity(fx("risky_admin_star"))), "PRIVILEGE_ESCALATION") == []


# --------------------------------------------- aggregation and output
def test_inline_and_group_policies_are_analysed():
    user = {"name": "bob", "type": "user", "arn": f"arn:aws:iam::{ACCOUNT}:user/bob",
            "inline_policies": [{"name": "Inline", "document": fx("risky_delete_on_star")}],
            "group_policies": [{"group": "Admins", "name": "GroupAdmin", "document": fx("risky_admin_star")}]}
    policies = {f["policy"] for f in run(user)}
    assert {"Inline", "GroupAdmin"} <= policies


def test_explicit_deny_is_noted_in_evidence():
    doc = {"Statement": [
        {"Effect": "Allow", "Action": "s3:*", "Resource": "*"},
        {"Effect": "Deny", "Action": "s3:DeleteBucket", "Resource": "*"}]}
    f = by_rule(run(identity(doc)), "WILDCARD_ACTION")[0]
    assert f["evidence"]["explicit_denies"][0]["actions"] == ["s3:DeleteBucket"]


def test_unparseable_policy_is_reported_not_crashed():
    bad = {"Statement": [{"Effect": "Nope", "Action": "s3:*", "Resource": "*"}]}
    f = run(identity(bad))
    assert f[0]["rule"] == "POLICY_PARSE_ERROR"


def test_invalid_input_raises():
    with pytest.raises(ValueError):
        detect_risks("not a dict")


def test_output_format_is_consistent_and_json_serialisable():
    sample = json.loads((REPO / "data" / "sample_input.json").read_text())
    findings = detect_risks(sample)
    assert findings
    for f in findings:
        assert REQUIRED_KEYS <= set(f)
        assert f["risk"] in VALID_SEVERITIES
        assert f["reason"] and isinstance(f["resource"], str)
    json.dumps(findings)  # must not raise


def test_findings_are_sorted_most_severe_first():
    sample = json.loads((REPO / "data" / "sample_input.json").read_text())
    order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}
    ranks = [order[f["risk"]] for f in detect_risks(sample)]
    assert ranks == sorted(ranks)
