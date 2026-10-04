import pytest
from analyzer.access_verifier import verify_access, check_trust_policy

ACCOUNT = "111122223333"
ROLE_ARN = f"arn:aws:iam::{ACCOUNT}:role/S3ReadRole"
BUCKET_OBJ = "arn:aws:s3:::capstone-bucket/data.txt"

EC2_TRUST = {"Version": "2012-10-17", "Statement": [
    {"Sid": "ec2", "Effect": "Allow", "Principal": {"Service": "ec2.amazonaws.com"}, "Action": "sts:AssumeRole"}]}


class FakeIAM:
    """Stands in for boto3 IAM client; no AWS account needed."""
    def __init__(self, decision="allowed", raises=None, missing=None):
        self.decision, self.raises, self.missing = decision, raises, missing
        self.calls = []

    def simulate_principal_policy(self, **kw):
        self.calls.append(kw)
        if self.raises:
            raise self.raises
        return {"EvaluationResults": [{
            "EvalActionName": kw["ActionNames"][0], "EvalDecision": self.decision,
            "MatchedStatements": [{"SourcePolicyId": "S3ReadPolicy"}],
            "MissingContextValues": self.missing or []}]}


def role(trust=EC2_TRUST):
    return {"name": "S3ReadRole", "arn": ROLE_ARN, "trust_policy": trust}


def test_allowed_path():
    r = verify_access(role(), "ec2.amazonaws.com", BUCKET_OBJ, iam_client=FakeIAM("allowed"))
    assert r["status"] == "allowed"
    assert r["verification_level"] == "policy_evaluation_only"
    assert any("[Trust]" in e for e in r["evidence"])


def test_trust_policy_blocks_principal():
    iam = FakeIAM("allowed")
    r = verify_access(role(), "lambda.amazonaws.com", BUCKET_OBJ, iam_client=iam)
    assert r["status"] == "blocked"
    assert iam.calls == []          # simulator never reached


def test_explicit_trust_deny_blocks():
    trust = {"Statement": EC2_TRUST["Statement"] + [
        {"Sid": "deny", "Effect": "Deny", "Principal": {"Service": "ec2.amazonaws.com"}, "Action": "sts:AssumeRole"}]}
    r = verify_access(role(trust), "ec2.amazonaws.com", BUCKET_OBJ, iam_client=FakeIAM())
    assert r["status"] == "blocked"


def test_explicit_permission_deny_blocks():
    r = verify_access(role(), "ec2.amazonaws.com", BUCKET_OBJ, iam_client=FakeIAM("explicitDeny"))
    assert r["status"] == "blocked"
    assert any("explicit deny" in e for e in r["evidence"])


def test_implicit_deny_blocks():
    assert verify_access(role(), "ec2.amazonaws.com", BUCKET_OBJ, iam_client=FakeIAM("implicitDeny"))["status"] == "blocked"


def test_simulator_failure_is_inconclusive():
    r = verify_access(role(), "ec2.amazonaws.com", BUCKET_OBJ, iam_client=FakeIAM(raises=RuntimeError("AccessDenied")))
    assert r["status"] == "inconclusive" and r["unresolved"]


def test_unsupported_condition_is_inconclusive():
    trust = {"Statement": [{"Effect": "Allow", "Principal": {"Service": "ec2.amazonaws.com"},
                            "Action": "sts:AssumeRole", "Condition": {"IpAddress": {"aws:SourceIp": "1.2.3.4/32"}}}]}
    r = verify_access(role(trust), "ec2.amazonaws.com", BUCKET_OBJ, iam_client=FakeIAM())
    assert r["status"] == "inconclusive"


def test_missing_context_value_is_inconclusive():
    trust = {"Statement": [{"Effect": "Allow", "Principal": {"AWS": "arn:aws:iam::999988887777:root"},
                            "Action": "sts:AssumeRole", "Condition": {"StringEquals": {"sts:ExternalId": "abc"}}}]}
    arn = "arn:aws:iam::999988887777:user/bob"
    assert verify_access(role(trust), arn, BUCKET_OBJ, iam_client=FakeIAM())["status"] == "inconclusive"
    ok = verify_access(role(trust), arn, BUCKET_OBJ, iam_client=FakeIAM(), trust_context={"sts:ExternalId": "abc"})
    assert ok["status"] == "allowed"
    bad = verify_access(role(trust), arn, BUCKET_OBJ, iam_client=FakeIAM(), trust_context={"sts:ExternalId": "zzz"})
    assert bad["status"] == "blocked"


def test_no_iam_client_never_returns_allowed():
    r = verify_access(role(), "ec2.amazonaws.com", BUCKET_OBJ)
    assert r["status"] == "inconclusive"


def test_missing_role_arn():
    assert verify_access({"name": "x"}, "ec2.amazonaws.com", BUCKET_OBJ)["status"] == "inconclusive"


def test_wildcard_principal_trust():
    t = {"Statement": [{"Effect": "Allow", "Principal": "*", "Action": "sts:AssumeRole"}]}
    assert check_trust_policy(t, "arn:aws:iam::1:user/x")["status"] == "allowed"
