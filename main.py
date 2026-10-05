"""Member 4 - orchestrator. Runs collect -> classify -> detect -> verify.

Usage:  python main.py --sample        (offline demo)
        python main.py --profile myprof [--simulator]
"""
import argparse
import json
import logging
from collections import Counter
from pathlib import Path

log = logging.getLogger("analyzer")
SAMPLE_PATH = Path(__file__).parent / "data" / "sample_data.json"
SEVERITIES = ["critical", "high", "medium", "low"]
STATUSES = ["allowed", "blocked", "inconclusive"]
TEST_ACTIONS = ["s3:GetObject"]
MAX_PATHS = 40


def load_sample():
    with open(SAMPLE_PATH, encoding="utf-8") as fh:
        return json.load(fh)


def select_paths(data):
    """Yield (role, principal, bucket, action): every trusted principal x S3 bucket."""
    n = 0
    buckets = [r for r in data.get("resources", []) if r.get("type") in ("s3_bucket", "s3")]
    for ident in data.get("identities", []):
        # `type` is the AWS entity kind; this filter decides which identities reach the verifier,
        # so an unrecognised kind is skipped silently here.
        if ident.get("type") != "role":
            continue
        principals = []
        for st in (ident.get("trust_policy") or {}).get("Statement", []):
            if st.get("Effect") != "Allow":
                continue
            from analyzer.policy_utils import trust_principals
            principals += [v for _, v in trust_principals(st)]
        for pr in dict.fromkeys(principals):
            for b in buckets:
                for act in TEST_ACTIONS:
                    if n >= MAX_PATHS:
                        return
                    n += 1
                    yield ident, pr, b, act


def run_analysis(use_sample=False, profile=None, use_simulator=False):
    """Always returns a dict with identities, resources, findings, verifications, source, warnings."""
    warnings, source = [], "sample" if use_sample else "aws"
    try:
        if use_sample:
            data = load_sample()
        else:
            from collector.aws_collector import collect_aws_data
            data = collect_aws_data(profile=profile)
    except Exception as exc:
        log.exception("Collection failed")
        warnings.append(f"AWS collection failed ({type(exc).__name__}: {exc}). Showing sample data instead.")
        data, source = load_sample(), "sample"

    data.setdefault("identities", [])
    data.setdefault("resources", [])

    try:
        from collector.classifier import classify_identities
        data["identities"] = classify_identities(data["identities"])
    except Exception as exc:
        warnings.append(f"Classification failed: {exc}")

    findings, verifications = [], []
    try:
        from analyzer.risk_detector import detect_risks
        findings = detect_risks(data)
    except Exception as exc:
        log.exception("Risk detection failed")
        warnings.append(f"Risk detection failed: {exc}")

    try:
        from analyzer.access_verifier import verify_access
        session = None
        if use_simulator and source == "aws":
            import boto3
            session = boto3.Session(profile_name=profile)
        for ident, principal, bucket, action in select_paths(data):
            try:
                verifications.append(verify_access(ident, principal, bucket, action=action,
                                                   use_simulator=use_simulator and source == "aws",
                                                   session=session))
            except TypeError:  # teammate's verify_access has the 3-arg signature
                verifications.append(verify_access(ident, principal, bucket))
    except Exception as exc:
        log.exception("Verification failed")
        warnings.append(f"Access verification failed: {exc}")

    return {"identities": data["identities"], "resources": data["resources"],
            "findings": findings, "verifications": verifications,
            "source": source, "warnings": warnings}


def finding_severity(finding):
    """detect_risks() emits `risk` as Critical/High/Medium/Low; normalise to the lowercase buckets."""
    return str(finding.get("risk") or finding.get("severity") or "low").strip().lower()


def identity_type(identity):
    """classify_identities() puts human/non_human/uncertain in classification.category;
    `type` is the AWS entity kind (user/role), not the classification."""
    category = (identity.get("classification") or {}).get("category")
    return {"non_human": "non-human"}.get(category, category or "unknown")


def summarize(results):
    ids = results.get("identities", [])
    types = Counter(identity_type(i) for i in ids)
    sev = Counter(finding_severity(f) for f in results.get("findings", []))
    ver = Counter(v.get("status", "inconclusive") for v in results.get("verifications", []))
    return {"total_identities": len(ids), "human": types.get("human", 0),
            "non_human": types.get("non-human", 0),
            "total_findings": len(results.get("findings", [])),
            "by_severity": {s: sev.get(s, 0) for s in SEVERITIES},
            "by_status": {s: ver.get(s, 0) for s in STATUSES}}


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--sample", action="store_true")
    ap.add_argument("--profile")
    ap.add_argument("--simulator", action="store_true")
    a = ap.parse_args()
    res = run_analysis(use_sample=a.sample, profile=a.profile, use_simulator=a.simulator)
    print(json.dumps(summarize(res), indent=2))
    for w in res["warnings"]:
        print("WARNING:", w)
