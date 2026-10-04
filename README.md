# Permission Analysis and Risk Detection (Member 2)

```
iam_risk/
├── analyzer/policy_parser.py     # normalises IAM policies, action matching, action power levels
├── analyzer/risk_detector.py     # detect_risks(data) + the 5 rules + severity logic
├── tests/test_risk_detector.py   # pytest suite
├── tests/fixtures/*.json         # safe / risky / context / edge-case policies
└── data/sample_input.json        # example input in the agreed schema
```

Run: `pip install -r requirements.txt && pytest -v`
Demo: `python -m analyzer.risk_detector data/sample_input.json`

## Input / output contract
Input: `{"account_id", "sensitive_resources": [...], "identities": [{name, type, arn, classification,
trust_policy, attached_policies:[{name, document}], inline_policies:[...], group_policies:[{group, name, document}]}]}`

Output (sorted Critical -> Low): `identity, risk, reason, resource` (required by the brief) plus
`rule, policy, evidence` (for dashboard grouping and for Member 3's verification).

## Detection logic
1. **Parse**: every policy is flattened into statements (`Statement`/`Action`/`Resource`/`Principal` may be
   scalar or list; `NotAction`, `NotResource`, `Condition` are kept).
2. **Collect**: managed, inline and group policies for each identity are analysed together.
3. **Apply rules**
   | Rule | Flags | Base severity |
   |---|---|---|
   | WILDCARD_ACTION / ALLOW_NOT_ACTION | `*`, `iam:*`, `service:*`, Allow+NotAction | `*` on `*` Critical; `iam:*` Critical on `*`, High scoped; `s3:*` etc. High on `*`/sensitive, Medium scoped; other services Medium/Low |
   | UNRESTRICTED_RESOURCE | non-wildcard actions on `Resource:*` | permission/write High, read Medium, list Low; allow-list for actions that need `*` |
   | TRUST_* | public principal, external account, same-account root, web-identity/SAML without sub/aud | `Principal:*` Critical; external root w/o ExternalId/OrgID High; with it Low; same-account root Low |
   | SENSITIVE_RESOURCE_ACCESS | S3 actions reaching a configured sensitive resource | list Low, read Medium, write High, permission/admin Critical; +1 if via `Resource:*` |
   | PRIVILEGE_ESCALATION | curated action combinations across all of an identity's policies (PassRole+RunInstances, CreatePolicyVersion, Attach/Put policy, UpdateAssumeRolePolicy, ...) | per-combo High/Critical |
4. **Score context**: severity is lowered one level when mitigating conditions exist (`aws:SourceIp`,
   `aws:PrincipalOrgID`, `aws:RequestedRegion`, `sts:ExternalId`, ...), lowered for a PassRole scoped to
   specific roles, and raised for sensitive or unrestricted targets.
5. **Output**: de-duplicated, JSON-compatible findings, each with a reason.

## Limitations
- SCPs, permission boundaries and session policies are not evaluated; resource-based policies only partially.
- Conditions are judged heuristically from a fixed list of common keys, not evaluated.
- Explicit Deny statements are listed in `evidence.explicit_denies` but do not remove or lower findings.
- `NotAction`/`NotResource` are handled conservatively.
- Escalation detection covers a curated list of known paths only; sensitive resources must be configured.
- Static analysis shows what is permitted on paper; the IAM Policy Simulator (Member 3) confirms real access.
