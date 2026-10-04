# Member 1 – AWS Data Collection & Identity Classification

## How to run
```bash
pip install boto3
export AWS_PROFILE=capstone-readonly      # a profile in ~/.aws/credentials or SSO
python -m collector.aws_collector          # writes data/collected_data.json
```
Other members develop against `data/sample_data.json` (same schema, fictitious account).

## Credentials (secure method)
- Use a **test account** and a dedicated **read-only** IAM identity (managed policies `SecurityAudit` + `ViewOnlyAccess`, or `IAMReadOnlyAccess` + `AmazonS3ReadOnlyAccess`).
- Prefer AWS SSO / named profiles. Never hardcode keys or commit `~/.aws` or `.env` files (add them to `.gitignore`).

## Data collection process
1. Open a boto3 session from the profile / environment (no keys in code).
2. Collect **groups** (and their policies) so inherited permissions are not missed.
3. Collect **users**: tags, console access (login profile), MFA, access keys, groups, attached + inline policies.
4. Collect **roles**: tags, trust policy, attached + inline policies (AWS service-linked roles are skipped).
5. For every managed policy, fetch the default version so the actual JSON statements are available to the risk engine (cached to avoid repeat calls).
6. Collect **S3 buckets**: bucket policy, public access block, tags.
7. Every AWS call is wrapped in `_safe()`: `AccessDenied`, missing policy, etc. are logged and replaced by empty values, so one failure never aborts the run.
8. Run the classifier, add metadata, and write JSON.

## Classification process
Score-based rules; each rule adds points to *human* or *non_human* and stores a readable signal.

| Signal | Points |
|---|---|
| Tag `Type`/`IdentityType` = human/employee … | +4 human |
| Tag = service/application/automation … | +4 non-human |
| Role trusted by an AWS service principal (lambda, ec2 …) | +4 non-human |
| AWS SSO reserved role / SAML federation | +4 / +3 human |
| User has console password | +3 human |
| User has MFA | +2 human |
| Service-style name (`svc-`, `ci`, `jenkins` …) | +2 non-human |
| `first.last` style user name | +1 human |
| Access keys but no console login | +1 non-human |
| OIDC federation (often CI/CD) | +1 non-human |

Result: if one side leads by ≥ 2 points → `human` / `non_human`; otherwise **`uncertain`** with `needs_review: true`.
Users are not assumed human and roles are not assumed non-human; a role assumable by plain AWS principals stays uncertain.

## Common schema (summary)
```
{ metadata: {account_id, collected_at, schema_version},
  identities: [ {id, arn, name, type: user|role, path, created, last_used, tags,
                 has_console_access, mfa_enabled, access_keys[], groups[],
                 attached_policies[{name, arn, document}], inline_policies[{name, document}],
                 group_policies[], trust_policy, classification{category, confidence, signals[], needs_review}} ],
  resources:  [ {id, arn, name, type: s3_bucket, bucket_policy, public_access_block, tags} ] }
```
Agree on this with the team on day 1; changing it later breaks everyone's modules.
