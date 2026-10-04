# What the Access-Path Verifier Does and Does Not Establish

## What it does
For the scenario **principal → sts:AssumeRole → IAM role → S3 action on a resource**, it:
1. Evaluates the role's **trust policy** locally (Allow/Deny, Principal, Action, and the conditions
   StringEquals, StringNotEquals, StringLike, ArnEquals, ArnLike).
2. Calls **IAM Policy Simulator** (`simulate_principal_policy`) for the role, action and resource.
3. Returns `allowed`, `blocked` or `inconclusive` with evidence and a list of unresolved checks.

## Status meaning
- **allowed** – trust policy permits the principal AND the simulator reports `allowed`. This is a *policy-level* result.
- **blocked** – trust policy denies/does not list the principal, or the simulator reports explicit/implicit deny.
- **inconclusive** – an unsupported condition, missing context value, simulator error, or missing input prevented a decision.

## What it does NOT establish
- Runtime success. `allowed` is not proof that a real call would succeed.
- Not evaluated: SCPs, S3 bucket policies/ACLs (unless supplied), Block Public Access, VPC endpoint policies,
  KMS key policies, session policies, network reachability, MFA/session state.
- Same-account root trust only means the principal is *eligible*; the principal's own IAM policy must also allow `sts:AssumeRole`.
- Unsupported trust constructs (NotPrincipal, NotAction, other condition operators) yield `inconclusive`.
- Only the tested action/resource pair is checked, not all paths.
