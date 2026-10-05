"""Streamlit dashboard.  Run:  streamlit run app.py"""
import json

import pandas as pd
import streamlit as st

from main import (SEVERITIES, STATUSES, finding_severity, identity_type,
                  run_analysis, summarize)

st.set_page_config(page_title="AWS Identity Risk Analyzer", page_icon="🛡️", layout="wide")

SEV_ICON = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢"}
STATUS_ICON = {"allowed": "✅", "blocked": "⛔", "inconclusive": "⚠️"}
IDENTITY_TYPES = ["human", "non-human", "uncertain"]


def _policies(identity):
    """Flatten the collector's three policy buckets into one displayable list."""
    out = []
    for key, label in (("attached_policies", "attached"), ("inline_policies", "inline"),
                       ("group_policies", "group")):
        for pol in identity.get(key) or []:
            out.append({"name": pol.get("name", "?"), "type": label, "document": pol.get("document") or {}})
    return out


def _res(value):
    """Verification results carry the whole bucket dict; show its ARN."""
    return value.get("arn", "?") if isinstance(value, dict) else value


# ---------------------------------------------------------------- data loading
def load(use_sample, profile, simulator):
    with st.spinner("Running analysis..."):
        try:
            st.session_state["results"] = run_analysis(use_sample=use_sample, profile=profile or None,
                                                       use_simulator=simulator)
        except Exception as exc:  # last line of defence
            st.session_state["results"] = {"identities": [], "resources": [], "findings": [],
                                           "verifications": [], "source": "none",
                                           "warnings": [f"Unexpected error: {exc}"]}


with st.sidebar:
    st.title("🛡️ Controls")
    use_sample = st.toggle("Use sample data", value=True,
                           help="Works offline. Turn off to scan your AWS account.")
    profile = st.text_input("AWS profile (optional)", disabled=use_sample)
    simulator = st.checkbox("Cross-check with IAM Policy Simulator", disabled=use_sample)
    if st.button("▶ Run analysis", type="primary", use_container_width=True):
        load(use_sample, profile, simulator)
    st.caption("Credentials come from your local AWS config / environment, never from this app.")

if "results" not in st.session_state:
    load(True, "", False)

R = st.session_state["results"]
S = summarize(R)
identities, findings, verifs = R.get("identities", []), R.get("findings", []), R.get("verifications", [])

st.title("AWS Identity-Centric Risk Analysis & Verification")
if R.get("source") == "sample":
    st.info("📁 Showing **sample data** (no live AWS account queried).")
elif R.get("source") == "aws":
    st.success("☁️ Showing **live AWS data**.")
for w in R.get("warnings", []):
    st.warning(w)

tabs = st.tabs(["📊 Overview", "👤 Identity Inventory", "🚨 Risk Findings",
                "🔍 Verification Results", "🛠️ Recommendations"])

# -------------------------------------------------------------------- overview
with tabs[0]:
    c = st.columns(4)
    c[0].metric("Total identities", S["total_identities"])
    c[1].metric("Human", S["human"])
    c[2].metric("Non-human", S["non_human"])
    c[3].metric("Risk findings", S["total_findings"])
    st.subheader("Findings by severity")
    c = st.columns(4)
    for col, sev in zip(c, SEVERITIES):
        col.metric(f"{SEV_ICON[sev]} {sev.title()}", S["by_severity"][sev])
    st.bar_chart(pd.DataFrame({"count": S["by_severity"]}).loc[SEVERITIES])
    st.subheader("Verification outcomes")
    c = st.columns(3)
    for col, s in zip(c, STATUSES):
        col.metric(f"{STATUS_ICON[s]} {s.title()}", S["by_status"][s])
    st.download_button("⬇ Download full report (JSON)", json.dumps(R, indent=2, default=str),
                       file_name="risk_report.json", mime="application/json")

# ------------------------------------------------------------------- inventory
with tabs[1]:
    if not identities:
        st.info("No identities collected.")
    else:
        c1, c2 = st.columns([2, 1])
        q = c1.text_input("🔎 Search by name or ARN")
        t = c2.multiselect("Type", IDENTITY_TYPES, default=IDENTITY_TYPES)
        rows = []
        for i in identities:
            kind = i.get("type", "?")
            rows.append({"Name": i.get("name", "?"), "Kind": kind, "Type": identity_type(i),
                         "Why": "; ".join((i.get("classification") or {}).get("signals", [])),
                         "Policies": ", ".join(p["name"] for p in _policies(i)) or "—",
                         "MFA": ("yes" if i.get("mfa_enabled") else "no") if kind == "user" else "—",
                         "ARN": i.get("arn", "")})
        df = pd.DataFrame(rows)
        df = df[df["Type"].isin(t)]
        if q:
            df = df[df["Name"].str.contains(q, case=False) | df["ARN"].str.contains(q, case=False)]
        st.dataframe(df, use_container_width=True, hide_index=True)
        names = df["Name"].tolist()
        if names:
            pick = st.selectbox("Inspect identity", names)
            ident = next(i for i in identities if i.get("name") == pick)
            a, b = st.columns(2)
            a.markdown("**Policies**")
            for p in _policies(ident):
                with a.expander(f"{p['name']} ({p['type']})"):
                    st.json(p["document"])
            b.markdown("**Trust policy**")
            b.json(ident.get("trust_policy") or {"info": "N/A (IAM user)"})

# -------------------------------------------------------------------- findings
with tabs[2]:
    if not findings:
        st.success("No risk findings detected.")
    else:
        c1, c2 = st.columns([2, 1])
        q = c1.text_input("🔎 Search findings")
        sevs = c2.multiselect("Severity", SEVERITIES, default=SEVERITIES)
        def _label(x):
            return f"{x.get('rule')} - {x.get('policy')} ({x.get('identity')})"

        flt = [f for f in findings if finding_severity(f) in sevs and
               (not q or q.lower() in json.dumps(f, default=str).lower())]
        st.dataframe(pd.DataFrame([{"Rule": f.get("rule"),
                                    "Severity": f"{SEV_ICON.get(finding_severity(f), '')} {finding_severity(f)}",
                                    "Identity": f.get("identity"), "Policy": f.get("policy"),
                                    "Resource": f.get("resource")} for f in flt]),
                     use_container_width=True, hide_index=True)
        if flt:
            sel = st.selectbox("Select a finding for details", [_label(x) for x in flt])
            f = flt[[_label(x) for x in flt].index(sel)]
            sev = finding_severity(f)
            ident = next((i for i in identities if i.get("name") == f.get("identity")), None)
            st.markdown(f"### {SEV_ICON.get(sev, '')} {f.get('rule')}")
            st.write(f"**Severity:** {sev}  \n**Identity:** {f.get('identity')}  \n"
                     f"**Identity ARN:** `{(ident or {}).get('arn') or 'n/a'}`  \n**Resource:** `{f.get('resource')}`")
            st.write(f"**Reason:** {f.get('reason')}")
            if f.get("remediation"):
                st.info(f"**Remediation:** {f['remediation']}")
            if ident:
                with st.expander("Identity policies (raw)"):
                    st.json({"policies": _policies(ident), "trust_policy": ident.get("trust_policy")})

# ---------------------------------------------------------------- verification
with tabs[3]:
    if not verifs:
        st.info("No access-path checks were run.")
    else:
        st.caption("✅ allowed = feasible path · ⛔ blocked = denied · ⚠️ inconclusive = depends on conditions not evaluated")
        sel = st.multiselect("Show statuses", STATUSES, default=STATUSES)
        shown = [v for v in verifs if v.get("status", "inconclusive") in sel]
        st.dataframe(pd.DataFrame([{"Status": f"{STATUS_ICON.get(v.get('status'), '⚠️')} {v.get('status')}",
                                    "Principal": v.get("principal"), "Role": v.get("role"),
                                    "Resource": _res(v.get("resource")), "Action": v.get("action", "n/a")}
                                   for v in shown]), use_container_width=True, hide_index=True)
        st.subheader("Evidence")
        for v in shown[:50]:
            icon = STATUS_ICON.get(v.get("status"), "⚠️")
            with st.expander(f"{icon} {v.get('principal')} → {v.get('role')} → {_res(v.get('resource'))} [{v.get('action', 'n/a')}]"):
                for e in v.get("evidence", []) or ["No evidence supplied by verifier."]:
                    st.write(f"- {e}")

# -------------------------------------------------------------- recommendations
with tabs[4]:
    if not findings:
        st.success("Nothing to remediate.")
    else:
        groups = {}
        for f in findings:
            groups.setdefault((f.get("policy"), finding_severity(f), f.get("remediation")), []).append(f.get("identity"))
        order = {s: n for n, s in enumerate(SEVERITIES)}
        for title, sev, fix in sorted(groups, key=lambda g: (order.get(g[1], 9), str(g[0]))):
            who = groups[(title, sev, fix)]
            with st.expander(f"{SEV_ICON.get(sev, '')} {sev.upper()} - {title}  ({len(who)} affected)"):
                if fix:
                    st.write(f"**Fix:** {fix}")
                st.write("**Affected:** " + ", ".join(sorted(set(map(str, who)))))
        csv = pd.DataFrame(findings).to_csv(index=False)
        st.download_button("⬇ Download findings (CSV)", csv, file_name="findings.csv", mime="text/csv")
