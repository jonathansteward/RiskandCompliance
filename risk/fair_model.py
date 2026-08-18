"""FAIR-informed inherent risk scoring, adapted from the Monte Carlo engine
in vendor_risk_engine.py (github.com/jonathansteward/VendorRiskAutomation).

Deliberately scoped to inherent risk only - no FAIR-CAM control-composite
residual-risk modeling. That requires remapping control categories and
threat-intel sourcing that's a larger, separate effort; this produces a
defensible, fully-understood range in the time available rather than a
harder-to-explain full implementation. See SOP.md for the full reasoning.
"""
import random
from statistics import mean as _mean

import requests

import grc_validation

# (min, likely, max) triangular-distribution inputs per rule. Illustrative -
# reasoned from published industry breach-cost benchmarks (e.g. IBM Cost of
# a Data Breach), not this org's own incident history. State that plainly
# whenever this output is shown, rather than waiting to be asked.
RISK_INPUTS = {
    "root-account-mfa-enabled": {
        "contact_frequency": (0.5, 1, 3),          # targeted root-credential attack attempts/year
        "probability_of_action": (0.6, 0.85, 0.95),  # high - a compromised root credential is high-value
        "loss_magnitude": (300_000, 1_000_000, 3_000_000),  # full account takeover - the most catastrophic control in scope
    },
    "iam-password-policy": {
        "contact_frequency": (2, 8, 15),           # credential-stuffing/brute-force attempts/year - common, low-effort
        "probability_of_action": (0.3, 0.6, 0.8),
        "loss_magnitude": (20_000, 150_000, 300_000),  # single IAM user compromise, compounding with weak policy
    },
    "cloudtrail-all-read-s3-data-event-check": {
        "contact_frequency": (0.5, 2, 5),          # attempted S3 data-object reads/year
        "probability_of_action": (0.2, 0.5, 0.7),
        "loss_magnitude": (80_000, 650_000, 1_200_000),  # amplified by lack of detection/response visibility
    },
}

# rule_name -> every sn_compliance_control it's mapped to, each with its own
# risk statement. A rule can map to more than one control (cloudtrail
# genuinely maps to two) - each gets its own sn_risk_risk record so exposure
# and current compliance state are tracked per control, not blended.
#
# Each control has its OWN statement, not a shared one, because ServiceNow
# enforces this natively: a live push against a second control sharing the
# first's statement was rejected with a 403 from a business rule named
# "Enforce Unique Item" - confirms one risk statement supports at most one
# risk assessment in this instance's configuration, not the many-to-one
# originally assumed. See SOP.md.
#
# Hardcoded here rather than re-queried from ServiceNow each run - only 3
# rules are in scope today.
RULE_CONTROLS = {
    "root-account-mfa-enabled": [
        {
            "sys_id": "522e4a7c837e071085a5c310feaad3ec",
            "name": "6.5 Require MFA for Administrative Access",
            "statement": "778467c583720b1085a5c310feaad3c4",
        },
    ],
    "iam-password-policy": [
        {
            "sys_id": "3dca5ebc83fe071085a5c310feaad349",
            "name": "5.2 Use Unique Passwords",
            "statement": "489467c583720b1085a5c310feaad3d4",
        },
    ],
    "cloudtrail-all-read-s3-data-event-check": [
        {
            "sys_id": "3f883e348336471085a5c310feaad3d1",
            "name": "3.14 Log Sensitive Data Access",
            "statement": "c89467c583720b1085a5c310feaad3db",
        },
        {
            "sys_id": "179a59c1833e871085a5c310feaad3b2",
            "name": "8.2 Collect Audit Logs",
            "statement": "eff33b4d83f20b1085a5c310feaad3dc",
        },
    ],
}

# rule_name -> sys_id of its row in u_aws_config_control_mapping - needed to
# look up that control's latest evidence (evidence links to this row, not
# directly to sn_compliance_control), so the risk record can carry the
# current gap without a report-time join across three tables.
RULE_MAPPING_SYS_IDS = {
    "root-account-mfa-enabled": "c793da3c83be071085a5c310feaad357",
    "iam-password-policy": "2a58123883fe071085a5c310feaad3b0",
    "cloudtrail-all-read-s3-data-event-check": "6058def483fe071085a5c310feaad33f",
}

# The "AWS" entity/asset in ServiceNow's GRC data model (sn_grc_profile) -
# the same profile the CIS controls are already mapped under. Verified live:
# sn_compliance_control's `profile` field on a known control resolves to
# this sys_id, which itself resolves to name="AWS".
AWS_ENTITY_PROFILE_SYS_ID = "e4cc257c833ec31085a5c310feaad30c"

# Made up for this exercise - a fictional named risk owner on the reserved
# example.com domain, so it can't be mistaken for a real deliverable inbox.
RISK_OWNER_EMAIL = "priya.natarajan@example.com"

# Risk rating scale (annualized loss exposure -> label), as specified:
# max expected value $1,000,000, five bands each $200K wide except the
# open-ended top band.
RISK_RATING_BANDS = [
    (200_000, "Low"),
    (400_000, "Medium Low"),
    (600_000, "Medium"),
    (800_000, "Medium High"),
]


def rate_risk(ale):
    """Map an annualized loss exposure figure to the defined 5-tier label."""
    for threshold, label in RISK_RATING_BANDS:
        if ale < threshold:
            return label
    return "High"


def _ordered_triangular(t):
    """Convert (min, likely, max) to random.triangular(low, high, mode) argument order."""
    lo, mode, hi = t
    return (lo, hi, mode)


def calculate_inherent_risk_distribution(contact_frequency, probability_of_action, loss_magnitude, iterations=10_000):
    """Monte Carlo simulation of inherent risk (ALE) via triangular distributions.

    Ported from vendor_risk_engine.py's calculate_inherent_risk_distribution -
    same math, same Open FAIR (FAIR-U) approach: express each input as a
    (min, likely, max) range, sample it `iterations` times, and report
    percentiles instead of a single point estimate.
    """
    samples = [
        random.triangular(*_ordered_triangular(contact_frequency))
        * random.triangular(*_ordered_triangular(probability_of_action))
        * random.triangular(*_ordered_triangular(loss_magnitude))
        for _ in range(iterations)
    ]
    samples.sort()
    n = len(samples)

    cf_min, cf_mode, cf_max = contact_frequency
    poa_min, poa_mode, poa_max = probability_of_action
    lm_min, lm_mode, lm_max = loss_magnitude

    return {
        "point_estimate": round(cf_mode * poa_mode * lm_mode, 2),
        "mean": round(_mean(samples), 2),
        "p10": round(samples[max(0, int(n * 0.10) - 1)], 2),
        "p50": round(samples[int(n * 0.50)], 2),
        "p90": round(samples[min(n - 1, int(n * 0.90))], 2),
        "iterations": iterations,
    }


def get_risk_assessment(rule_name):
    """Run the Monte Carlo for one rule and return the distribution plus a
    ready-to-use description string, or None if this rule has no defined
    risk inputs yet."""
    inputs = RISK_INPUTS.get(rule_name)
    if not inputs:
        return None

    distribution = calculate_inherent_risk_distribution(**inputs)

    description = (
        f"Annualized loss exposure: ${distribution['p10']:,.0f}-${distribution['p90']:,.0f} "
        f"(90% confidence range), median ${distribution['p50']:,.0f}. "
        f"Based on {distribution['iterations']:,} Monte Carlo samples of illustrative "
        f"threat-frequency and loss-magnitude ranges, reasoned from published industry "
        f"breach-cost benchmarks - not this organization's own incident history."
    )

    cf_mode = inputs["contact_frequency"][1]
    poa_mode = inputs["probability_of_action"][1]
    lm_mode = inputs["loss_magnitude"][1]
    # ServiceNow recalculates inherent_ale itself as inherent_sle x
    # inherent_aro (confirmed live - it silently overwrites whatever's sent
    # here), so rate and send the matching point estimate rather than the
    # Monte Carlo median, which would otherwise be discarded anyway.
    inherent_ale = distribution["point_estimate"]

    return {
        "distribution": distribution,
        "description": description,
        "inherent_sle": lm_mode,
        "inherent_aro": round(cf_mode * poa_mode, 4),
        "inherent_ale": inherent_ale,
        "rating": rate_risk(inherent_ale),
    }


def push_risk_to_servicenow(sn_i, sn_u, sn_p, rule_name, control_sys_id, control_name=None, statement_sys_id=None):
    """Compute the risk assessment for a rule and create/update the
    sn_risk_risk record for one specific control, linked via
    u_compliance_control.

    Same GET-then-PATCH-or-POST pattern as update_service_now()/push_evidence().
    Queries by (rule, control) together, not control alone, so a rule with
    multiple controls gets one independent record per control rather than
    them colliding on a single row.
    """
    assessment = get_risk_assessment(rule_name)
    if not assessment:
        print(f"No risk inputs defined for {rule_name}, skipping.")
        return None

    base_url = f"https://{sn_i}.service-now.com/api/now/table/sn_risk_risk"
    headers = {"Content-Type": "application/json", "Accept": "application/json"}

    label = f"{rule_name} ({control_name})" if control_name else rule_name
    query_url = f"{base_url}?sysparm_query=u_compliance_control={control_sys_id}&sysparm_limit=1"
    get_response = requests.get(query_url, auth=(sn_u, sn_p), headers=headers)
    if get_response.status_code != 200:
        print(f"Failed to query sn_risk_risk for {label}. Status: {get_response.status_code}")
        print(get_response.text)
        return None

    description = assessment["description"]
    mapping_sys_id = RULE_MAPPING_SYS_IDS.get(rule_name)
    if mapping_sys_id:
        # Denormalize the latest evidence gap onto the risk record itself,
        # rather than joining u_aws_config_evidence in at report time -
        # that table is one row per resource per run by design, so a join
        # would multiply this control into as many rows as it has
        # accumulated history instead of showing one row per control.
        latest = grc_validation.get_latest_evidence_guidance(sn_i, sn_u, sn_p, mapping_sys_id)
        if latest and latest.get("gap_summary"):
            description += f"\n\nCurrent gap: {latest['gap_summary']}"

    payload = {
        "u_compliance_control": control_sys_id,
        "profile": AWS_ENTITY_PROFILE_SYS_ID,
        "name": f"AWS Config: {label} - inherent risk",
        "description": description,
        "inherent_sle": assessment["inherent_sle"],
        "inherent_aro": assessment["inherent_aro"],
        "inherent_ale": assessment["inherent_ale"],
        "u_risk_rating": assessment["rating"],
        "u_risk_owner_email": RISK_OWNER_EMAIL,
        # Currently non-compliant, so this record is a live/current risk -
        # see set_risk_active() for the counterpart that flips this off.
        "active": "true",
    }
    if statement_sys_id:
        payload["statement"] = statement_sys_id

    results = get_response.json().get("result", [])
    if results:
        sys_id = results[0]["sys_id"]
        response = requests.patch(f"{base_url}/{sys_id}", auth=(sn_u, sn_p), headers=headers, json=payload)
        action = "Updated"
    else:
        response = requests.post(base_url, auth=(sn_u, sn_p), headers=headers, json=payload)
        action = "Created"

    if response.status_code in (200, 201):
        print(f"{action} risk record for {label}: {assessment['rating']} (${assessment['inherent_ale']:,.0f})")
        result = response.json()["result"]
        result["_rating"] = assessment["rating"]
        result["_inherent_ale"] = assessment["inherent_ale"]
        return result
    else:
        print(f"Failed to push risk for {label}. Status: {response.status_code}")
        print(response.text)
        return None


def push_risk_for_rule(sn_i, sn_u, sn_p, rule_name):
    """Push one sn_risk_risk record per control a rule is mapped to (see
    RULE_CONTROLS) - handles the one-rule-to-many-controls case, e.g.
    cloudtrail-all-read-s3-data-event-check mapping to two CIS controls.
    """
    controls = RULE_CONTROLS.get(rule_name, [])
    if not controls:
        print(f"No controls mapped for {rule_name}, skipping risk push.")
        return []

    return [
        push_risk_to_servicenow(
            sn_i, sn_u, sn_p, rule_name, control["sys_id"], control["name"], control["statement"]
        )
        for control in controls
    ]


def set_risk_active(sn_i, sn_u, sn_p, control_sys_id, active):
    """Flip a control's existing risk record active/inactive without
    recomputing the assessment - used when a control's compliance status
    means its risk record shouldn't be treated as current anymore (e.g. the
    control is compliant again), where a fresh Monte Carlo run would be
    wasted work.
    """
    base_url = f"https://{sn_i}.service-now.com/api/now/table/sn_risk_risk"
    headers = {"Content-Type": "application/json", "Accept": "application/json"}

    query_url = f"{base_url}?sysparm_query=u_compliance_control={control_sys_id}&sysparm_limit=1"
    get_response = requests.get(query_url, auth=(sn_u, sn_p), headers=headers)
    if get_response.status_code != 200:
        print(f"Failed to query sn_risk_risk for {control_sys_id}. Status: {get_response.status_code}")
        return None

    results = get_response.json().get("result", [])
    if not results:
        return None  # no existing risk record for this control - nothing to flip

    sys_id = results[0]["sys_id"]
    response = requests.patch(
        f"{base_url}/{sys_id}", auth=(sn_u, sn_p), headers=headers,
        json={"active": "true" if active else "false"},
    )
    if response.status_code == 200:
        print(f"Set active={active} on risk record for control {control_sys_id}")
        return response.json()["result"]
    else:
        print(f"Failed to set active on risk record for {control_sys_id}. Status: {response.status_code}")
        return None


def sync_risk_for_rule(sn_i, sn_u, sn_p, rule_name, is_non_compliant):
    """Daily entry point: push a fresh assessment (active=true) when the
    rule is currently non-compliant, or mark its existing risk record(s)
    inactive - without recomputing - when it isn't.
    """
    controls = RULE_CONTROLS.get(rule_name, [])
    if not controls:
        return []

    if is_non_compliant:
        return push_risk_for_rule(sn_i, sn_u, sn_p, rule_name)

    return [
        set_risk_active(sn_i, sn_u, sn_p, control["sys_id"], active=False)
        for control in controls
    ]


if __name__ == "__main__":
    # Manual test harness: python -m risk.fair_model
    # Runs the Monte Carlo for each defined rule and prints the result -
    # no ServiceNow calls, just verifying the math/output before wiring in.
    for rule_name in RISK_INPUTS:
        assessment = get_risk_assessment(rule_name)
        print(f"\n{rule_name} - rating: {assessment['rating']}")
        print(f"  {assessment['description']}")
        print(f"  point_estimate=${assessment['distribution']['point_estimate']:,.0f}  "
              f"mean=${assessment['distribution']['mean']:,.0f}")
