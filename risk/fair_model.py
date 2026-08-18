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

# (min, likely, max) triangular-distribution inputs per rule. Illustrative -
# reasoned from published industry breach-cost benchmarks (e.g. IBM Cost of
# a Data Breach), not this org's own incident history. State that plainly
# whenever this output is shown, rather than waiting to be asked.
RISK_INPUTS = {
    "root-account-mfa-enabled": {
        "contact_frequency": (0.5, 1, 3),          # targeted root-credential attack attempts/year
        "probability_of_action": (0.5, 0.7, 0.9),  # high - a compromised root credential is high-value
        "loss_magnitude": (100_000, 500_000, 2_000_000),  # full account takeover
    },
    "iam-password-policy": {
        "contact_frequency": (2, 5, 12),           # credential-stuffing/brute-force attempts/year
        "probability_of_action": (0.3, 0.5, 0.7),
        "loss_magnitude": (20_000, 75_000, 250_000),  # single IAM user compromise
    },
    "cloudtrail-all-read-s3-data-event-check": {
        "contact_frequency": (0.5, 2, 5),          # attempted S3 data-object reads/year
        "probability_of_action": (0.2, 0.4, 0.6),
        "loss_magnitude": (50_000, 200_000, 600_000),  # amplified by lack of detection/response visibility
    },
}

# rule_name -> sys_id of the sn_risk_definition (Risk Statement) created for it
RISK_STATEMENTS = {
    "root-account-mfa-enabled": "778467c583720b1085a5c310feaad3c4",
    "iam-password-policy": "489467c583720b1085a5c310feaad3d4",
    "cloudtrail-all-read-s3-data-event-check": "c89467c583720b1085a5c310feaad3db",
}


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

    return {
        "distribution": distribution,
        "description": description,
        "inherent_sle": lm_mode,
        "inherent_aro": round(cf_mode * poa_mode, 4),
        # ServiceNow recalculates inherent_ale itself as inherent_sle x
        # inherent_aro (confirmed live - it silently overwrites whatever's
        # sent here), so send the matching point estimate rather than the
        # Monte Carlo median, which would otherwise be discarded anyway.
        "inherent_ale": distribution["point_estimate"],
    }


def push_risk_to_servicenow(sn_i, sn_u, sn_p, rule_name, control_sys_id):
    """Compute the risk assessment for a rule and create/update its
    sn_risk_risk record, linked to the control via u_compliance_control.

    Same GET-then-PATCH-or-POST pattern as update_service_now()/push_evidence().
    """
    assessment = get_risk_assessment(rule_name)
    if not assessment:
        print(f"No risk inputs defined for {rule_name}, skipping.")
        return None

    base_url = f"https://{sn_i}.service-now.com/api/now/table/sn_risk_risk"
    headers = {"Content-Type": "application/json", "Accept": "application/json"}

    query_url = f"{base_url}?sysparm_query=u_compliance_control={control_sys_id}&sysparm_limit=1"
    get_response = requests.get(query_url, auth=(sn_u, sn_p), headers=headers)
    if get_response.status_code != 200:
        print(f"Failed to query sn_risk_risk for {rule_name}. Status: {get_response.status_code}")
        print(get_response.text)
        return None

    payload = {
        "u_compliance_control": control_sys_id,
        "name": f"AWS Config: {rule_name} - inherent risk",
        "description": assessment["description"],
        "inherent_sle": assessment["inherent_sle"],
        "inherent_aro": assessment["inherent_aro"],
        "inherent_ale": assessment["inherent_ale"],
    }
    statement_sys_id = RISK_STATEMENTS.get(rule_name)
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
        print(f"{action} risk record for {rule_name}: median ${assessment['inherent_ale']:,.0f}")
        return response.json()["result"]
    else:
        print(f"Failed to push risk for {rule_name}. Status: {response.status_code}")
        print(response.text)
        return None


if __name__ == "__main__":
    # Manual test harness: python -m risk.fair_model
    # Runs the Monte Carlo for each defined rule and prints the result -
    # no ServiceNow calls, just verifying the math/output before wiring in.
    for rule_name in RISK_INPUTS:
        assessment = get_risk_assessment(rule_name)
        print(f"\n{rule_name}")
        print(f"  {assessment['description']}")
        print(f"  point_estimate=${assessment['distribution']['point_estimate']:,.0f}  "
              f"mean=${assessment['distribution']['mean']:,.0f}")
