import os

import anthropic
import boto3
from dotenv import load_dotenv

import agent.remediation as remediation
import grc_validation
from risk.fair_model import RULE_CONTROLS, sync_risk_for_rule
from risk.report import send_daily_report


def main():

    # Load environment variables
    load_dotenv()

    SN_I = os.getenv("SN_I")
    SN_T = os.getenv("SN_T")
    SN_U = os.getenv("SN_U")
    SN_P = os.getenv("SN_P")
    ANTHROPIC_API_KEY = os.getenv("ANTHROPIC_API_KEY")

    config_client = boto3.client('config')
    claude_client = anthropic.Anthropic(api_key=ANTHROPIC_API_KEY) if ANTHROPIC_API_KEY else None

    # Get Status of security controls
    statuses = grc_validation.get_all_control_statuses(config_client)

    # Update ServiceNow GRC table with statuses from AWS; previous_status
    # lets us tell a brand-new failure from one that's still failing.
    rule_context = grc_validation.update_service_now(SN_I, SN_T, statuses, SN_U, SN_P)

    # Only generate fresh remediation guidance for rules that just became
    # non-compliant. A rule that was already non-compliant last run carries
    # forward its existing guidance instead of paying for another Claude
    # call on a finding that hasn't changed.
    guidance_by_rule = {}
    for rule_name, info in statuses.items():
        if info.get("compliance") != "NON_COMPLIANT":
            continue

        context = rule_context.get(rule_name)
        if not context:
            continue

        is_new_failure = context["previous_status"] != "NON_COMPLIANT"

        if is_new_failure and claude_client:
            rule_definition = grc_validation.get_rule_definition(config_client, rule_name)
            guidance = remediation.get_remediation_guidance(
                claude_client, rule_name, rule_definition, info.get("resources", [])
            )
            guidance_by_rule[rule_name] = {
                "standard_summary": guidance["standard_summary"],
                "gap_summary": guidance["gap_summary"],
                "remediation_steps_text": remediation.format_remediation_steps(guidance["remediation_steps"]),
            }
            print(f"Generated new remediation guidance for {rule_name} (new failure).")
        else:
            carried_forward = grc_validation.get_latest_evidence_guidance(SN_I, SN_U, SN_P, context["sys_id"])
            if carried_forward:
                guidance_by_rule[rule_name] = carried_forward
                print(f"Carried forward existing guidance for {rule_name} (still failing).")
            else:
                print(f"No prior guidance to carry forward for {rule_name} yet.")

    # Record per-resource evidence for non-compliant rules, including guidance
    grc_validation.push_evidence(SN_I, SN_U, SN_P, statuses, rule_context, guidance_by_rule)

    # Sync risk assessments for every rule with a mapped control: push a
    # fresh assessment when currently non-compliant, or mark existing
    # records inactive (without recomputing) when they aren't.
    for rule_name in RULE_CONTROLS:
        is_non_compliant = statuses.get(rule_name, {}).get("compliance") == "NON_COMPLIANT"
        sync_risk_for_rule(SN_I, SN_U, SN_P, rule_name, is_non_compliant)

    # Daily elevated-risk report (Medium High/High only) - pulls fresh from
    # ServiceNow rather than reusing in-memory state, so it reflects what
    # was actually written above, and no-ops cleanly if nothing qualifies.
    send_daily_report(
        sn_i=SN_I, sn_u=SN_U, sn_p=SN_P, sn_t=SN_T,
        webhook_url=os.getenv("SLACK_WEBHOOK_URL"),
        from_email=os.getenv("EMAIL_FROM"),
        to_email=os.getenv("EMAIL_TO"),
        owner_email="priya.natarajan@example.com",
        smtp_server=os.getenv("SMTP_SERVER"),
        smtp_port=os.getenv("SMTP_PORT"),
        app_password=os.getenv("EMAIL_APP_PASSWORD"),
    )


if __name__ == "__main__":
    main()
