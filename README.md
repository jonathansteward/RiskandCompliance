# RiskandCompliance

Continuous AWS security control monitoring using AWS Config, Python, Claude, and ServiceNow IRM — evidence collection, AI-generated remediation guidance, FAIR-informed risk quantification, and daily executive reporting, all wired into the GRC platform via API rather than a UI. A separate policy-as-code gate (Terraform + Conftest) blocks non-compliant infrastructure at the pull-request stage, before it ever ships.

Full write-up on the original pipeline: [Implementing AWS Continuous Monitoring Using Python, AWS Config, and ServiceNow IRM](https://www.linkedin.com/pulse/implementing-aws-continuous-monitoring-using-python-config-steward-b4jme) (covers the foundational status-sync pipeline; the evidence trail, AI remediation guidance, risk quantification, and reporting described below were added afterward).

## Problem

Monitoring security control effectiveness and managing risk is a heavy manual lift. Cloud configuration drifts continuously; compliance evidence and risk posture are usually captured point-in-time and go stale within days. GRC platforms are typically operated by clicking through a UI — a passive record, not part of the control loop. This project is a working example of how GRC Engineering closes that gap: two complementary control points, both extending the platform through its API rather than its UI.

## Two Control Points

**Detect** — AWS Config → ServiceNow → quantified, prioritized risk, running daily. Catches drift after the fact, decides what it means, and tells the right people.

**Prevent** — Terraform → Conftest policy-as-code gate, running on every pull request. Blocks non-compliant infrastructure before it's ever deployed, using the same control catalog as the runtime side.

## How It Works — Detection Pipeline

1. **Selected 7 key AWS Config rules** based on top cloud risks:
   - `root-account-mfa-enabled`
   - `iam-password-policy`
   - `cloudtrail-all-read-s3-data-event-check`
   - `s3-account-level-public-access-blocks-periodic`
   - `s3-bucket-public-read-prohibited`
   - `s3-bucket-public-write-prohibited`
   - `subnet-auto-assign-public-ip-disabled`
2. **Mapped the AWS Config rules to CIS v8 control objectives** in ServiceNow IRM to align with standard benchmarks.
3. **Created custom ServiceNow tables**: `u_aws_config_control_mapping` tracks each rule's current compliance status; `u_aws_config_evidence` holds the actual finding trail — one row per non-compliant resource per run, insert-only, linked back to the control mapping by a Reference field. History is never overwritten, so drift over time stays visible instead of being clobbered by the next run.
4. **Defined an "AWS" entity (asset)** in ServiceNow and mapped the CIS v8 controls to it for aggregate risk and compliance reporting.
5. **Created control indicators** in ServiceNow with custom logic that pulls the compliance status for each control's mapped rule from the custom table and updates the control's state automatically — no manual attestation required:
   ```javascript
   // Get the AWS Config rule mapped to this control
   var ruleName = "root-account-mfa-enabled";

   // Query custom table for latest compliance result
   var gr = new GlideRecord(aws_table_name);
   gr.addQuery(rule_name_column_from_aws_table, ruleName);
   gr.setLimit(1);
   gr.query();

   // Get object to update control status on control record
   var gr2 = new GlideRecord('sn_compliance_control');
   if (gr2.get(sys_id_of_table)) {

       if (gr.next()) {
           var status = gr.u_status + '';

           if (status == 'COMPLIANT') {
               result.value = 100;
               result.passed = true;
               gr2.setValue("status", "compliant");
           } else if (status == 'NON_COMPLIANT') {
               result.value = 0;
               result.passed = false;
               gr2.setValue("status", "non_compliant");
           } else {
               result.value = "No AWS data found";
               result.passed = false;
               gr2.setValue("status", "non_compliant");
           }

           // Attach record as supporting data
           result.supportingDataIds = [gr.getUniqueValue()];
       } else {
           result.value = "No AWS data found";
           result.passed = false;
           gr2.setValue("status", "non_compliant");
       }

       gr2.update();
   }
   ```
6. **Python pipeline** ([main.py](main.py), [grc_validation.py](grc_validation.py)) runs the full loop:
   - Pulls compliance status for all 7 rules via `describe_compliance_by_config_rule`, plus resource-level evidence (annotation, resource id, timestamp) via `get_compliance_details_by_config_rule` for anything non-compliant.
   - Writes status to ServiceNow, capturing each rule's *previous* status before overwriting it — the fact everything downstream (guidance, evidence, risk) is gated on.
   - **Remediation guidance** ([agent/remediation.py](agent/remediation.py)): a single forced Claude tool call — not a multi-step agent, since every input it needs (the control's policy/standard, pulled directly from AWS Config's own rule description; the evidence gap) is already known in advance for a given finding. Drift-gated: only called for genuinely new failures, or a rule that's never had guidance generated at all (self-heals rules that predate this feature); a still-failing rule carries forward its last guidance instead of paying for a repeat call.
   - **Evidence** (`push_evidence()`): inserts the guidance alongside the resource-level finding into `u_aws_config_evidence`.
   - **Risk quantification** ([risk/fair_model.py](risk/fair_model.py)): a FAIR-informed Monte Carlo model (triangular distributions, 10,000 iterations) computes annualized loss exposure for currently non-compliant, control-mapped rules, rates it on a 5-tier scale (Low → High), and pushes it into ServiceNow's native Risk Management (`sn_risk_risk`), linked to both the specific control and the AWS entity, with a risk owner and a real risk statement (`sn_risk_definition`). Deliberately scoped to inherent risk only — not a full FAIR-CAM implementation with control-composite residual risk — and labeled as such.
   - **Daily report** ([risk/report.py](risk/report.py)): pulls live from ServiceNow (not in-memory state) every currently non-compliant, Medium High/High finding, splits it into changed-vs-persisting using ServiceNow's own native audit trail, and asks Claude for a grounded executive summary plus a distinct per-control non-compliance summary (one batched call, not one per control) with the recommended fix pulled from the evidence already generated. Renders a structured PDF and delivers it to Slack (direct file upload via a Bot Token — Incoming Webhooks can't upload files) and email (PDF attachment).
7. **[get_status.yml](.github/workflows/get_status.yml)** runs the whole pipeline daily (and supports manual `workflow_dispatch` runs).

## How It Works — Prevention Pipeline (Policy as Code)

1. **Terraform examples** ([terraform/examples/](terraform/examples/)) — a compliant and a deliberately non-compliant version of the infrastructure each of the 7 controls governs (where Terraform-manageable; `root-account-mfa-enabled` has no API for root MFA enrollment, so it's excluded from this gate by design).
2. **Conftest / Rego policies** ([terraform/policy/](terraform/policy/)) — one policy file per control, evaluated against `terraform plan` output (not raw `.tf`), each `deny` message tagged with its control ID.
3. **[terraform_scan.yml](.github/workflows/terraform_scan.yml)** runs on every pull request: `terraform plan` (against CI-only mock AWS credentials — this is a policy check on a plan, never a real deployment) → `terraform show -json` → `conftest test` → results posted to the PR's checks tab.
4. **Branch protection** requires the `Compliance Gate` check to pass before merge, enforced even for repo admins — validated live with real PRs (a non-compliant-resources PR reports `mergeStateStatus: BLOCKED`; a compliant one is clean).

## Lessons Learned & Architecture Tradeoffs

This started as a quick script to pull the status of one AWS Config rule. By the end it turned into a much bigger exercise in how you actually turn cloud security telemetry into evidence, guidance, and quantified risk a GRC program can use. Some of what stuck with me:

Just knowing a rule failed isn't much use on its own — you need to know which resource caused it, so the pipeline pulls that detail for anything non-compliant instead of stopping at a status.

I also learned it's worth keeping AWS Config and ServiceNow doing separate jobs. AWS Config can tell you whether a configuration is compliant; it has no concept of what control that maps to or what it means for risk. That interpretation belongs in ServiceNow, and trying to blend the two gets messy fast. The same principle held for everything added later: **Python owns compute and judgment, ServiceNow owns the record and native workflow** — re-derived at every fork, not assumed once. It's why the FAIR-informed Monte Carlo simulation lives in Python (ServiceNow's scripting sandbox has no vectorized math and hard execution-time limits) while the risk record, the audit trail, and the control indicators stay squarely ServiceNow's.

Related to that: I originally thought about having the automation write directly to a control's status field, but that felt wrong once I thought it through. It's better for the automation to just drop evidence into a table and let an existing ServiceNow control indicator read it and decide the result. That keeps the line between "here's the evidence" and "here's what it means for the control" intact.

Auditability was another thing I underestimated at first. A pass/fail flag by itself doesn't tell an auditor much — attaching the actual evidence record to the indicator result (`result.supportingDataIds`) is what lets someone go back and answer "why was this control considered effective on this date."

Same goes for history — overwriting last week's status with this week's throws away the ability to see drift over time, which is really the whole point of calling something "continuous monitoring" instead of a one-off check. The evidence table and the daily report's change-history section (backed by ServiceNow's own field-level audit trail, not a separate file to keep in sync) both exist because of this.

Not every scope decision was obvious, and a few only became right in hindsight: full FAIR-CAM (control-composite residual risk, threat-intel sourcing) was the "correct" model, but building it under a real deadline was real risk — shipping a smaller, explicitly-labeled FAIR-*informed* inherent-risk model was the more defensible call, reusing the Monte Carlo engine from a separate project that does implement the fuller version. Same logic applied to the AI layer: a multi-step tool-use agent sounds more sophisticated than a single call, but it only earns its complexity when the next lookup genuinely depends on what the last one returned — for drafting remediation guidance, every input is already known in advance, so a single forced tool call is the simpler, more testable, more honest architecture. (There's exactly one place in this pipeline where a real multi-step agent would be justified — investigating *why* an auto-remediation attempt failed — and it isn't built yet, on purpose.)

The platform doesn't always do what its own documentation implies, and that's worth knowing empirically, not assuming. ServiceNow silently recalculates a risk record's `inherent_ale` field as `SLE × ARO` and discards whatever's explicitly sent to it — found by comparing numbers, not by reading documentation that doesn't exist. Its risk-lifecycle `active` field is governed by a native workflow that rejects direct writes entirely, confirmed by watching a `PATCH` response report success while the underlying value never changed. A risk statement, it turns out, supports at most one risk assessment — discovered when a second write was rejected by a business rule called `Enforce Unique Item`. None of these are documented anywhere obvious; all three were routed around rather than fought once understood.

Where the automation actually runs turned out to be a real decision. I went with GitHub Actions over a local VM or something AWS-native mostly for the scheduling, secrets handling, and to keep the pipeline from being tied to one cloud. A VM sitting on my machine also just stops working the moment the laptop sleeps, which obviously isn't something you can rely on in production.

Secrets were an easy one to get right early: local `.env` file, gitignored, and GitHub Actions secrets in CI. Never in the repo itself — verified across the full git history, not just assumed. Less obvious until a later security pass: getting secrets *out* of the repo isn't the same as getting them *scoped* correctly. The AWS and ServiceNow credentials this pipeline runs on turned out to have far more access than the two read-only Config calls and handful of table writes it actually performs — a good reminder that "not committed" and "least privilege" are two separate properties, and only one of them is easy to verify by grepping.

ServiceNow ACLs caught me off guard once — being authenticated doesn't mean you can see every table. I hit a "record doesn't exist or ACL restricts the record retrieval" error on one table while another worked fine, which was a good reminder that access control, field permissions, and application scope are all part of building an integration, not just auth.

The project also started out generating a PDF and emailing it, which is fine as a report but isn't really "continuous" anything. The more useful mental model ended up being a loop: collect, evaluate, store evidence, test the control, generate guidance, quantify risk, update ServiceNow, alert the right people, repeat. The daily PDF report is one output of that loop now, grounded in the same evidence and risk data living in ServiceNow — not a separate, disconnected artifact.

## Setup

### Prerequisites
- Python 3.10+
- An AWS account with AWS Config enabled and IAM credentials scoped to `config:DescribeComplianceByConfigRule` and `config:GetComplianceDetailsByConfigRule` (a dedicated, narrowly-scoped credential — not a broadly-privileged account)
- A ServiceNow instance with Policy and Compliance Management active, plus Risk Management if you want the FAIR-informed risk quantification wired up
- An Anthropic API key (remediation guidance and the daily report's summaries)
- A Slack workspace, if you want the daily report delivered there (a Bot Token with `files:write`/`chat:write` scopes — Incoming Webhooks can't upload files)
- A Gmail (or other SMTP) account with an app-specific password, if you want the daily report emailed

### 1. Clone and install dependencies
```bash
git clone <repo-url>
cd RiskandCompliance
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### 2. Configure environment variables
Create a `.env` file in the project root (this file is gitignored and should never be committed):
```
SN_I=<your-servicenow-instance-name>
SN_T=<servicenow-table-name>
SN_U=<servicenow-username>
SN_P=<servicenow-password>

AWS_ACCESS_KEY_ID=<your-access-key-id>
AWS_SECRET_ACCESS_KEY=<your-secret-access-key>
AWS_DEFAULT_REGION=<your-aws-region>

ANTHROPIC_API_KEY=<your-anthropic-api-key>

SLACK_BOT_TOKEN=<xoxb-... bot token, files:write and chat:write scopes>
SLACK_CHANNEL_ID=<target channel id>

EMAIL_FROM=<sender address>
EMAIL_TO=<recipient address>
SMTP_SERVER=smtp.gmail.com
SMTP_PORT=587
EMAIL_APP_PASSWORD=<app-specific password, not your regular account password>
```
AWS credentials are also picked up by `boto3` via the standard credential chain (`aws configure`, environment variables, or an instance/role profile) if you'd rather not put them in `.env`.

### 3. Run locally
```bash
python main.py
```
This runs the full detection pipeline: pulls current compliance status and evidence for every enabled AWS Config rule, generates/carries-forward remediation guidance, updates ServiceNow, computes and pushes FAIR-informed risk for the mapped controls, and sends the daily report to Slack/email if anything's currently elevated.

### 4. Automated daily run (GitHub Actions)
[.github/workflows/get_status.yml](.github/workflows/get_status.yml) runs the pipeline daily and can also be triggered manually. Add the following as repository secrets (Settings → Secrets and variables → Actions):
- `SN_I`, `SN_T`, `SN_U`, `SN_P`
- `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_DEFAULT_REGION`
- `ANTHROPIC_API_KEY`
- `SLACK_BOT_TOKEN`, `SLACK_CHANNEL_ID`
- `EMAIL_FROM`, `EMAIL_TO`, `SMTP_SERVER`, `SMTP_PORT`, `EMAIL_APP_PASSWORD`

### 5. Policy-as-code gate (Terraform + Conftest)
[.github/workflows/terraform_scan.yml](.github/workflows/terraform_scan.yml) runs on every pull request automatically — no additional secrets needed, since it only ever plans against mock AWS credentials, never a real deployment. To require it before merge: Settings → Branches → branch protection rule on `main` → require the `Compliance Gate` status check.
