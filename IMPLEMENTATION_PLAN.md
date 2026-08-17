# Extend RiskandCompliance repo for GRC/Security Engineering interviews

## Context

You're interviewing for a role that wants: AI agent workflows (Claude/MCP) automating GRC tasks, GRC-platform extension via API/webhooks rather than the default UI, automated executive readouts, continuous control monitoring with evidence pipelines, controls codified into CI/CD and Terraform checks, compliance checkpoints in PR/design-review flow, FAIR-informed quantitative risk modeling, TPRM automation, IGA/access dashboards, customer trust-surface automation, and security-awareness automation.

Your existing repo (`RiskandCompliance`) already has real bones: a Python pipeline (`main.py` + `grc_validation.py`) that pulls 7 AWS Config rules via boto3, maps them to CIS v8 controls, and pushes evidence into a custom ServiceNow IRM table via REST (basic auth, GET-then-PATCH-or-POST), scheduled weekly through GitHub Actions. The README's own "Lessons Learned" section already flags a real gap — no history, each run overwrites the last — which is a great thing to visibly close. There's also dead code (`generate_report`/`send_email` using a legacy `gpt-3.5-turbo` call, with `openai` not even in `requirements.txt`) that's a natural slot for a modern Claude agent.

Rather than bolting on unrelated demo modules for every JD bullet (TPRM, IGA, trust center, training all require new mock domains with no natural tie-in), the plan goes deep on the ~7 bullets that are natural extensions of this one coherent evidence pipeline, and treats the rest as documented roadmap/talking points. Decisions already made:
- **Scope:** tight, coherent core — not broad shallow coverage.
- **GRC platform:** keep ServiceNow as platform of record; strengthen the README narrative rather than bolt on a second Vanta/Drata-class integration.
- **AI depth:** Claude API tool-use agent (Anthropic SDK tool runner), not a full MCP server — noted in the README as a deliberate scoping call, with "real MCP server" as the stated next step.

Two originally-proposed ideas — a CI/CD Terraform gate against insecure resources, and Slack/email alerts on noncompliance — are both included and are exactly the two features that connect the runtime (AWS Config) side to the IaC side.

## Recommended approach

Work in tiers; each tier is buildable independently once its dependency is done. Suggested pace: ~4 focused days.

### Tier 0 — Foundation fixes (~1–2 hrs, do first)
- Delete dead code: `generate_report()` and `send_email()` from `grc_validation.py` (lines ~101–164), and their now-unused imports (`smtplib`, `reportlab.*`, `email.mime.*`, `textwrap`). These get rebuilt properly in Tiers 4–5.
- Fix `requirements.txt`: remove the `openai` dependency drift by deleting the code that needed it; add `anthropic`, `numpy`, `PyYAML`; keep `reportlab` (now genuinely used by Tier 4's renderer).
- Move or delete `control_status_report (2).pdf` (stale artifact of the deleted path).
- Create `controls/control_catalog.yaml` + `controls/catalog.py` — the shared control taxonomy (control ID → AWS Config rule name → Conftest/Rego policy reference → CIS v8 ref → description) that unifies runtime and IaC-time checks. This is the backbone every later tier keys off of.

### Tier 1 — Evidence history / drift detection
Closes the exact gap the README already documents. Implement as a **git-committed append-only JSONL log** (`evidence/history.jsonl`) rather than new ServiceNow schema — lower setup risk, and "git as immutable evidence store" is a defensible interview answer.
- `evidence/evidence_store.py`: `append_evidence()`, `load_history()`, `detect_drift()` (diffs current run against most recent prior run per rule).
- Wire into `main.py` right after `get_all_control_statuses()`; leave `update_service_now()` untouched so the existing ServiceNow GlideRecord control indicator keeps working.
- `.github/workflows/get_status.yml`: add `permissions: contents: write` and a step to commit `evidence/history.jsonl` back after each run.
- README: update the inline GlideRecord JS sample to show the production-grade fix (`orderByDesc('sys_created_on')`) and explicitly mark this gap as closed under Lessons Learned.

### Tier 2 — Terraform + CI/CD compliance gate
- `terraform/examples/insecure-aws/`: intentionally-broken resources (open S3 bucket/public-access-block, `0.0.0.0/0` SSH security group, weak IAM password policy, public-IP-on-launch subnet) each mapped to a control ID. Mirror `terraform/examples/secure-aws/` with fixed versions for a "before/after" demo.
- Scanner: **Conftest** (Open Policy Agent/Rego), not Checkov — policies are hand-written Rego rules under `terraform/policy/*.rego`, one `deny` rule per control, each violation message prefixed with its control ID (e.g. `sprintf("[CTRL-005] S3 bucket %s allows public read access", [name])`). Since you own every rule (unlike Checkov's prebuilt library), the control catalog is the actual source of truth rather than an external ID you have to map into it — a stronger "policy-as-code" story for an interview, at the cost of writing more checks yourself instead of reusing a shipped library. Terraform is scanned via `terraform plan -out=tfplan && terraform show -json tfplan | conftest test -` (plan JSON, not raw `.tf`, so variable defaults/interpolation are resolved).
- New workflow `.github/workflows/terraform_scan.yml`: triggers on PRs touching `terraform/**`, runs `terraform plan` + `conftest test`, fails the job on `deny` results, uploads Conftest's JSON output, calls the Tier 3 script. Note: Terraform is scanned at plan-time only — never `apply` the insecure examples against real AWS.

### Tier 3 — PR/design-review checkpoint bot
- `scripts/post_pr_comment.py`: parses Conftest's JSON output → extracts the `[CTRL-xxx]` tag from each `msg` to join findings to the control catalog → posts a markdown findings table as a PR comment via the GitHub REST API → sets a named commit status (`compliance/terraform-gate`) via the Checks API, which is what actually gates the PR (branch protection can require it). This is the strongest "API/webhook, not UI" evidence in the whole repo — worth highlighting.

### Tier 4 — Claude tool-use executive agent (replaces dead gpt-3.5 path)
- `agent/tools.py`: callable tools — `query_evidence_history`, `get_control_catalog_entry`, `calculate_risk_exposure` (wraps Tier 6), `draft_servicenow_remediation_task` (reuses the `requests`/`HTTPBasicAuth` pattern already in `grc_validation.py`, defaults to `dry_run=True` while iterating).
- `agent/executive_agent.py`: uses the Anthropic SDK's tool runner (`client.beta.messages.tool_runner`) with `claude-sonnet-5`, produces a leadership-ready markdown readout (posture summary, quantified top risks, trend narrative, recommended actions), rendered to PDF via a small `reportlab` renderer (legitimate reuse of the dependency, fed agent output instead of a raw prompt).
- Gate the agent call behind `drift` being non-empty or an explicit manual-dispatch input, so you're not burning API spend on no-op weekly runs.

### Tier 5 — Slack + email notification on noncompliance
- `notifications/notify.py`: `send_slack_alert()` via a Slack **Incoming Webhook** (one-way, no OAuth app needed — justify this choice explicitly, note Bot-token/`chat.postMessage` as the interactive upgrade path) and `send_email_alert()` (refactored from the deleted `send_email()`, now conditional on drift and attaching the Tier 4 PDF).
- Fires from `main.py` right after `detect_drift()` returns non-empty results.

### Tier 6 — Lightweight FAIR-informed risk module
- `risk/risk_ranges.yaml` (illustrative loss-magnitude/frequency ranges per control) + `risk/fair_model.py`: numpy-vectorized Monte Carlo loss-exceedance calc producing mean/P90 Annual Loss Expectancy, computed only for currently non-compliant controls. Explicitly label this "FAIR-**informed**," not a full FAIR implementation, in the README — a clearly-scoped simplification beats an over-built module you can't defend under questioning.
- Feeds Tier 4's `calculate_risk_exposure` tool so the readout can say "$180K mean annual loss exposure (P90 $420K)" instead of just "NON_COMPLIANT."

### Tier 7 — README narrative (ongoing, finish last)
- Link the orphaned `Image.png` into "How It Works."
- Expand "Lessons Learned" with each tier's deliberate tradeoff (git-log vs. ServiceNow history table; Conftest/Rego vs. Checkov; webhook vs. Slack app; tool-use agent vs. full MCP server; FAIR-informed vs. full FAIR).
- Add a **"JD Requirement → Repo Evidence" table** mapping each bullet you built to the specific file/function — this doubles as your interview cheat sheet.
- Add a **"Roadmap"** section explicitly naming TPRM, IGA/access dashboards, trust-center automation, and security-awareness automation as natural next extensions of the same evidence-pipeline pattern — signals awareness of the full JD without pretending you built all of it.

## Sequencing

`controls/control_catalog.yaml` (Tier 0) is a hard dependency for Tiers 2, 3, 4, 6. `evidence/evidence_store.py` (Tier 1) is a hard dependency for Tier 4's history tool and all of Tier 5. Build Tier 6 (FAIR) before or alongside Tier 4, since the agent's risk tool wraps it. Tier 7 is continuous but the JD-mapping table is written last.

## Scope risks to flag now

- Demo drift without touching live AWS: seed `evidence/history.jsonl` with synthetic prior-run rows rather than toggling real resources insecure/secure in a live account.
- `permissions: contents: write` for the evidence-commit step will fail silently against a protected `main` branch — verify early.
- Confirm the ServiceNow dev instance/custom table credentials are still live before building on them.
- Needs a personal Slack workspace (trivial), an Anthropic API key with iteration budget, and careful Rego policy testing (Conftest gives no prebuilt checks, so bugs in your own policies are the main flakiness risk) so the PR gate isn't flaky for a live interview demo.

## Verification

- `python main.py` runs end-to-end locally against `.env` creds: pulls AWS Config statuses, appends evidence, detects drift (seed synthetic history to force a drift event), pushes ServiceNow, conditionally fires the Claude agent + Slack/email alert.
- Open a PR touching `terraform/examples/insecure-aws/` and confirm `terraform_scan.yml` fails the check and posts a PR comment with the mapped findings table; repeat against `secure-aws/` to confirm it passes.
- Inspect a generated `reports/exec_readout_<run_id>.md`/`.pdf` for coherent, correctly-cited content (drift called out, risk figures present, remediation tasks referenced).
- Confirm `evidence/history.jsonl` is committed back by the scheduled/manual GitHub Actions run.

## Critical files
- `grc_validation.py`, `main.py` (existing pipeline)
- `controls/control_catalog.yaml`, `controls/catalog.py` (new)
- `evidence/evidence_store.py` (new)
- `terraform/examples/insecure-aws/`, `terraform/policy/` (new)
- `.github/workflows/terraform_scan.yml`, `.github/workflows/get_status.yml`
- `agent/executive_agent.py`, `agent/tools.py` (new)
- `notifications/notify.py`, `risk/fair_model.py` (new)
- `README.md`
