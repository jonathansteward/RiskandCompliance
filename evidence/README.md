# Evidence

Terraform plan JSON files (`terraform show -json`) generated during the CI/CD compliance gate are stored here before being evaluated by Conftest (`terraform/policy/`). Committing these alongside the Conftest results they produced gives an audit trail of exactly what was scanned and when — the same "evidence, not just a pass/fail flag" principle the AWS Config → ServiceNow side of this pipeline already follows (see the README's Lessons Learned section).

This directory will also hold `history.jsonl`, the append-only AWS Config compliance history log described in `IMPLEMENTATION_PLAN.md` (Tier 1), once that's built.
