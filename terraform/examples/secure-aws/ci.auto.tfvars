# Default values so `terraform plan` runs non-interactively in CI (which
# never actually applies these, so global bucket-name uniqueness doesn't
# matter here). Override with -var for a real local plan/apply.
cloudtrail_bucket_name = "ci-plan-cloudtrail-compliant-example"
example_bucket_name    = "ci-plan-example-compliant-example"
