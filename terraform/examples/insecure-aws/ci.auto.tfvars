# Default values so `terraform plan` runs non-interactively in CI (which
# never actually applies these, so global bucket-name uniqueness doesn't
# matter here). Override with -var for a real local plan/apply.
cloudtrail_bucket_name   = "ci-plan-cloudtrail-noncompliant-example"
public_read_bucket_name  = "ci-plan-public-read-example"
public_write_bucket_name = "ci-plan-public-write-example"
