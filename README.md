# RiskandCompliance
Automating AWS continuous security control monitoring by using AWS Config, Python, and ServiceNow GRC to engineer and automate risk and compliance for 7 key controls. A GitHub action workflow has been put in place to run the code weekly to review operational status of the controls. The AWS config rules are mapped to CIS controls in ServiceNow GRC through control indicators which are mapped to the AWS asset record. Each run of the code gets the status of each enabled AWS config rule and updates ServiceNow GRC table records. The control indicator that is mapped to each rule will collect the status of the relevant AWS config rules from the updated table to streamline evidence collection, reporting, and risk management.

Full write-up: [Implementing AWS Continuous Monitoring Using Python, AWS Config, and ServiceNow IRM](https://www.linkedin.com/pulse/implementing-aws-continuous-monitoring-using-python-config-steward-b4jme)

## Problem
Monitoring security control effectiveness and managing risk is a heavy manual lift. This project is a working example of how GRC Engineering can drive continuous monitoring of AWS security requirements using AWS Config, ServiceNow IRM, Python, and GitHub Actions — replacing manual attestation with an automated, evidence-backed pipeline.

## How It Works

1. **Selected 7 key AWS Config rules** based on top cloud risks:
   - `root-account-mfa-enabled`
   - `iam-password-policy`
   - `cloudtrail-all-read-s3-data-event-check`
   - `s3-account-level-public-access-blocks-periodic`
   - `s3-bucket-public-read-prohibited`
   - `s3-bucket-public-write-prohibited`
   - `subnet-auto-assign-public-ip-disabled`
2. **Mapped the AWS Config rules to CIS v8 control objectives** in ServiceNow IRM to align with standard benchmarks.
3. **Created a custom ServiceNow table** to track the compliance status of each AWS Config rule.
4. **Defined an "AWS" entity (asset)** in ServiceNow and mapped the CIS v8 controls to it for aggregate risk and compliance reporting.
5. **Created weekly control indicators** in ServiceNow with custom logic that pulls the compliance status for each control's mapped rule from the custom table and updates the control's state automatically — no manual attestation required:
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
6. **Wrote the Python pipeline** ([grc_validation.py](grc_validation.py)) that pulls rule status from the AWS Config API via `describe_compliance_by_config_rule` (and resource-level detail via `get_compliance_details_by_config_rule` for non-compliant rules), then pushes each rule's status into the ServiceNow GRC table over the REST API — patching the record if it exists, creating it if it doesn't.
7. **Wrapped it all in the [get_status.yml](.github/workflows/get_status.yml) GitHub Action**, which runs the sync weekly (and supports manual `workflow_dispatch` runs) so control status and evidence stay continuously up to date.

## Lessons Learned & Architecture Tradeoffs
This started as a quick script to pull the status of one AWS Config rule. By the end it turned into a much bigger exercise in how you actually turn cloud security telemetry into evidence a GRC program can use. Some of what stuck with me:

Just knowing a rule failed isn't much use on its own — you need to know which resource caused it, so the pipeline pulls that detail for anything non-compliant instead of stopping at a status.

I also learned it's worth keeping AWS Config and ServiceNow doing separate jobs. AWS Config can tell you whether a configuration is compliant; it has no concept of what control that maps to or what it means for risk. That interpretation belongs in ServiceNow, and trying to blend the two gets messy fast.

Related to that: I originally thought about having the automation write directly to a control's status field, but that felt wrong once I thought it through. It's better for the automation to just drop evidence into a table and let an existing ServiceNow control indicator read it and decide the result. That keeps the line between "here's the evidence" and "here's what it means for the control" intact.

Auditability was another thing I underestimated at first. A pass/fail flag by itself doesn't tell an auditor much — attaching the actual evidence record to the indicator result (`result.supportingDataIds`) is what lets someone go back and answer "why was this control considered effective on this date."

Same goes for history — overwriting last week's status with this week's throws away the ability to see drift over time, which is really the whole point of calling something "continuous monitoring" instead of a one-off check.

Where the automation actually runs turned out to be a real decision. I went with GitHub Actions over a local VM or something AWS-native mostly for the scheduling, secrets handling, and to keep the pipeline from being tied to one cloud. A VM sitting on my machine also just stops working the moment the laptop sleeps, which obviously isn't something you can rely on in production.

S3 came up as an option for storing reports, but it's worth remembering that's all it does — store things. Something still has to actually run the code and call the AWS Config API.

Secrets were an easy one to get right early: local `.env` file, gitignored, and GitHub Actions secrets in CI. Never in the repo itself.

ServiceNow ACLs caught me off guard once — being authenticated doesn't mean you can see every table. I hit a "record doesn't exist or ACL restricts the record retrieval" error on one table while another worked fine, which was a good reminder that access control, field permissions, and application scope are all part of building an integration, not just auth.

The project also started out generating a PDF and emailing it, which is fine as a report but isn't really "continuous" anything. The more useful mental model ended up being a loop: collect, evaluate, store evidence, test the control, update ServiceNow, let it influence risk, repeat. The PDF is just one possible output of that loop, not the point of it.

## Setup

### Prerequisites
- Python 3.10+
- An AWS account with AWS Config enabled and IAM credentials that can call `config:DescribeComplianceByConfigRule` and `config:GetComplianceDetailsByConfigRule`
- A ServiceNow instance with a table for tracking AWS Config rule statuses

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
```

AWS credentials are picked up by `boto3` using the standard credential chain, so either configure them via `aws configure`, environment variables, or an instance/role profile:
```
AWS_ACCESS_KEY_ID=<your-access-key-id>
AWS_SECRET_ACCESS_KEY=<your-secret-access-key>
AWS_DEFAULT_REGION=<your-aws-region>
```

### 3. Run locally
```bash
python main.py
```
This pulls the current compliance status of every enabled AWS Config rule and creates/updates matching records in the configured ServiceNow table.

### 4. Automated weekly run (GitHub Actions)
The workflow at [.github/workflows/get_status.yml](.github/workflows/get_status.yml) runs the sync every Friday and can also be triggered manually. To enable it, add the following as repository secrets (Settings → Secrets and variables → Actions):
- `SN_I`, `SN_T`, `SN_U`, `SN_P`
- `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_DEFAULT_REGION`