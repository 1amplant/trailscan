# trailscan

**Open source SOC 2 AWS readiness scanner.**  
Point-in-time check of your AWS environment against the SOC 2 Trust Services Criteria — straight from your terminal.

> trailscan gives you a snapshot. For **continuous monitoring, audit-ready PDF reports, and multi-source evidence** (AWS + GitHub + Okta + Google Workspace) → **[TrailProof](https://trailproof.app)**

```
$ trailscan

trailscan v0.1.0  — SOC 2 AWS readiness scanner
Profile: default   Region: us-east-1

── IAM ────────────────────────────────────────────
  ✔  Root MFA enabled
  ✘  IAM users with console access missing MFA
     ↳ Enable MFA for all IAM users: IAM → Users → select user → Security credentials → MFA device → Assign MFA device.

── S3 ─────────────────────────────────────────────
  ✔  S3 account-level public access block enabled
  ...

════════════════════════════════════════════════════
  SOC 2 AWS Readiness Score
────────────────────────────────────────────────────
  ████████████████████░░░░░░░░░░░░░░░░░░░░  52%  AT RISK
────────────────────────────────────────────────────
  ✔ Passed : 18    ✘ Failed : 17    ⚠ Warned : 3
════════════════════════════════════════════════════
```

---

## What it checks

trailscan runs **35 checks** across 9 AWS services, each mapped to a SOC 2 TSC control.

| Service | Checks | Controls |
|---|---|---|
| IAM | Root MFA, user MFA, password policy, root access keys, key rotation, unused credentials, overly permissive policies, cross-account access | CC6.1, CC6.2, CC6.3 |
| S3 | Account public access block, bucket public access block, bucket ACL, encryption, access logging, versioning, public bucket policies | CC6.1, CC7.2, CC9.1 |
| CloudTrail | Multi-region trail enabled, log file validation, CloudWatch integration, KMS encryption, S3 bucket logging | CC7.2, CC7.3 |
| EC2 | Security groups open to world, EBS encryption, IMDSv2, public snapshots, stopped instances | CC6.1, CC6.6, CC6.7 |
| RDS | Publicly accessible, storage encryption, backup retention, deletion protection | CC6.1, CC9.1 |
| GuardDuty | Detector enabled | CC7.2 |
| VPC | Flow logs enabled | CC6.6, CC7.2 |
| KMS | Customer-managed key rotation | CC6.1 |
| CloudWatch | Root usage alarm, unauthorized API alarm, IAM changes alarm | CC6.1, CC7.2 |

---

## Install

```bash
git clone https://github.com/1amplant/trailscan
cd trailscan
pip install -e .
```

Requires Python 3.10+ and `boto3`. No other dependencies.

---

## Usage

```bash
# Use default AWS profile
trailscan

# Use a named profile
trailscan --profile staging

# Specify a region
trailscan --region us-west-2

# Only show failures
trailscan --failed-only

# Verbose mode (shows raw evidence per finding)
trailscan --verbose

# Export to JSON
trailscan --output json --output-file report.json

# Export to CSV
trailscan --output csv --output-file report.csv

# Run specific checks only
trailscan --checks iam.mfa_enabled_root s3.public_access_block

# All options
trailscan --help
```

### Credentials

trailscan uses standard AWS credential resolution — in order:

1. `--profile` flag → named profile from `~/.aws/credentials`
2. `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` env vars
3. `AWS_PROFILE` env var
4. Default profile
5. EC2 instance profile / ECS task role

The IAM user or role running trailscan needs **read-only** permissions. The minimum policy is:

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Action": [
      "iam:Get*", "iam:List*", "iam:GenerateCredentialReport",
      "s3:GetBucketAcl", "s3:GetBucketEncryption", "s3:GetBucketLogging",
      "s3:GetBucketPolicy", "s3:GetBucketPublicAccessBlock",
      "s3:GetBucketVersioning", "s3:GetAccountPublicAccessBlock", "s3:ListAllMyBuckets",
      "cloudtrail:DescribeTrails", "cloudtrail:GetTrailStatus", "cloudtrail:GetEventSelectors",
      "logs:DescribeMetricFilters",
      "cloudwatch:DescribeAlarmsForMetric",
      "ec2:DescribeSecurityGroups", "ec2:DescribeInstances",
      "ec2:DescribeSnapshots", "ec2:DescribeVolumes", "ec2:DescribeFlowLogs",
      "ec2:DescribeRegions", "ec2:GetEbsEncryptionByDefault",
      "rds:DescribeDBInstances",
      "guardduty:ListDetectors", "guardduty:GetDetector",
      "kms:ListKeys", "kms:DescribeKey", "kms:GetKeyRotationStatus",
      "sts:GetCallerIdentity"
    ],
    "Resource": "*"
  }]
}
```

---

## Exit codes

| Code | Meaning |
|------|---------|
| `0`  | All checks passed (no FAILs) |
| `2`  | One or more checks failed |
| `1`  | Error (bad credentials, region not set, etc.) |

This makes trailscan easy to drop into CI:

```yaml
# .github/workflows/soc2.yml
- name: SOC 2 readiness scan
  run: trailscan --output json --output-file soc2-report.json
  env:
    AWS_ACCESS_KEY_ID: ${{ secrets.AWS_ACCESS_KEY_ID }}
    AWS_SECRET_ACCESS_KEY: ${{ secrets.AWS_SECRET_ACCESS_KEY }}
    AWS_DEFAULT_REGION: us-east-1
```

---

## SOC 2 TSC mapping

| Control | Description |
|---------|-------------|
| CC6.1 | Logical and physical access controls |
| CC6.2 | Authentication and credentials |
| CC6.3 | Role-based access |
| CC6.6 | Boundary protection |
| CC6.7 | Data-in-transit and at-rest encryption |
| CC7.2 | Monitoring and anomaly detection |
| CC7.3 | Incident response |
| CC9.1 | Risk mitigation (backups, availability) |

---

## Limitations

- **Point-in-time only** — trailscan is a snapshot, not continuous monitoring.
- **AWS only** — no GitHub, Okta, Google Workspace, or HR system checks.
- **Single account** — runs against the account your credentials belong to; no cross-account scanning.
- **No historical data** — each run is independent; results are not stored.

Need continuous monitoring, historical evidence, multi-account scanning, audit-ready PDF reports, and policy templates?  
→ **[TrailProof](https://trailproof.app)** automates SOC 2 evidence collection across AWS, GitHub, Okta, and more.

---

## License

MIT
