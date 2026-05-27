import boto3
from botocore.exceptions import ClientError

from trailscan.engine.base import BaseCheck
from trailscan.engine.models import Finding, Severity, Status


class IMDSv2Required(BaseCheck):
    check_id = "ec2.imds_v2_required"
    control_id = "CC6.6"
    title = "EC2 instances require IMDSv2"
    remediation = (
        "Enforce IMDSv2 on existing instances: EC2 Console → Instances → select instance "
        "→ Actions → Instance settings → Modify instance metadata options → set HTTP tokens to 'Required'. "
        "Or via CLI: aws ec2 modify-instance-metadata-options --instance-id <id> --http-tokens required. "
        "To enforce IMDSv2 on all new instances, set an account-level default: "
        "aws ec2 modify-instance-metadata-defaults --http-tokens required"
    )

    def run(self, session: boto3.Session, account_id: str) -> list[Finding]:
        ec2 = session.client("ec2")
        region = ec2.meta.region_name
        findings: list[Finding] = []

        try:
            paginator = ec2.get_paginator("describe_instances")
            reservations: list[dict] = []
            for page in paginator.paginate(
                Filters=[{"Name": "instance-state-name", "Values": ["running", "stopped"]}]
            ):
                reservations.extend(page["Reservations"])
        except ClientError as e:
            return [self._error(f"arn:aws:ec2:{region}:{account_id}:instance/*", region, e)]

        for reservation in reservations:
            for instance in reservation["Instances"]:
                instance_id = instance["InstanceId"]
                http_tokens = instance.get("MetadataOptions", {}).get("HttpTokens", "optional")

                findings.append(Finding(
                    check_id=self.check_id,
                    control_id=self.control_id,
                    title=self.title,
                    status=Status.PASS if http_tokens == "required" else Status.FAIL,
                    severity=Severity.MEDIUM,
                    resource_arn=f"arn:aws:ec2:{region}:{account_id}:instance/{instance_id}",
                    region=region,
                    evidence={"InstanceId": instance_id, "HttpTokens": http_tokens},
                    remediation=self.remediation,
                ))

        return findings
