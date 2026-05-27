import boto3
from botocore.exceptions import ClientError

from trailscan.engine.base import BaseCheck
from trailscan.engine.models import Finding, Severity, Status


class EBSEncryption(BaseCheck):
    check_id = "ec2.ebs_encryption"
    control_id = "CC6.7"
    title = "EBS volumes are encrypted at rest"
    remediation = (
        "Enable EBS encryption by default for all new volumes: EC2 Console → Settings "
        "→ EBS encryption → Manage → enable 'Always encrypt new EBS volumes'. "
        "For existing unencrypted volumes: create a snapshot, copy the snapshot with encryption enabled, "
        "then create a new encrypted volume from the snapshot and replace the original. "
        "Or via CLI to enable default encryption: aws ec2 enable-ebs-encryption-by-default"
    )

    def run(self, session: boto3.Session, account_id: str) -> list[Finding]:
        ec2 = session.client("ec2")
        region = ec2.meta.region_name
        findings: list[Finding] = []

        try:
            paginator = ec2.get_paginator("describe_volumes")
            volumes: list[dict] = []
            for page in paginator.paginate():
                volumes.extend(page["Volumes"])
        except ClientError as e:
            return [self._error(f"arn:aws:ec2:{region}:{account_id}:volume/*", region, e)]

        for vol in volumes:
            vol_id = vol["VolumeId"]
            encrypted = vol.get("Encrypted", False)

            findings.append(Finding(
                check_id=self.check_id,
                control_id=self.control_id,
                title=self.title,
                status=Status.PASS if encrypted else Status.FAIL,
                severity=Severity.HIGH,
                resource_arn=f"arn:aws:ec2:{region}:{account_id}:volume/{vol_id}",
                region=region,
                evidence={"VolumeId": vol_id, "Encrypted": encrypted, "State": vol.get("State")},
                remediation=self.remediation,
            ))

        return findings
