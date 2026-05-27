import boto3
from botocore.exceptions import ClientError

from trailscan.engine.base import BaseCheck
from trailscan.engine.models import Finding, Severity, Status


class PublicSnapshots(BaseCheck):
    check_id = "ec2.public_snapshots"
    control_id = "CC6.1"
    title = "EBS snapshots are not publicly accessible"
    remediation = (
        "Make public snapshots private: EC2 Console → Snapshots → select snapshot "
        "→ Actions → Modify permissions → set to Private. "
        "Or via CLI: aws ec2 modify-snapshot-attribute --snapshot-id <snap-id> "
        "--attribute createVolumePermission --operation-type remove "
        "--group-names all. "
        "Review all snapshots to ensure no customer data is exposed publicly."
    )

    def run(self, session: boto3.Session, account_id: str) -> list[Finding]:
        ec2 = session.client("ec2")
        region = ec2.meta.region_name
        findings: list[Finding] = []

        try:
            paginator = ec2.get_paginator("describe_snapshots")
            snapshots: list[dict] = []
            for page in paginator.paginate(OwnerIds=["self"]):
                snapshots.extend(page["Snapshots"])
        except ClientError as e:
            return [self._error(f"arn:aws:ec2:{region}:{account_id}:snapshot/*", region, e)]

        for snap in snapshots:
            snap_id = snap["SnapshotId"]
            resource_arn = f"arn:aws:ec2:{region}:{account_id}:snapshot/{snap_id}"

            try:
                perms = ec2.describe_snapshot_attribute(
                    SnapshotId=snap_id, Attribute="createVolumePermission"
                )["CreateVolumePermissions"]
            except ClientError as e:
                findings.append(self._error(resource_arn, region, e))
                continue

            is_public = any(p.get("Group") == "all" for p in perms)

            findings.append(Finding(
                check_id=self.check_id,
                control_id=self.control_id,
                title=self.title,
                status=Status.FAIL if is_public else Status.PASS,
                severity=Severity.CRITICAL,
                resource_arn=resource_arn,
                region=region,
                evidence={"SnapshotId": snap_id, "IsPublic": is_public},
                remediation=self.remediation,
            ))

        return findings
