import boto3
from botocore.exceptions import ClientError

from trailscan.engine.base import BaseCheck
from trailscan.engine.models import Finding, Severity, Status


class RDSStorageEncrypted(BaseCheck):
    check_id = "rds.storage_encrypted"
    control_id = "CC6.7"
    title = "RDS instances have storage encryption enabled"
    remediation = (
        "RDS encryption cannot be enabled on an existing unencrypted instance directly. "
        "To encrypt: create a snapshot of the instance → copy the snapshot with encryption enabled "
        "→ restore a new instance from the encrypted snapshot → update application connection strings "
        "→ delete the old instance. "
        "For new instances, always enable encryption at creation time in the RDS Console under Storage."
    )

    def run(self, session: boto3.Session, account_id: str) -> list[Finding]:
        rds = session.client("rds")
        region = rds.meta.region_name
        findings: list[Finding] = []

        try:
            paginator = rds.get_paginator("describe_db_instances")
            instances: list[dict] = []
            for page in paginator.paginate():
                instances.extend(page["DBInstances"])
        except ClientError as e:
            return [self._error(f"arn:aws:rds:{region}:{account_id}:db:*", region, e)]

        for db in instances:
            encrypted = db.get("StorageEncrypted", False)

            findings.append(Finding(
                check_id=self.check_id,
                control_id=self.control_id,
                title=self.title,
                status=Status.PASS if encrypted else Status.FAIL,
                severity=Severity.HIGH,
                resource_arn=db["DBInstanceArn"],
                region=region,
                evidence={"DBInstanceIdentifier": db["DBInstanceIdentifier"], "StorageEncrypted": encrypted},
                remediation=self.remediation,
            ))

        return findings
