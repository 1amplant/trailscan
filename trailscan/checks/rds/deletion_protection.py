import boto3
from botocore.exceptions import ClientError

from trailscan.engine.base import BaseCheck
from trailscan.engine.models import Finding, Severity, Status


class RDSDeletionProtection(BaseCheck):
    check_id = "rds.deletion_protection"
    control_id = "CC9.1"
    title = "RDS instances have deletion protection enabled"
    remediation = (
        "Enable deletion protection: RDS Console → Databases → select instance → Modify "
        "→ Deletion protection → enable → Apply immediately. "
        "Or via CLI: aws rds modify-db-instance --db-instance-identifier <id> "
        "--deletion-protection --apply-immediately. "
        "This prevents accidental deletion of production databases."
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
            protected = db.get("DeletionProtection", False)

            findings.append(Finding(
                check_id=self.check_id,
                control_id=self.control_id,
                title=self.title,
                status=Status.PASS if protected else Status.WARN,
                severity=Severity.MEDIUM,
                resource_arn=db["DBInstanceArn"],
                region=region,
                evidence={"DBInstanceIdentifier": db["DBInstanceIdentifier"], "DeletionProtection": protected},
                remediation=self.remediation,
            ))

        return findings
