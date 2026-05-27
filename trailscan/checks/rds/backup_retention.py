import boto3
from botocore.exceptions import ClientError

from trailscan.engine.base import BaseCheck
from trailscan.engine.models import Finding, Severity, Status

MIN_RETENTION_DAYS = 7


class RDSBackupRetention(BaseCheck):
    check_id = "rds.backup_retention"
    control_id = "CC9.1"
    title = "RDS instances have automated backups enabled (retention >= 7 days)"
    remediation = (
        "Enable automated backups with a minimum 7-day retention: RDS Console → Databases "
        "→ select instance → Modify → Backup → set backup retention period to 7 or more days "
        "→ Apply immediately. "
        "Or via CLI: aws rds modify-db-instance --db-instance-identifier <id> "
        "--backup-retention-period 7 --apply-immediately"
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
            retention = db.get("BackupRetentionPeriod", 0)
            pass_check = retention >= MIN_RETENTION_DAYS

            findings.append(Finding(
                check_id=self.check_id,
                control_id=self.control_id,
                title=self.title,
                status=Status.PASS if pass_check else Status.FAIL,
                severity=Severity.HIGH,
                resource_arn=db["DBInstanceArn"],
                region=region,
                evidence={"DBInstanceIdentifier": db["DBInstanceIdentifier"], "BackupRetentionPeriod": retention},
                remediation=self.remediation,
            ))

        return findings
