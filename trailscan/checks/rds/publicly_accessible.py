import boto3
from botocore.exceptions import ClientError

from trailscan.engine.base import BaseCheck
from trailscan.engine.models import Finding, Severity, Status


class RDSPubliclyAccessible(BaseCheck):
    check_id = "rds.publicly_accessible"
    control_id = "CC6.6"
    title = "RDS instances are not publicly accessible"
    remediation = (
        "Disable public accessibility: RDS Console → Databases → select instance "
        "→ Modify → Connectivity → Public access → set to 'No' → Apply immediately. "
        "Move the RDS instance to a private subnet with no internet gateway route. "
        "Applications should connect via the VPC internally, not over the public internet."
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
            public = db.get("PubliclyAccessible", False)

            findings.append(Finding(
                check_id=self.check_id,
                control_id=self.control_id,
                title=self.title,
                status=Status.FAIL if public else Status.PASS,
                severity=Severity.HIGH,
                resource_arn=db["DBInstanceArn"],
                region=region,
                evidence={"DBInstanceIdentifier": db["DBInstanceIdentifier"], "Engine": db.get("Engine"), "PubliclyAccessible": public},
                remediation=self.remediation,
            ))

        return findings
