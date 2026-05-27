import boto3
from botocore.exceptions import ClientError

from trailscan.engine.base import BaseCheck
from trailscan.engine.models import Finding, Severity, Status


class LogFileValidation(BaseCheck):
    check_id = "cloudtrail.log_file_validation"
    control_id = "CC7.2"
    title = "CloudTrail log file validation is enabled"
    remediation = (
        "Enable log file validation on existing trails: CloudTrail Console → Trails "
        "→ select trail → Edit → enable 'Log file validation'. "
        "Or via CLI: aws cloudtrail update-trail --name <trail-name> --enable-log-file-validation. "
        "This creates a digest file every hour that allows you to detect if log files were modified or deleted."
    )

    def run(self, session: boto3.Session, account_id: str) -> list[Finding]:
        ct = session.client("cloudtrail")
        findings: list[Finding] = []

        try:
            trails = ct.describe_trails(includeShadowTrails=False)["trailList"]
        except ClientError as e:
            return [self._error("arn:aws:cloudtrail:::trail/*", "global", e)]

        for trail in trails:
            trail_arn = trail["TrailARN"]
            region = trail.get("HomeRegion", "unknown")
            validation_on = trail.get("LogFileValidationEnabled", False)

            findings.append(Finding(
                check_id=self.check_id,
                control_id=self.control_id,
                title=self.title,
                status=Status.PASS if validation_on else Status.FAIL,
                severity=Severity.MEDIUM,
                resource_arn=trail_arn,
                region=region,
                evidence={"TrailName": trail.get("Name"), "LogFileValidationEnabled": validation_on},
                remediation=self.remediation,
            ))

        return findings
