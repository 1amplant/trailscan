import boto3
from botocore.exceptions import ClientError

from trailscan.engine.base import BaseCheck
from trailscan.engine.models import Finding, Severity, Status


class CloudWatchIntegration(BaseCheck):
    check_id = "cloudtrail.cloudwatch_integration"
    control_id = "CC7.2"
    title = "CloudTrail is integrated with CloudWatch Logs"
    remediation = (
        "Connect CloudTrail to CloudWatch Logs: CloudTrail Console → Trails → select trail "
        "→ Edit → CloudWatch Logs → enable and specify a log group name. "
        "Create an IAM role that allows CloudTrail to write to CloudWatch Logs when prompted. "
        "This is required for CloudWatch metric filters and alarms to work on CloudTrail events."
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
            log_group_arn = trail.get("CloudWatchLogsLogGroupArn")
            role_arn = trail.get("CloudWatchLogsRoleArn")
            integrated = bool(log_group_arn and role_arn)

            findings.append(Finding(
                check_id=self.check_id,
                control_id=self.control_id,
                title=self.title,
                status=Status.PASS if integrated else Status.FAIL,
                severity=Severity.MEDIUM,
                resource_arn=trail_arn,
                region=region,
                evidence={
                    "TrailName": trail.get("Name"),
                    "CloudWatchLogsLogGroupArn": log_group_arn,
                    "Integrated": integrated,
                },
                remediation=self.remediation,
            ))

        return findings
