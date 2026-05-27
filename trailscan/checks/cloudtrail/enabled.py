import boto3
from botocore.exceptions import ClientError

from trailscan.engine.base import BaseCheck
from trailscan.engine.models import Finding, Severity, Status


class CloudTrailEnabled(BaseCheck):
    check_id = "cloudtrail.enabled"
    control_id = "CC7.2"
    title = "CloudTrail is enabled with at least one active multi-region trail"
    remediation = (
        "Create a multi-region CloudTrail trail: CloudTrail Console → Trails → Create trail. "
        "Enable 'Apply trail to all regions', enable log file validation, and deliver logs "
        "to an S3 bucket and optionally to CloudWatch Logs. "
        "Or via CLI: aws cloudtrail create-trail --name my-trail --s3-bucket-name <bucket> "
        "--is-multi-region-trail --enable-log-file-validation, "
        "then aws cloudtrail start-logging --name my-trail"
    )

    def run(self, session: boto3.Session, account_id: str) -> list[Finding]:
        ct = session.client("cloudtrail")
        resource_arn = "arn:aws:cloudtrail:::trail/*"

        try:
            trails = ct.describe_trails(includeShadowTrails=False)["trailList"]
        except ClientError as e:
            return [self._error(resource_arn, "global", e)]

        if not trails:
            return [Finding(
                check_id=self.check_id,
                control_id=self.control_id,
                title=self.title,
                status=Status.FAIL,
                severity=Severity.CRITICAL,
                resource_arn=resource_arn,
                region="global",
                evidence={"trails": [], "error": "No CloudTrail trails found"},
                remediation=self.remediation,
            )]

        active_multi_region = []
        for trail in trails:
            trail_arn = trail["TrailARN"]
            if not trail.get("IsMultiRegionTrail"):
                continue
            try:
                status = ct.get_trail_status(Name=trail_arn)
                if status.get("IsLogging"):
                    active_multi_region.append({"TrailARN": trail_arn, "Name": trail.get("Name")})
            except ClientError:
                continue

        has_active = len(active_multi_region) > 0

        return [Finding(
            check_id=self.check_id,
            control_id=self.control_id,
            title=self.title,
            status=Status.PASS if has_active else Status.FAIL,
            severity=Severity.CRITICAL,
            resource_arn=resource_arn,
            region="global",
            evidence={
                "TotalTrails": len(trails),
                "ActiveMultiRegionTrails": active_multi_region,
            },
            remediation=self.remediation,
        )]
