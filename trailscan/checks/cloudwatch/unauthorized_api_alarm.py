import boto3

from trailscan.engine.base import BaseCheck
from trailscan.engine.models import Finding, Severity, Status
from trailscan.checks.cloudwatch._helpers import (
    get_cloudtrail_log_groups,
    get_metric_filters_for_log_group,
    alarm_exists_for_metric,
    filter_matches_keywords,
)

_UNAUTH_KEYWORDS = ["AccessDenied", "UnauthorizedOperation", "accessDenied", "unauthorized"]


class UnauthorizedAPIAlarm(BaseCheck):
    check_id = "cloudwatch.unauthorized_api_alarm"
    control_id = "CC7.2"
    title = "CloudWatch alarm exists for unauthorized API calls"
    remediation = (
        "Create a CloudWatch metric filter and alarm for unauthorized API calls: "
        "1. CloudWatch → Log groups → select CloudTrail log group → Metric filters → Create. "
        "2. Filter pattern: { ($.errorCode = \"AccessDenied\") || ($.errorCode = \"UnauthorizedOperation\") }. "
        "3. Create a metric then an alarm triggering when count > 0 over a 5-minute period. "
        "4. Attach an SNS topic to send email or Slack notifications."
    )

    def run(self, session: boto3.Session, account_id: str) -> list[Finding]:
        log_groups = get_cloudtrail_log_groups(session)
        resource_arn = f"arn:aws:cloudwatch::{account_id}:alarm/unauthorized-api"

        if not log_groups:
            return []

        for lg_name, region in log_groups:
            logs_client = session.client("logs", region_name=region)
            cw_client = session.client("cloudwatch", region_name=region)

            for f in get_metric_filters_for_log_group(logs_client, lg_name):
                if not filter_matches_keywords(f.get("filterPattern", ""), _UNAUTH_KEYWORDS):
                    continue
                for mt in f.get("metricTransformations", []):
                    if alarm_exists_for_metric(cw_client, mt.get("metricNamespace", ""), mt.get("metricName", "")):
                        return [Finding(
                            check_id=self.check_id,
                            control_id=self.control_id,
                            title=self.title,
                            status=Status.PASS,
                            severity=Severity.HIGH,
                            resource_arn=resource_arn,
                            region=region,
                            evidence={"LogGroup": lg_name, "FilterName": f.get("filterName"), "AlarmExists": True},
                            remediation=self.remediation,
                        )]

        first_region = log_groups[0][1] if log_groups else (session.region_name or "us-east-1")
        return [Finding(
            check_id=self.check_id,
            control_id=self.control_id,
            title=self.title,
            status=Status.FAIL,
            severity=Severity.HIGH,
            resource_arn=resource_arn,
            region=first_region,
            evidence={"LogGroupsChecked": [lg for lg, _ in log_groups], "AlarmExists": False},
            remediation=self.remediation,
        )]
