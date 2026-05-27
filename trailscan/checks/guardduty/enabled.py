import boto3
from botocore.exceptions import ClientError

from trailscan.engine.base import BaseCheck
from trailscan.engine.models import Finding, Severity, Status


class GuardDutyEnabled(BaseCheck):
    check_id = "guardduty.enabled"
    control_id = "CC7.2"
    title = "GuardDuty is enabled for threat detection"
    remediation = (
        "Enable GuardDuty: GuardDuty Console → Get Started → Enable GuardDuty. "
        "Or via CLI: aws guardduty create-detector --enable. "
        "Enable in every active region — GuardDuty is region-specific. "
        "Set up SNS notifications for findings so the team is alerted. "
        "Consider enabling S3 Protection and EKS Protection for broader coverage."
    )

    def run(self, session: boto3.Session, account_id: str) -> list[Finding]:
        gd = session.client("guardduty")
        region = gd.meta.region_name
        resource_arn = f"arn:aws:guardduty:{region}:{account_id}:detector"

        try:
            detector_ids = gd.list_detectors()["DetectorIds"]
        except ClientError as e:
            return [self._error(resource_arn, region, e)]

        if not detector_ids:
            return [Finding(
                check_id=self.check_id,
                control_id=self.control_id,
                title=self.title,
                status=Status.WARN,
                severity=Severity.HIGH,
                resource_arn=resource_arn,
                region=region,
                evidence={"DetectorIds": [], "reason": "No GuardDuty detector found in this region"},
                remediation=self.remediation,
            )]

        findings: list[Finding] = []
        for detector_id in detector_ids:
            det_arn = f"arn:aws:guardduty:{region}:{account_id}:detector/{detector_id}"
            try:
                detector = gd.get_detector(DetectorId=detector_id)
            except ClientError as e:
                findings.append(self._error(det_arn, region, e))
                continue

            enabled = detector.get("Status") == "ENABLED"
            findings.append(Finding(
                check_id=self.check_id,
                control_id=self.control_id,
                title=self.title,
                status=Status.PASS if enabled else Status.WARN,
                severity=Severity.HIGH,
                resource_arn=det_arn,
                region=region,
                evidence={"DetectorId": detector_id, "Status": detector.get("Status")},
                remediation=self.remediation,
            ))

        return findings
