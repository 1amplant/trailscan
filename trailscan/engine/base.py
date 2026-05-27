from abc import ABC, abstractmethod

import boto3

from trailscan.engine.models import Finding, Severity, Status


class BaseCheck(ABC):
    check_id: str
    control_id: str
    title: str
    remediation: str = ""

    @abstractmethod
    def run(self, session: boto3.Session, account_id: str) -> list[Finding]:
        """Execute the check and return a list of findings."""

    def _error(self, resource_arn: str, region: str, exc: Exception) -> Finding:
        return Finding(
            check_id=self.check_id,
            control_id=self.control_id,
            title=self.title,
            status=Status.ERROR,
            severity=Severity.INFO,
            resource_arn=resource_arn,
            region=region,
            evidence={"error": str(exc)},
            remediation=self.remediation,
        )
