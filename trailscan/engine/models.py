from __future__ import annotations

from dataclasses import dataclass, field


class Status:
    PASS = "pass"
    FAIL = "fail"
    WARN = "warn"
    ERROR = "error"


class Severity:
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class Finding:
    check_id: str
    control_id: str
    title: str
    status: str
    severity: str
    resource_arn: str
    region: str
    evidence: dict
    remediation: str = ""

    def to_dict(self) -> dict:
        return {
            "check_id": self.check_id,
            "control_id": self.control_id,
            "title": self.title,
            "status": self.status,
            "severity": self.severity,
            "resource_arn": self.resource_arn,
            "region": self.region,
            "evidence": self.evidence,
            "remediation": self.remediation,
        }
