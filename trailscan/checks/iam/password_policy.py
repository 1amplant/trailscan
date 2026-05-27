import boto3
from botocore.exceptions import ClientError

from trailscan.engine.base import BaseCheck
from trailscan.engine.models import Finding, Severity, Status

_REQUIREMENTS: list[tuple[str, object, str]] = [
    ("MinimumPasswordLength",       14,   ">="),
    ("RequireUppercaseCharacters",  True, "=="),
    ("RequireLowercaseCharacters",  True, "=="),
    ("RequireNumbers",              True, "=="),
    ("RequireSymbols",              True, "=="),
    ("MaxPasswordAge",              90,   "<="),
    ("PasswordReusePrevention",     24,   ">="),
]


class PasswordPolicy(BaseCheck):
    check_id = "iam.password_policy"
    control_id = "CC6.1"
    title = "IAM account password policy meets SOC 2 requirements"
    remediation = (
        "Go to IAM Console → Account settings → Edit password policy. "
        "Set minimum length to 14+, require uppercase, lowercase, numbers and symbols, "
        "set max password age to 90 days, and prevent reuse of the last 24 passwords. "
        "Or via CLI: aws iam update-account-password-policy --minimum-password-length 14 "
        "--require-symbols --require-numbers --require-uppercase-characters "
        "--require-lowercase-characters --max-password-age 90 --password-reuse-prevention 24"
    )

    def run(self, session: boto3.Session, account_id: str) -> list[Finding]:
        iam = session.client("iam")
        resource_arn = f"arn:aws:iam::{account_id}:account-password-policy"

        try:
            policy = iam.get_account_password_policy()["PasswordPolicy"]
        except ClientError as e:
            if e.response["Error"]["Code"] == "NoSuchEntity":
                return [Finding(
                    check_id=self.check_id,
                    control_id=self.control_id,
                    title=self.title,
                    status=Status.FAIL,
                    severity=Severity.HIGH,
                    resource_arn=resource_arn,
                    region="global",
                    evidence={"error": "No IAM account password policy is configured"},
                    remediation=self.remediation,
                )]
            return [self._error(resource_arn, "global", e)]

        failures = _evaluate(policy)

        return [Finding(
            check_id=self.check_id,
            control_id=self.control_id,
            title=self.title,
            status=Status.FAIL if failures else Status.PASS,
            severity=Severity.MEDIUM,
            resource_arn=resource_arn,
            region="global",
            evidence={"PasswordPolicy": policy, "failures": failures},
            remediation=self.remediation,
        )]


def _evaluate(policy: dict) -> list[str]:
    failures = []
    for field, required, op in _REQUIREMENTS:
        value = policy.get(field)
        if op == ">=" and (value is None or value < required):
            failures.append(f"{field}: got {value!r}, need >= {required}")
        elif op == "<=" and value is not None and value > required:
            failures.append(f"{field}: got {value!r}, need <= {required}")
        elif op == "==" and value is not True:
            failures.append(f"{field} must be enabled")
    return failures
