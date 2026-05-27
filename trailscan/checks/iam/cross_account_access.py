import json

import boto3
from botocore.exceptions import ClientError

from trailscan.engine.base import BaseCheck
from trailscan.engine.models import Finding, Severity, Status


class CrossAccountAccessWithoutExternalId(BaseCheck):
    check_id = "iam.cross_account_no_external_id"
    control_id = "CC6.1"
    title = "Cross-account IAM roles require an ExternalId condition"
    remediation = (
        "Add an ExternalId condition to any IAM role that trusts an external AWS account. "
        "In the role's trust policy, add: \"Condition\": {\"StringEquals\": {\"sts:ExternalId\": \"<unique-id>\"}}. "
        "Coordinate the ExternalId value with the trusted party. "
        "This prevents confused-deputy attacks where a malicious third party tricks "
        "a trusted service into accessing your account."
    )

    def run(self, session: boto3.Session, account_id: str) -> list[Finding]:
        iam = session.client("iam")
        findings: list[Finding] = []

        try:
            roles = _paginate(iam, "list_roles", "Roles")
        except ClientError as e:
            return [self._error(f"arn:aws:iam::{account_id}:role/*", "global", e)]

        for role in roles:
            role_arn = role["Arn"]
            trust_doc = role["AssumeRolePolicyDocument"]
            if isinstance(trust_doc, str):
                trust_doc = json.loads(trust_doc)

            issues = _check_trust_policy(trust_doc, account_id)
            if issues is None:
                continue

            findings.append(Finding(
                check_id=self.check_id,
                control_id=self.control_id,
                title=self.title,
                status=Status.FAIL if issues else Status.PASS,
                severity=Severity.HIGH,
                resource_arn=role_arn,
                region="global",
                evidence={
                    "RoleName": role["RoleName"],
                    "Issues": issues,
                },
                remediation=self.remediation,
            ))

        return findings


def _check_trust_policy(doc: dict, own_account_id: str) -> list[str] | None:
    issues = []
    trusts_external = False

    for stmt in doc.get("Statement", []):
        if stmt.get("Effect") != "Allow":
            continue
        principal = stmt.get("Principal", {})
        aws_principals = principal if isinstance(principal, str) else principal.get("AWS", [])
        if isinstance(aws_principals, str):
            aws_principals = [aws_principals]

        for p in aws_principals:
            if own_account_id not in p and p != "*":
                trusts_external = True
                conditions = stmt.get("Condition", {})
                has_external_id = "sts:ExternalId" in conditions.get("StringEquals", {})
                if not has_external_id:
                    issues.append(f"Principal {p} trusted without ExternalId condition")
            elif p == "*":
                trusts_external = True
                issues.append("Principal: * grants access to any AWS account")

    return issues if trusts_external else None


def _paginate(client, method: str, key: str) -> list:
    results = []
    paginator = client.get_paginator(method)
    for page in paginator.paginate():
        results.extend(page[key])
    return results
