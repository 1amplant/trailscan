import json

import boto3
from botocore.exceptions import ClientError

from trailscan.engine.base import BaseCheck
from trailscan.engine.models import Finding, Severity, Status


class OverlyPermissivePolicies(BaseCheck):
    check_id = "iam.overly_permissive_policies"
    control_id = "CC6.1"
    title = "Customer-managed IAM policies do not allow Action:* on Resource:*"
    remediation = (
        "Replace wildcard policies with least-privilege policies. "
        "In IAM Console → Policies → select the policy → Edit → remove any statements "
        "with Action: '*' and Resource: '*'. Replace with specific actions and resources "
        "required for the role. Use IAM Access Analyzer to generate least-privilege policies "
        "based on actual usage."
    )

    def run(self, session: boto3.Session, account_id: str) -> list[Finding]:
        iam = session.client("iam")
        findings: list[Finding] = []

        try:
            policies = _paginate(iam, "list_policies", "Policies", Scope="Local")
        except ClientError as e:
            return [self._error(f"arn:aws:iam::{account_id}:policy/*", "global", e)]

        for policy in policies:
            policy_arn = policy["Arn"]

            try:
                version_id = policy["DefaultVersionId"]
                doc = iam.get_policy_version(
                    PolicyArn=policy_arn, VersionId=version_id
                )["PolicyVersion"]["Document"]
                if isinstance(doc, str):
                    doc = json.loads(doc)
            except ClientError as e:
                findings.append(self._error(policy_arn, "global", e))
                continue

            wildcards = _find_wildcard_statements(doc)

            findings.append(Finding(
                check_id=self.check_id,
                control_id=self.control_id,
                title=self.title,
                status=Status.FAIL if wildcards else Status.PASS,
                severity=Severity.HIGH,
                resource_arn=policy_arn,
                region="global",
                evidence={
                    "PolicyName": policy["PolicyName"],
                    "WildcardStatements": wildcards,
                },
                remediation=self.remediation,
            ))

        return findings


def _find_wildcard_statements(doc: dict) -> list[dict]:
    wildcards = []
    for stmt in doc.get("Statement", []):
        if stmt.get("Effect") != "Allow":
            continue
        actions = stmt.get("Action", [])
        resources = stmt.get("Resource", [])
        if isinstance(actions, str):
            actions = [actions]
        if isinstance(resources, str):
            resources = [resources]
        if "*" in actions and "*" in resources:
            wildcards.append(stmt)
    return wildcards


def _paginate(client, method: str, key: str, **kwargs) -> list:
    results = []
    paginator = client.get_paginator(method)
    for page in paginator.paginate(**kwargs):
        results.extend(page[key])
    return results
