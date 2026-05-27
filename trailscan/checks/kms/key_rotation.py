import boto3
from botocore.exceptions import ClientError

from trailscan.engine.base import BaseCheck
from trailscan.engine.models import Finding, Severity, Status


class KMSKeyRotation(BaseCheck):
    check_id = "kms.key_rotation_enabled"
    control_id = "CC6.1"
    title = "KMS customer-managed keys have automatic rotation enabled"
    remediation = (
        "Enable key rotation: KMS Console → Customer managed keys → select key "
        "→ Key rotation tab → enable 'Automatically rotate this KMS key every year'. "
        "Or via CLI: aws kms enable-key-rotation --key-id <key-id>. "
        "Key rotation only applies to symmetric encryption keys — asymmetric keys must be rotated manually."
    )

    def run(self, session: boto3.Session, account_id: str) -> list[Finding]:
        kms = session.client("kms")
        region = kms.meta.region_name
        findings: list[Finding] = []

        try:
            paginator = kms.get_paginator("list_keys")
            keys: list[dict] = []
            for page in paginator.paginate():
                keys.extend(page["Keys"])
        except ClientError as e:
            return [self._error(f"arn:aws:kms:{region}:{account_id}:key/*", region, e)]

        if not keys:
            return []

        for key in keys:
            key_id = key["KeyId"]
            key_arn = key["KeyArn"]

            try:
                metadata = kms.describe_key(KeyId=key_id)["KeyMetadata"]
            except ClientError:
                continue

            if metadata.get("KeyManager") != "CUSTOMER":
                continue
            if metadata.get("KeyState") not in ("Enabled",):
                continue
            if metadata.get("KeySpec", "SYMMETRIC_DEFAULT") != "SYMMETRIC_DEFAULT":
                continue
            if metadata.get("KeyUsage", "ENCRYPT_DECRYPT") != "ENCRYPT_DECRYPT":
                continue

            try:
                rotation_resp = kms.get_key_rotation_status(KeyId=key_id)
                rotation_enabled = rotation_resp.get("KeyRotationEnabled", False)
            except ClientError as e:
                findings.append(self._error(key_arn, region, e))
                continue

            findings.append(Finding(
                check_id=self.check_id,
                control_id=self.control_id,
                title=self.title,
                status=Status.PASS if rotation_enabled else Status.FAIL,
                severity=Severity.MEDIUM,
                resource_arn=key_arn,
                region=region,
                evidence={"KeyId": key_id, "KeyRotationEnabled": rotation_enabled},
                remediation=self.remediation,
            ))

        return findings
