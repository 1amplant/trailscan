import boto3
from botocore.exceptions import ClientError

from trailscan.engine.base import BaseCheck
from trailscan.engine.models import Finding, Severity, Status

_HIGH_RISK_PORTS = {22, 3389, 3306, 5432, 1433, 27017, 6379}


class SecurityGroupOpenToWorld(BaseCheck):
    check_id = "ec2.security_group_open_to_world"
    control_id = "CC6.6"
    title = "Security groups do not allow unrestricted inbound access"
    remediation = (
        "Remove 0.0.0.0/0 inbound rules from security groups: EC2 Console → Security Groups "
        "→ select group → Inbound rules → Edit → delete or restrict the open rule. "
        "Replace with specific IP ranges or security group references. "
        "For SSH (22) and RDP (3389): use a bastion host or AWS Systems Manager Session Manager instead. "
        "For databases (3306, 5432, etc.): allow only from application security groups, never from the internet."
    )

    def run(self, session: boto3.Session, account_id: str) -> list[Finding]:
        ec2 = session.client("ec2")
        region = ec2.meta.region_name
        findings: list[Finding] = []

        try:
            paginator = ec2.get_paginator("describe_security_groups")
            groups: list[dict] = []
            for page in paginator.paginate():
                groups.extend(page["SecurityGroups"])
        except ClientError as e:
            return [self._error(f"arn:aws:ec2:{region}:{account_id}:security-group/*", region, e)]

        for sg in groups:
            sg_id = sg["GroupId"]
            resource_arn = f"arn:aws:ec2:{region}:{account_id}:security-group/{sg_id}"
            open_rules = _open_inbound_rules(sg.get("IpPermissions", []))

            if not open_rules:
                findings.append(Finding(
                    check_id=self.check_id,
                    control_id=self.control_id,
                    title=self.title,
                    status=Status.PASS,
                    severity=Severity.HIGH,
                    resource_arn=resource_arn,
                    region=region,
                    evidence={"GroupId": sg_id, "GroupName": sg.get("GroupName", "")},
                    remediation=self.remediation,
                ))
                continue

            all_traffic = any(r["all_traffic"] for r in open_rules)
            high_risk = any(
                r["from_port"] in _HIGH_RISK_PORTS or r["to_port"] in _HIGH_RISK_PORTS
                for r in open_rules if not r["all_traffic"]
            )
            severity = Severity.CRITICAL if all_traffic else (Severity.HIGH if high_risk else Severity.MEDIUM)

            findings.append(Finding(
                check_id=self.check_id,
                control_id=self.control_id,
                title=self.title,
                status=Status.FAIL,
                severity=severity,
                resource_arn=resource_arn,
                region=region,
                evidence={"GroupId": sg_id, "GroupName": sg.get("GroupName", ""), "OpenInboundRules": open_rules},
                remediation=self.remediation,
            ))

        return findings


def _open_inbound_rules(permissions: list[dict]) -> list[dict]:
    open_rules: list[dict] = []
    for perm in permissions:
        protocol = perm.get("IpProtocol", "")
        open_cidrs = (
            [r["CidrIp"] for r in perm.get("IpRanges", []) if r.get("CidrIp") == "0.0.0.0/0"]
            + [r["CidrIpv6"] for r in perm.get("Ipv6Ranges", []) if r.get("CidrIpv6") == "::/0"]
        )
        if not open_cidrs:
            continue
        all_traffic = protocol == "-1"
        open_rules.append({
            "protocol": "all" if all_traffic else protocol,
            "from_port": perm.get("FromPort"),
            "to_port": perm.get("ToPort"),
            "all_traffic": all_traffic,
            "open_cidrs": open_cidrs,
        })
    return open_rules
