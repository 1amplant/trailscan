import boto3
from botocore.exceptions import ClientError

from trailscan.engine.base import BaseCheck
from trailscan.engine.models import Finding, Severity, Status


class VPCFlowLogsEnabled(BaseCheck):
    check_id = "vpc.flow_logs_enabled"
    control_id = "CC7.2"
    title = "VPC flow logs are enabled"
    remediation = (
        "Enable VPC flow logs: VPC Console → Your VPCs → select VPC → Flow logs tab "
        "→ Create flow log → deliver to CloudWatch Logs or S3. "
        "Or via CLI: aws ec2 create-flow-logs --resource-type VPC --resource-ids <vpc-id> "
        "--traffic-type ALL --log-destination-type cloud-watch-logs "
        "--log-group-name /aws/vpc/flowlogs --deliver-logs-permission-arn <role-arn>. "
        "Capture ALL traffic (not just REJECT) for complete audit coverage."
    )

    def run(self, session: boto3.Session, account_id: str) -> list[Finding]:
        ec2 = session.client("ec2")
        region = ec2.meta.region_name
        findings: list[Finding] = []

        try:
            vpcs = ec2.describe_vpcs()["Vpcs"]
            all_flow_logs = ec2.describe_flow_logs()["FlowLogs"]
        except ClientError as e:
            return [self._error(f"arn:aws:ec2:{region}:{account_id}:vpc/*", region, e)]

        active_by_vpc: dict[str, bool] = {}
        for fl in all_flow_logs:
            if fl.get("FlowLogStatus") == "ACTIVE":
                active_by_vpc[fl.get("ResourceId", "")] = True

        for vpc in vpcs:
            vpc_id = vpc["VpcId"]
            has_logs = active_by_vpc.get(vpc_id, False)

            findings.append(Finding(
                check_id=self.check_id,
                control_id=self.control_id,
                title=self.title,
                status=Status.PASS if has_logs else Status.FAIL,
                severity=Severity.HIGH,
                resource_arn=f"arn:aws:ec2:{region}:{account_id}:vpc/{vpc_id}",
                region=region,
                evidence={"VpcId": vpc_id, "IsDefault": vpc.get("IsDefault", False), "FlowLogsEnabled": has_logs},
                remediation=self.remediation,
            ))

        return findings
