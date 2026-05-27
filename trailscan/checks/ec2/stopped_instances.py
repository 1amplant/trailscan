import boto3
from botocore.exceptions import ClientError

from trailscan.engine.base import BaseCheck
from trailscan.engine.models import Finding, Severity, Status


class StoppedInstances(BaseCheck):
    check_id = "ec2.stopped_instances"
    control_id = "CC6.1"
    title = "No unreviewed stopped EC2 instances"
    remediation = (
        "Review all stopped instances and terminate any that are no longer needed. "
        "Stopped instances still hold IAM roles, EBS volumes, and may run outdated software when restarted. "
        "EC2 Console → Instances → filter by 'stopped' state → review each instance. "
        "Terminate with: aws ec2 terminate-instances --instance-ids <id>. "
        "Tag instances you intentionally keep stopped with a reason and review date."
    )

    def run(self, session: boto3.Session, account_id: str) -> list[Finding]:
        ec2 = session.client("ec2")
        region = ec2.meta.region_name
        findings: list[Finding] = []

        try:
            paginator = ec2.get_paginator("describe_instances")
            reservations: list[dict] = []
            for page in paginator.paginate(
                Filters=[{"Name": "instance-state-name", "Values": ["stopped"]}]
            ):
                reservations.extend(page["Reservations"])
        except ClientError as e:
            return [self._error(f"arn:aws:ec2:{region}:{account_id}:instance/*", region, e)]

        for reservation in reservations:
            for instance in reservation["Instances"]:
                instance_id = instance["InstanceId"]
                launch_time = instance.get("LaunchTime")

                findings.append(Finding(
                    check_id=self.check_id,
                    control_id=self.control_id,
                    title=self.title,
                    status=Status.WARN,
                    severity=Severity.LOW,
                    resource_arn=f"arn:aws:ec2:{region}:{account_id}:instance/{instance_id}",
                    region=region,
                    evidence={
                        "InstanceId": instance_id,
                        "InstanceType": instance.get("InstanceType"),
                        "LaunchTime": launch_time.isoformat() if launch_time else None,
                    },
                    remediation=self.remediation,
                ))

        return findings
