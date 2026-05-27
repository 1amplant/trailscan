from trailscan.checks.ec2.security_groups import SecurityGroupOpenToWorld
from trailscan.checks.ec2.ebs_encryption import EBSEncryption
from trailscan.checks.ec2.imds_v2 import IMDSv2Required
from trailscan.checks.ec2.public_snapshots import PublicSnapshots
from trailscan.checks.ec2.stopped_instances import StoppedInstances

ALL_EC2_CHECKS = [
    SecurityGroupOpenToWorld,
    EBSEncryption,
    IMDSv2Required,
    PublicSnapshots,
    StoppedInstances,
]
