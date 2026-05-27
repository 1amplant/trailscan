from trailscan.checks.iam import ALL_IAM_CHECKS
from trailscan.checks.s3 import ALL_S3_CHECKS
from trailscan.checks.cloudtrail import ALL_CLOUDTRAIL_CHECKS
from trailscan.checks.ec2 import ALL_EC2_CHECKS
from trailscan.checks.rds import ALL_RDS_CHECKS
from trailscan.checks.guardduty import ALL_GUARDDUTY_CHECKS
from trailscan.checks.vpc import ALL_VPC_CHECKS
from trailscan.checks.kms import ALL_KMS_CHECKS
from trailscan.checks.cloudwatch import ALL_CLOUDWATCH_CHECKS

ALL_CHECKS = (
    ALL_IAM_CHECKS
    + ALL_S3_CHECKS
    + ALL_CLOUDTRAIL_CHECKS
    + ALL_EC2_CHECKS
    + ALL_RDS_CHECKS
    + ALL_GUARDDUTY_CHECKS
    + ALL_VPC_CHECKS
    + ALL_KMS_CHECKS
    + ALL_CLOUDWATCH_CHECKS
)
