from trailscan.checks.cloudtrail.enabled import CloudTrailEnabled
from trailscan.checks.cloudtrail.log_validation import LogFileValidation
from trailscan.checks.cloudtrail.cloudwatch_integration import CloudWatchIntegration
from trailscan.checks.cloudtrail.kms_encryption import CloudTrailKMSEncryption
from trailscan.checks.cloudtrail.s3_bucket_logging import CloudTrailS3BucketLogging

ALL_CLOUDTRAIL_CHECKS = [
    CloudTrailEnabled,
    LogFileValidation,
    CloudWatchIntegration,
    CloudTrailKMSEncryption,
    CloudTrailS3BucketLogging,
]
