from trailscan.checks.s3.public_access_block import AccountPublicAccessBlock, BucketPublicAccessBlock
from trailscan.checks.s3.bucket_acl import BucketACL
from trailscan.checks.s3.bucket_encryption import BucketEncryption
from trailscan.checks.s3.bucket_logging import BucketLogging
from trailscan.checks.s3.bucket_versioning import BucketVersioning
from trailscan.checks.s3.bucket_policy import BucketPolicyPublic

ALL_S3_CHECKS = [
    AccountPublicAccessBlock,
    BucketPublicAccessBlock,
    BucketACL,
    BucketEncryption,
    BucketLogging,
    BucketVersioning,
    BucketPolicyPublic,
]
