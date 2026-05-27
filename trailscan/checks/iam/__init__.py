from trailscan.checks.iam.mfa_enabled import RootMFAEnabled, UsersMFAEnabled
from trailscan.checks.iam.password_policy import PasswordPolicy
from trailscan.checks.iam.root_account_usage import RootAccessKeys
from trailscan.checks.iam.access_key_rotation import AccessKeyRotation
from trailscan.checks.iam.unused_credentials import UnusedCredentials
from trailscan.checks.iam.overly_permissive_policies import OverlyPermissivePolicies
from trailscan.checks.iam.cross_account_access import CrossAccountAccessWithoutExternalId

ALL_IAM_CHECKS = [
    RootMFAEnabled,
    UsersMFAEnabled,
    PasswordPolicy,
    RootAccessKeys,
    AccessKeyRotation,
    UnusedCredentials,
    OverlyPermissivePolicies,
    CrossAccountAccessWithoutExternalId,
]
