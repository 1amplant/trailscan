from trailscan.checks.cloudwatch.root_usage_alarm import RootUsageAlarm
from trailscan.checks.cloudwatch.unauthorized_api_alarm import UnauthorizedAPIAlarm
from trailscan.checks.cloudwatch.iam_changes_alarm import IAMChangesAlarm

ALL_CLOUDWATCH_CHECKS = [
    RootUsageAlarm,
    UnauthorizedAPIAlarm,
    IAMChangesAlarm,
]
