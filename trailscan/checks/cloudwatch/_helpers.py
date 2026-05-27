from __future__ import annotations

import boto3
from botocore.exceptions import ClientError


def get_cloudtrail_log_groups(session: boto3.Session) -> list[tuple[str, str]]:
    ct = session.client("cloudtrail")
    try:
        trails = ct.describe_trails(includeShadowTrails=False)["trailList"]
    except ClientError:
        return []

    results: list[tuple[str, str]] = []
    for trail in trails:
        lg_arn = trail.get("CloudWatchLogsLogGroupArn")
        if not lg_arn:
            continue
        parts = lg_arn.split(":")
        if len(parts) >= 7:
            lg_name = parts[6]
            home_region = trail.get("HomeRegion", session.region_name or "us-east-1")
            results.append((lg_name, home_region))
    return results


def get_metric_filters_for_log_group(logs_client, log_group_name: str) -> list[dict]:
    try:
        paginator = logs_client.get_paginator("describe_metric_filters")
        filters: list[dict] = []
        for page in paginator.paginate(logGroupName=log_group_name):
            filters.extend(page.get("metricFilters", []))
        return filters
    except ClientError:
        return []


def alarm_exists_for_metric(cw_client, namespace: str, metric_name: str) -> bool:
    try:
        resp = cw_client.describe_alarms_for_metric(MetricName=metric_name, Namespace=namespace)
        return len(resp.get("MetricAlarms", [])) > 0
    except ClientError:
        return False


def filter_matches_keywords(filter_pattern: str, keywords: list[str]) -> bool:
    pattern_lower = filter_pattern.lower()
    return any(kw.lower() in pattern_lower for kw in keywords)
