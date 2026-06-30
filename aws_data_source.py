import json
import re
import pandas as pd
import streamlit as st
from pathlib import Path
from datetime import datetime, timedelta

REPORT_DIR = Path("reports")

# ── lazy boto3 helper ──────────────────────────────

def _client(name):
    try:
        import boto3
        return boto3.client(name)
    except Exception:
        return None


# ── CloudWatch Logs Insights ───────────────────────

CW_QUERY = """
fields @timestamp, @message
| filter @message like /(?i)(Failed password|Invalid user|authentication failure|sudo|ConsoleLogin|RootLogin|Unauthorized)/
| sort @timestamp desc
| limit 500
"""


def _run_cw_logs_query(log_group_name, hours=1):
    logs = _client("logs")
    if not logs:
        return []
    now_ts = datetime.utcnow().timestamp()
    start = int(now_ts - hours * 3600)
    end = int(now_ts)
    for attempt_start in [start, 0]:
        try:
            resp = logs.start_query(
                logGroupName=log_group_name,
                startTime=attempt_start,
                endTime=end,
                queryString=CW_QUERY,
            )
            query_id = resp["queryId"]
            import time as _time
            for _ in range(20):
                _time.sleep(1)
                result = logs.get_query_results(queryId=query_id)
                if result["status"] == "Complete":
                    return result.get("results", [])
            return []
        except Exception:
            continue
    return []


def _list_log_groups():
    logs = _client("logs")
    if not logs:
        return []
    groups = []
    try:
        paginator = logs.get_paginator("describe_log_groups")
        for page in paginator.paginate():
            for lg in page.get("logGroups", []):
                groups.append(lg["logGroupName"])
    except Exception:
        pass
    return groups


# ── CloudTrail ─────────────────────────────────────

def _fetch_cloudtrail_events(hours=24):
    ct = _client("cloudtrail")
    if not ct:
        return []
    events = []
    try:
        resp = ct.lookup_events(
            LookupAttributes=[
                {"AttributeKey": "EventName", "AttributeValue": "ConsoleLogin"},
            ],
            StartTime=datetime.utcnow() - timedelta(hours=hours),
            EndTime=datetime.utcnow(),
            MaxResults=50,
        )
        events.extend(resp.get("Events", []))
    except Exception:
        pass
    try:
        resp = ct.lookup_events(
            LookupAttributes=[
                {"AttributeKey": "EventName", "AttributeValue": "CreateAccessKey"},
            ],
            StartTime=datetime.utcnow() - timedelta(hours=hours),
            EndTime=datetime.utcnow(),
            MaxResults=50,
        )
        events.extend(resp.get("Events", []))
    except Exception:
        pass
    return events


# ── CloudWatch Metrics (EC2) ───────────────────────

def _fetch_ec2_metrics(instance_id):
    cw = _client("cloudwatch")
    if not cw or not instance_id:
        return {}
    metrics = {}
    for name in ["CPUUtilization", "StatusCheckFailed", "NetworkIn", "NetworkOut"]:
        try:
            resp = cw.get_metric_statistics(
                Namespace="AWS/EC2",
                MetricName=name,
                Dimensions=[{"Name": "InstanceId", "Value": instance_id}],
                StartTime=datetime.utcnow() - timedelta(hours=1),
                EndTime=datetime.utcnow(),
                Period=300,
                Statistics=["Average", "Maximum"],
            )
            points = resp.get("Datapoints", [])
            metrics[name] = points[-1] if points else None
        except Exception:
            metrics[name] = None
    return metrics


# ── EC2 Instance list ──────────────────────────────

def _fetch_ec2_instances():
    ec2 = _client("ec2")
    if not ec2:
        return []
    try:
        resp = ec2.describe_instances()
        instances = []
        for r in resp.get("Reservations", []):
            for inst in r.get("Instances", []):
                instances.append({
                    "InstanceId": inst["InstanceId"],
                    "State": inst["State"]["Name"],
                    "InstanceType": inst["InstanceType"],
                    "LaunchTime": inst["LaunchTime"].isoformat(),
                    "PublicIp": inst.get("PublicIpAddress", ""),
                    "PrivateIp": inst.get("PrivateIpAddress", ""),
                    "Name": next((t["Value"] for t in inst.get("Tags", []) if t["Key"] == "Name"), ""),
                })
        return instances
    except Exception:
        return []


# ── helpers ────────────────────────────────────────

def _determine_severity(msg):
    msg = msg.lower()
    if re.search(r"root|admin|multiple.*(failed|invalid)", msg):
        return "CRITICAL"
    if re.search(r"failed password|invalid user|authentication failure", msg):
        return "HIGH"
    if re.search(r"sudo|unauthorized|consolelogin", msg):
        return "MEDIUM"
    return "LOW"


def _extract_ip_from_msg(msg):
    ip_match = re.search(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", msg)
    return ip_match.group(0) if ip_match else "N/A"


def _extract_user_from_msg(msg):
    for pattern in [r"for\s+(\S+)", r"user\s+(\S+)", r"Invalid\s+user\s+(\S+)"]:
        m = re.search(pattern, msg, re.IGNORECASE)
        if m:
            return m.group(1)
    return "unknown"


def _parse_cw_timestamp(ts_str):
    try:
        return pd.to_datetime(ts_str, errors="coerce")
    except Exception:
        return pd.NaT


# ── public API ─────────────────────────────────────

@st.cache_data(ttl=25, show_spinner="Querying CloudWatch Logs...")
def fetch_findings():
    incidents = []

    # ── CloudWatch Logs Insights ────────────────────
    log_groups = _list_log_groups()
    for lg in log_groups:
        results = _run_cw_logs_query(lg, hours=1)
        for row in results:
            fields = {f["field"]: f.get("value", "") for f in row}
            msg = fields.get("@message", "")
            ts = fields.get("@timestamp", "")
            incidents.append({
                "id": f"cw-{hash(msg) % 10**12:012d}",
                "incident_id": f"cw-{hash(msg) % 10**8:08d}",
                "timestamp": _parse_cw_timestamp(ts),
                "source_ip": _extract_ip_from_msg(msg),
                "severity": _determine_severity(msg),
                "finding_type": "CloudWatch Logs",
                "hostname": lg.split("/")[-1] if "/" in lg else lg,
                "username": _extract_user_from_msg(msg),
                "attack_count": 1,
                "status": "OPEN",
                "assigned_to": "",
                "notes": "",
                "action_taken": "",
                "description": msg[:200],
                "mitre_technique": "",
                "mitre_tactic": "",
            })

    # ── CloudTrail events ──────────────────────────
    for event in _fetch_cloudtrail_events(hours=1):
        msg = event.get("CloudTrailEvent", "{}")
        try:
            ev = json.loads(msg)
        except Exception:
            ev = {}
        user = ev.get("userIdentity", {}).get("userName", "") or ev.get("userIdentity", {}).get("arn", "")
        incidents.append({
            "id": event.get("EventId", ""),
            "incident_id": event.get("EventId", "")[-12:],
            "timestamp": event.get("EventTime", ""),
            "source_ip": ev.get("sourceIPAddress", "N/A"),
            "severity": "MEDIUM" if "ConsoleLogin" in str(event.get("EventName", "")) else "LOW",
            "finding_type": f"CloudTrail-{event.get('EventName', '')}",
            "hostname": "aws",
            "username": user[:50] if user else "",
            "attack_count": 1,
            "status": "OPEN",
            "assigned_to": "",
            "notes": "",
            "action_taken": "",
            "description": f"{event.get('EventName', '')} by {user}"[:200],
            "mitre_technique": "",
            "mitre_tactic": "",
        })

    if incidents:
        df = pd.DataFrame(incidents)
        if "timestamp" in df.columns:
            df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")
        return df

    # ── Fallback: local JSON files ──────────────────
    local = []
    if REPORT_DIR.exists():
        for file in REPORT_DIR.glob("incident_*.json"):
            try:
                with open(file) as f:
                    local.append(json.load(f))
            except Exception:
                pass
    if local:
        df = pd.DataFrame(local)
        if "timestamp" in df.columns:
            df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")
        return df

    return pd.DataFrame()


@st.cache_data(ttl=25, show_spinner="Checking AWS instances...")
def fetch_ec2_instances():
    return _fetch_ec2_instances()


@st.cache_data(ttl=25, show_spinner="Fetching CloudWatch metrics...")
def fetch_ec2_metrics(instance_id):
    return _fetch_ec2_metrics(instance_id)


@st.cache_data(ttl=60, show_spinner="Listing log groups...")
def fetch_log_groups():
    return _list_log_groups()
