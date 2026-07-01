import json
import re
import pandas as pd
import streamlit as st
from datetime import datetime, timedelta, timezone


# ── lazy boto3 helper ──────────────────────────────

def _client(name):
    try:
        import boto3
        return boto3.client(name)
    except Exception:
        return None


# ── CloudWatch Logs Insights ───────────────────────

SECURITY_PATTERN = re.compile(
    r"(?i)(Failed password|Invalid user|authentication failure|useradd|usermod|"
    r"/etc/shadow|POSSIBLE BREAK-IN|"
    r"sudo.*(curl|wget|chmod|apt (update|upgrade|install)|dpkg|pip|npm|yarn|make)|"
    r"ConsoleLogin|RootLogin|Unauthorized|Connection reset)"
)

RAW_QUERY = "fields @timestamp, @message | sort @timestamp desc | limit 1000"

CW_QUERY = """
fields @timestamp, @message
| filter @message like /(?i)(Failed password|Invalid user|authentication failure|useradd|usermod|\\/etc\\/shadow|POSSIBLE BREAK-IN|sudo.*(curl|wget|chmod|apt (update|upgrade|install)|dpkg|pip|npm|yarn|make)|ConsoleLogin|RootLogin|Unauthorized|Connection reset)/
| sort @timestamp desc
| limit 500
"""


def _run_cw_logs_query(log_group_name, hours=6, query=None):
    logs = _client("logs")
    if not logs:
        return []
    qs = query if query is not None else CW_QUERY
    now_ts = datetime.now(timezone.utc).timestamp()
    end = int(now_ts)
    for attempt_start in [int(now_ts - hours * 3600), int(now_ts - 3600)]:
        try:
            resp = logs.start_query(
                logGroupName=log_group_name,
                startTime=attempt_start,
                endTime=end,
                queryString=qs,
            )
            query_id = resp["queryId"]
            import time as _time
            for _ in range(20):
                _time.sleep(1)
                result = logs.get_query_results(queryId=query_id)
                if result["status"] == "Complete":
                    results = result.get("results", [])
                    if results:
                        return results
                    break
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
            StartTime=datetime.now(timezone.utc) - timedelta(hours=hours),
            EndTime=datetime.now(timezone.utc),
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
            StartTime=datetime.now(timezone.utc) - timedelta(hours=hours),
            EndTime=datetime.now(timezone.utc),
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
    for name in ["CPUUtilization", "StatusCheckFailed", "NetworkIn", "NetworkOut",
                  "NetworkPacketsIn", "NetworkPacketsOut"]:
        try:
            resp = cw.get_metric_statistics(
                Namespace="AWS/EC2",
                MetricName=name,
                Dimensions=[{"Name": "InstanceId", "Value": instance_id}],
                StartTime=datetime.now(timezone.utc) - timedelta(hours=2),
                EndTime=datetime.now(timezone.utc),
                Period=300,
                Statistics=["Average", "Maximum"],
            )
            points = resp.get("Datapoints", [])
            points.sort(key=lambda p: p["Timestamp"])
            metrics[name] = points if points else None
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
    if re.search(r"useradd.*new user|\/etc\/shadow|possible break.in", msg):
        return "CRITICAL"
    if re.search(r"failed password|invalid user|authentication failure", msg):
        return "HIGH"
    # ubuntu's own sudo is normal admin work, never an incident
    if re.search(r"sudo:\s+ubuntu", msg):
        return "LOW"
    # non-ubuntu sudo with suspicious commands is a threat
    if re.search(r"sudo.*(curl|wget|chmod)", msg):
        return "MEDIUM"
    # other admin installation commands by non-ubuntu users
    if re.search(r"sudo.*(apt |dpkg |pip |npm |yarn |make )", msg):
        return "MEDIUM"
    if re.search(r"usermod|consolelogin|unauthorized|connection reset", msg):
        return "MEDIUM"
    return "LOW"


def _extract_ip_from_msg(msg):
    ip_match = re.search(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", msg)
    return ip_match.group(0) if ip_match else "N/A"


def _extract_user_from_msg(msg):
    m = re.search(r"Invalid\s+user\s+(\S+)", msg, re.IGNORECASE)
    if m:
        user = m.group(1)
        return "unknown" if user.lower() in ("from", "for", "by") else user
    for pattern in [r"for\s+(\S+)", r"user\s+(\S+)"]:
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
    log_groups = [lg for lg in _list_log_groups() if lg.endswith("/auth.log") or lg.endswith("/syslog")]
    for lg in log_groups:
        results = _run_cw_logs_query(lg, hours=12, query=RAW_QUERY)
        for row in results:
            fields = {f["field"]: f.get("value", "") for f in row}
            msg = fields.get("@message", "")
            if not SECURITY_PATTERN.search(msg):
                continue
            # ubuntu's own sudo commands are legitimate admin work, not incidents
            if re.search(r"sudo:\s+ubuntu", msg, re.IGNORECASE):
                continue
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
    for event in _fetch_cloudtrail_events(hours=6):
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

    return pd.DataFrame()


@st.cache_data(ttl=25, show_spinner="Fetching raw logs...")
def fetch_raw_logs(log_group, stream=None, limit=100):
    logs = _client("logs")
    if not logs:
        return []
    try:
        now_ts = datetime.now(timezone.utc).timestamp()
        end = int(now_ts)
        start = int(now_ts - 12 * 3600)
        resp = logs.start_query(
            logGroupName=log_group,
            startTime=start,
            endTime=end,
            queryString="fields @timestamp, @message | sort @timestamp desc | limit {}".format(limit),
        )
        query_id = resp["queryId"]
        import time as _time
        for _ in range(20):
            _time.sleep(1)
            result = logs.get_query_results(queryId=query_id)
            if result["status"] == "Complete":
                events = []
                for row in result.get("results", []):
                    fields = {f["field"]: f.get("value", "") for f in row}
                    ts = fields.get("@timestamp", "")
                    msg = fields.get("@message", "")
                    events.append({
                        "timestamp": pd.to_datetime(ts).timestamp() * 1000 if ts else 0,
                        "message": msg,
                    })
                events.reverse()
                return events
        return []
    except Exception:
        return []


@st.cache_data(ttl=25, show_spinner="Checking AWS instances...")
def fetch_ec2_instances():
    return _fetch_ec2_instances()


@st.cache_data(ttl=25, show_spinner="Fetching CloudWatch metrics...")
def fetch_ec2_metrics(instance_id):
    return _fetch_ec2_metrics(instance_id)


@st.cache_data(ttl=60, show_spinner="Listing log groups...")
def fetch_log_groups():
    return _list_log_groups()
