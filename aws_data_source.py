import json
import os
import re
import pandas as pd
import streamlit as st
from datetime import datetime, timedelta, timezone
from dotenv import load_dotenv

load_dotenv()


# ── Configuration & Environment Variables ──────────────────────────────

def _load_trusted_fingerprints():
    """Load trusted SSH key fingerprints from TRUSTED_FINGERPRINTS env var."""
    val = os.environ.get("TRUSTED_FINGERPRINTS", "").strip()
    if not val:
        return set()
    return {fp.strip() for fp in val.split(",") if fp.strip()}


def _load_trusted_users():
    """Load trusted SSH usernames from TRUSTED_USERS env var."""
    val = os.environ.get("TRUSTED_USERS", "").strip()
    if not val:
        return {"ubuntu", "ec2-user", "admin"}  # sensible defaults
    return {u.strip() for u in val.split(",") if u.strip()}


AUTHORIZED_KEY_FINGERPRINTS = _load_trusted_fingerprints()
TRUSTED_SSH_USERS = _load_trusted_users()

if not AUTHORIZED_KEY_FINGERPRINTS:
    print("WARNING: TRUSTED_FINGERPRINTS is empty — every SSH login will be flagged as UNAUTHORIZED_KEY_ACCEPTED")

# ── Regex Patterns ─────────────────────────────────────────────────────

# Success: "Accepted publickey for <user> from <ip> port <port> <key_type> <fingerprint>"
SUCCESS_PATTERN = re.compile(
    r"(?i)Accepted publickey for (\S+) from (\S+) port \d+ (?:ssh2:\s*)?(?:RSA|ECDSA|ED25519|DSA) (SHA256:\S+)"
)

# Failures only — no Accepted publickey here
SECURITY_PATTERN = re.compile(
    r"(?i)(Failed password|Failed publickey|Invalid user|authentication failure|"
    r"Connection reset|Connection closed by authenticating user|"
    r"Did not receive identification string)"
)

# Sudo detection
SUDO_PATTERN = re.compile(r"(?i)sudo[:]\s+(\S+)")
SUSPICIOUS_SUDO_CMDS = re.compile(
    r"(?i)sudo.*(curl|wget|chmod\s+\+x|nc\s|/etc/passwd|/etc/shadow|"
    r"authorized_keys|ssh-add|ssh-keygen)"
)

# Post-login suspicious commands (for TODO stub)
POST_LOGIN_SUSPICIOUS_CMDS = re.compile(
    r"(?i)(curl|wget|chmod\s+\+x|nc\s|/etc/passwd|/etc/shadow|"
    r"authorized_keys|ssh-add|ssh-keygen|useradd|usermod)"
)

RAW_QUERY = "fields @timestamp, @message | sort @timestamp desc | limit 1000"


# ── lazy boto3 helper ──────────────────────────────

def _client(name):
    try:
        import boto3
        session = boto3.Session()
        region = session.region_name or "us-east-1"
        return session.client(name, region_name=region)
    except ImportError:
        print("aws_data_source: boto3 is not installed")
        return None
    except Exception as e:
        print(f"aws_data_source: _client({name}) failed: {e}")
        return None


# ── CloudWatch Logs Insights ───────────────────────

def _run_cw_logs_query(log_group_name, hours=6, query=None):
    logs = _client("logs")
    if not logs:
        return []
    qs = query if query is not None else RAW_QUERY
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

def _extract_fingerprint(msg):
    m = re.search(r"(?:RSA|ECDSA|ED25519|DSA)\s+(SHA256:\S+)", msg)
    return m.group(1) if m else ""


def _extract_ip_from_msg(msg):
    ip_match = re.search(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", msg)
    return ip_match.group(0) if ip_match else "N/A"


def _extract_user_from_msg(msg):
    # For failed attempts: "Invalid user <user>", "Failed password for <user>"
    m = re.search(r"(?:Invalid\s+user|Failed\s+password\s+for)\s+(\S+)", msg, re.IGNORECASE)
    if m:
        user = m.group(1)
        return "unknown" if user.lower() in ("from", "for", "by") else user
    return "unknown"


def _parse_cw_timestamp(ts_str):
    try:
        return pd.to_datetime(ts_str, errors="coerce")
    except Exception:
        return pd.NaT


# TODO: Implement post-login behavioral check for stolen trusted keys
# This function should query CloudWatch Logs for commands executed within
# a 5-minute window after a successful trusted login from the same IP.
# For now, returns False (no suspicious activity detected).
def check_post_login_behavior(timestamp, source_ip, log_group):
    """
    Check for suspicious commands executed shortly after a successful login.
    
    Args:
        timestamp: datetime of the successful login
        source_ip: IP address of the login
        log_group: CloudWatch log group name
        
    Returns:
        Tuple of (is_suspicious: bool, description: str)
    """
    # TODO: Implement by querying logs for source_ip in the 5-minute window
    # after timestamp, looking for POST_LOGIN_SUSPICIOUS_CMDS matches.
    # Example query structure:
    # fields @timestamp, @message
    # | filter @message like /<source_ip>/
    # | filter @timestamp > <login_ts> and @timestamp < <login_ts + 5min>
    # | filter @message like /curl|wget|chmod|nc|authorized_keys/
    return False, ""


def _build_base_incident(ts, source_ip, hostname, username, finding_type, severity, description, attack_count=1):
    """Build a standardized incident dict matching the DataFrame schema."""
    return {
        "id": f"cw-{hash(description) % 10**12:012d}",
        "incident_id": f"cw-{hash(description) % 10**8:08d}",
        "timestamp": _parse_cw_timestamp(ts),
        "source_ip": source_ip,
        "severity": severity,
        "finding_type": finding_type,
        "hostname": hostname,
        "username": username,
        "attack_count": attack_count,
        "status": "OPEN",
        "assigned_to": "",
        "notes": "",
        "action_taken": "",
        "description": description[:200],
        "mitre_technique": "",
        "mitre_tactic": "",
    }


# ── helper functions (exported for dashboard.py) ─────────────────

def _determine_severity(msg):
    """Classify log message severity. Used by dashboard log explorer."""
    msg = msg.lower()
    if re.search(r"useradd.*new user|/etc/shadow|possible break.in", msg):
        return "CRITICAL"
    if re.search(r"failed password|failed publickey|invalid user|authentication failure", msg):
        return "HIGH"
    # trusted user sudo is normal admin work
    if re.search(r"sudo:\s+(ubuntu|ec2-user|admin)", msg):
        return "LOW"
    # suspicious sudo commands
    if re.search(r"sudo.*(curl|wget|chmod)", msg):
        return "MEDIUM"
    if re.search(r"usermod|consolelogin|unauthorized|connection reset", msg):
        return "MEDIUM"
    if re.search(r"did not receive identification string", msg):
        return "LOW"
    if re.search(r"accepted publickey", msg):
        return "LOW"
    return "LOW"


def get_log_entry_severity(msg):
    """Fingerprint-aware severity matching fetch_findings() logic.

    Returns a severity string (CRITICAL/HIGH/MEDIUM/LOW) or None if the
    entry is not a security concern. Log Explorer uses this instead of
    the simple regex approach so its flags match the Investigation tab.
    """
    success_match = SUCCESS_PATTERN.search(msg)
    if success_match:
        fingerprint = success_match.group(3)
        username = success_match.group(1)

        # Trusted Admin — skip entirely (matches Step B in fetch_findings)
        if fingerprint in AUTHORIZED_KEY_FINGERPRINTS and username in TRUSTED_SSH_USERS:
            return None

        # No fingerprint — parse error
        if not fingerprint:
            return "MEDIUM"

        # Untrusted fingerprint — rogue key
        if fingerprint not in AUTHORIZED_KEY_FINGERPRINTS:
            return "CRITICAL"

        # Trusted key but untrusted user — anomalous
        if username not in TRUSTED_SSH_USERS:
            return "HIGH"

        return None

    # Failure patterns (matches Step C severity in fetch_findings)
    msg_lower = msg.lower()
    if "failed password" in msg_lower:
        return "HIGH"
    if "failed publickey" in msg_lower:
        return "HIGH"
    if "invalid user" in msg_lower:
        return "HIGH"
    if "authentication failure" in msg_lower:
        return "HIGH"
    if "connection reset" in msg_lower:
        return "MEDIUM"
    if "connection closed by authenticating user" in msg_lower:
        return "MEDIUM"
    if "did not receive identification string" in msg_lower:
        return "LOW"

    # Sudo-based threats
    if re.search(r"sudo.*(curl|wget|chmod)", msg_lower):
        return "MEDIUM"

    # Other notable events
    if re.search(r"useradd.*new user|/etc/shadow|possible break.in", msg_lower):
        return "CRITICAL"
    if re.search(r"usermod|consolelogin|unauthorized", msg_lower):
        return "MEDIUM"

    return None


def _extract_fingerprint(msg):
    m = re.search(r"(?:RSA|ECDSA|ED25519|DSA)\s+(SHA256:\S+)", msg)
    return m.group(1) if m else ""


def _extract_ip_from_msg(msg):
    ip_match = re.search(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", msg)
    return ip_match.group(0) if ip_match else "N/A"


def _extract_user_from_msg(msg):
    # Format: "Invalid user <username> from <IP>"  →  extract username
    m = re.search(r"Invalid\s+user\s+(\S+)\s+from", msg, re.IGNORECASE)
    if m:
        return m.group(1)
    # Format: "Invalid user from <IP>"  →  no username provided
    if re.search(r"Invalid\s+user\s+from\b", msg, re.IGNORECASE):
        return "unknown"
    # Format: "Connection closed by invalid user <IP>"  →  don't capture IP as username
    m = re.search(r"Connection\s+closed\s+by\s+invalid\s+user\s+(\S+)", msg, re.IGNORECASE)
    if m:
        candidate = m.group(1)
        if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", candidate):
            return "unknown"
        return candidate
    # Standard patterns
    m = re.search(r"(?:Invalid\s+user|Failed\s+password\s+for)\s+(\S+)", msg, re.IGNORECASE)
    if m:
        user = m.group(1)
        return "unknown" if user.lower() in ("from", "for", "by") else user
    for pattern in [r"for\s+(\S+)", r"user\s+(\S+)"]:
        m = re.search(pattern, msg, re.IGNORECASE)
        if m:
            return m.group(1)
    return "unknown"


# Keep for backward compatibility with dashboard.py log explorer
# These are the OLD patterns - dashboard uses them for display filtering
SECURITY_PATTERN = re.compile(
    r"(?i)(Failed password|Failed publickey|Invalid user|authentication failure|useradd|usermod|"
    r"/etc/shadow|POSSIBLE BREAK-IN|"
    r"sudo.*(curl|wget|chmod)|"
    r"ConsoleLogin|RootLogin|Unauthorized|Connection reset|"
    r"Connection closed by authenticating user|"
    r"Did not receive identification string)"
)


# ── public API ─────────────────────────────────────

@st.cache_data(ttl=25, show_spinner="Querying CloudWatch Logs...")
def fetch_findings():
    incidents = []

    # ── CloudWatch Logs Insights ────────────────────
    log_groups = [lg for lg in _list_log_groups() if lg.endswith("/auth.log") or lg.endswith("/syslog")]

    for lg in log_groups:
        results = _run_cw_logs_query(lg, hours=12, query=RAW_QUERY)
        if not results:
            continue

        # Step A: Fetch and Categorize
        successful_logins = []
        failed_attempts = []

        for row in results:
            fields = {f["field"]: f.get("value", "") for f in row}
            msg = fields.get("@message", "")
            ts = fields.get("@timestamp", "")

            # Categorize using new regex patterns
            success_match = SUCCESS_PATTERN.search(msg)
            if success_match:
                successful_logins.append({
                    "timestamp": ts,
                    "message": msg,
                    "username": success_match.group(1),
                    "source_ip": success_match.group(2),
                    "fingerprint": success_match.group(3),
                    "log_group": lg,
                })
                continue

            if SECURITY_PATTERN.search(msg):
                failed_attempts.append({
                    "timestamp": ts,
                    "message": msg,
                    "source_ip": _extract_ip_from_msg(msg),
                    "username": _extract_user_from_msg(msg),
                    "log_group": lg,
                })

        # Step B: Process Successful Logins
        for login in successful_logins:
            username = login["username"]
            source_ip = login["source_ip"]
            fingerprint = login["fingerprint"]
            ts = login["timestamp"]
            hostname = lg.split("/")[-1] if "/" in lg else lg

            # Trusted Admin Check: trusted fingerprint AND trusted user
            if fingerprint in AUTHORIZED_KEY_FINGERPRINTS and username in TRUSTED_SSH_USERS:
                # Legitimate admin — skip entirely
                continue

            # Debug: print raw message and extracted fingerprint for troubleshooting
            print(f"DEBUG Accepted publickey: username={username} ip={source_ip} fingerprint={fingerprint!r}")

            # No fingerprint extracted → regex mismatch on this log format
            if not fingerprint:
                incidents.append(_build_base_incident(
                    ts=ts,
                    source_ip=source_ip,
                    hostname=hostname,
                    username=username,
                    finding_type="SSH_LOGIN_PARSE_ERROR",
                    severity="MEDIUM",
                    description=f"Accepted publickey for {username} from {source_ip} — no fingerprint extracted, SUCCESS_PATTERN may need adjustment",
                ))
                continue

            # Rogue Key Check: fingerprint NOT trusted
            if fingerprint not in AUTHORIZED_KEY_FINGERPRINTS:
                incidents.append(_build_base_incident(
                    ts=ts,
                    source_ip=source_ip,
                    hostname=hostname,
                    username=username,
                    finding_type="UNAUTHORIZED_KEY_ACCEPTED",
                    severity="CRITICAL",
                    description=f"Accepted publickey for {username} from {source_ip} using untrusted fingerprint {fingerprint}",
                ))
                continue

            # Trusted Key, Untrusted User Check: fingerprint trusted but user not trusted
            if fingerprint in AUTHORIZED_KEY_FINGERPRINTS and username not in TRUSTED_SSH_USERS:
                incidents.append(_build_base_incident(
                    ts=ts,
                    source_ip=source_ip,
                    hostname=hostname,
                    username=username,
                    finding_type="ANOMALOUS_USER_LOGIN",
                    severity="HIGH",
                    description=f"Trusted key used by untrusted user {username} from {source_ip}",
                ))
                continue

            # Fallback: fingerprint trusted, user trusted but not caught above (shouldn't happen)
            # Could add post-login check here for stolen keys
            suspicious, desc = check_post_login_behavior(
                _parse_cw_timestamp(ts), source_ip, lg
            )
            if suspicious:
                incidents.append(_build_base_incident(
                    ts=ts,
                    source_ip=source_ip,
                    hostname=hostname,
                    username=username,
                    finding_type="SUSPICIOUS_POST_LOGIN_ACTIVITY",
                    severity="CRITICAL",
                    description=desc or f"Suspicious post-login activity from {source_ip} (user: {username})",
                ))

        # Step C: Process Failed Logins
        ip_fail_counts = {}
        for fail in failed_attempts:
            source_ip = fail["source_ip"]
            username = fail["username"]
            ts = fail["timestamp"]
            msg = fail["message"]
            hostname = lg.split("/")[-1] if "/" in lg else lg

            # Determine specific finding type and severity
            msg_lower = msg.lower()
            if "failed password" in msg_lower:
                finding_type = "FAILED_PASSWORD"
                severity = "HIGH"
            elif "failed publickey" in msg_lower:
                finding_type = "FAILED_PUBLICKEY"
                severity = "HIGH"
            elif "invalid user" in msg_lower:
                finding_type = "INVALID_USER"
                severity = "HIGH"
            elif "authentication failure" in msg_lower:
                finding_type = "AUTHENTICATION_FAILURE"
                severity = "HIGH"
            elif "connection reset" in msg_lower:
                finding_type = "CONNECTION_RESET"
                severity = "MEDIUM"
            elif "did not receive identification string" in msg_lower:
                finding_type = "NO_IDENTIFICATION"
                severity = "LOW"
            else:
                finding_type = "FAILED_LOGIN"
                severity = "MEDIUM"

            # Dedup: skip if same IP + within 2 seconds (invalid user + connection closed pair)
            ts_parsed = _parse_cw_timestamp(ts)
            is_dup = False
            if source_ip and source_ip != "N/A" and ts_parsed is not pd.NaT:
                for existing in incidents:
                    if existing.get("source_ip") == source_ip:
                        existing_ts = existing.get("timestamp")
                        if existing_ts is not pd.NaT and abs(existing_ts - ts_parsed) < pd.Timedelta(seconds=2):
                            is_dup = True
                            break
            if is_dup:
                continue

            incidents.append(_build_base_incident(
                ts=ts,
                source_ip=source_ip,
                hostname=hostname,
                username=username,
                finding_type=finding_type,
                severity=severity,
                description=msg[:200],
            ))

            # Track for brute-force rollup
            if source_ip and source_ip != "N/A":
                ip_fail_counts.setdefault(source_ip, []).append(fail)

        # Brute Force Rollup: >= 5 failures from same IP
        for ip, fails in ip_fail_counts.items():
            if len(fails) >= 5:
                usernames = list({f["username"] for f in fails if f["username"]})
                last_ts = fails[-1]["timestamp"]
                incidents.append(_build_base_incident(
                    ts=last_ts,
                    source_ip=ip,
                    hostname="auth.log",
                    username=", ".join(usernames[:5]) if usernames else "multiple",
                    finding_type="BRUTE_FORCE",
                    severity="CRITICAL",
                    description=f"Brute-force attack detected — {len(fails)} failed auth attempts from {ip} targeting users: {', '.join(usernames[:5]) if usernames else 'unknown'}",
                    attack_count=len(fails),
                ))

        # Step E: Sudo Logic — check for suspicious sudo in raw results
        for row in results:
            fields = {f["field"]: f.get("value", "") for f in row}
            msg = fields.get("@message", "")
            ts = fields.get("@timestamp", "")

            sudo_match = SUDO_PATTERN.search(msg)
            if not sudo_match:
                continue

            sudo_user = sudo_match.group(1).lower()
            # Skip trusted users' sudo
            if sudo_user in TRUSTED_SSH_USERS:
                continue

            # Check for suspicious commands
            if SUSPICIOUS_SUDO_CMDS.search(msg):
                source_ip = _extract_ip_from_msg(msg)
                username = _extract_user_from_msg(msg)
                hostname = lg.split("/")[-1] if "/" in lg else lg

                incidents.append(_build_base_incident(
                    ts=ts,
                    source_ip=source_ip,
                    hostname=hostname,
                    username=username,
                    finding_type="PRIVILEGE_ESCALATION",
                    severity="MEDIUM",
                    description=msg[:200],
                ))

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


@st.cache_data(ttl=25, show_spinner="Checking log pipeline...")
def fetch_pipeline_status():
    """Return a dict with raw log counts and security-filtered stats for diagnostics."""
    result = {"log_groups": [], "raw_logs_seen": 0, "security_matches": 0, "ubuntu_filtered": 0}
    log_groups = [lg for lg in _list_log_groups() if lg.endswith("/auth.log") or lg.endswith("/syslog")]
    result["log_groups"] = log_groups
    for lg in log_groups:
        rows = _run_cw_logs_query(lg, hours=12, query=RAW_QUERY)
        result["raw_logs_seen"] += len(rows)
        for row in rows:
            fields = {f["field"]: f.get("value", "") for f in row}
            msg = fields.get("@message", "")
            if SECURITY_PATTERN.search(msg):
                result["security_matches"] += 1
                if re.search(r"sudo:\s+ubuntu", msg, re.IGNORECASE):
                    result["ubuntu_filtered"] += 1
            # Also count successful logins
            if SUCCESS_PATTERN.search(msg):
                result["security_matches"] += 1
    return result


@st.cache_data(ttl=60, show_spinner="Listing log groups...")
def fetch_log_groups():
    return _list_log_groups()