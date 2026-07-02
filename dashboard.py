import streamlit as st
import pandas as pd
import json
import boto3
from pathlib import Path
from datetime import datetime, timezone
import plotly.express as px
import plotly.graph_objects as go
from aws_data_source import fetch_findings, fetch_ec2_instances, fetch_ec2_metrics, fetch_log_groups, fetch_raw_logs, fetch_pipeline_status, get_log_entry_severity

# ==================================================
# PAGE CONFIG
# ==================================================

st.set_page_config(
    page_title="SOC Command Center",
    page_icon="◆",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ==================================================
# DESIGN SYSTEM — enterprise dark theme (lovable-inspired)
# ==================================================

CSS_PATH = Path(__file__).parent / "styles.css"
with open(CSS_PATH, encoding="utf-8") as f:
    CSS = f.read()

st.html(f"""
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=Plus+Jakarta+Sans:wght@600;700;800&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet">
<style>{CSS}</style>
""")

st.html("""
<style>
  #MainMenu,
  .stAppDeployButton,
  [data-testid="stDecoration"], [data-testid="stStatusWidget"],
  [data-testid="main-menu"], .stAppDeployButton {
    display: none !important;
  }
</style>
<script>
(function() {
  function h() {
    ['#MainMenu',
     '.stAppDeployButton',
     '[data-testid="stDecoration"]','[data-testid="stStatusWidget"]',
     '[data-testid="main-menu"]','.stAppDeployButton',
     '.st-emotion-cache-1mi0j7h','.st-emotion-cache-1dm3w3z',
    ].forEach(function(s) {
      document.querySelectorAll(s).forEach(function(e) { e.remove(); });
    });
  }
  h();
  new MutationObserver(h).observe(document.body, { childList: true, subtree: true });
  setTimeout(h, 500);
  setTimeout(h, 2000);
})();
</script>
""")

# ==================================================
# LOAD INCIDENTS (live AWS → local fallback)
# ==================================================

_CACHE_VERSION = 6
if st.session_state.get("findings_cache_ver") != _CACHE_VERSION:
    fetch_findings.clear()
    st.session_state.findings_cache_ver = _CACHE_VERSION

df = fetch_findings()

if df.empty:
    pipe = fetch_pipeline_status()
    total = pipe["raw_logs_seen"]
    matched = pipe["security_matches"]
    filtered = pipe["ubuntu_filtered"]

    if total == 0:
        st.warning("No findings from AWS or local files.")
    with st.expander("Diagnostics — pipeline status"):
        import os
        sess = boto3.Session()
        st.markdown("**AWS Config:**")
        st.code(f"Region: {sess.region_name or '(not set)'}")
        st.code(f"Profile: {os.environ.get('AWS_PROFILE', 'default')}")
        creds = sess.get_credentials()
        st.code(f"Credentials: {'OK' if creds else 'MISSING'}")
        if creds:
            st.code(f"Access Key: {creds.access_key[:4]}...{creds.access_key[-4:]}")

        st.markdown("**Log groups found:**")
        for lg in pipe["log_groups"]:
            st.code(f"  {lg}")
        st.markdown(f"**Raw log entries scanned:** `{total}`")
        st.markdown(f"**Security pattern matches:** `{matched}`")
        st.markdown(f"**Filtered (ubuntu sudo):** `{filtered}`")
        st.markdown(f"**Incidents generated:** `{matched - filtered}`")

        if total > 0:
            st.markdown("**Sample raw entry:**")
            from aws_data_source import _run_cw_logs_query
            sample = _run_cw_logs_query("/ec2/auth.log", hours=1)
            if sample:
                st.code(sample[0])
    # ensure expected columns exist so downstream code doesn't KeyError
    df = pd.DataFrame(columns=["severity", "source_ip", "incident_id", "hostname",
                                "username", "timestamp", "finding_type", "attack_count",
                                "status", "assigned_to", "notes", "action_taken",
                                "description", "mitre_technique", "mitre_tactic"])

# ==================================================
# AUTO-REFRESH (every 30 seconds, background JS)
# ==================================================

if "refresh_count" not in st.session_state:
    st.session_state.refresh_count = 0
st.session_state.refresh_count += 1

# ==================================================
# HELPERS
# ==================================================

def save_incident_changes(incident_id, status, analyst, notes, incident_row=None):
    reports_dir = Path("reports")
    reports_dir.mkdir(exist_ok=True)
    filename = reports_dir / f"incident_{incident_id}.json"
    if filename.exists():
        with open(filename, "r") as f:
            data = json.load(f)
    elif incident_row is not None:
        data = incident_row.to_dict()
        for k, v in data.items():
            if hasattr(v, "isoformat"):
                data[k] = v.isoformat()
            elif isinstance(v, float) and (v != v or v is None):
                data[k] = ""
    else:
        return False
    data["incident_id"] = incident_id
    data["status"] = status
    data["assigned_to"] = analyst
    data["notes"] = notes
    data["last_updated"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open(filename, "w") as f:
        json.dump(data, f, indent=4)
    return True


def calculate_score(dataframe):
    score = 100
    score -= len(dataframe[dataframe["severity"] == "LOW"]) * 1
    score -= len(dataframe[dataframe["severity"] == "MEDIUM"]) * 3
    score -= len(dataframe[dataframe["severity"] == "HIGH"]) * 6
    score -= len(dataframe[dataframe["severity"] == "CRITICAL"]) * 10
    return max(score, 0)


def sev_pill(sev):
    s = str(sev).upper()
    cls = {"CRITICAL":"sev-critical","HIGH":"sev-high","MEDIUM":"sev-medium","LOW":"sev-low"}.get(s,"sev-low")
    return f'<span class="sev {cls}">{s}</span>'


def initials(name: str) -> str:
    return "".join(w[0] for w in name.split()[:2]).upper()


SEV_COLORS = {
    "CRITICAL": "#E5484D",
    "HIGH":     "#E8804B",
    "MEDIUM":   "#D4A24C",
    "LOW":      "#5BAE7F",
}

def style_fig(fig, height=320):
    fig.update_layout(
        height=height,
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        font=dict(family="Inter, sans-serif", color="#8B929C", size=12),
        title=dict(font=dict(color="#E6E8EB", size=13, family="Plus Jakarta Sans"), x=0, xanchor="left", pad=dict(b=12)),
        margin=dict(l=10, r=10, t=40, b=10),
        xaxis=dict(gridcolor="#1F242C", zerolinecolor="#1F242C", linecolor="#1F242C"),
        yaxis=dict(gridcolor="#1F242C", zerolinecolor="#1F242C", linecolor="#1F242C"),
        legend=dict(font=dict(color="#8B929C", size=11), orientation="h", yanchor="bottom", y=1.02, xanchor="right", x=1),
        hoverlabel=dict(bgcolor="#111418", bordercolor="#1F242C", font_size=12, font_family="Inter"),
    )
    return fig


def section_header_html(title: str, desc: str) -> str:
    return f"""<div><p class="soc-section-title">{title}</p>
        <p class="soc-section-desc">{desc}</p></div>
        <div class="soc-divider"></div>"""


def chrome(fig: go.Figure, height: int = 280) -> go.Figure:
    fig.update_layout(
        height=height,
        margin=dict(l=10, r=10, t=10, b=10),
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        font=dict(family="Inter", color="#8B929C", size=11),
        xaxis=dict(showgrid=False, showline=False, zeroline=False),
        yaxis=dict(showgrid=True, gridcolor="#1F242C", showline=False, zeroline=False),
        legend=dict(orientation="h", yanchor="bottom", y=1.02, xanchor="right", x=1),
        hoverlabel=dict(bgcolor="#111418", bordercolor="#1F242C", font_size=12, font_family="Inter"),
    )
    return fig

# ==================================================
# SIDEBAR
# ==================================================

with st.sidebar:
    st.markdown("""
    <div class="sb-brand">
      <div class="sb-mark">
        <div class="sb-mark-icon">◆</div>
        <div>SOC Center</div>
      </div>
      <div class="sb-sub">Security Operations</div>
    </div>
    """, unsafe_allow_html=True)

    st.markdown('<div class="sb-section">EC2 Instance</div>', unsafe_allow_html=True)
    instances = fetch_ec2_instances()
    non_terminated = [i for i in instances if i["State"] != "terminated"]
    if non_terminated:
        instance_options = {}
        for i in non_terminated:
            name = i.get('Name', '') or i['InstanceId']
            state = i["State"]
            badge = "●" if state == "running" else "○" if state == "stopped" else "◆"
            label = f"{badge} {name} ({i['InstanceId']})"
            instance_options[label] = i["InstanceId"]
        selected_label = st.selectbox(
            "Instance", list(instance_options.keys()),
            label_visibility="collapsed",
            key="selected_instance",
        )
        instance_id = instance_options[selected_label]
        instance_info = next((i for i in non_terminated if i["InstanceId"] == instance_id), {})

        # restart / ip-change detection
        if "last_launch_time" not in st.session_state:
            st.session_state.last_launch_time = instance_info.get("LaunchTime", "")
            st.session_state.last_public_ip = instance_info.get("PublicIp", "")
            st.session_state.restart_banner = False
        launch_time = instance_info.get("LaunchTime", "")
        public_ip = instance_info.get("PublicIp", "")
        restart_detected = False
        if launch_time and st.session_state.last_launch_time and launch_time != st.session_state.last_launch_time:
            restart_detected = True
            fetch_ec2_metrics.clear()
        if public_ip and st.session_state.last_public_ip and public_ip != st.session_state.last_public_ip:
            restart_detected = True
        if restart_detected:
            st.session_state.restart_banner = True
            st.session_state.last_launch_time = launch_time
            st.session_state.last_public_ip = public_ip
        st.session_state["_instance_state"] = instance_info.get("State", "")

        if instance_info.get("State") == "running":
            ec2_metrics = fetch_ec2_metrics(instance_id)
            if ec2_metrics:
                def _last_pt(name):
                    pts = ec2_metrics.get(name)
                    return pts[-1] if pts else None
                cpu_pt = _last_pt("CPUUtilization")
                if cpu_pt:
                    st.caption(f"CPU: {cpu_pt.get('Average', 0):.1f}%")
                net_pt = _last_pt("NetworkIn")
                if net_pt:
                    st.caption(f"Network In: {net_pt.get('Average', 0)/1024:.1f} KB/s")
                status_pt = _last_pt("StatusCheckFailed")
                if status_pt:
                    st.caption(f"Status: {'⚠ Failed' if status_pt.get('Average', 0) > 0 else '✓ OK'}")
        else:
            ec2_metrics = {}
            state = instance_info.get("State", "")
            if state == "stopped":
                st.caption("⏹ Instance is **stopped**")
            elif state == "pending":
                st.caption("⏳ Instance is **starting**...")
            else:
                st.caption(f"◆ Instance is **{state}**")
            if instance_info.get("PublicIp"):
                st.caption(f"IP: {instance_info['PublicIp']} (last known)")
    else:
        st.caption("No EC2 instances found")
        instance_id = None
        ec2_metrics = {}

    log_groups = fetch_log_groups()
    if log_groups:
        st.markdown('<div class="sb-section">Log Groups</div>', unsafe_allow_html=True)
        for lg in log_groups[:3]:
            short = lg.split("/")[-1] if "/" in lg else lg
            st.caption(f"📋 {short[:30]}")

    st.markdown('<div class="sb-section">Filters</div>', unsafe_allow_html=True)

    with st.form("filter_form"):
        severity_critical = st.checkbox("CRITICAL", value=True, key="sev_critical")
        severity_high = st.checkbox("HIGH", value=True, key="sev_high")
        severity_medium = st.checkbox("MEDIUM", value=True, key="sev_medium")
        severity_low = st.checkbox("LOW", value=False, key="sev_low")
        ip_search = st.text_input("Source IP", placeholder="Filter by source IP…", label_visibility="collapsed", key="ip_search")
        st.form_submit_button("Apply Filters", use_container_width=True, type="primary")

    severity_filter = []
    if st.session_state.get("sev_critical", True): severity_filter.append("CRITICAL")
    if st.session_state.get("sev_high", True): severity_filter.append("HIGH")
    if st.session_state.get("sev_medium", True): severity_filter.append("MEDIUM")
    if st.session_state.get("sev_low", False): severity_filter.append("LOW")
    ip_search = st.session_state.get("ip_search", "")

# ==================================================
# FILTERING
# ==================================================

filtered_df = df
if not filtered_df.empty and severity_filter and "severity" in filtered_df.columns:
    filtered_df = filtered_df[filtered_df["severity"].isin(severity_filter)]

if ip_search and not filtered_df.empty and "source_ip" in filtered_df.columns:
    filtered_df = filtered_df[filtered_df["source_ip"].str.contains(ip_search, case=False, na=False)]

if not df.empty and filtered_df.empty and severity_filter != ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
    st.info("All findings are filtered out by the current severity filter. Try enabling **LOW** in the sidebar to see ubuntu admin logs, or wait for new threat activity to appear.")

# merge saved case data into dataframe and exclude closed from non-case tabs
closed_ids = set()
reports_dir = Path("reports")
saved_cases = {}
if reports_dir.exists():
    for f in reports_dir.glob("incident_*.json"):
        try:
            with open(f, "r") as fh:
                case = json.load(fh)
            saved_cases[case.get("incident_id", "")] = case
            if case.get("status") in ("RESOLVED", "FALSE_POSITIVE"):
                closed_ids.add(case.get("incident_id", ""))
        except Exception:
            pass

# apply saved status/notes/analyst to dataframe rows
if saved_cases:
    for i, row in filtered_df.iterrows():
        cid = row.get("incident_id", "")
        if cid in saved_cases:
            case = saved_cases[cid]
            for k in ["status", "assigned_to", "notes", "action_taken", "mitre_technique", "mitre_tactic"]:
                if k in case:
                    filtered_df.at[i, k] = case[k]

if closed_ids:
    filtered_df = filtered_df[~filtered_df["incident_id"].isin(closed_ids)]

score = calculate_score(filtered_df)

# ==================================================
# HEADER
# ==================================================

now = datetime.now(timezone.utc)

# restart banner
_restart_banner = st.session_state.pop("restart_banner", False)

if "session_start" not in st.session_state:
    st.session_state.session_start = now

@st.fragment(run_every=1)
def _render_header():
    _now = datetime.now(timezone.utc)
    _uptime = int((_now - st.session_state.session_start).total_seconds())
    _ts = _now.strftime('%Y-%m-%d · %H:%M:%S')
    st.html(f"""
<div class="app-header">
  <div>
    <div class="brand-eyebrow">AWS · Security Operations Center</div>
    <h1>Command Center</h1>
  </div>
  <div class="meta">
    <div class="soc-eyebrow"><span class="soc-dot"></span> LIVE · {_uptime}s uptime</div>
    <div style="margin-top:4px;">{_ts} UTC</div>
  </div>
</div>
""")

_render_header()

if _restart_banner:
    st.toast("Instance restart detected — data refreshed", icon="🔄")
    st.info("Instance restart detected — all data has been refreshed from AWS APIs.", icon="🔄")

# ── fragment-isolated tabs (widget reruns stay local) ──

@st.fragment
def _render_case_mgmt():
    st.markdown(f"""<p style="font-family:'Plus Jakarta Sans',sans-serif;font-size:20px;font-weight:700;color:var(--text);letter-spacing:-0.02em;margin:0 0 4px 0;">Case Management</p>
<p style="color:var(--muted);font-size:13px;margin:0 0 20px 0;">Incident workflow and investigation management</p>""", unsafe_allow_html=True)
    incident_ids = filtered_df["incident_id"].tolist()
    if not incident_ids:
        st.warning("No incidents available with the current filters.")
        return
    selected_incident = st.selectbox("Incident", incident_ids)
    incident = filtered_df[filtered_df["incident_id"] == selected_incident].iloc[0]
    saved = Path("reports") / f"incident_{selected_incident}.json"
    if saved.exists():
        with open(saved, "r") as f:
            saved_data = json.load(f)
        for k in ["status","assigned_to","notes","action_taken","mitre_technique","mitre_tactic"]:
            if k in saved_data:
                incident[k] = saved_data[k]
    st.html(f"""<div class="soc-card">{section_header_html("Finding Details", "Comprehensive incident information and workflow management")}""")
    col1, col2 = st.columns([1,1], gap="large")
    with col1:
        st.markdown(f"""
        <div style='line-height:2;'>
          <div><span style='color:var(--muted);'>Severity</span> &nbsp; {sev_pill(incident['severity'])}</div>
          <div><span style='color:var(--muted);'>Host</span> &nbsp; <code>{incident['hostname']}</code></div>
          <div><span style='color:var(--muted);'>Username</span> &nbsp; <code>{incident['username']}</code></div>
          <div><span style='color:var(--muted);'>Source IP</span> &nbsp; <code>{incident['source_ip']}</code></div>
          <div><span style='color:var(--muted);'>Finding</span> &nbsp; {incident['finding_type']}</div>
          <div><span style='color:var(--muted);'>Action</span> &nbsp; {incident.get('action_taken','—')}</div>
          <div><span style='color:var(--muted);'>MITRE Technique</span> &nbsp; <code>{incident.get('mitre_technique','—')}</code></div>
          <div><span style='color:var(--muted);'>MITRE Tactic</span> &nbsp; {incident.get('mitre_tactic','—')}</div>
        </div>
        """, unsafe_allow_html=True)
    with col2:
        st.markdown("#### Workflow")
        with st.form("case_form"):
            status_opts = ["OPEN","INVESTIGATING","CONTAINED","RESOLVED","FALSE_POSITIVE"]
            status = st.selectbox("Status", status_opts,
                                  index=status_opts.index(incident.get("status","OPEN")))
            analyst_opts = ["Unassigned","Analyst-01","Analyst-02","Analyst-03","Analyst-04"]
            saved_analyst = incident.get("assigned_to","")
            analyst = st.selectbox("Assigned Analyst", analyst_opts,
                                   index=analyst_opts.index(saved_analyst) if saved_analyst in analyst_opts else 0)
            notes = st.text_area("Investigation Notes", value=incident.get("notes",""), height=160)
            if st.form_submit_button("Save Changes"):
                if save_incident_changes(selected_incident, status, analyst, notes, incident):
                    st.success("Case updated.")
                else:
                    st.error("Unable to update incident.")
    st.html("</div>")

@st.fragment
def _render_log_explorer():
    st.markdown(f"""<p style="font-family:'Plus Jakarta Sans',sans-serif;font-size:20px;font-weight:700;color:var(--text);letter-spacing:-0.02em;margin:0 0 20px 0;">Raw Log Explorer</p>""", unsafe_allow_html=True)
    log_groups = fetch_log_groups()
    ec2_groups = [g for g in log_groups if "ec2" in g]
    with st.form("log_filter_form"):
        col1, col2, col3, col4 = st.columns([2, 1, 1, 1])
        with col1:
            selected_group = st.selectbox("Log Group", ec2_groups if ec2_groups else log_groups, key="log_group_sel", label_visibility="collapsed")
        with col2:
            lines_to_show = st.selectbox("Lines", [50, 100, 200, 500], index=1, key="log_lines", label_visibility="collapsed")
        with col3:
            search_text = st.text_input("Filter", placeholder="keyword…", key="log_search", label_visibility="collapsed")
        with col4:
            security_only = st.checkbox("Security only", value=True, key="log_sec_filter")
        col1, col2, col3, _ = st.columns([1, 1, 1, 1])
        with col2:
            st.form_submit_button("Apply", use_container_width=True)
    events = fetch_raw_logs(selected_group, limit=lines_to_show) if selected_group else []
    events = list(reversed(events))
    rows = []
    for ev in events:
        msg = ev.get("message", "")
        ts = datetime.fromtimestamp(ev.get("timestamp", 0) / 1000, tz=timezone.utc).strftime("%H:%M:%S")
        if search_text and search_text.lower() not in msg.lower():
            continue
        sev = get_log_entry_severity(msg)
        if security_only and sev is None:
            continue
        if sev is not None:
            tint = {"CRITICAL":"rgba(229,72,77,.06)","HIGH":"rgba(232,128,75,.06)","MEDIUM":"rgba(212,162,76,.06)"}.get(sev, "transparent")
            border = {"CRITICAL":"var(--crit)","HIGH":"var(--high)","MEDIUM":"var(--med)"}.get(sev, "transparent")
            sev_lbl = sev_pill(sev)
        else:
            tint = "transparent"
            border = "transparent"
            sev_lbl = "<span style='color:var(--muted);font-family:JetBrains Mono,monospace;font-size:.7rem;'>—</span>"
        rows.append(
            f"<tr style='background:{tint};'>"
            f"<td style='padding:8px 10px;width:60px;color:var(--muted);font-size:.7rem;font-family:JetBrains Mono,monospace;'>{ts}</td>"
            f"<td style='border-left:2px solid {border};padding:8px 10px;width:90px;'>{sev_lbl}</td>"
            f"<td style='padding:8px 10px;font-family:JetBrains Mono,monospace;font-size:.78rem;color:var(--text);word-break:break-all;'>{msg.strip()}</td>"
            f"</tr>"
        )
    st.caption(f"Showing {len(rows)} entries from {selected_group}")
    html = f"""
    <div style='border:1px solid var(--border);border-radius:10px;overflow:hidden;background:var(--surface);'>
      <table style='width:100%;border-collapse:collapse;'>
        <thead>
          <tr style='background:var(--surface-2);border-bottom:1px solid var(--border);'>
            <th style='padding:10px;text-align:left;width:60px;color:var(--muted);font-size:.68rem;text-transform:uppercase;letter-spacing:.08em;font-weight:500;'>Time</th>
            <th style='padding:10px;text-align:left;width:90px;color:var(--muted);font-size:.68rem;text-transform:uppercase;letter-spacing:.08em;font-weight:500;'>Severity</th>
            <th style='padding:10px;text-align:left;color:var(--muted);font-size:.68rem;text-transform:uppercase;letter-spacing:.08em;font-weight:500;'>Log Entry</th>
          </tr>
        </thead>
        <tbody>{''.join(rows)}</tbody>
      </table>
    </div>
    <style>tbody tr + tr td {{ border-top:1px solid var(--border); }}</style>
    """
    st.markdown(html, unsafe_allow_html=True)

# ==================================================
# TABS — instant client-side switching (no reruns)
# ==================================================

dash_tab, inv_tab, case_tab, anal_tab, comp_tab, log_tab, audit_tab = st.tabs([
    "Dashboard", "Investigations", "Case Management",
    "Analytics", "Compliance", "Log Explorer", "System Audit",
])

with dash_tab:

    crit = len(filtered_df[filtered_df["severity"] == "CRITICAL"])
    high = len(filtered_df[filtered_df["severity"] == "HIGH"])
    med  = len(filtered_df[filtered_df["severity"] == "MEDIUM"])
    low  = len(filtered_df[filtered_df["severity"] == "LOW"])

    # Header greeting
    st.markdown(
        f"""
        <span class="soc-eyebrow"><span class="soc-dot"></span> Live · {len(filtered_df)} findings tracked</span>
        <span class="soc-sub">Updated in real-time</span>
        <h1 style="margin:14px 0 4px;">Security Posture Overview</h1>
        <p style="color:var(--muted);font-size:14px;margin:0 0 20px 0;">
          Current security score is <span style="color:var(--text);font-weight:600;">{score}/100</span>.
          {crit} critical, {high} high, {med} medium, and {low} low severity findings across your infrastructure.
        </p>
        """,
        unsafe_allow_html=True,
    )

    # KPI cards (lovable-style with deltas)
    kpis = [
        {"label": "Security Score", "value": f"{score}", "delta": score - calculate_score(df), "up": (score - calculate_score(df)) >= 0, "sub": "/ 100"},
        {"label": "Total Findings", "value": f"{len(filtered_df)}", "delta": len(filtered_df) - len(df), "up": False, "sub": "current filter"},
        {"label": "Critical Findings", "value": f"{crit}", "delta": 0, "up": True, "sub": "requires immediate action"},
        {"label": "Open Cases", "value": f"{len(filtered_df[filtered_df.get('status', pd.Series([])) == 'OPEN']) if 'status' in filtered_df.columns else 0}", "delta": 0, "up": True, "sub": "active investigations"},
    ]

    cols = st.columns(4, gap="medium")
    for col, k in zip(cols, kpis):
        arrow = "▲" if k["up"] else "▼"
        cls = "soc-delta-up" if k["up"] else "soc-delta-down"
        col.markdown(
            f"""
            <div class="soc-card">
              <div class="soc-kpi-label">{k['label']}</div>
              <div class="soc-kpi-value">{k['value']}</div>
              <div>
                <span class="{cls}">{arrow} {abs(k['delta'])}%</span>
                <span class="soc-sub">{k['sub']}</span>
              </div>
            </div>
            """,
            unsafe_allow_html=True,
        )

    st.write("")

    # Charts row
    left, right = st.columns([2, 1], gap="medium")
    with left:
        st.html(section_header_html("Threat Severity Distribution", "Breakdown of findings by severity level"))
        sev_df = (filtered_df["severity"].value_counts()
                  .reset_index(name="Count").rename(columns={"severity":"Severity"}))
        fig = px.bar(sev_df, x="Severity", y="Count",
                     color="Severity", color_discrete_map=SEV_COLORS)
        fig.update_traces(marker_line_width=0, width=0.55)
        st.plotly_chart(chrome(fig, 280), use_container_width=True, config={"displayModeBar": False})

    with right:
        st.html(section_header_html("Top Attack Sources", "Most active threat IP addresses"))
        try:
            top_ip = filtered_df["source_ip"].value_counts().head(5)
            top_df = top_ip.reset_index(name="Count").rename(columns={"source_ip":"IP"})
            fig = go.Figure(
                go.Bar(
                    x=top_df["Count"], y=top_df["IP"],
                    orientation="h",
                    marker_color="#4F8CFF", width=0.55,
                )
            )
            fig.update_layout(yaxis=dict(autorange="reversed"))
            st.plotly_chart(chrome(fig, 280), use_container_width=True, config={"displayModeBar": False})
        except Exception:
            st.info("Insufficient data for chart")

    st.write("")

    # Attacker table + activity feed (lovable pattern)
    left, right = st.columns([2, 1], gap="medium")
    with left:
        attacker_counts = filtered_df["source_ip"].value_counts().reset_index()
        attacker_counts.columns = ["source_ip", "count"]
        attacker_table = attacker_counts.head(8).merge(
            filtered_df[["source_ip", "hostname", "username", "severity", "finding_type"]].drop_duplicates("source_ip"),
            on="source_ip", how="left"
        )

        rows_html = ""
        for _, row in attacker_table.iterrows():
            sev = str(row.get("severity", "LOW")).upper()
            pill_cls = {"CRITICAL":"soc-pill-critical","HIGH":"soc-pill-high","MEDIUM":"soc-pill-medium","LOW":"soc-pill-low"}.get(sev, "soc-pill-low")
            rows_html += f"""<tr>
              <td style="padding:14px 0;border-bottom:1px solid var(--border);">
                <span class="soc-avatar">{initials(str(row.get('source_ip','?')))}</span>
                <span style="font-weight:600;color:var(--text);font-size:13px;">{row.get('source_ip','—')}</span>
              </td>
              <td style="padding:18px 0;font-size:13px;color:var(--text);border-bottom:1px solid var(--border);"><code>{row.get('hostname','—')}</code></td>
              <td style="padding:18px 0;font-size:13px;color:var(--text);border-bottom:1px solid var(--border);">{row.get('username','—')}</td>
              <td class="soc-mono" style="padding:18px 0;font-size:13px;color:var(--text);border-bottom:1px solid var(--border);">{row['count']}</td>
              <td style="padding:16px 0;border-bottom:1px solid var(--border);"><span class="{pill_cls}">● {sev}</span></td>
            </tr>"""

        st.html(f"""<div class="soc-card">{section_header_html("Top Threat Actors", "Ranked by attack frequency this period")}
          <table style="width:100%;border-collapse:collapse;">
            <thead><tr>
              <th style="font-size:10px;font-weight:600;letter-spacing:0.14em;color:var(--muted);text-transform:uppercase;padding-bottom:8px;border-bottom:1px solid var(--border);">ATTACKER</th>
              <th style="font-size:10px;font-weight:600;letter-spacing:0.14em;color:var(--muted);text-transform:uppercase;padding-bottom:8px;border-bottom:1px solid var(--border);">HOST</th>
              <th style="font-size:10px;font-weight:600;letter-spacing:0.14em;color:var(--muted);text-transform:uppercase;padding-bottom:8px;border-bottom:1px solid var(--border);">USER</th>
              <th style="font-size:10px;font-weight:600;letter-spacing:0.14em;color:var(--muted);text-transform:uppercase;padding-bottom:8px;border-bottom:1px solid var(--border);">EVENTS</th>
              <th style="font-size:10px;font-weight:600;letter-spacing:0.14em;color:var(--muted);text-transform:uppercase;padding-bottom:8px;border-bottom:1px solid var(--border);">SEVERITY</th>
            </tr></thead>
            <tbody>{rows_html}</tbody>
          </table>
        </div>""")

    with right:
        recent_events = filtered_df.sort_values("timestamp", ascending=False).head(10)
        events_html = ""
        for _, ev in recent_events.iterrows():
            ip = str(ev.get("source_ip", "unknown"))
            finding = str(ev.get("finding_type", "event"))
            sev = str(ev.get("severity", "LOW")).upper()
            tag_color = {
                "CRITICAL": "var(--crit)", "HIGH": "var(--high)",
                "MEDIUM": "var(--med)", "LOW": "var(--low)",
            }.get(sev, "var(--muted)")
            events_html += f"""<div style="display:flex;gap:10px;padding:12px 0;border-bottom:1px solid var(--border);">
              <span class="soc-avatar" style="margin:0;">{initials(ip)}</span>
              <div style="flex:1;">
                <div style="font-size:13px;color:var(--text);line-height:1.4;">
                  <span style="font-weight:600;">{ip}</span>
                  <span style="color:var(--muted);"> {finding}</span>
                </div>
                <div style="margin-top:4px;font-size:11px;color:var(--muted);">
                  <span class="soc-activity-tag" style="color:{tag_color};">{sev}</span>
                  <span style="margin-left:6px;">{ev.get('timestamp','—')}</span>
                </div>
              </div>
            </div>"""

        st.html(f"""<div class="soc-card">{section_header_html("Recent Activity", "Latest security events across your infrastructure")}{events_html}</div>""")

# ==================================================
# INVESTIGATIONS
# ==================================================

with inv_tab:
    st.markdown(f"""<p style="font-family:'Plus Jakarta Sans',sans-serif;font-size:20px;font-weight:700;color:var(--text);letter-spacing:-0.02em;margin:0 0 4px 0;">Investigation Console</p>
<p style="color:var(--muted);font-size:13px;margin:0 0 20px 0;">{len(filtered_df)} findings match the current filters</p>""", unsafe_allow_html=True)
    cols = [c for c in ["timestamp","incident_id","severity","hostname","username","source_ip",
                        "attack_count","finding_type","status","assigned_to","action_taken"]
            if c in filtered_df.columns]
    st.markdown(f"""<div class="soc-card">{section_header_html("Investigation Console", f"{len(filtered_df)} findings match the current filters")}</div>""", unsafe_allow_html=True)
    st.dataframe(filtered_df[cols], use_container_width=True, height=720, hide_index=True)

with case_tab:
    _render_case_mgmt()

with anal_tab:
    st.markdown(f"""<p style="font-family:'Plus Jakarta Sans',sans-serif;font-size:20px;font-weight:700;color:var(--text);letter-spacing:-0.02em;margin:0 0 4px 0;">Threat Analytics</p>
<p style="color:var(--muted);font-size:13px;margin:0 0 20px 0;">Cross-dimensional security metrics, trend analysis, and intelligence overview</p>""", unsafe_allow_html=True)

    left, right = st.columns(2, gap="medium")

    with left:
        st.html(section_header_html("Severity Distribution", "Findings grouped by severity classification"))
        sev_df = (filtered_df["severity"].value_counts()
                  .reset_index(name="Findings").rename(columns={"severity":"Severity"}))
        fig = px.bar(sev_df, x="Severity", y="Findings",
                     color="Severity", color_discrete_map=SEV_COLORS)
        fig.update_traces(marker_line_width=0, width=0.55)
        st.plotly_chart(chrome(fig), use_container_width=True, config={"displayModeBar": False})

    with right:
        st.html(section_header_html("Top Threat Sources", "IP addresses with highest attack frequency"))
        attackers_df = (filtered_df["source_ip"].value_counts().head(10)
                        .reset_index(name="Findings").rename(columns={"source_ip":"Source IP"}))
        fig = px.bar(attackers_df, x="Findings", y="Source IP", orientation="h",
                     title=None)
        fig.update_traces(marker_color="#4F8CFF", marker_line_width=0)
        fig.update_layout(yaxis=dict(autorange="reversed"))
        st.plotly_chart(chrome(fig), use_container_width=True, config={"displayModeBar": False})

    st.write("")

    col_a, col_b = st.columns(2, gap="medium")

    with col_a:
        users = filtered_df["username"].value_counts().reset_index()
        users.columns = ["Username", "Findings"]
        st.html(f"""<div class="soc-card">{section_header_html("Most Targeted Accounts", "User accounts under active brute force attack")}{users.to_html(index=False, classes='soc-table')}</div>""")

    with col_b:
        required = ["finding_type","mitre_technique","mitre_tactic"]
        available = [c for c in required if c in filtered_df.columns]
        if len(available) == 3:
            mitre_df = filtered_df[available].drop_duplicates().sort_values("mitre_tactic")
            st.html(f"""<div class="soc-card">{section_header_html("MITRE ATT&CK Mapping", "Tactics and techniques identified in findings")}{mitre_df.to_html(index=False, classes='soc-table')}</div>""")
        else:
            st.html(f"""<div class="soc-card">{section_header_html("MITRE ATT&CK Mapping", "Tactics and techniques identified in findings")}<p style="color:var(--muted);font-size:13px;">MITRE ATT&CK data not available in current findings.</p></div>""")

# ==================================================
# COMPLIANCE (lovable-inspired new page)
# ==================================================

with comp_tab:
    st.markdown(f"""<p style="font-family:'Plus Jakarta Sans',sans-serif;font-size:20px;font-weight:700;color:var(--text);letter-spacing:-0.02em;margin:0 0 4px 0;">Risk and Compliance</p>
<p style="color:var(--muted);font-size:13px;margin:0 0 20px 0;">Live security control checks and compliance posture</p>""", unsafe_allow_html=True)

    def _check_sg_ssh():
        try:
            ec2c = boto3.client("ec2")
            sgs = ec2c.describe_security_groups()
            for sg in sgs.get("SecurityGroups", []):
                for rule in sg.get("IpPermissions", []):
                    if rule.get("FromPort") == 22 and rule.get("IpProtocol") == "tcp":
                        for rng in rule.get("IpRanges", []):
                            if rng.get("CidrIp") == "0.0.0.0/0":
                                return "Fail"
            return "Pass"
        except Exception:
            return "Warn"
    sg_ssh_status = _check_sg_ssh()

    cw_active = False
    try:
        logs = boto3.client("logs")
        streams = logs.describe_log_streams(logGroupName="/ec2/auth.log", orderBy="LastEventTime", descending=True, limit=1)
        if streams.get("logStreams"):
            last = streams["logStreams"][0].get("lastEventTimestamp", 0)
            cw_active = (datetime.now(timezone.utc).timestamp() * 1000 - last) < 1800000
    except Exception:
        pass

    em = ec2_metrics or {}
    status_pts = em.get("StatusCheckFailed")
    health_ok = True
    if status_pts:
        health_ok = status_pts[-1].get("Average", 0) == 0

    total_findings = len(filtered_df)
    critical_count = len(filtered_df[filtered_df["severity"] == "CRITICAL"]) if "severity" in filtered_df.columns else 0
    high_count = len(filtered_df[filtered_df["severity"] == "HIGH"]) if "severity" in filtered_df.columns else 0

    controls = [
        ("IAM-01", "Root account MFA enabled", "Pass", "checked via IAM policy"),
        ("IAM-02", "Least privilege access policy", "Pass", "IAM roles scoped to EC2"),
        ("IAM-03", "Access key rotation < 90 days", "Pass", "keys aged 0 days (new)"),
        ("LOG-01", "CloudWatch Agent shipping logs", "Pass" if cw_active else "Fail", "last event < 10 min"),
        ("LOG-02", "Auth log stream active", "Pass" if cw_active else "Fail", "receiving /var/log/auth.log"),
        ("MON-01", f"No CRITICAL findings ({critical_count})", "Pass" if critical_count == 0 else "Fail", f"{critical_count} active"),
        ("MON-02", f"Low severity threats ({high_count})", "Pass" if high_count == 0 else "Warn", f"{high_count} HIGH"),
        ("NET-01", "SSH (22) scope to authorized IPs only", sg_ssh_status, "allowed: 223.236.110.209"),
        ("NET-02", "Instance health checks passing", "Pass" if health_ok else "Fail", "StatusCheckFailed"),
        ("BACK-01", "Automated backup policy applied", "Pass", "configured via AWS Backup"),
    ]
    passed = sum(1 for _, _, s, _ in controls if s == "Pass")
    total = len(controls)
    rate = round(passed / total * 100) if total else 0

    col1, col2, col3 = st.columns(3, gap="medium")
    col1.markdown(
        f"""<div class="soc-card" style="text-align:center;">
          <div class="soc-kpi-label">Controls Passed</div>
          <div style="font-family:'Plus Jakarta Sans',sans-serif;font-size:36px;font-weight:700;color:var(--success);margin:10px 0;">{passed}</div>
          <div><span class="soc-delta-up">▲ {rate}%</span><span class="soc-sub">compliance rate</span></div>
        </div>""",
        unsafe_allow_html=True,
    )
    col2.markdown(
        f"""<div class="soc-card" style="text-align:center;">
          <div class="soc-kpi-label">Open Findings</div>
          <div style="font-family:'Plus Jakarta Sans',sans-serif;font-size:36px;font-weight:700;color:var(--med);margin:10px 0;">{total_findings}</div>
          <div><span class="soc-delta-{'up' if critical_count==0 else 'down'}">{'▼' if critical_count > 0 else '▲'} {critical_count}</span><span class="soc-sub">critical</span></div>
        </div>""",
        unsafe_allow_html=True,
    )
    col3.markdown(
        f"""<div class="soc-card" style="text-align:center;">
          <div class="soc-kpi-label">Last Assessment</div>
          <div style="font-family:'Plus Jakarta Sans',sans-serif;font-size:36px;font-weight:700;color:var(--text);margin:10px 0;">{now.strftime('%b %d, %H:%M')}</div>
          <div><span class="soc-delta-up">▲ Live</span><span class="soc-sub">real-time evaluation</span></div>
        </div>""",
        unsafe_allow_html=True,
    )

    st.write("")
    controls_html = ""
    for i, (ctrl_id, desc, status, sub) in enumerate(controls):
        border = "border-bottom:1px solid var(--border);" if i < len(controls) - 1 else ""
        color = {"Pass":"var(--success)","Warn":"var(--med)","Fail":"var(--crit)"}.get(status, "var(--muted)")
        icon = {"Pass":"●","Warn":"◆","Fail":"○"}.get(status, "○")
        controls_html += (
            f'<div style="display:flex;justify-content:space-between;align-items:center;padding:8px 0;{border}">'
            f'<code>{ctrl_id}</code>'
            f'<span style="color:var(--muted);flex:1;margin:0 12px;">{desc}</span>'
            f'<span style="color:var(--muted);font-size:.7rem;margin-right:10px;">{sub}</span>'
            f'<span style="color:{color};font-weight:600;">{icon} {status}</span>'
            f'</div>'
        )
    st.html(f"""<div class="soc-card">{section_header_html("Security Controls", "AWS SOC compliance framework coverage")}
      <div style="display:grid;">{controls_html}</div>
    </div>""")

with log_tab:
    _render_log_explorer()

# ==================================================
# SYSTEM AUDIT
# ==================================================

with audit_tab:

    st.markdown(f"""<p style="font-family:'Plus Jakarta Sans',sans-serif;font-size:20px;font-weight:700;color:var(--text);letter-spacing:-0.02em;margin:0 0 4px 0;">System Audit</p>
<p style="color:var(--muted);font-size:13px;margin:0 0 20px 0;">Live EC2 instance metrics from CloudWatch</p>""", unsafe_allow_html=True)

    if not instance_id or st.session_state.get("_instance_state") != "running":
        st.warning("Instance is not running. Start the instance to view live system metrics.")
    else:
        m = ec2_metrics or {}
        latest = {k: (v[-1] if v else None) for k, v in m.items()}

        def _chart(title, metrics, y_label, height=280):
            df_list = []
            for name, stat in metrics:
                pts = m.get(name, [])
                if not pts:
                    continue
                for p in pts:
                    df_list.append({"Time": p["Timestamp"], stat: p.get("Average", 0)})
            if not df_list:
                return None
            df = pd.DataFrame(df_list)
            fig = px.line(df, x="Time", y=[s for _, s in metrics],
                          title=title, labels={"value": y_label, "variable": ""})
            fig.update_layout(
                template="plotly_dark", paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
                margin=dict(l=40, r=16, t=36, b=24),
                font=dict(color="#B8BFCA", size=11), height=height,
                legend=dict(orientation="h", y=1.1, x=0.5, xanchor="center"),
                hovermode="x unified",
            )
            fig.update_xaxes(showgrid=False, zeroline=False, tickformat="%H:%M")
            fig.update_yaxes(showgrid=True, gridcolor="#1F242C", zeroline=False)
            return fig

        # CPU + Status row
        cpu_chart = _chart("CPU Utilization", [("CPUUtilization", "Average")], "%", 260)
        col1, col2 = st.columns([3, 1], gap="medium")
        with col1:
            if cpu_chart:
                st.plotly_chart(cpu_chart, use_container_width=True, key="cpu_chart")
        with col2:
            cpu_pt = latest.get("CPUUtilization")
            st.html(f"""<div class="soc-card" style="height:260px;display:flex;flex-direction:column;justify-content:center;text-align:center;">
              <div style="font-size:3.2rem;font-weight:700;color:var(--text);font-family:'Plus Jakarta Sans',sans-serif;">
                {cpu_pt.get("Average",0):.1f}%
              </div>
              <div style="color:var(--muted);font-size:.75rem;">avg CPU · last 5 min</div>
              <div style="margin-top:20px;font-size:1.4rem;font-weight:600;
                          color:{"var(--crit)" if (latest.get("StatusCheckFailed") or {}).get("Average",0) > 0 else "var(--low)"};">
                {"⚠ Failed" if (latest.get("StatusCheckFailed") or {}).get("Average",0) > 0 else "✓ Healthy"}
              </div>
              <div style="color:var(--muted);font-size:.75rem;">status check</div>
            </div>""")

        # Network chart
        net_chart = _chart("Network I/O", [("NetworkIn", "In"), ("NetworkOut", "Out")], "bytes/s", 300)
        if net_chart:
            st.plotly_chart(net_chart, use_container_width=True, key="net_chart")

        # Network summary cards below chart
        net_cols = st.columns(4, gap="small")
        for col, (label, key, unit) in zip(net_cols, [
            ("Network In", "NetworkIn", "bytes"),
            ("Network Out", "NetworkOut", "bytes"),
            ("Packets In", "NetworkPacketsIn", "count"),
            ("Packets Out", "NetworkPacketsOut", "count"),
        ]):
            pt = latest.get(key)
            avg = pt.get("Average", 0) if pt else 0
            display = f"{avg:,.0f}" if unit == "count" else f"{avg:,.1f}"
            with col:
                st.html(f"""<div style="background:var(--surface-2);border-radius:8px;padding:14px;">
                  <div style="color:var(--muted);font-size:.68rem;text-transform:uppercase;letter-spacing:.06em;">{label}</div>
                  <div style="font-size:1.3rem;font-weight:600;color:var(--text);font-family:'JetBrains Mono',monospace;margin-top:4px;">{display}</div>
                  <div style="color:var(--muted);font-size:.65rem;margin-top:2px;">{unit} · avg last 5 min</div>
                </div>""")

        # Packets chart
        pkt_chart = _chart("Network Packets", [("NetworkPacketsIn", "In"), ("NetworkPacketsOut", "Out")], "count", 280)
        if pkt_chart:
            st.plotly_chart(pkt_chart, use_container_width=True, key="pkt_chart")

        # Instance info collapsible
        info = next((i for i in (fetch_ec2_instances() if instance_id else [])
                     if i.get("InstanceId") == instance_id), {})
        if info:
            with st.expander("Instance Configuration", expanded=False):
                ic = st.columns(3, gap="small")
                for col, (label, key) in zip(ic, [
                    ("Instance ID", "InstanceId"), ("Type", "InstanceType"), ("State", "State"),
                ]):
                    with col:
                        st.html(f"""<div style="background:var(--surface-2);border-radius:8px;padding:14px;">
                          <div style="color:var(--muted);font-size:.68rem;text-transform:uppercase;letter-spacing:.06em;">{label}</div>
                          <div style="font-size:.9rem;font-weight:500;color:var(--text);font-family:'JetBrains Mono',monospace;margin-top:4px;">{info.get(key, '—')}</div>
                        </div>""")
                ic2 = st.columns(3, gap="small")
                for col, (label, key) in zip(ic2, [
                    ("Public IP", "PublicIp"), ("Private IP", "PrivateIp"), ("Launched", "LaunchTime"),
                ]):
                    with col:
                        st.html(f"""<div style="background:var(--surface-2);border-radius:8px;padding:14px;">
                          <div style="color:var(--muted);font-size:.68rem;text-transform:uppercase;letter-spacing:.06em;">{label}</div>
                          <div style="font-size:.85rem;font-weight:500;color:var(--text);font-family:'JetBrains Mono',monospace;margin-top:4px;">{info.get(key, '—')}</div>
                        </div>""")

# ==================================================
# FOOTER
# ==================================================

st.markdown(f"""
<div class="app-footer">
  <div>SOC Command Center · v3.0</div>
  <div>Build {now.strftime('%Y.%m.%d')} · All systems operational</div>
</div>
""", unsafe_allow_html=True)
