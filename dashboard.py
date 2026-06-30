import streamlit as st
import pandas as pd
import json
from pathlib import Path
from datetime import datetime
import plotly.express as px
import plotly.graph_objects as go
from streamlit_option_menu import option_menu
from streamlit_autorefresh import st_autorefresh
from aws_data_source import fetch_findings, fetch_ec2_instances, fetch_ec2_metrics, fetch_log_groups

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

df = fetch_findings()

if df.empty:
    st.warning("No findings from AWS or local files. Re-run the dashboard once CloudWatch data or local reports are available.")

# ==================================================
# AUTO-REFRESH (every 30 seconds, background JS)
# ==================================================

if "refresh_count" not in st.session_state:
    st.session_state.refresh_count = 0

refresh_count = st_autorefresh(interval=30000, key="auto_refresh")
if refresh_count > st.session_state.refresh_count:
    st.session_state.refresh_count = refresh_count

# ==================================================
# HELPERS
# ==================================================

def save_incident_changes(incident_id, status, analyst, notes):
    filename = Path("reports") / f"incident_{incident_id}.json"
    if not filename.exists():
        return False
    with open(filename, "r") as f:
        data = json.load(f)
    data["status"] = status
    data["assigned_to"] = analyst
    data["notes"] = notes
    data["last_updated"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open(filename, "w") as f:
        json.dump(data, f, indent=4)
    return True


def load_latest_audit():
    audit_dir = Path("reports")
    audits = sorted(audit_dir.glob("audit_*.json"), reverse=True)
    if not audits:
        return None
    try:
        with open(audits[0], "r") as f:
            return json.load(f)
    except Exception:
        return None


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


def get_log_severity(log_entry):
    log_lower = log_entry.lower()
    if "failed password" not in log_lower:
        return None
    for _, incident in df.iterrows():
        source_ip = str(incident.get("source_ip", "")).lower()
        hostname = str(incident.get("hostname", "")).lower()
        if source_ip in log_lower or hostname in log_lower:
            return incident.get("severity", "LOW")
    return None


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

    selected = option_menu(
        menu_title=None,
        options=["Dashboard", "Investigations", "Case Management", "Analytics", "Compliance", "Log Explorer", "System Audit"],
        icons=["grid-1x2", "search", "folder2-open", "graph-up", "shield-check", "terminal", "cpu"],
        default_index=0,
        key="nav_menu",
        styles={
            "container": {"padding": "0", "background-color": "transparent"},
            "icon": {"color": "#8B929C", "font-size": "14px"},
            "nav-link": {
                "font-size": "13px",
                "font-weight": "500",
                "color": "#B8BFCA",
                "padding": "9px 12px",
                "margin": "2px 0",
                "border-radius": "6px",
                "--hover-color": "#161A20",
                "font-family": "Inter, sans-serif",
            },
            "nav-link-selected": {
                "background-color": "#161A20",
                "color": "#FFFFFF",
                "font-weight": "500",
                "border-left": "2px solid #4F8CFF",
                "border-radius": "6px",
            },
        },
    )

    st.markdown('<div class="sb-section">EC2 Instance</div>', unsafe_allow_html=True)
    instances = fetch_ec2_instances()
    instance_options = {f"{i.get('Name', '')} ({i['InstanceId']})": i["InstanceId"] for i in instances if i["State"] == "running"}
    if instance_options:
        selected_instance = st.selectbox(
            "Instance", list(instance_options.keys()),
            label_visibility="collapsed",
            key="selected_instance",
        )
        instance_id = instance_options[selected_instance]
        ec2_metrics = fetch_ec2_metrics(instance_id)
        if ec2_metrics:
            cpu = ec2_metrics.get("CPUUtilization")
            if cpu:
                st.caption(f"CPU: {cpu.get('Average', 0):.1f}%")
            net = ec2_metrics.get("NetworkIn")
            if net:
                st.caption(f"Network: {net.get('Average', 0)/1024:.1f} KB/s")
            status = ec2_metrics.get("StatusCheckFailed")
            if status:
                st.caption(f"Status: {'⚠ Failed' if status.get('Average', 0) > 0 else '✓ OK'}")
    else:
        all_instances = [i for i in instances if i["State"] != "terminated"]
        if all_instances:
            st.caption(f"{len(all_instances)} stopped instance(s)")
        else:
            st.caption("No running EC2 instances")
        instance_id = None
        ec2_metrics = {}

    log_groups = fetch_log_groups()
    if log_groups:
        st.markdown('<div class="sb-section">Log Groups</div>', unsafe_allow_html=True)
        for lg in log_groups[:3]:
            short = lg.split("/")[-1] if "/" in lg else lg
            st.caption(f"📋 {short[:30]}")

    st.markdown('<div class="sb-section">Filters</div>', unsafe_allow_html=True)

    severity_critical = st.checkbox("CRITICAL", value=False, key="sev_critical")
    severity_high = st.checkbox("HIGH", value=False, key="sev_high")
    severity_medium = st.checkbox("MEDIUM", value=False, key="sev_medium")
    severity_low = st.checkbox("LOW", value=False, key="sev_low")
    severity_filter = []
    if severity_critical: severity_filter.append("CRITICAL")
    if severity_high: severity_filter.append("HIGH")
    if severity_medium: severity_filter.append("MEDIUM")
    if severity_low: severity_filter.append("LOW")

    ip_search = st.text_input("Source IP", placeholder="Filter by source IP…", label_visibility="collapsed")

# ==================================================
# FILTERING
# ==================================================

filtered_df = df
if severity_filter:
    filtered_df = filtered_df[filtered_df["severity"].isin(severity_filter)]

if ip_search:
    filtered_df = filtered_df[filtered_df["source_ip"].str.contains(ip_search, case=False, na=False)]

score = calculate_score(filtered_df)

# ==================================================
# HEADER
# ==================================================

now = datetime.utcnow()
st.markdown(f"""
<div class="app-header">
  <div>
    <div class="brand-eyebrow">AWS · Security Operations Center</div>
    <h1>Command Center</h1>
  </div>
  <div class="meta">
    <div class="soc-eyebrow"><span class="soc-dot"></span> LIVE · {st.session_state.refresh_count} refreshes</div>
    <div style="margin-top:4px;">{now.strftime('%Y-%m-%d · %H:%M:%S UTC')}</div>
  </div>
</div>
""", unsafe_allow_html=True)

# ==================================================
# DASHBOARD (lovable-inspired redesign)
# ==================================================

if selected == "Dashboard":

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

elif selected == "Investigations":
    st.markdown(f"""<p style="font-family:'Plus Jakarta Sans',sans-serif;font-size:20px;font-weight:700;color:var(--text);letter-spacing:-0.02em;margin:0 0 4px 0;">Investigation Console</p>
<p style="color:var(--muted);font-size:13px;margin:0 0 20px 0;">{len(filtered_df)} findings match the current filters</p>""", unsafe_allow_html=True)

    cols = [c for c in ["timestamp","incident_id","severity","hostname","username","source_ip",
                        "attack_count","finding_type","status","assigned_to","action_taken"]
            if c in filtered_df.columns]
    st.markdown(f"""<div class="soc-card">{section_header_html("Investigation Console", f"{len(filtered_df)} findings match the current filters")}</div>""", unsafe_allow_html=True)
    st.dataframe(filtered_df[cols], use_container_width=True, height=720, hide_index=True)

# ==================================================
# CASE MANAGEMENT
# ==================================================

elif selected == "Case Management":
    st.markdown(f"""<p style="font-family:'Plus Jakarta Sans',sans-serif;font-size:20px;font-weight:700;color:var(--text);letter-spacing:-0.02em;margin:0 0 4px 0;">Case Management</p>
<p style="color:var(--muted);font-size:13px;margin:0 0 20px 0;">Incident workflow and investigation management</p>""", unsafe_allow_html=True)
    incident_ids = filtered_df["incident_id"].tolist()

    if not incident_ids:
        st.warning("No incidents available with the current filters.")
    else:
        selected_incident = st.selectbox("Incident", incident_ids)
        incident = filtered_df[filtered_df["incident_id"] == selected_incident].iloc[0]

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
            status_opts = ["OPEN","INVESTIGATING","CONTAINED","RESOLVED","FALSE_POSITIVE"]
            status = st.selectbox("Status", status_opts,
                                  index=status_opts.index(incident.get("status","OPEN")))
            analyst = st.selectbox("Assigned Analyst",
                                   ["Unassigned","Analyst-01","Analyst-02","Analyst-03","Analyst-04"],
                                   index=0)
            notes = st.text_area("Investigation Notes", value=incident.get("notes",""), height=160)

            if st.button("Save Changes"):
                if save_incident_changes(selected_incident, status, analyst, notes):
                    st.success("Case updated.")
                else:
                    st.error("Unable to update incident.")
        st.html("</div>")

# ==================================================
# ANALYTICS (lovable-inspired redesign)
# ==================================================

elif selected == "Analytics":
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

elif selected == "Compliance":
    st.markdown(f"""<p style="font-family:'Plus Jakarta Sans',sans-serif;font-size:20px;font-weight:700;color:var(--text);letter-spacing:-0.02em;margin:0 0 4px 0;">Risk and Compliance</p>
<p style="color:var(--muted);font-size:13px;margin:0 0 20px 0;">Policy attestations, security controls, and audit-grade evidence</p>""", unsafe_allow_html=True)

    col1, col2, col3 = st.columns(3, gap="medium")
    col1.markdown(
        f"""<div class="soc-card" style="text-align:center;">
          <div class="soc-kpi-label">Controls Passed</div>
          <div style="font-family:'Plus Jakarta Sans',sans-serif;font-size:36px;font-weight:700;color:var(--success);margin:10px 0;">47</div>
          <div><span class="soc-delta-up">▲ 92%</span><span class="soc-sub">compliance rate</span></div>
        </div>""",
        unsafe_allow_html=True,
    )
    col2.markdown(
        f"""<div class="soc-card" style="text-align:center;">
          <div class="soc-kpi-label">Open Findings</div>
          <div style="font-family:'Plus Jakarta Sans',sans-serif;font-size:36px;font-weight:700;color:var(--med);margin:10px 0;">4</div>
          <div><span class="soc-delta-down">▼ 2</span><span class="soc-sub">since last audit</span></div>
        </div>""",
        unsafe_allow_html=True,
    )
    col3.markdown(
        f"""<div class="soc-card" style="text-align:center;">
          <div class="soc-kpi-label">Last Assessment</div>
          <div style="font-family:'Plus Jakarta Sans',sans-serif;font-size:36px;font-weight:700;color:var(--text);margin:10px 0;">{now.strftime('%b %d')}</div>
          <div><span class="soc-delta-up">▲ On track</span><span class="soc-sub">quarterly cycle</span></div>
        </div>""",
        unsafe_allow_html=True,
    )

    st.write("")
    controls = [
        ("IAM-01", "Root account MFA enabled", "Pass"),
        ("IAM-02", "Least privilege access policy", "Pass"),
        ("IAM-03", "Access key rotation < 90 days", "Pass"),
        ("LOG-01", "CloudTrail enabled in all regions", "Pass"),
        ("LOG-02", "VPC Flow Logs enabled", "Pass"),
        ("MON-01", "CloudWatch alarm on unauthorized API calls", "Fail"),
        ("ENC-01", "S3 default encryption enabled", "Pass"),
        ("NET-01", "Security group ingress restricted", "Fail"),
        ("NET-02", "Network ACLs configured", "Pass"),
        ("BACK-01", "Automated backup policy applied", "Pass"),
    ]
    controls_html = ""
    for i, (ctrl_id, desc, status) in enumerate(controls):
        border = "border-bottom:1px solid var(--border);" if i < len(controls) - 1 else ""
        color = "var(--success)" if status == "Pass" else "var(--crit)"
        icon = "●" if status == "Pass" else "○"
        controls_html += f'<div style="display:flex;justify-content:space-between;align-items:center;padding:8px 0;{border}"><code>{ctrl_id}</code><span style="color:var(--muted);">{desc}</span><span style="color:{color};font-weight:600;">{icon} {status}</span></div>'
    st.html(f"""<div class="soc-card">{section_header_html("Security Controls", "AWS SOC compliance framework coverage")}
      <div style="display:grid;">{controls_html}</div>
    </div>""")

# ==================================================
# LOG EXPLORER
# ==================================================

elif selected == "Log Explorer":
    st.markdown(f"""<p style="font-family:'Plus Jakarta Sans',sans-serif;font-size:20px;font-weight:700;color:var(--text);letter-spacing:-0.02em;margin:0 0 20px 0;">Raw Log Explorer</p>""", unsafe_allow_html=True)

    LOG_FILE = Path("logs/auth.log")
    if not LOG_FILE.exists():
        st.error("`logs/auth.log` not found.")
    else:
        with open(LOG_FILE, "r", encoding="utf-8") as f:
            logs = f.readlines()

        st.html(f"""<div class="soc-card">{section_header_html("Search & Filter", "Query raw authentication logs for forensic analysis")}""")
        col1, col2 = st.columns([3,1])
        with col1:
            search_text = st.text_input("Search", placeholder="Filter by IP, user, or keyword…",
                                        label_visibility="collapsed")
        with col2:
            lines_to_show = st.selectbox("Lines", [100, 500, 1000, 5000], index=1, label_visibility="collapsed")

        if search_text:
            logs = [l for l in logs if search_text.lower() in l.lower()]

        st.caption(f"Showing {min(len(logs), lines_to_show):,} of {len(logs):,} entries")
        st.html("</div>")

        recent_logs = logs[-lines_to_show:]
        rows = []
        for entry in recent_logs:
            sev = get_log_severity(entry)
            tint = {
                "CRITICAL": "rgba(229,72,77,.06)",
                "HIGH":     "rgba(232,128,75,.06)",
                "MEDIUM":   "rgba(212,162,76,.06)",
                "LOW":      "rgba(91,174,127,.06)",
            }.get(sev, "transparent")
            border = {
                "CRITICAL": "var(--crit)", "HIGH": "var(--high)",
                "MEDIUM": "var(--med)", "LOW": "var(--low)",
            }.get(sev, "transparent")
            sev_lbl = sev_pill(sev) if sev else "<span style='color:var(--muted);font-family:JetBrains Mono,monospace;font-size:.7rem;'>—</span>"
            rows.append(
                f"<tr style='background:{tint};'>"
                f"<td style='border-left:2px solid {border};padding:8px 10px;width:90px;'>{sev_lbl}</td>"
                f"<td style='padding:8px 10px;font-family:JetBrains Mono,monospace;font-size:.78rem;color:var(--text);word-break:break-all;'>{entry.strip()}</td>"
                f"</tr>"
            )

        html = f"""
        <div style='border:1px solid var(--border);border-radius:10px;overflow:hidden;background:var(--surface);'>
          <table style='width:100%;border-collapse:collapse;'>
            <thead>
              <tr style='background:var(--surface-2);border-bottom:1px solid var(--border);'>
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
# SYSTEM AUDIT
# ==================================================

elif selected == "System Audit":

    audit = load_latest_audit()
    if not audit:
        st.warning("No audit reports found.")
    else:
        ts = audit.get("timestamp", "—")
        st.markdown(f"""<p style="font-family:'Plus Jakarta Sans',sans-serif;font-size:20px;font-weight:700;color:var(--text);letter-spacing:-0.02em;margin:0 0 4px 0;">System Audit</p>
<p style="color:var(--muted);font-size:13px;margin:0 0 20px 0;">Latest audit · {ts}</p>""", unsafe_allow_html=True)

        st.html(f"""<div class="soc-card">{section_header_html("System State", "Current system configuration and health snapshot")}""")
        fields = [
            ("Logged In Users", "logged_in_users", 100),
            ("Open Ports", "open_ports", 160),
            ("Running Processes", "running_processes", 240),
            ("Memory Usage", "memory_usage", 120),
            ("Disk Usage", "disk_usage", 120),
            ("System Uptime", "uptime", 90),
        ]
        for label, key, height in fields:
            st.markdown(f"#### {label}")
            st.text_area(label, str(audit.get(key, "")), height=height,
                         disabled=True, label_visibility="collapsed")
        st.html("</div>")

# ==================================================
# FOOTER
# ==================================================

st.markdown(f"""
<div class="app-footer">
  <div>SOC Command Center · v3.0</div>
  <div>Build {now.strftime('%Y.%m.%d')} · All systems operational</div>
</div>
""", unsafe_allow_html=True)
