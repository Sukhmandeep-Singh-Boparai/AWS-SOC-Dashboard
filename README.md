# AWS SOC Dashboard

A Streamlit-based Security Operations Center dashboard deployed on EC2 for real-time monitoring of AWS infrastructure via CloudWatch Logs, CloudWatch Metrics, and CloudTrail.

## Architecture

```
┌──────────────┐    ┌─────────────────┐    ┌──────────────────────┐
│  EC2 Instance │───▶│  SOC Dashboard  │───▶│  AWS APIs (boto3)   │
│  (monitored)  │    │                  │    │                      │
│               │    │  Port 8501       │    │  CloudWatch Logs     │
│  /var/log/    │    │  systemd         │    │  CloudWatch Metrics  │
│  auth.log     │    │  soc-dashboard   │    │  EC2 Describe        │
└──────────────┘    └─────────────────┘    │  CloudTrail          │
                           │               └──────────────────────┘
                    ┌──────┴──────┐
                    │  IAM Role   │
                    └─────────────┘
```

The dashboard runs on a dedicated EC2 instance (Ubuntu 24.04) and authenticates to AWS via an attached IAM role — no hardcoded credentials. It monitors a separate EC2 instance that ships `/var/log/auth.log` to CloudWatch via the CloudWatch Agent.

## Features

- **Live Security Monitoring** — CloudWatch Logs Insights queries for SSH auth events across all log groups
- **EC2 Metrics** — CPU utilization, network I/O, and status checks for selected instances
- **Threat Detection** — Brute-force rollups, unauthorized key acceptance, privilege escalation, and MITRE ATT&CK mapping
- **Case Management** — Incident workflow with status tracking, analyst assignment, and notes
- **Raw Log Explorer** — Browse and search CloudWatch logs with severity highlighting and Excel export
- **Risk & Compliance** — Live security control checks (SSH scope, CloudWatch health, IAM posture)
- **System Audit** — Real-time EC2 system metrics with historical charts
- **Auto-Refresh** — Dashboard refreshes every 30 seconds

## Deployment

### Access

```
http://<public-ip>:8501
```

The public IP changes if the instance is stopped and started. Look it up via the AWS Console.

### Service Management

The dashboard runs as a systemd service with auto-start on boot and auto-restart on failure.

```bash
# Status
sudo systemctl status soc-dashboard

# Restart
sudo systemctl restart soc-dashboard

# Logs
sudo journalctl -u soc-dashboard -f
```

## Files

| File | Purpose |
|------|---------|
| `dashboard.py` | Main Streamlit application (tabs, visualizations, workflow) |
| `aws_data_source.py` | Data pipeline — CloudWatch Logs, CloudTrail, EC2 metrics |
| `styles.css` | Dark theme CSS |
| `requirements.txt` | Python dependencies |

## Development Setup

```bash
pip install -r requirements.txt
streamlit run dashboard.py
```

For local development, configure AWS credentials via environment variables or `~/.aws/credentials`.

## Screenshots

<img width="1907" alt="SOC Dashboard" src="assets/dashboard.png">
