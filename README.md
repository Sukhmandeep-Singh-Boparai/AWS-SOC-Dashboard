# AWS SOC Dashboard

A Streamlit-based Security Operations Center dashboard that monitors EC2 instances in real-time via AWS CloudWatch.

## Features

- **Live Monitoring** — CloudWatch Logs Insights queries for security events across all log groups
- **EC2 Metrics** — CPU, network I/O, and status checks for selected instances
- **CloudTrail Integration** — Recent management events (ConsoleLogin, RootLogin, etc.)
- **Auto-Refresh** — Dashboard refreshes every 30 seconds
- **Local Fallback** — Uses local incident reports when AWS data is unavailable

## Files

| File | Purpose |
|------|---------|
| `dashboard.py` | Main Streamlit app with sidebar navigation and visualizations |
| `aws_data_source.py` | Data pipeline — CloudWatch Logs, CloudTrail, EC2 metrics, fallback |
| `styles.css` | Dark theme styling |
| `requirements.txt` | Python dependencies |

## Quick Start

```bash
pip install -r requirements.txt
streamlit run dashboard.py
```

Requires AWS credentials configured via `~/.aws/credentials` or environment variables.

**SCREENSHOT**

<img width="1907" height="997" alt="Screenshot 2026-07-01 103011" src="https://github.com/user-attachments/assets/90f002fb-2a62-46e9-a337-bdaeb284bfbb" />
