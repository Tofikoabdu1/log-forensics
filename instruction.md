# Log Forensics — Incident Response Challenge

## Background

You are a security analyst responding to a suspected intrusion on **webserver01**.
The server runs an SSH daemon and an nginx web server.
Log files are in `/app/logs/`.

Rotated logs (`.gz`) cover the day **before** the incident; the plain-text logs
cover the day **of** the incident.

> **Time zones:** SSH auth and cron log entries use the **+03:00** offset.
> Nginx access log entries use **UTC (+0000)**. You must account for this when
> correlating events across log files.

## Your Task

Analyse the logs and write a JSON report to `/app/report.json` containing
**exactly** these five string fields:

```json
{
  "attacker_ip":           "<IPv4 address of the external attacker>",
  "compromised_account":   "<local username whose password was guessed>",
  "first_compromise_time": "<UTC timestamp of the first successful attacker login, YYYY-MM-DDTHH:MM:SSZ>",
  "exfiltrated_file":      "<URL path of the file the attacker retrieved with HTTP 200>",
  "persistence_path":      "<absolute path of the script added to the compromised user's crontab>"
}
```

## Field Formats

| Field | Format | Example |
|---|---|---|
| `attacker_ip` | Bare IPv4 address | `203.0.113.1` |
| `compromised_account` | Local Unix username | `jsmith` |
| `first_compromise_time` | UTC, `YYYY-MM-DDTHH:MM:SSZ` | `2024-03-15T02:17:43Z` |
| `exfiltrated_file` | URL path starting with `/` | `/backups/archive.tar.gz` |
| `persistence_path` | Absolute filesystem path, no arguments | `/var/tmp/.keepalive.sh` |

All values are **exact strings** — spelling, case, and format matter.
`first_compromise_time` **must be converted to UTC** regardless of the timezone
recorded in the source log.

## Available Logs

| File | Contents | Timezone |
|---|---|---|
| `/app/logs/auth.log.1.gz` | Rotated SSH auth log (day −1) | +03:00 |
| `/app/logs/auth.log` | Current SSH auth log (day 0) | +03:00 |
| `/app/logs/cron.log` | Cron daemon log (both days) | +03:00 |
| `/app/logs/nginx-access.log.1.gz` | Rotated nginx access log (day −1) | UTC |
| `/app/logs/nginx-access.log` | Current nginx access log (day 0) | UTC |

## Constraints

- Python 3 is available. The only tools guaranteed present are those in a
  standard Ubuntu 24.04 install plus `python3` and `gzip`.
- Do **not** hard-code values — your script must derive them from the log files.
- Write `/app/report.json` before exiting.

## Scoring

Each of the five fields is worth **0.2 points** (exact match required).
Maximum score: **1.0**.
