#!/usr/bin/env bash
# Reference solution for the log-forensics benchmark task.
# Parses /app/logs/* and writes /app/report.json.
# Uses only Python 3 stdlib + gzip (both present in the Docker image).
set -euo pipefail

python3 - <<'PYEOF'
"""
Log-forensics solver.

Algorithm
---------
1. Scan auth logs for the first "Accepted password" login from an external IP.
   That gives attacker_ip, compromised_account, and first_compromise_time (UTC).

2. Scan nginx logs for an HTTP 200 GET by that IP — that is the exfiltrated file.
   We prefer the request that occurs after the SSH compromise time (chronologically).

3. Scan cron.log for cron jobs running as compromised_account that appear for the
   first time after the compromise time; the path of that job is persistence_path.
"""

import gzip
import json
import re
import sys
from datetime import datetime, timezone, timedelta

LOG_DIR = "/app/logs"
TZ_PLUS3 = timezone(timedelta(hours=3))


# ── Helpers ───────────────────────────────────────────────────────────────────

def open_log(path: str):
    if path.endswith(".gz"):
        return gzip.open(path, "rt", encoding="utf-8")
    return open(path, "r", encoding="utf-8")


def read_lines(path: str) -> list[str]:
    with open_log(path) as fh:
        return fh.readlines()


# ── Step 1: Find the successful external password login ───────────────────────

auth_files = [
    f"{LOG_DIR}/auth.log.1.gz",
    f"{LOG_DIR}/auth.log",
]

# Regex: ISO 8601 timestamp with +HH:MM offset, hostname, sshd, "Accepted password"
AUTH_ACCEPT_RE = re.compile(
    r"(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\+\d{2}:\d{2})"
    r"\s+\S+\s+sshd\[\d+\]:\s+"
    r"Accepted password for (\S+) from (\S+) port"
)

compromise_event = None          # (datetime_utc, attacker_ip, username)

for af in auth_files:
    for line in read_lines(af):
        m = AUTH_ACCEPT_RE.search(line)
        if not m:
            continue
        ts_str, user, ip = m.group(1), m.group(2), m.group(3)
        # Ignore RFC-1918 and loopback sources — only external IPs matter
        if (ip.startswith("10.")
                or ip.startswith("192.168.")
                or ip.startswith("172.")
                or ip.startswith("127.")):
            continue
        dt_local = datetime.fromisoformat(ts_str)
        dt_utc   = dt_local.astimezone(timezone.utc)
        if compromise_event is None or dt_utc < compromise_event[0]:
            compromise_event = (dt_utc, ip, user)

if compromise_event is None:
    print("ERROR: no external Accepted-password login found in auth logs", file=sys.stderr)
    sys.exit(1)

comp_time_utc, attacker_ip, compromised_account = compromise_event
first_compromise_time = comp_time_utc.strftime("%Y-%m-%dT%H:%M:%SZ")


# ── Step 2: Find the exfiltrated file ────────────────────────────────────────

nginx_files = [
    f"{LOG_DIR}/nginx-access.log.1.gz",
    f"{LOG_DIR}/nginx-access.log",
]

# Combined Log Format timestamp: [DD/Mon/YYYY:HH:MM:SS +0000]
NGINX_TS_RE   = re.compile(r"\[(\d{2}/\w+/\d{4}:\d{2}:\d{2}:\d{2} \+\d{4})\]")
NGINX_REQ_RE  = re.compile(r'"(?:GET|POST|HEAD|PUT|DELETE|OPTIONS) (\S+) HTTP/[\d.]+" 200 ')

# Nginx timestamp format
NGINX_TS_FMT = "%d/%b/%Y:%H:%M:%S %z"

best_exfil   = None             # (datetime_utc, url_path)

for nf in nginx_files:
    for line in read_lines(nf):
        if attacker_ip not in line:
            continue
        if '" 200 ' not in line:
            continue
        req_m = NGINX_REQ_RE.search(line)
        if not req_m:
            continue
        url_path = req_m.group(1)
        # Parse nginx timestamp for ordering (prefer post-compromise)
        ts_m = NGINX_TS_RE.search(line)
        if ts_m:
            dt_utc = datetime.strptime(ts_m.group(1), NGINX_TS_FMT).astimezone(timezone.utc)
        else:
            dt_utc = timezone.utc  # fallback: treat as epoch 0
        if best_exfil is None or dt_utc > best_exfil[0]:
            best_exfil = (dt_utc, url_path)

if best_exfil is None:
    print("ERROR: no HTTP 200 GET by attacker IP found in nginx logs", file=sys.stderr)
    sys.exit(1)

exfiltrated_file = best_exfil[1]


# ── Step 3: Find the persistence cron job ────────────────────────────────────

cron_file = f"{LOG_DIR}/cron.log"

# Regex: ISO 8601 timestamp, hostname, CRON[pid], (username) CMD (path)
CRON_RE = re.compile(
    r"(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\+\d{2}:\d{2})"
    r"\s+\S+\s+CRON\[\d+\]:\s+"
    r"\(" + re.escape(compromised_account) + r"\) CMD \(([^)]+)\)"
)

cron_lines = read_lines(cron_file)

# First pass: collect all cron paths for this user BEFORE the compromise
known_legit: set[str] = set()
for line in cron_lines:
    m = CRON_RE.search(line)
    if not m:
        continue
    ts_str, cmd_path = m.group(1), m.group(2)
    dt_utc = datetime.fromisoformat(ts_str).astimezone(timezone.utc)
    if dt_utc < comp_time_utc:
        known_legit.add(cmd_path)

# Second pass: first NEW path seen AFTER the compromise
persistence_path = None
for line in cron_lines:
    m = CRON_RE.search(line)
    if not m:
        continue
    ts_str, cmd_path = m.group(1), m.group(2)
    dt_utc = datetime.fromisoformat(ts_str).astimezone(timezone.utc)
    if dt_utc > comp_time_utc and cmd_path not in known_legit:
        persistence_path = cmd_path
        break

if persistence_path is None:
    print("ERROR: no new cron job found for compromised account after compromise", file=sys.stderr)
    sys.exit(1)


# ── Output ────────────────────────────────────────────────────────────────────

report = {
    "attacker_ip":           attacker_ip,
    "compromised_account":   compromised_account,
    "first_compromise_time": first_compromise_time,
    "exfiltrated_file":      exfiltrated_file,
    "persistence_path":      persistence_path,
}

output_path = "/app/report.json"
with open(output_path, "w", encoding="utf-8") as fh:
    json.dump(report, fh, indent=2)
    fh.write("\n")

print(f"Wrote {output_path}:")
print(json.dumps(report, indent=2))
PYEOF
