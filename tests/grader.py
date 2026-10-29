"""
Grader for the log-forensics benchmark task.
Reads /app/report.json, compares each field against the answer key,
and writes a 0.0–1.0 score to /logs/verifier/reward.txt.

Uses only the Python standard library.
Run as a script (python3 /tests/grader.py) — no pytest required.
"""

import json
import pathlib
import sys
from datetime import datetime, timezone

ANSWER_FILE = pathlib.Path("/tests/answer.json")
REPORT_FILE = pathlib.Path("/app/report.json")
REWARD_FILE = pathlib.Path("/logs/verifier/reward.txt")

FIELDS = [
    "attacker_ip",
    "compromised_account",
    "first_compromise_time",
    "exfiltrated_file",
    "persistence_path",
]

POINTS_PER_FIELD = 0.2


# ── Timestamp helpers ─────────────────────────────────────────────────────────

def parse_utc(s: str) -> datetime | None:
    """Parse a UTC timestamp string into an aware datetime.

    Accepts YYYY-MM-DDTHH:MM:SSZ and YYYY-MM-DDTHH:MM:SS+00:00.
    Returns None on failure.
    """
    for fmt in (
        "%Y-%m-%dT%H:%M:%SZ",
        "%Y-%m-%dT%H:%M:%S+00:00",
        "%Y-%m-%dT%H:%M:%S",
    ):
        try:
            dt = datetime.strptime(s.strip(), fmt)
            return dt.replace(tzinfo=timezone.utc)
        except ValueError:
            pass
    return None


def times_equal(got: str, expected: str) -> bool:
    dt_got = parse_utc(got)
    dt_exp = parse_utc(expected)
    if dt_got is None or dt_exp is None:
        return False
    return dt_got == dt_exp


# ── Scoring ───────────────────────────────────────────────────────────────────

def score_report(report: dict, answer: dict) -> tuple[float, list[str]]:
    score = 0.0
    details = []
    for field in FIELDS:
        got = str(report.get(field, "")).strip()
        exp = str(answer.get(field, "")).strip()
        if field == "first_compromise_time":
            correct = times_equal(got, exp)
        else:
            correct = got == exp
        mark = "PASS" if correct else "FAIL"
        details.append(f"  [{mark}] {field}: got={got!r}  expected={exp!r}")
        if correct:
            score += POINTS_PER_FIELD
    return round(score, 1), details


def write_reward(score: float) -> None:
    REWARD_FILE.parent.mkdir(parents=True, exist_ok=True)
    REWARD_FILE.write_text(f"{score:.1f}\n", encoding="utf-8")


# ── Main ──────────────────────────────────────────────────────────────────────

def main() -> None:
    # Guard: report missing
    if not REPORT_FILE.exists():
        write_reward(0.0)
        print(f"FAIL: {REPORT_FILE} not found — score 0.0")
        sys.exit(0)

    # Guard: report not parseable
    try:
        report = json.loads(REPORT_FILE.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError) as exc:
        write_reward(0.0)
        print(f"FAIL: could not parse report.json: {exc} — score 0.0")
        sys.exit(0)

    if not isinstance(report, dict):
        write_reward(0.0)
        print("FAIL: report.json is not a JSON object — score 0.0")
        sys.exit(0)

    # Guard: answer key missing (grading infrastructure error)
    if not ANSWER_FILE.exists():
        write_reward(0.0)
        print(f"GRADING ERROR: answer key not found at {ANSWER_FILE} — score 0.0")
        sys.exit(1)

    answer = json.loads(ANSWER_FILE.read_text(encoding="utf-8"))
    score, details = score_report(report, answer)

    write_reward(score)

    print(f"\nScore: {score:.1f} / 1.0")
    for line in details:
        print(line)


if __name__ == "__main__":
    main()

