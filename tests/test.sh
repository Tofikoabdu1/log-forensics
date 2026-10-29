#!/usr/bin/env bash
# Verifier entry-point for the log-forensics task.
# Always writes a score (0.0–1.0) to /logs/verifier/reward.txt.
# Exit code: 0 (grading always completes; partial credit is recorded).
set -uo pipefail

REWARD=/logs/verifier/reward.txt
mkdir -p "$(dirname "$REWARD")"

# Default to 0 so reward.txt exists even if Python crashes
echo "0.0" > "$REWARD"

python3 /tests/grader.py

echo "Reward: $(cat "$REWARD")"
