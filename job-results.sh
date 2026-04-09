#!/bin/bash
# Usage: ./job-results.sh jobs/2026-04-10__00-33-08/result.json
#    or: ./job-results.sh jobs/2026-04-10__00-33-08

set -euo pipefail

INPUT="${1:-}"
if [ -z "$INPUT" ]; then
    echo "Usage: $0 <path-to-result.json-or-job-dir>"
    echo "  e.g. $0 jobs/2026-04-10__00-33-08/result.json"
    echo "  e.g. $0 jobs/2026-04-10__00-33-08"
    exit 1
fi

# Resolve job directory whether they passed the dir or the result.json
if [ -f "$INPUT" ]; then
    JOB_DIR="$(dirname "$INPUT")"
else
    JOB_DIR="$INPUT"
fi

if [ ! -d "$JOB_DIR" ]; then
    echo "Error: directory not found: $JOB_DIR"
    exit 1
fi

RESULT_FILE="$JOB_DIR/result.json"
if [ ! -f "$RESULT_FILE" ]; then
    echo "Error: no result.json in $JOB_DIR"
    exit 1
fi

# Find trial directories (anything that's a dir and not config/logs)
TRIAL_DIRS=()
for d in "$JOB_DIR"/*/; do
    [ -d "$d" ] && [ -f "$d/result.json" ] && TRIAL_DIRS+=("$d")
done

python3 - "$RESULT_FILE" "${TRIAL_DIRS[@]}" <<'PYEOF'
import json, sys, os
from datetime import datetime

result_file = sys.argv[1]
trial_dirs = sys.argv[2:]

# ── Job summary ──
with open(result_file) as f:
    job = json.load(f)

print("=" * 60)
print("JOB SUMMARY")
print("=" * 60)
print(f"  Job ID:    {job.get('id', 'N/A')}")
print(f"  Started:   {job.get('started_at', 'N/A')}")
print(f"  Finished:  {job.get('finished_at', 'N/A')}")
print(f"  Trials:    {job.get('n_total_trials', 'N/A')}")

stats = job.get("stats", {}).get("evals", {})
for eval_name, eval_data in stats.items():
    metrics = eval_data.get("metrics", [{}])
    mean = metrics[0].get("mean", "N/A") if metrics else "N/A"
    reward_icon = "\033[32m✓\033[0m" if mean == 1.0 else "\033[31m✗\033[0m"
    print(f"  Reward:    {mean} {reward_icon}")

# ── Per-trial details ──
for trial_dir in trial_dirs:
    trial_result_file = os.path.join(trial_dir, "result.json")
    ctrf_file = os.path.join(trial_dir, "verifier", "ctrf.json")

    with open(trial_result_file) as f:
        trial = json.load(f)

    trial_name = trial.get("trial_name", os.path.basename(trial_dir.rstrip("/")))
    agent_name = trial.get("config", {}).get("agent", {}).get("name", "unknown")
    reward = trial.get("verifier_result", {}).get("rewards", {}).get("reward", "N/A")

    print()
    print("=" * 60)
    print(f"TRIAL: {trial_name}")
    print("=" * 60)
    print(f"  Agent:     {agent_name}")
    print(f"  Task:      {trial.get('task_name', 'N/A')}")
    reward_icon = "\033[32m✓\033[0m" if reward == 1.0 else "\033[31m✗\033[0m"
    print(f"  Reward:    {reward} {reward_icon}")

    # Timing
    for phase in ["environment_setup", "agent_setup", "agent_execution", "verifier"]:
        info = trial.get(phase, {})
        started = info.get("started_at")
        finished = info.get("finished_at")
        if started and finished:
            try:
                s = datetime.fromisoformat(started.replace("Z", "+00:00"))
                e = datetime.fromisoformat(finished.replace("Z", "+00:00"))
                dur = e - s
                print(f"  {phase:24s} {str(dur).split('.')[0]}")
            except Exception:
                pass

    # Exception?
    exc = trial.get("exception_info")
    if exc:
        print(f"\n  \033[31mEXCEPTION: {exc}\033[0m")

    # ── Test results from ctrf.json ──
    if not os.path.exists(ctrf_file):
        print(f"\n  No ctrf.json found (verifier may not have run)")
        continue

    with open(ctrf_file) as f:
        ctrf = json.load(f)

    summary = ctrf.get("results", {}).get("summary", {})
    tests = ctrf.get("results", {}).get("tests", [])

    total = summary.get("tests", len(tests))
    passed = summary.get("passed", 0)
    failed = summary.get("failed", 0)
    skipped = summary.get("skipped", 0)

    if total == passed:
        color = "\033[32m"  # green
    elif passed > 0:
        color = "\033[33m"  # yellow
    else:
        color = "\033[31m"  # red

    print(f"\n  Tests: {color}{passed}/{total} passed\033[0m", end="")
    if failed:
        print(f", {failed} failed", end="")
    if skipped:
        print(f", {skipped} skipped", end="")
    print()
    print()

    # Show each test
    for t in tests:
        name = t["name"].replace("test_outputs.py::", "")
        status = t["status"]
        dur = t.get("duration", 0)

        if status == "passed":
            icon = "\033[32m✓\033[0m"
        elif status == "failed":
            icon = "\033[31m✗\033[0m"
        else:
            icon = "\033[33m?\033[0m"

        print(f"    {icon} {name:40s} ({dur:.2f}s)")

    # Show failure details
    failures = [t for t in tests if t["status"] == "failed"]
    if failures:
        print(f"\n  {'─' * 50}")
        print(f"  FAILURE DETAILS")
        print(f"  {'─' * 50}")
        for t in failures:
            name = t["name"].replace("test_outputs.py::", "")
            print(f"\n  \033[31m✗ {name}\033[0m")
            msg = t.get("message", "")
            if msg:
                print(f"    {msg}")
            trace = t.get("trace", "")
            if trace:
                # Show last assertion line
                lines = trace.strip().split("\n")
                for line in lines:
                    stripped = line.strip()
                    if stripped.startswith("E "):
                        print(f"    \033[31m{stripped}\033[0m")

print()
PYEOF
