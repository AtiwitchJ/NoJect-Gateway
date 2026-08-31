"""
Ratchet gate for the red-team harnesses.

A harness that only prints results cannot stop a regression: nobody notices
when a rule change quietly re-opens a bypass that was closed last month.
This turns the harnesses into a CI gate.

The gate is a RATCHET against a recorded baseline, not a fixed percentage:

  - More bypasses than the baseline  -> FAIL. Something regressed.
  - Fewer bypasses than the baseline -> FAIL, with instructions to lower it.
    Coverage improvements must be locked in, or the next regression is
    measured against a stale, too-permissive number.
  - Equal -> pass.

A percentage threshold would let a fixed bypass be silently traded for a new
one, since the total stays the same. The ratchet is on the count, and the
baseline file records which specific payloads are still expected to bypass
so the diff is reviewable.
"""

import json
import re
import sys
from pathlib import Path
from typing import List

BASELINE_PATH = Path(__file__).with_name("redteam_baseline.json")

# Some case names embed a measured duration ("ReDoS probe (10.5ms)"), which
# differs on every run. Comparing those raw would report the same case as a
# NEW bypass each time and make the gate permanently red.
_VARIABLE_SUFFIX = re.compile(r"\s*\(\s*[\d.]+\s*(ms|s|us|µs)\s*\)\s*$")


def _stable(name: str) -> str:
    return _VARIABLE_SUFFIX.sub("", name).strip()


def _load() -> dict:
    if not BASELINE_PATH.exists():
        return {}
    try:
        return json.loads(BASELINE_PATH.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        print(f"[redteam-gate] could not read baseline: {exc}", file=sys.stderr)
        return {}


def check(harness: str, bypassed_names: List[str], total: int) -> int:
    """Compare this run against the baseline. Returns a process exit code."""
    baseline = _load()
    entry = baseline.get(harness)
    bypassed_names = sorted({_stable(n) for n in bypassed_names})
    count = len(bypassed_names)

    if entry is None:
        print(
            f"\n[redteam-gate] no baseline for {harness!r}. "
            f"Recording is manual — add this to {BASELINE_PATH.name}:\n"
            f'  "{harness}": {{"max_bypasses": {count}, "total": {total}, '
            f'"known": {json.dumps(sorted(bypassed_names))}}}'
        )
        return 0

    allowed = entry.get("max_bypasses", 0)
    known = {_stable(n) for n in entry.get("known", [])}
    new = sorted(set(bypassed_names) - known)
    fixed = sorted(known - set(bypassed_names))

    print(f"\n[redteam-gate] {harness}: {count} bypassed of {total} (baseline {allowed})")

    if new:
        print("[redteam-gate] NEW bypasses not present in the baseline:")
        for name in new:
            print(f"    + {name}")

    if count > allowed:
        print(
            f"[redteam-gate] FAIL: {count} bypasses exceeds the baseline of {allowed}. "
            "A detection rule regressed, or new attacks were added without fixing them."
        )
        return 1

    if count < allowed:
        print("[redteam-gate] Bypasses now fixed:")
        for name in fixed:
            print(f"    - {name}")
        print(
            f"[redteam-gate] FAIL: coverage improved ({count} < {allowed}) but the "
            f"baseline still allows {allowed}. Lower max_bypasses to {count} and update "
            f'"known" in {BASELINE_PATH.name} so the gain is locked in.'
        )
        return 1

    if new:
        print(
            "[redteam-gate] FAIL: bypass count matches the baseline but the set "
            "changed — a fixed bypass was traded for a new one. Review the diff above."
        )
        return 1

    print("[redteam-gate] OK: no regression.")
    return 0
