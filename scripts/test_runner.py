#!/usr/bin/env python3
"""
DetectLab-CI Test Runner
Validates Sigma rules against real EVTX attack samples.
Evaluates both detection blocks and filter blocks.
Reports detection rate and fails CI if below threshold.
"""

import sys
import pathlib
import yaml
import re

try:
    import Evtx.Evtx as evtx
except ImportError:
    print("ERROR: python-evtx not installed. Run: pip install python-evtx")
    sys.exit(1)


# ── Configuration ─────────────────────────────────────────────────────────────

RULES_DIR       = pathlib.Path("sigma-rules")
MALICIOUS_DIR   = pathlib.Path("tests/log_samples/malicious")
CLEAN_DIR       = pathlib.Path("tests/log_samples/clean")
MIN_DETECT_RATE = 0.80

# Map rule file (relative to sigma-rules/) → technique folder in malicious/
RULE_TO_TECHNIQUE = {
    "windows/execution/powershell_encoded_command.yml":      "T1059.001",
    "windows/persistence/scheduled_task_creation.yml":       "T1053.005",
    "windows/credential_access/lsass_process_access.yml":    "T1003.001",
    "windows/persistence/registry_run_key_persistence.yml":  "T1547.001",
    "windows/privilege_escalation/uac_bypass_fodhelper.yml": "T1548.002",
}


# ── YAML loader ───────────────────────────────────────────────────────────────

def load_rule(path: pathlib.Path) -> dict:
    try:
        return yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except Exception as e:
        print(f"    ERROR loading rule {path}: {e}")
        return {}


# ── Sigma detection + filter extractor ───────────────────────────────────────

def extract_blocks(rule: dict) -> tuple[list, list]:
    """
    Parse the Sigma detection block into two lists:
      detection_pairs : (field, value) from selection/non-filter blocks
      filter_pairs    : (field, value) from filter_* blocks

    Handles:
      - dict blocks  : {Field|modifier: value_or_list}
      - list blocks  : [{Field: value}, ...]
      - scalar values
      - nested all-of lists (contains|all style)
    """
    detection = rule.get("detection", {})

    detection_pairs: list[tuple[str, str]] = []
    filter_pairs:    list[tuple[str, str]] = []

    def extract_pairs_from_block(block) -> list[tuple[str, str]]:
        pairs = []
        if isinstance(block, dict):
            for field, pattern in block.items():
                if field == "condition":
                    continue
                field_clean = field.split("|")[0]
                if isinstance(pattern, list):
                    for p in pattern:
                        if p is not None:
                            pairs.append((field_clean, str(p)))
                elif pattern is not None:
                    pairs.append((field_clean, str(pattern)))
        elif isinstance(block, list):
            for item in block:
                if isinstance(item, dict):
                    pairs.extend(extract_pairs_from_block(item))
                elif item is not None:
                    pairs.append(("_raw", str(item)))
        return pairs

    for key, block in detection.items():
        if key == "condition":
            continue
        pairs = extract_pairs_from_block(block)
        if key.startswith("filter"):
            filter_pairs.extend(pairs)
        else:
            detection_pairs.extend(pairs)

    return detection_pairs, filter_pairs


# ── EVTX parser ───────────────────────────────────────────────────────────────

def parse_evtx(path: pathlib.Path) -> list[str]:
    """Return list of raw XML strings from an EVTX file."""
    events = []
    try:
        with evtx.Evtx(str(path)) as log:
            for record in log.records():
                try:
                    events.append(record.xml())
                except Exception:
                    continue
    except Exception as e:
        print(f"    WARNING: could not parse {path.name} — {e}")
    return events


# ── Match logic ───────────────────────────────────────────────────────────────

def any_pair_matches(event_xml: str, pairs: list[tuple[str, str]]) -> bool:
    """
    Return True if ANY (field, value) pair matches the event XML.
    Case-insensitive substring match — covers contains/endswith/startswith.
    """
    event_lower = event_xml.lower()
    for _, value in pairs:
        if value.lower() in event_lower:
            return True
    return False


def all_pairs_match(event_xml: str, pairs: list[tuple[str, str]]) -> bool:
    """
    Return True if ALL (field, value) pairs match the event XML.
    Used for contains|all style detections.
    """
    event_lower = event_xml.lower()
    for _, value in pairs:
        if value.lower() not in event_lower:
            return False
    return True


def event_is_detected(event_xml: str,
                      detection_pairs: list[tuple[str, str]],
                      filter_pairs:    list[tuple[str, str]]) -> bool:
    """
    Apply detection logic:
      1. Event must match at least one detection pair
      2. Event must NOT match any filter pair
    """
    if not any_pair_matches(event_xml, detection_pairs):
        return False
    if filter_pairs and any_pair_matches(event_xml, filter_pairs):
        return False
    return True


# ── Core test function ────────────────────────────────────────────────────────

def test_rule(rule_path:     pathlib.Path,
              sample_folder: pathlib.Path,
              expect_match:  bool = True) -> tuple[bool, str, int]:
    """
    Test a Sigma rule against all EVTX files in sample_folder.

    Returns:
      (passed: bool, message: str, match_count: int)
    """
    rule = load_rule(rule_path)
    if not rule:
        return False, "Could not load rule file", 0

    detection_pairs, filter_pairs = extract_blocks(rule)

    if not detection_pairs:
        return False, "No detection strings found in rule", 0

    evtx_files = list(sample_folder.rglob("*.evtx"))
    if not evtx_files:
        return False, f"No EVTX files in {sample_folder}", 0

    match_count = 0
    for evtx_file in evtx_files:
        for event_xml in parse_evtx(evtx_file):
            if event_is_detected(event_xml, detection_pairs, filter_pairs):
                match_count += 1

    matched = match_count > 0
    file_count = len(evtx_files)

    if expect_match:
        if matched:
            return True,  f"PASS — {match_count} match(es) across {file_count} file(s)", match_count
        else:
            return False, f"FAIL — 0 matches across {file_count} file(s)", 0
    else:
        if not matched:
            return True,  f"PASS — 0 false positives across {file_count} file(s)", 0
        else:
            return False, f"FAIL — {match_count} false positive(s) across {file_count} file(s)", match_count


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    print("=" * 64)
    print("  DetectLab-CI — EVTX Test Runner")
    print("=" * 64)

    passed  = 0
    failed  = 0
    skipped = 0
    results = []

    # ── 1. Malicious sample tests ─────────────────────────────────────────
    print("\n[1/2] Detection test — malicious EVTX samples\n")

    for rule_rel, technique in RULE_TO_TECHNIQUE.items():
        rule_path  = RULES_DIR / rule_rel
        sample_dir = MALICIOUS_DIR / technique
        rule_name  = pathlib.Path(rule_rel).stem

        print(f"  ▸ {rule_name}")
        print(f"    technique : {technique}")

        if not rule_path.exists():
            msg = f"Rule file not found: {rule_path}"
            print(f"    ⚠  SKIP — {msg}\n")
            skipped += 1
            results.append((rule_name, technique, "SKIP", msg, 0))
            continue

        if not sample_dir.exists() or not any(sample_dir.rglob("*.evtx")):
            msg = f"No EVTX samples in {sample_dir}"
            print(f"    ⚠  SKIP — {msg}\n")
            skipped += 1
            results.append((rule_name, technique, "SKIP", msg, 0))
            continue

        # Show what was extracted for transparency
        rule = load_rule(rule_path)
        det, fil = extract_blocks(rule)
        print(f"    detection strings : {len(det)}")
        print(f"    filter strings    : {len(fil)}")

        ok, msg, count = test_rule(rule_path, sample_dir, expect_match=True)

        status = "PASS" if ok else "FAIL"
        icon   = "✓" if ok else "✗"
        print(f"    {icon}  {status} — {msg}\n")

        if ok:
            passed += 1
        else:
            failed += 1

        results.append((rule_name, technique, status, msg, count))

    # ── 2. Clean baseline — false positive check ──────────────────────────
    print("[2/2] False positive check — clean baseline\n")

    fp_total    = 0
    fp_results  = []
    clean_files = list(CLEAN_DIR.rglob("*.evtx")) if CLEAN_DIR.exists() else []

    if not clean_files:
        print(f"  ⚠  No clean baseline EVTX found in {CLEAN_DIR}")
        print("     Add clean EVTX files to run FP check\n")
    else:
        for rule_rel, technique in RULE_TO_TECHNIQUE.items():
            rule_path = RULES_DIR / rule_rel
            rule_name = pathlib.Path(rule_rel).stem

            if not rule_path.exists():
                continue

            ok, msg, count = test_rule(rule_path, CLEAN_DIR, expect_match=False)

            icon  = "✓" if ok else "⚠"
            label = "0 FP" if ok else f"{count} FP"
            print(f"  {icon}  {rule_name:<45} {label}")

            fp_total += count
            fp_results.append((rule_name, ok, count))

    # ── Summary ───────────────────────────────────────────────────────────
    total_tested = passed + failed
    detect_rate  = passed / total_tested if total_tested > 0 else 0.0

    print("\n" + "=" * 64)
    print("  SUMMARY")
    print("=" * 64)
    print(f"  Rules tested   : {total_tested}")
    print(f"  Passed         : {passed}")
    print(f"  Failed         : {failed}")
    print(f"  Skipped        : {skipped}")
    print(f"  Detection rate : {detect_rate:.0%}")
    print(f"  Threshold      : {MIN_DETECT_RATE:.0%}")
    if clean_files:
        print(f"  False positives: {fp_total}")

    # ── Results table ─────────────────────────────────────────────────────
    print()
    col = 48
    print(f"  {'Rule':<{col}} {'Technique':<14} {'Status'}")
    print(f"  {'-'*col} {'-'*14} {'-'*6}")
    for rule_name, technique, status, msg, count in results:
        icon = "✓" if status == "PASS" else ("⚠" if status == "SKIP" else "✗")
        print(f"  {icon} {rule_name:<{col-1}} {technique:<14} {status}")

    print()

    # ── CI gate ───────────────────────────────────────────────────────────
    if total_tested == 0:
        print("WARNING: No rules were tested — check EVTX sample paths")
        sys.exit(0)

    if detect_rate < MIN_DETECT_RATE:
        print(f"FAIL: detection rate {detect_rate:.0%} is below "
              f"threshold {MIN_DETECT_RATE:.0%}")
        print("Fix failing rules before merging.")
        sys.exit(1)

    if failed > 0:
        print(f"WARNING: {failed} rule(s) failed but overall rate "
              f"{detect_rate:.0%} is above threshold.")
    else:
        print(f"PASS: all {passed} rules detected successfully. "
              f"Detection rate: {detect_rate:.0%}")


if __name__ == "__main__":
    main()