#!/usr/bin/env python3
import json
import re
import sys
import time
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

import requests
import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent
SIGMA_ROOT = REPO_ROOT / "sigma-rules"
DOCS_DIR = REPO_ROOT / "docs"
REPORT_FILE = DOCS_DIR / "gap_report.md"
CACHE_FILE = REPO_ROOT / ".attck_cache.json"

MITRE_URL = (
    "https://raw.githubusercontent.com/mitre/cti/master/"
    "enterprise-attack/enterprise-attack.json"
)
CACHE_TTL_SECONDS = 7 * 24 * 60 * 60
REQUEST_TIMEOUT = 60

TAG_RE = re.compile(r"^attack\.t(\d+(?:\.\d+)?)$")


def format_tactic(phase):
    if not phase:
        return ""
    parts = []
    for word in phase.replace("-", " ").split():
        parts.append(word if word == "and" else word.capitalize())
    return " ".join(parts)


def load_attack_data():
    if CACHE_FILE.exists():
        age = time.time() - CACHE_FILE.stat().st_mtime
        if age < CACHE_TTL_SECONDS:
            try:
                with open(CACHE_FILE, "r", encoding="utf-8") as fh:
                    return json.load(fh)
            except (OSError, json.JSONDecodeError):
                pass
    try:
        resp = requests.get(MITRE_URL, timeout=REQUEST_TIMEOUT)
        resp.raise_for_status()
    except requests.RequestException as exc:
        print(
            f"[gap_analysis] WARNING: MITRE download failed ({exc})",
            file=sys.stderr,
        )
        if CACHE_FILE.exists():
            try:
                with open(CACHE_FILE, "r", encoding="utf-8") as fh:
                    return json.load(fh)
            except (OSError, json.JSONDecodeError):
                return None
        return None

    data = resp.json()
    try:
        with open(CACHE_FILE, "w", encoding="utf-8") as fh:
            json.dump(data, fh)
    except OSError as exc:
        print(
            f"[gap_analysis] WARNING: cache write failed ({exc})",
            file=sys.stderr,
        )
    return data


def parse_techniques(stix):
    techniques = {}
    for obj in stix.get("objects", []):
        if obj.get("type") != "attack-pattern":
            continue
        if obj.get("x_mitre_deprecated") is True:
            continue
        if obj.get("revoked") is True:
            continue
        if obj.get("x_mitre_is_subtechnique") is True:
            continue
        platforms = obj.get("x_mitre_platforms") or []
        if "Windows" not in platforms:
            continue
        ext_id = None
        for ref in obj.get("external_references") or []:
            if ref.get("source_name") == "mitre-attack":
                ext_id = ref.get("external_id")
                break
        if not ext_id:
            continue
        tactic = ""
        for phase in obj.get("kill_chain_phases") or []:
            if phase.get("kill_chain_name") == "mitre-attack":
                tactic = format_tactic(phase.get("phase_name", ""))
                break
        techniques[ext_id] = {
            "name": obj.get("name", ""),
            "tactic": tactic,
        }
    return techniques


def collect_sigma_coverage():
    coverage = defaultdict(set)
    if not SIGMA_ROOT.exists():
        return coverage
    for path in sorted(SIGMA_ROOT.rglob("*.yml")):
        try:
            with open(path, "r", encoding="utf-8") as fh:
                data = yaml.safe_load(fh)
        except (yaml.YAMLError, OSError):
            continue
        if not isinstance(data, dict):
            continue
        for tag in data.get("tags") or []:
            if not isinstance(tag, str):
                continue
            m = TAG_RE.match(tag.strip().lower())
            if not m:
                continue
            tid = "T" + m.group(1)
            coverage[tid].add(path.name)
            if "." in tid:
                parent = tid.split(".", 1)[0]
                coverage[parent].add(path.name)
    return coverage


def build_report(techniques, coverage, generated_at):
    total = len(techniques)
    covered_ids = sorted(t for t in techniques if t in coverage)
    gap_ids = sorted(t for t in techniques if t not in coverage)
    covered_count = len(covered_ids)
    gap_count = len(gap_ids)
    pct = (covered_count / total * 100) if total else 0.0

    lines = [
        "# ATT&CK Coverage Gap Report",
        f"Generated: {generated_at}",
        "",
        "## Summary",
        "| Metric | Value |",
        "|--------|-------|",
        f"| Total Windows techniques | {total} |",
        f"| Covered | {covered_count} |",
        f"| Gaps | {gap_count} |",
        f"| Coverage | {pct:.2f}% |",
        "",
        "## Covered Techniques",
        "| Technique ID | Name | Rule |",
        "|---|---|---|",
    ]
    for tid in covered_ids:
        name = techniques[tid]["name"].replace("|", "\\|")
        rules = ", ".join(sorted(coverage[tid])).replace("|", "\\|")
        lines.append(f"| {tid} | {name} | {rules} |")
    lines.extend(
        [
            "",
            "## Gap Techniques (not covered)",
            "| Technique ID | Name | Tactic |",
            "|---|---|---|",
        ]
    )
    for tid in gap_ids:
        name = techniques[tid]["name"].replace("|", "\\|")
        tactic = techniques[tid]["tactic"]
        lines.append(f"| {tid} | {name} | {tactic} |")
    lines.append("")
    return lines, covered_count, total, pct, gap_count


def emit_step_summary(lines, covered_count, total, pct):
    start = lines.index("## Gap Techniques (not covered)")
    print("## ATT&CK Coverage Gap Report")
    print("")
    print(f"**Coverage: {pct:.2f}% ({covered_count}/{total} techniques)**")
    print("")
    for line in lines[start:]:
        print(line)


def write_unavailable_report():
    DOCS_DIR.mkdir(parents=True, exist_ok=True)
    REPORT_FILE.write_text(
        "# ATT&CK Coverage Gap Report\n\n"
        "_ATT&CK data unavailable \u2014 download failed and no cache present._\n",
        encoding="utf-8",
    )


def main():
    stix = load_attack_data()
    if stix is None:
        print(
            "[gap_analysis] WARNING: No ATT&CK data available; "
            "skipping gap analysis",
            file=sys.stderr,
        )
        write_unavailable_report()
        return 0

    techniques = parse_techniques(stix)
    coverage = collect_sigma_coverage()
    generated_at = datetime.now(timezone.utc).isoformat(timespec="seconds")
    lines, covered_count, total, pct, gap_count = build_report(
        techniques, coverage, generated_at
    )

    try:
        DOCS_DIR.mkdir(parents=True, exist_ok=True)
        REPORT_FILE.write_text("\n".join(lines), encoding="utf-8")
    except OSError as exc:
        print(
            f"[gap_analysis] WARNING: failed to write report ({exc})",
            file=sys.stderr,
        )
        return 0

    emit_step_summary(lines, covered_count, total, pct)
    print(
        f"[gap_analysis] ATT&CK techniques (Windows, non-deprecated): {total}"
    )
    print(f"[gap_analysis] Covered by Sigma rules: {covered_count}")
    print(f"[gap_analysis] Gaps: {gap_count}")
    print(f"[gap_analysis] Coverage: {pct:.2f}%")
    print(
        f"[gap_analysis] Report written to: "
        f"{REPORT_FILE.relative_to(REPO_ROOT).as_posix()}"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
