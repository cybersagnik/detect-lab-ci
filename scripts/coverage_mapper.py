#!/usr/bin/env python3
"""
DetectLab-CI ATT&CK coverage layer generator.

Reads Sigma rules from sigma-rules/, extracts MITRE ATT&CK technique tags,
and emits navigator/coverage_layer.json in Navigator layer format 4.5.

The layer is structured so every sub-technique child is paired with a
parent scaffold entry (no color/score/comment) and both entries have
showSubtechniques=true. Without the parent scaffold, Navigator's tree
builder orphans the child rows and the exported SVG silently drops them.
"""
import json
import re
import sys
import time
from collections import defaultdict
from datetime import date
from pathlib import Path

import requests
import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent
SIGMA_ROOT = REPO_ROOT / "sigma-rules"
NAVIGATOR_DIR = REPO_ROOT / "navigator"
LAYER_FILE = NAVIGATOR_DIR / "coverage_layer.json"
CACHE_FILE = REPO_ROOT / ".attck_cache.json"

COVERED_COLOR = "#1d9e75"
TAG_RE = re.compile(r"^attack\.t(\d+(?:\.\d+)?)$")
TECH_ID_RE = re.compile(r"^T(\d+)(?:\.(\d+))?$")

MITRE_URL = (
    "https://raw.githubusercontent.com/mitre/cti/master/"
    "enterprise-attack/enterprise-attack.json"
)
CACHE_TTL_SECONDS = 7 * 24 * 60 * 60
REQUEST_TIMEOUT = 60

LAYER_FORMAT = "4.5"
NAVIGATOR_VERSION = "4.9"
ATTACK_VERSION = "19"


def natural_sort_key(tech_id):
    """
    Return a sort key that orders technique IDs as humans expect:

        T1003      -> (1003, -1)
        T1003.001  -> (1003, 1)
        T1003.010  -> (1003, 10)
        T1016      -> (1016, -1)

    Parents come immediately before their own sub-techniques, and
    parents without sub-techniques sit at the same sort position as
    a notional first child.
    """
    m = TECH_ID_RE.match(tech_id)
    if not m:
        return (10**9, 10**9)
    parent_num = int(m.group(1))
    sub_num = int(m.group(2)) if m.group(2) is not None else -1
    return (parent_num, sub_num)


def sort_technique_ids(ids):
    return sorted(ids, key=natural_sort_key)


def extract_technique_ids(tags):
    """
    Return the list of technique IDs found in a Sigma rule's tags list.
    Sub-technique IDs (e.g. T1547.001) are returned alongside the parent
    ID (T1547) so callers can decide how to handle the relationship.
    """
    if not tags or not isinstance(tags, list):
        return []
    out = []
    for tag in tags:
        if not isinstance(tag, str):
            continue
        m = TAG_RE.match(tag.strip().lower())
        if not m:
            continue
        raw = m.group(1)
        full_id = "T" + raw
        parent_id = "T" + raw.split(".", 1)[0]
        out.append((parent_id, full_id))
    return out


def collect_rules():
    """
    Walk sigma-rules/ and return:
        coverage: dict[technique_id] -> set(rule_filename)
        rule_count: int
    Sub-technique IDs are preserved as-is; the parent ID is NOT folded
    in here so the layer builder can decide whether the parent should
    carry coverage metadata or exist only as a scaffold.
    """
    coverage = defaultdict(set)
    rule_count = 0
    if not SIGMA_ROOT.exists():
        return coverage, rule_count
    for path in sorted(SIGMA_ROOT.rglob("*.yml")):
        try:
            with open(path, "r", encoding="utf-8") as fh:
                data = yaml.safe_load(fh)
        except (yaml.YAMLError, OSError) as exc:
            print(
                f"[coverage_mapper] Skipping {path.name}: {exc}",
                file=sys.stderr,
            )
            continue
        if not isinstance(data, dict):
            continue
        techs = extract_technique_ids(data.get("tags") or [])
        if not techs:
            continue
        rule_count += 1
        for _parent_id, full_id in techs:
            coverage[full_id].add(path.name)
    return coverage, rule_count


# ── MITRE STIX bundle loading & validation ────────────────────────────────────
# The script shares .attck_cache.json with gap_analysis.py so we don't
# re-download the ~36 MB bundle. If the cache is missing or stale we try
# the network; if that fails we proceed without validation and the
# maintainer can re-run when connectivity is restored.

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
            f"[coverage_mapper] WARNING: MITRE download failed ({exc}); "
            f"proceeding without ATT&CK validation",
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
            f"[coverage_mapper] WARNING: cache write failed ({exc})",
            file=sys.stderr,
        )
    return data


def parse_technique_index(stix):
    """
    Build {external_id: {is_subtechnique, parent_id, deprecated, name}}
    from the STIX bundle. Deprecated/revoked techniques are kept in the
    index but flagged so callers can reject them.
    """
    if not stix:
        return {}
    by_stix_id = {}
    for obj in stix.get("objects", []):
        if obj.get("type") != "attack-pattern":
            continue
        ext_id = None
        for ref in obj.get("external_references") or []:
            if ref.get("source_name") == "mitre-attack":
                ext_id = ref.get("external_id")
                break
        if not ext_id:
            continue
        by_stix_id[obj["id"]] = ext_id

    index = {}
    for obj in stix.get("objects", []):
        if obj.get("type") != "attack-pattern":
            continue
        ext_id = None
        for ref in obj.get("external_references") or []:
            if ref.get("source_name") == "mitre-attack":
                ext_id = ref.get("external_id")
                break
        if not ext_id:
            continue
        parent_ref = obj.get("x_mitre_parent_technique_ref")
        parent_id = by_stix_id.get(parent_ref) if parent_ref else None
        index[ext_id] = {
            "is_subtechnique": obj.get("x_mitre_is_subtechnique") is True,
            "parent_id": parent_id,
            "deprecated": (
                obj.get("x_mitre_deprecated") is True
                or obj.get("revoked") is True
            ),
            "name": obj.get("name", ""),
        }
    return index


def validate_techniques(coverage, technique_index):
    """
    Return [(technique_id, reason), ...] for every entry in coverage that
    is missing from the ATT&CK index or marked deprecated.
    """
    invalid = []
    for tid in coverage:
        info = technique_index.get(tid)
        if info is None:
            invalid.append((tid, "not found in configured ATT&CK version"))
            continue
        if info["deprecated"]:
            invalid.append((tid, "deprecated or revoked in ATT&CK"))
    return invalid


# ── Layer construction ───────────────────────────────────────────────────────

def derive_parent(full_id):
    """T1547.001 -> T1547.  T1547 -> T1547."""
    if "." not in full_id:
        return full_id
    return full_id.split(".", 1)[0]


def build_layer(coverage, technique_index=None):
    """
    Build the Navigator layer JSON dict.

    Algorithm:
      1. Split coverage into sub-techniques (IDs containing '.') and
         standalone techniques (parent IDs without a '.').
      2. Each sub-technique implies exactly one parent scaffold entry
         (no color/score/comment, enabled=true, showSubtechniques=true).
         A parent scaffold is emitted at most once per parent even
         when many children share the parent.
      3. A standalone ID that is also the parent of a covered
         sub-technique is treated as overlap: the parent is emitted
         ONLY as a scaffold, and the rules that tagged the standalone
         parent are folded into each of that parent's child comments
         so no coverage information is lost. The spec is "all original
         metadata remains attached only to the child entries".
      4. Validation: when a technique_index is supplied (from the
         MITRE STIX bundle), any sub-technique, parent, or standalone
         ID that is missing or marked deprecated is excluded from the
         layer and reported via the second return value.
      5. Output order: every emitted ID sorted with natural_sort_key
         so a parent always renders immediately before its own
         children (T1547 before T1547.001) and sibling groups stay
         interleaved by parent number.
    """
    subtechs = [tid for tid in coverage if "." in tid]
    standalone = [tid for tid in coverage if "." not in tid]

    subtech_parent_ids = {derive_parent(t) for t in subtechs}
    overlap = set(standalone) & subtech_parent_ids

    invalid_ids = set()
    if technique_index:
        candidates = set(subtechs) | set(standalone) | set(subtech_parent_ids)
        for tid in candidates:
            info = technique_index.get(tid)
            if info is None or info["deprecated"]:
                invalid_ids.add(tid)

    emit_ids = set()
    for tid in subtechs:
        if tid not in invalid_ids:
            emit_ids.add(tid)
    for tid in subtech_parent_ids:
        if tid not in invalid_ids:
            emit_ids.add(tid)
    for tid in standalone:
        if tid not in invalid_ids and tid not in overlap:
            emit_ids.add(tid)

    techniques = []
    for tid in sort_technique_ids(emit_ids):
        if tid in subtech_parent_ids:
            techniques.append({
                "techniqueID": tid,
                "enabled": True,
                "showSubtechniques": True,
            })
            continue
        rules = set(coverage[tid])
        parent_id = derive_parent(tid)
        if parent_id in overlap:
            rules.update(coverage[parent_id])
        techniques.append({
            "techniqueID": tid,
            "color": COVERED_COLOR,
            "comment": ", ".join(sorted(rules)),
            "enabled": True,
            "showSubtechniques": True,
        })

    layer = {
        "name": "DetectLab-CI Coverage",
        "versions": {
            "attack": ATTACK_VERSION,
            "navigator": NAVIGATOR_VERSION,
            "layer": LAYER_FORMAT,
        },
        "domain": "enterprise-attack",
        "description": (
            f"Auto-generated by coverage_mapper.py on {date.today().isoformat()}"
        ),
        "filters": {"platforms": ["Windows"]},
        "sorting": 0,
        "hideDisabled": False,
        "techniques": techniques,
        "legendItems": [{"label": "Covered", "color": COVERED_COLOR}],
        "metadata": [],
        "links": [],
    }
    return layer, invalid_ids


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    coverage, rule_count = collect_rules()
    if rule_count == 0:
        print(
            "[coverage_mapper] No Sigma rules with technique tags found",
            file=sys.stderr,
        )
        return 1

    stix = load_attack_data()
    technique_index = parse_technique_index(stix) if stix else None

    if technique_index:
        invalid = validate_techniques(coverage, technique_index)
        for tid, reason in sorted(invalid):
            print(
                f"[coverage_mapper] WARNING: invalid technique {tid} "
                f"({reason}); skipping",
                file=sys.stderr,
            )

    layer, invalid_ids = build_layer(coverage, technique_index)

    try:
        NAVIGATOR_DIR.mkdir(parents=True, exist_ok=True)
        with open(LAYER_FILE, "w", encoding="utf-8") as fh:
            json.dump(layer, fh, indent=2, ensure_ascii=False)
            fh.write("\n")
    except OSError as exc:
        print(
            f"[coverage_mapper] Failed to write {LAYER_FILE}: {exc}",
            file=sys.stderr,
        )
        return 1

    print(f"[coverage_mapper] Scanned {rule_count} rules")
    print(f"[coverage_mapper] ATT&CK version: {ATTACK_VERSION}")
    print(f"[coverage_mapper] Covered techniques: {len(layer['techniques'])}")
    if invalid_ids:
        print(
            f"[coverage_mapper] Skipped {len(invalid_ids)} invalid "
            f"technique ID(s) — see warnings above",
            file=sys.stderr,
        )
    print(
        f"[coverage_mapper] Layer written to: "
        f"{LAYER_FILE.relative_to(REPO_ROOT).as_posix()}"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
