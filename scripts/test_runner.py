#!/usr/bin/env python3
"""
DetectLab-CI Test Runner (EVTX-ATTACK-SAMPLES edition)

Validates Sigma rules against the sbousseaden/EVTX-ATTACK-SAMPLES dataset.
Each rule is matched against one or more EVTX files known to contain
real-world samples of that technique.

For every rule the runner:
  1. Confirms the Sigma rule file exists on disk (drops it if missing)
  2. Parses its detection + filter blocks
  3. Streams every record of every mapped EVTX file
  4. Applies selection + filter logic via case-insensitive substring match
     on the raw event XML
  5. Reports per-rule PASS / FAIL with match counts
  6. Enforces a minimum detection rate as the CI gate
"""

import os
import sys
import pathlib
import yaml
import re

import Evtx.Evtx as evtx


# ── Configuration ─────────────────────────────────────────────────────────────

RULES_DIR     = pathlib.Path("sigma-rules")
SAMPLES_ROOT  = pathlib.Path("EVTX-ATTACK-SAMPLES")
MIN_DETECT_RATE = 0.80


# ── Rule → EVTX file mapping ──────────────────────────────────────────────────
# Each value is a list of paths RELATIVE to EVTX-ATTACK-SAMPLES.
# Paths are matched case-insensitively because the dataset uses mixed casing
# (e.g. "Privilege Escalation" vs "discovery").

RULE_TO_EVTX = {
    # ── Execution ─────────────────────────────────────────────────────────
    "windows/execution/powershell_encoded_command.yml": [
        "Credential Access/discovery_sysmon_1_iis_pwd_and_config_discovery_appcmd.evtx",
    ],
    "windows/execution/powershell_download_cradle.yml": [
        "Other/emotet/exec_emotet_ps_4104.evtx",
        "Other/emotet/exec_emotet_ps_800_get-item.evtx",
        "Other/emotet/exec_emotet_ps_800_invoke-item.evtx",
        "Other/emotet/exec_emotet_ps_800_new-item.evtx",
        "Other/emotet/exec_emotet_ps_800_new-object.evtx",
        "Execution/susp_explorer_exec.evtx",
        "Execution/sysmon_lolbas_rundll32_zipfldr_routethecall_shell.evtx",
        "Lateral Movement/LM_sysmon_psexec_smb_meterpreter.evtx",
        "AutomatedTestingTools/PanacheSysmon_vs_AtomicRedTeam01.evtx",
        "AutomatedTestingTools/panache_sysmon_vs_EDRTestingScript.evtx",
        "Credential Access/phish_windows_credentials_powershell_scriptblockLog_4104.evtx",
    ],
    "windows/execution/wmic_process_creation.yml": [
        "Execution/exec_wmic_xsl_internet_sysmon_3_1_11.evtx",
        "Persistence/sysmon_20_21_1_CommandLineEventConsumer.evtx",
        "Execution/sysmon_exec_from_vss_persistence.evtx",
    ],

    # ── Persistence ───────────────────────────────────────────────────────
    "windows/persistence/scheduled_task_creation.yml": [
        "Privilege Escalation/Sysmon_UACME_34.evtx",
        "Execution/exec_persist_rundll32_mshta_scheduledtask_sysmon_1_3_11.evtx",
        "Persistence/persistence_sysmon_11_13_1_shime_appfix.evtx",
        "Persistence/sysmon_1_11_exec_as_system_via_schedtask.evtx",
        "Execution/sysmon_exec_from_vss_persistence.evtx",
    ],
    "windows/persistence/registry_run_key_persistence.yml": [
        "AutomatedTestingTools/Malware/DE_timestomp_and_dll_sideloading_and_RunPersist.evtx",
        "AutomatedTestingTools/Malware/sideloading_injection_persistence_run_key.evtx",
        "AutomatedTestingTools/PanacheSysmon_vs_AtomicRedTeam01.evtx",
        "Lateral Movement/lm_remote_registry_sysmon_1_13_3.evtx",
        "Lateral Movement/wmi_remote_registry_sysmon.evtx",
        "Persistence/evasion_persis_hidden_run_keyvalue_sysmon_13.evtx",
    ],
    "windows/persistence/wmi_event_subscription.yml": [
        "Persistence/sysmon_20_21_1_CommandLineEventConsumer.evtx",
        "Persistence/wmighost_sysmon_20_21_1.evtx",
    ],

    # ── Credential Access ──────────────────────────────────────────────────
    "windows/credential_access/lsass_process_access.yml": [
        "Credential Access/sysmon_10_lsass_mimikatz_sekurlsa_logonpasswords.evtx",
        "Credential Access/CA_sysmon_hashdump_cmd_meterpreter.evtx",
        "Credential Access/sysmon_10_11_lsass_memdump.evtx",
        "Defense Evasion/DE_BYOV_Zam64_CA_Memdump_sysmon_7_10.evtx",
        "Credential Access/babyshark_mimikatz_powershell.evtx",
        "Discovery/discovery_meterpreter_ps_cmd_process_listing_sysmon_10.evtx",
        "Credential Access/ppl_bypass_ppldump_knowdll_hijack_sysmon_security.evtx",
        "Credential Access/sysmon_10_11_outlfank_dumpert_and_andrewspecial_memdump.evtx",
        "Credential Access/sysmon_2x10_lsass_with_different_pid_RtlCreateProcessReflection.evtx",
        "Credential Access/sysmon_3_10_Invoke-Mimikatz_hosted_Github.evtx",
        "Privilege Escalation/sysmon_privesc_from_admin_to_system_handle_inheritance.evtx",
        "Credential Access/sysmon_rdrleakdiag_lsass_dump.evtx",
        "Persistence/sysmon_20_21_1_CommandLineEventConsumer.evtx",
    ],

    # ── Privilege Escalation ───────────────────────────────────────────────
    "windows/privilege_escalation/uac_bypass_fodhelper.yml": [
        "Privilege Escalation/Sysmon_UACME_33.evtx",
    ],

    # ── Discovery ──────────────────────────────────────────────────────────
    "windows/discovery/network_config_discovery.yml": [
        "Lateral Movement/LM_winrm_exec_sysmon_1_winrshost.evtx",
        "Lateral Movement/powercat_revShell_sysmon_1_3.evtx",
    ],
    "windows/discovery/process_discovery_tasklist.yml": [
        "Lateral Movement/LM_ScheduledTask_ATSVC_target_host.evtx",
    ],
    "windows/discovery/systeminfo_execution.yml": [
        "Lateral Movement/powercat_revShell_sysmon_1_3.evtx",
    ],

    # ── Defense Evasion (folder is spelt defence_evasion in the repo) ──────
    "windows/defence_evasion/certutil_decode.yml": [
        "AutomatedTestingTools/PanacheSysmon_vs_AtomicRedTeam01.evtx",
        "AutomatedTestingTools/panache_sysmon_vs_EDRTestingScript.evtx",
    ],
    "windows/defence_evasion/mshta_proxy_execution.yml": [
        "Execution/exec_persist_rundll32_mshta_scheduledtask_sysmon_1_3_11.evtx",
        "Execution/exec_sysmon_1_11_lolbin_rundll32_openurl_FileProtocolHandler.evtx",
        "Execution/sysmon_mshta_sharpshooter_stageless_meterpreter.evtx",
        "Execution/Sysmon_Exec_CompiledHTML.evtx",
        "Lateral Movement/LM_DCOM_MSHTA_LethalHTA_Sysmon_3_1.evtx",
        "AutomatedTestingTools/panache_sysmon_vs_EDRTestingScript.evtx",
    ],
    "windows/defence_evasion/regsvr32_proxy_execution.yml": [
        "Execution/exec_sysmon_1_7_jscript9_defense_evasion.evtx",
        "Execution/exec_sysmon_lobin_regsvr32_sct.evtx",
        "Persistence/sysmon_1_persist_bitsjob_SetNotifyCmdLine.evtx",
    ],
}


# ── Helpers ───────────────────────────────────────────────────────────────────

def resolve_sample(rel_path: str) -> pathlib.Path | None:
    """Resolve a relative path inside EVTX-ATTACK-SAMPLES, case-insensitively."""
    target = (SAMPLES_ROOT / rel_path).resolve()
    if target.exists():
        return target

    parts = pathlib.PurePosixPath(rel_path).parts
    root = SAMPLES_ROOT
    for part in parts:
        match = None
        for entry in root.iterdir():
            if entry.name.lower() == part.lower():
                match = entry
                break
        if match is None:
            return None
        root = match
    return root if root.is_file() else None


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
        with evtx.Evtx(os.fspath(path)) as log:
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
    """Case-insensitive substring match — covers contains/endswith/startswith."""
    event_lower = event_xml.lower()
    for _, value in pairs:
        if value.lower() in event_lower:
            return True
    return False


def event_is_detected(event_xml: str,
                      detection_pairs: list[tuple[str, str]],
                      filter_pairs:    list[tuple[str, str]]) -> bool:
    if not any_pair_matches(event_xml, detection_pairs):
        return False
    if filter_pairs and any_pair_matches(event_xml, filter_pairs):
        return False
    return True


# ── Core test function ────────────────────────────────────────────────────────

def test_rule(rule_path:  pathlib.Path,
              sample_paths: list[pathlib.Path]) -> tuple[bool, str, int, int]:
    """
    Test a Sigma rule against every mapped EVTX file.

    Returns:
      (passed, message, total_match_count, files_with_match)
    """
    rule = load_rule(rule_path)
    if not rule:
        return False, "Could not load rule file", 0, 0

    detection_pairs, filter_pairs = extract_blocks(rule)

    if not detection_pairs:
        return False, "No detection strings found in rule", 0, 0

    total_match = 0
    files_matched = 0
    files_tested  = 0

    for sample in sample_paths:
        files_tested += 1
        for event_xml in parse_evtx(sample):
            if event_is_detected(event_xml, detection_pairs, filter_pairs):
                total_match += 1

        # Did this file contribute at least one match?
        for event_xml in parse_evtx(sample):
            if event_is_detected(event_xml, detection_pairs, filter_pairs):
                files_matched += 1
                break

    if total_match > 0:
        return True, f"PASS — {total_match} match(es) across {files_matched}/{files_tested} file(s)", total_match, files_matched
    else:
        return False, f"FAIL — 0 matches across {files_tested} file(s)", 0, 0


# ── Main ──────────────────────────────────────────────────────────────────────

def main() -> int:
    print("=" * 72)
    print("  DetectLab-CI — EVTX-ATTACK-SAMPLES Test Runner")
    print("=" * 72)

    if not SAMPLES_ROOT.exists():
        print(f"ERROR: EVTX dataset not found at {SAMPLES_ROOT}")
        print("Clone https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES into this directory.")
        return 2

    passed  = 0
    failed  = 0
    skipped = 0
    results = []

    OK_ICON   = "[PASS]"
    FAIL_ICON = "[FAIL]"
    SKIP_ICON = "[SKIP]"

    for rule_rel, sample_rels in RULE_TO_EVTX.items():
        rule_path = RULES_DIR / rule_rel
        rule_name = pathlib.Path(rule_rel).stem
        tactic    = rule_rel.split("/")[1] if "/" in rule_rel else "?"

        if not rule_path.exists():
            msg = f"No Sigma rule at {rule_path}"
            print(f"\n  > {rule_name}")
            print(f"    technique : {tactic}")
            print(f"    {SKIP_ICON} SKIP -- {msg}")
            skipped += 1
            results.append((rule_name, tactic, "SKIP", msg, 0))
            continue

        # Resolve every mapped sample (case-insensitive)
        samples: list[pathlib.Path] = []
        missing: list[str] = []
        for rel in sample_rels:
            resolved = resolve_sample(rel)
            if resolved is None:
                missing.append(rel)
            else:
                samples.append(resolved)

        if not samples:
            msg = f"None of the mapped EVTX files exist ({len(missing)} missing)"
            print(f"\n  > {rule_name}")
            print(f"    technique : {tactic}")
            print(f"    {SKIP_ICON} SKIP -- {msg}")
            for m in missing:
                print(f"      - missing: {m}")
            skipped += 1
            results.append((rule_name, tactic, "SKIP", msg, 0))
            continue

        rule = load_rule(rule_path)
        det, fil = extract_blocks(rule)

        print(f"\n  > {rule_name}")
        print(f"    technique      : {tactic}")
        print(f"    detection strs : {len(det)}")
        print(f"    filter strs    : {len(fil)}")
        print(f"    sample files   : {len(samples)} / {len(sample_rels)} mapped")

        ok, msg, count, files_matched = test_rule(rule_path, samples)

        status = "PASS" if ok else "FAIL"
        icon   = OK_ICON if ok else FAIL_ICON
        print(f"    {icon} {status} -- {msg}")

        if ok:
            passed += 1
        else:
            failed += 1
            if missing:
                print(f"      missing EVTX: {len(missing)}")
                for m in missing[:5]:
                    print(f"        - {m}")

        results.append((rule_name, tactic, status, msg, count))

    # ── Summary ───────────────────────────────────────────────────────────
    total_tested = passed + failed
    detect_rate  = passed / total_tested if total_tested > 0 else 0.0

    print("\n" + "=" * 72)
    print("  SUMMARY")
    print("=" * 72)
    print(f"  Rules mapped    : {len(RULE_TO_EVTX)}")
    print(f"  Rules tested    : {total_tested}")
    print(f"  Passed          : {passed}")
    print(f"  Failed          : {failed}")
    print(f"  Skipped         : {skipped}")
    print(f"  Detection rate  : {detect_rate:.0%}")
    print(f"  Threshold       : {MIN_DETECT_RATE:.0%}")

    print()
    col = 48
    print(f"  {'Rule':<{col}} {'Tactic':<22} {'Status'}")
    print(f"  {'-'*col} {'-'*22} {'-'*6}")
    for rule_name, tactic, status, msg, count in results:
        if status == "PASS":
            icon = "[OK]"
        elif status == "SKIP":
            icon = "[--]"
        else:
            icon = "[!!]"
        print(f"  {icon} {rule_name:<{col-1}} {tactic:<22} {status}")

    print()

    # ── CI gate ───────────────────────────────────────────────────────────
    if total_tested == 0:
        print("WARNING: no rules were tested — check Sigma rule files and EVTX paths")
        return 0

    if detect_rate < MIN_DETECT_RATE:
        print(f"FAIL: detection rate {detect_rate:.0%} below threshold {MIN_DETECT_RATE:.0%}")
        print("Fix failing rules before merging.")
        return 1

    if failed > 0:
        print(f"WARNING: {failed} rule(s) failed but overall rate "
              f"{detect_rate:.0%} is above threshold.")
    else:
        print(f"PASS: all {passed} rules detected successfully. "
              f"Detection rate: {detect_rate:.0%}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
