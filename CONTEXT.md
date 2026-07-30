# CONTEXT.md — DetectLab-CI

Detection-as-code pipeline that converts Sigma rules into SIEM queries
(KQL for Microsoft Sentinel, SPL for Splunk), validates them against a
real-world EVTX dataset in CI, and tracks ATT&CK coverage.

Repo: <https://github.com/cybersagnik/detect-lab-ci>

---

## 1. Repository layout

```
detect-lab-ci/
├── README.md
├── CONTEXT.md                  ← this file
├── .gitattributes              ← LF line endings for yml/md/py
├── .gitignore                  ← excludes /Sigma, .attck_cache.json, converted/
├── .gitmodules                 ← EVTX-ATTACK-SAMPLES (sbousseaden) submodule
├── sigma-rules/                ← hand-authored Sigma rules (source of truth)
│   └── windows/                ← all rules are Windows-only
│       ├── credential_access/  (1 rule)
│       ├── defence_evasion/    (3 rules)   ← British spelling intentional
│       ├── discovery/          (3 rules)
│       ├── execution/          (3 rules)
│       ├── persistence/        (3 rules)
│       └── privilege_escalation/ (1 rule)
│                                 Total: 14 rules, 13 unique MITRE sub-techniques
├── converted/                  ← auto-generated, gitignored
│   ├── kql/windows/<tactic>/<rule>.txt
│   └── spl/windows/<tactic>/<rule>.txt
├── navigator/
│   └── coverage_layer.json     ← ATT&CK Navigator layer (auto-generated)
├── docs/
│   ├── atomic-results.md       ← ART validation log (14/14 fired)
│   ├── gap_report.md           ← ATT&CK coverage gap report (auto-generated)
│   ├── images/                 ← Wazuh alert screenshots
│   └── rules_rationale/        ← one .md per validated rule
├── scripts/
│   ├── test_runner.py          ← CI test runner against EVTX-ATTACK-SAMPLES
│   ├── coverage_mapper.py      ← builds ATT&CK Navigator layer
│   ├── gap_analysis.py         ← builds docs/gap_report.md
│   └── requirements.txt
├── .github/workflows/
│   └── detect-ci.yml           ← single CI pipeline
└── EVTX-ATTACK-SAMPLES/        ← submodule (sbousseaden)
```

---

## 2. High-level pipeline (`.github/workflows/detect-ci.yml`)

Triggered on push & PR to `master`, runs `ubuntu-latest`.

1. Checkout (with submodules: recursive)
2. Setup Python 3.11
3. `pip install sigma-cli pySigma-backend-splunk pySigma-backend-microsoft365defender pySigma-pipeline-sysmon`
4. `sigma version`, `sigma list targets`, `sigma list pipelines` (diagnostics)
5. **Lint**: `sigma check sigma-rules/windows/**/*.yml`
6. **EVTX test runner**: `python scripts/test_runner.py` — gate at `MIN_DETECT_RATE = 0.80`
7. **Convert → KQL** (`sigma convert -t kusto -p sysmon`) → `converted/kql/`
8. **Convert → SPL** (`sigma convert -t splunk -p sysmon`) → `converted/spl/`
9. On push to `master`: auto-commit regenerated `converted/` back to repo
10. `coverage_mapper.py` → `navigator/coverage_layer.json`
11. `gap_analysis.py` → `docs/gap_report.md` + GitHub Step Summary
12. Upload artifacts (`converted/`, `coverage_layer.json`, `gap_report.md`)

Permissions: `contents: write` (needed for the auto-commit step).

---

## 3. Sigma rules — current inventory (14 rules / 13 sub-techniques)

| Tactic | Rule | Technique | Primary EID |
|---|---|---|---|
| execution | `powershell_encoded_command.yml` | T1059.001 | Sysmon 1 |
| execution | `powershell_download_cradle.yml` | T1059.001 | PS 4104 |
| execution | `wmic_process_creation.yml` | T1047 | Sysmon 1 |
| persistence | `scheduled_task_creation.yml` | T1053.005 | Sysmon 1 / Sec 4698 |
| persistence | `registry_run_key_persistence.yml` | T1547.001 | **Sysmon 13** (registry_set) |
| persistence | `wmi_event_subscription.yml` | T1546.003 | Sysmon 19/20/21 |
| credential_access | `lsass_process_access.yml` | T1003.001 | Sysmon 10 |
| privilege_escalation | `uac_bypass_fodhelper.yml` | T1548.002 | Sysmon 1 |
| discovery | `network_config_discovery.yml` | T1016 | Sysmon 1 |
| discovery | `process_discovery_tasklist.yml` | T1057 | Sysmon 1 |
| discovery | `systeminfo_execution.yml` | T1082 | Sysmon 1 |
| defence_evasion | `certutil_decode.yml` | T1140 | Sysmon 1 |
| defence_evasion | `mshta_proxy_execution.yml` | T1218.005 | Sysmon 1 |
| defence_evasion | `regsvr32_proxy_execution.yml` | T1218.010 | Sysmon 1 |

Conventions used by every rule:
- `author: Sagnik Ray`
- `logsource: { category, product: windows }`
- `level:` ∈ {low, medium, high, critical}
- `tags:` always includes `attack.<tactic>` and `attack.t####[.###]`
- `detection.condition:` always explicit; uses `selection_*` and `filter_*` blocks
- `falsepositives:` is a list, never a single string

Folder naming note: the tactic folder is `defence_evasion` (British
spelling), intentionally matching MITRE and the workflow glob path.

---

## 4. Scripts

### `scripts/test_runner.py`
- Loads `RULE_TO_EVTX` dict — 14 rules mapped to one or more EVTX
  files inside the `EVTX-ATTACK-SAMPLES` submodule.
- For each rule: parses Sigma `detection`/`filter` blocks into
  `(field, value)` pairs and does **case-insensitive substring match**
  on raw event XML (covers `contains`, `endswith`, `startswith`).
- Reports PASS / FAIL / SKIP per rule.
- **CI gate**: `MIN_DETECT_RATE = 0.80` — overall PASS rate of tested
  rules must be ≥ 80 % or the pipeline fails.
- Fail-closed on zero tests run (return code 1).
- Resolves EVTX paths case-insensitively because the upstream dataset
  uses mixed casing (`Privilege Escalation` vs `discovery`).

### `scripts/coverage_mapper.py`
- Reads every `*.yml` under `sigma-rules/`.
- Parses `attack.t####(.###)` tags → technique IDs.
- Writes `navigator/coverage_layer.json` (ATT&CK v14 / Navigator 4.9,
  layer format 4.5, domain `enterprise-attack`, Windows platform only).
- Covered colour: `#1d9e75`.

### `scripts/gap_analysis.py`
- Downloads MITRE `enterprise-attack.json` (cached at `.attck_cache.json`
  with a 7-day TTL) — works offline once cached.
- Filters to **non-deprecated, non-subtechnique, Windows-platform** ATT&CK
  techniques → currently **176**.
- Cross-references Sigma coverage: a subtechnique tag also marks its
  parent as covered (e.g. `t1059.001` ⇒ `T1059`).
- Writes `docs/gap_report.md` with Summary, Covered, and Gap tables;
  also prints the Gap section to `$GITHUB_STEP_SUMMARY`.

### `scripts/requirements.txt`
```
sigma-cli
pySigma-backend-splunk
pySigma-backend-microsoft365defender    ← installed in CI but never used
pySigma-pipeline-sysmon
python-evtx
pyyaml
lxml                                     ← not imported by any script
requests
```

---

## 5. Lab environment

- Windows VM (Atomic Red Team target) — runs Sysmon (SwiftOnSecurity
  config) + Wazuh Agent.
- WSL2 Ubuntu — Wazuh Manager + Indexer + Dashboard.
- Adversary emulation: Atomic Red Team via `Invoke-AtomicRedTeam`.

Validation summary (see `docs/atomic-results.md`): **14/14 rules fired**
in Wazuh, primary event IDs listed in §3 above.

---

## 6. CI/CD conventions

- **Branch**: `master` (not `main`).
- **Committer for auto-commits**: `github-actions[bot]`.
- **Auto-commit message**:
  `ci: auto-update converted KQL and SPL queries [skip ci]`
- **`[skip ci]`** in the message prevents a feedback loop.
- Auto-commit only fires on `push` to `master`, never on PRs.
- `converted/` is committed despite being in `.gitignore` — `.gitignore`
  is overridden by explicit `git add converted/` in the workflow.
  (Long-term: keep `converted/` checked in so PRs can diff query output.)
- Line endings: LF only (`.gitattributes`).

---

## 7. ATT&CK coverage (latest numbers)

| Source | Covered | Total | % |
|---|---|---|---|
| `navigator/coverage_layer.json` (sub-tech IDs) | 13 | — | — |
| `docs/gap_report.md` "Covered" (parent IDs only) | 12 | 176 | 6.82 % |

The two reports use different ID granularity: the layer keeps subtech
suffixes (e.g. `T1003.001`), while the gap report collapses them to
parents (e.g. `T1003`). They are consistent in the underlying set of
covered Sigma rules — only the roll-up label differs.

---

## 8. Known contradictions / drift in the repo

The following were found by cross-checking docs, rules, scripts, and the
workflow. They need to be reconciled by the next maintainer:

### 8.1 Lab OS — README vs `docs/atomic-results.md`
- `README.md` line 11: "Windows Server 2022 VM".
- `docs/atomic-results.md` line 7: "Windows 10 VM (VirtualBox)".
- `git log` shows the lab was originally Windows 10; the README was
  later updated to advertise Server 2022. Whichever is current, the two
  documents must agree.

### 8.2 Phase status — README is stale
- `README.md` line 8: "Phase 1 in progress — first 5 rules + CI lint pipeline."
- Actual state: 14 rules, EVTX test runner, KQL+SPL conversion, ATT&CK
  Navigator layer, gap analysis, and ART validation are all live in CI.
- README should be bumped to Phase 3 (or current phase) and the rule
  count updated.

### 8.3 `registry_run_key_persistence.yml` vs `docs/atomic-results.md`
- Rule on disk: `logsource.category: registry_set` (Sysmon EID 13).
- Converted KQL emits `EventID == 13`.
- `docs/rules_rationale/T1547.001.md` confirms Sysmon EID 13 throughout.
- BUT `docs/atomic-results.md` (T1547.001 section) claims: "Rule updated
  from `registry_set` to `process_creation` logsource to match observed
  telemetry." That change was **never applied to the rule file**. Either:
  - revert the doc claim, or
  - actually migrate the rule to `process_creation`.
- The "ART Validation Summary" table in the same file also mislabels
  T1547.001 as "Sysmon 13" while it simultaneously cites EID 1 prose —
  pick one.

### 8.4 Wazuh version drift
- `README.md` line 12: "WSL2 Ubuntu — Wazuh Manager + Indexer + Dashboard".
- `docs/atomic-results.md` line 9: "SIEM | Wazuh 4.x (WSL2 Ubuntu)".
- Minor — add a specific Wazuh version to README for reproducibility.

### 8.5 Coverage count: 12 vs 13
- `gap_report.md`: "Covered | 12".
- `coverage_layer.json`: 13 techniques listed.
- Cause: gap report uses parent IDs only (T1003, T1059, …); layer uses
  sub-technique IDs (T1003.001, T1059.001, …). One rule (`lsass`) is
  the only reason they differ (subtech T1003.001 ↔ parent T1003).
- `T1059` and `T1218` are collapsed in the gap report even though two
  rules each contribute to those parents.
- Fix: have `gap_analysis.py` also emit a sub-technique view, or have
  `coverage_mapper.py` emit a parent-ID view, so the two reports line up.

### 8.6 Mismatched pip packages in CI
- `requirements.txt` lists `pySigma-backend-microsoft365defender`, and
  the workflow `pip install`s it.
- The conversion steps only ever call `-t kusto` (Microsoft Sentinel
  backend) and `-t splunk`. The M365D backend is **never exercised** in
  CI.
- Fix: either drop the M365D package, or add a third conversion step
  that uses `-t microsoft-365-defender`.

### 8.7 `lxml` unused
- `requirements.txt` lists `lxml`, but none of `coverage_mapper.py`,
  `gap_analysis.py`, or `test_runner.py` import it. They rely on `pyyaml`
  + `python-evtx`. Safe to drop.

### 8.8 `coverage_layer.json` "attack" version
- The layer hard-codes `"attack": "14"`. MITRE ATT&CK has moved on (v14
  was current in 2023). If you regenerate against a newer STIX bundle,
  bump this manually or compute it from the STIX `x_mitre_version`.

### 8.9 `.gitignore` vs auto-commit
- `.gitignore` line 4: `converted/`.
- The CI workflow does `git add converted/ && git commit … && git push`.
  The ignore is bypassed by explicit `git add` (git's override semantics),
  so `converted/` **is** committed in practice. Decide whether you want
  it tracked or not — the current "both" state is confusing.
- The `.attck_cache.json` entry is correct — it must stay ignored (it
  is a 36 MB MITRE bundle dump).

---

## 9. File-by-file cheat sheet

| Path | Purpose | Edited by |
|---|---|---|
| `sigma-rules/windows/**/*.yml` | Source-of-truth detection rules | Human |
| `converted/**/*.txt` | Generated KQL/SPL — **do not hand-edit** | CI |
| `navigator/coverage_layer.json` | Generated ATT&CK layer — **do not hand-edit** | CI |
| `docs/gap_report.md` | Generated gap report — **do not hand-edit** | CI |
| `docs/atomic-results.md` | Hand-written lab validation log | Human |
| `docs/rules_rationale/*.md` | Hand-written per-rule rationale | Human |
| `scripts/*.py` | Pipeline scripts | Human |
| `.github/workflows/detect-ci.yml` | CI definition | Human |
| `README.md` | Top-level project intro | Human |
| `.attck_cache.json` | MITRE bundle cache (gitignored, ~36 MB) | CI |
| `EVTX-ATTACK-SAMPLES/` | Submodule, git submodule | Upstream |

---

## 10. Quick reference for contributors

- Add a new rule:
  1. Drop the `.yml` under `sigma-rules/windows/<tactic>/`.
  2. Append a `RULE_TO_EVTX` entry in `scripts/test_runner.py` with at
     least one EVTX path (case-insensitive folder names OK).
  3. Run `python scripts/test_runner.py` locally.
  4. Open a PR — CI will lint, test, convert, regenerate layer + gap
     report, and surface results in `$GITHUB_STEP_SUMMARY`.
- Update a rule: edit YAML, push. CI regenerates `converted/`,
  `coverage_layer.json`, and `gap_report.md` automatically.
- Add a rationale doc: `docs/rules_rationale/T####.md`, link from
  the rule's `references:` list (optional).
