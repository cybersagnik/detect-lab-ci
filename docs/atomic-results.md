# Atomic Red Team Validation Results

**Lab Environment**

| Component | Details |
|---|---|
| OS | Windows 10 VM |
| Telemetry | Sysmon (SwiftOnSecurity config) |
| SIEM | Wazuh 4.x (WSL2 Ubuntu) |
| Wazuh Agent | Deployed on Windows 10 VM |
| Adversary Emulation | Atomic Red Team (Invoke-AtomicRedTeam) |

---

## T1059.001 — Encoded PowerShell Execution

**Rule file:** `sigma-rules/windows/execution/powershell_encoded_command.yml`

| Field | Value |
|---|---|
| ART Test | `Invoke-AtomicTest T1059.001 -TestNumbers 4` |
| Date Tested | YYYY-MM-DD |
| Wazuh Alert Fired | ✅ Yes |
| Primary Event Source | Sysmon |
| Event ID | 1 (ProcessCreate) |
| Key Field | `data.win.eventdata.commandLine` |
| Key Value Observed | `powershell.exe -e <Base64 blob>` |
| Secondary Event ID | 4104 (PowerShell Script Block Logging) |
| False Positives on Clean Baseline | None |
| Cleanup Command | `Invoke-AtomicTest T1059.001 -TestNumbers 17 -Cleanup` |

**What happened:**
Sysmon EID 1 fired within seconds of ART execution. The alert appeared
in Wazuh showing `powershell.exe` spawned with `-e` followed
by a Base64 string in the CommandLine field. PowerShell Script Block log
EID 4104 also fired showing the decoded payload.

**Wazuh alert screenshot:**

![Wazuh Alert For T1059.001](/docs/images/T1059-001.png)

---

## T1053.005 — Scheduled Task Creation via schtasks.exe

**Rule file:** `sigma-rules/windows/persistence/scheduled_task_creation.yml`

| Field | Value |
|---|---|
| ART Test | `Invoke-AtomicTest T1053.005 -TestNumbers 1` |
| Date Tested | YYYY-MM-DD |
| Wazuh Alert Fired | ✅ Yes |
| Primary Event Source | Sysmon |
| Event ID | 1 (ProcessCreate) |
| Key Field | `data.win.eventdata.commandLine` |
| Key Value Observed | `schtasks.exe /Create /SC ONCE /TR cmd.exe` |
| Secondary Event ID | 4698 (Scheduled Task Created — Windows Security Log) |
| False Positives on Clean Baseline | None |
| Cleanup Command | `Invoke-AtomicTest T1053.005 -TestNumbers 1 -Cleanup` |

**What happened:**
Sysmon EID 1 fired showing `schtasks.exe` process creation with `/Create`
and `/SC` in the CommandLine. Windows Security EID 4698 also appeared
confirming the task was registered in the Task Scheduler. Both events
appeared in Wazuh within the same second.

**Wazuh alert screenshot:**

![Wazuh alert for T1053.005](/docs/images/T1053-005.png)

---

## T1003.001 — LSASS Memory Access (Credential Dumping)

**Rule file:** `sigma-rules/windows/credential_access/lsass_process_access.yml`

| Field | Value |
|---|---|
| ART Test | `Invoke-AtomicTest T1003.001 -TestNumbers 1` |
| Date Tested | YYYY-MM-DD |
| Wazuh Alert Fired | ✅ Yes |
| Primary Event Source | Sysmon |
| Event ID | 1 (ProcessCreate) |
| Key Field | `data.win.eventdata.targetImage` |
| Key Value Observed | `C:\Windows\System32\lsass.exe` |
| False Positives on Clean Baseline | MsMpEng.exe (Windows Defender) — filtered in rule |
| Cleanup Command | `Invoke-AtomicTest T1003.001 -TestNumbers 1 -Cleanup` |

**What happened:**
Sysmon EID 1 fired showing the source process (procdump.exe) opening
a handle to `lsass.exe`. MsMpEng.exe also triggered EID 10 on lsass
during the test — confirmed correctly filtered by the `filter_legitimate`
block in the rule. Only the procdump access produced a Wazuh alert.

**Wazuh alert screenshot:**

![Wazuh alert on Process Access](/docs/images/T1003-001.png)

---

## T1547.001 — Registry Run Key Persistence

**Rule file:** `sigma-rules/windows/persistence/registry_run_key_persistence.yml`

| Field | Value |
|---|---|
| ART Test | `Invoke-AtomicTest T1547.001 -TestNumbers 1` |
| Date Tested | YYYY-MM-DD |
| Wazuh Alert Fired | ✅ Yes |
| Primary Event Source | Sysmon |
| Event ID | 13 (RegistryEvent — Value Set) |
| Key Field | `data.win.eventdata.targetObject` |
| Key Value Observed | `HKCU\Software\Microsoft\Windows\CurrentVersion\Run\` |
| False Positives on Clean Baseline | None |
| Cleanup Command | `Invoke-AtomicTest T1547.001 -TestNumbers 1 -Cleanup` |

**What happened:**
Sysmon EID 13 fired showing a registry value written to the Run key
under HKCU by a process running outside System32. The alert appeared
in Wazuh with the full registry path visible in `targetObject` and
the process that made the change in `image`.

**Wazuh alert screenshot:**

![Wazuh Alert for T1547.001](/docs/images/T1547-001.png)

---

## T1548.002 — UAC Bypass via Fodhelper.exe

**Rule file:** `sigma-rules/windows/privilege_escalation/uac_bypass_fodhelper.yml`

| Field | Value |
|---|---|
| ART Test | `Invoke-AtomicTest T1548.002 -TestNumbers 3` |
| Date Tested | YYYY-MM-DD |
| Wazuh Alert Fired | ✅ Yes |
| Primary Event Source | Sysmon |
| Event ID | 1 (ProcessCreate) |
| Key Field | `data.win.eventdata.parentImage` |
| Key Value Observed | `C:\Windows\System32\fodhelper.exe` |
| Child Process Observed | `cmd.exe` (spawned elevated, no UAC prompt) |
| False Positives on Clean Baseline | None |
| Cleanup Command | `Invoke-AtomicTest T1548.002 -TestNumbers 3 -Cleanup` |

**What happened:**
ART set registry keys under `HKCU\Software\Classes\ms-settings\Shell\Open\command`
then executed `fodhelper.exe`. Fodhelper spawned `cmd.exe` with a High
integrity token — no UAC dialog appeared. Sysmon EID 1 fired immediately
showing `fodhelper.exe` as the parent process, which is the detection
signal. No legitimate child processes from fodhelper were observed on
the clean baseline.

**Wazuh alert screenshot:**

![Wazuh Alert for T1548.002](/docs/images/T1548-002.png)

---

## Phase 1 Summary

| # | Technique | Rule | ART Test | Alert | Primary EID | FP on Clean |
|---|---|---|---|---|---|---|
| 1 | T1059.001 | Encoded PowerShell | T1059.001-4 | ✅ | Sysmon 1 | None |
| 2 | T1053.005 | Scheduled Task | T1053.005-1 | ✅ | Sysmon 1, Win 4698 | None |
| 3 | T1003.001 | LSASS Access | T1003.001-1 | ✅ | Sysmon 10 | MsMpEng (filtered) |
| 4 | T1547.001 | Registry Run Key | T1547.001-1 | ✅ | Sysmon 13 | None |
| 5 | T1548.002 | UAC Bypass Fodhelper | T1548.002-3 | ✅ | Sysmon 1 | None |

**Detection rate: 5/5 (100%)** 
