# DetectLab-CI

Detection-as-code pipeline: Sigma rules → CI validation → KQL + SPL output → ATT&CK coverage

[![CI](https://github.com/cybersagnik/detect-lab-ci/actions/workflows/detect-ci.yml/badge.svg)](https://github.com/cybersagnik/detect-lab-ci/actions)

## Status
Phase 1 in progress — first 5 rules + CI lint pipeline.

## Lab
- Windows Server 2022 VM — Sysmon + Wazuh Agent + Atomic Red Team
- WSL2 Ubuntu — Wazuh Manager + Indexer + Dashboard