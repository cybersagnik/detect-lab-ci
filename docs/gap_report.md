# ATT&CK Coverage Gap Report
Generated: 2026-07-30T06:59:08+00:00

## Summary
| Metric | Value |
|--------|-------|
| Total Windows techniques | 176 |
| Covered | 12 |
| Gaps | 164 |
| Coverage | 6.82% |

## Covered Techniques
| Technique ID | Name | Rule |
|---|---|---|
| T1003 | OS Credential Dumping | lsass_process_access.yml |
| T1016 | System Network Configuration Discovery | network_config_discovery.yml |
| T1047 | Windows Management Instrumentation | wmic_process_creation.yml |
| T1053 | Scheduled Task/Job | scheduled_task_creation.yml |
| T1057 | Process Discovery | process_discovery_tasklist.yml |
| T1059 | Command and Scripting Interpreter | powershell_download_cradle.yml, powershell_encoded_command.yml |
| T1082 | System Information Discovery | systeminfo_execution.yml |
| T1140 | Deobfuscate/Decode Files or Information | certutil_decode.yml |
| T1218 | System Binary Proxy Execution | mshta_proxy_execution.yml, regsvr32_proxy_execution.yml |
| T1546 | Event Triggered Execution | wmi_event_subscription.yml |
| T1547 | Boot or Logon Autostart Execution | registry_run_key_persistence.yml |
| T1548 | Abuse Elevation Control Mechanism | uac_bypass_fodhelper.yml |

## Gap Techniques (not covered)
| Technique ID | Name | Tactic |
|---|---|---|
| T1001 | Data Obfuscation | Command and Control |
| T1005 | Data from Local System | Collection |
| T1006 | Direct Volume Access | Stealth |
| T1007 | System Service Discovery | Discovery |
| T1008 | Fallback Channels | Command and Control |
| T1010 | Application Window Discovery | Discovery |
| T1011 | Exfiltration Over Other Network Medium | Exfiltration |
| T1012 | Query Registry | Discovery |
| T1014 | Rootkit | Stealth |
| T1018 | Remote System Discovery | Discovery |
| T1020 | Automated Exfiltration | Exfiltration |
| T1021 | Remote Services | Lateral Movement |
| T1025 | Data from Removable Media | Collection |
| T1027 | Obfuscated Files or Information | Stealth |
| T1029 | Scheduled Transfer | Exfiltration |
| T1030 | Data Transfer Size Limits | Exfiltration |
| T1033 | System Owner/User Discovery | Discovery |
| T1036 | Masquerading | Stealth |
| T1037 | Boot or Logon Initialization Scripts | Persistence |
| T1039 | Data from Network Shared Drive | Collection |
| T1040 | Network Sniffing | Credential Access |
| T1041 | Exfiltration Over C2 Channel | Exfiltration |
| T1046 | Network Service Discovery | Discovery |
| T1048 | Exfiltration Over Alternative Protocol | Exfiltration |
| T1049 | System Network Connections Discovery | Discovery |
| T1052 | Exfiltration Over Physical Medium | Exfiltration |
| T1055 | Process Injection | Stealth |
| T1056 | Input Capture | Collection |
| T1068 | Exploitation for Privilege Escalation | Privilege Escalation |
| T1069 | Permission Groups Discovery | Discovery |
| T1070 | Indicator Removal | Stealth |
| T1071 | Application Layer Protocol | Command and Control |
| T1072 | Software Deployment Tools | Execution |
| T1074 | Data Staged | Collection |
| T1078 | Valid Accounts | Stealth |
| T1080 | Taint Shared Content | Lateral Movement |
| T1083 | File and Directory Discovery | Discovery |
| T1087 | Account Discovery | Discovery |
| T1090 | Proxy | Command and Control |
| T1091 | Replication Through Removable Media | Lateral Movement |
| T1092 | Communication Through Removable Media | Command and Control |
| T1095 | Non-Application Layer Protocol | Command and Control |
| T1098 | Account Manipulation | Persistence |
| T1102 | Web Service | Command and Control |
| T1104 | Multi-Stage Channels | Command and Control |
| T1105 | Ingress Tool Transfer | Command and Control |
| T1106 | Native API | Execution |
| T1110 | Brute Force | Credential Access |
| T1111 | Multi-Factor Authentication Interception | Credential Access |
| T1112 | Modify Registry | Defense Impairment |
| T1113 | Screen Capture | Collection |
| T1114 | Email Collection | Collection |
| T1115 | Clipboard Data | Collection |
| T1119 | Automated Collection | Collection |
| T1120 | Peripheral Device Discovery | Discovery |
| T1123 | Audio Capture | Collection |
| T1124 | System Time Discovery | Discovery |
| T1125 | Video Capture | Collection |
| T1127 | Trusted Developer Utilities Proxy Execution | Stealth |
| T1129 | Shared Modules | Execution |
| T1132 | Data Encoding | Command and Control |
| T1133 | External Remote Services | Persistence |
| T1134 | Access Token Manipulation | Stealth |
| T1135 | Network Share Discovery | Discovery |
| T1136 | Create Account | Persistence |
| T1137 | Office Application Startup | Persistence |
| T1176 | Software Extensions | Persistence |
| T1185 | Browser Session Hijacking | Collection |
| T1187 | Forced Authentication | Credential Access |
| T1189 | Drive-by Compromise | Initial Access |
| T1190 | Exploit Public-Facing Application | Initial Access |
| T1195 | Supply Chain Compromise | Initial Access |
| T1197 | BITS Jobs | Stealth |
| T1199 | Trusted Relationship | Initial Access |
| T1200 | Hardware Additions | Initial Access |
| T1201 | Password Policy Discovery | Discovery |
| T1202 | Indirect Command Execution | Stealth |
| T1203 | Exploitation for Client Execution | Execution |
| T1204 | User Execution | Execution |
| T1205 | Traffic Signaling | Stealth |
| T1207 | Rogue Domain Controller | Defense Impairment |
| T1210 | Exploitation of Remote Services | Lateral Movement |
| T1211 | Exploitation for Stealth | Stealth |
| T1212 | Exploitation for Credential Access | Credential Access |
| T1213 | Data from Information Repositories | Collection |
| T1216 | System Script Proxy Execution | Stealth |
| T1217 | Browser Information Discovery | Discovery |
| T1219 | Remote Access Tools | Command and Control |
| T1220 | XSL Script Processing | Stealth |
| T1221 | Template Injection | Stealth |
| T1222 | File and Directory Permissions Modification | Defense Impairment |
| T1480 | Execution Guardrails | Stealth |
| T1482 | Domain Trust Discovery | Discovery |
| T1484 | Domain or Tenant Policy Modification | Defense Impairment |
| T1485 | Data Destruction | Impact |
| T1486 | Data Encrypted for Impact | Impact |
| T1489 | Service Stop | Impact |
| T1490 | Inhibit System Recovery | Impact |
| T1491 | Defacement | Impact |
| T1495 | Firmware Corruption | Impact |
| T1496 | Resource Hijacking | Impact |
| T1497 | Virtualization/Sandbox Evasion | Stealth |
| T1498 | Network Denial of Service | Impact |
| T1499 | Endpoint Denial of Service | Impact |
| T1505 | Server Software Component | Persistence |
| T1518 | Software Discovery | Discovery |
| T1529 | System Shutdown/Reboot | Impact |
| T1531 | Account Access Removal | Impact |
| T1534 | Internal Spearphishing | Lateral Movement |
| T1539 | Steal Web Session Cookie | Credential Access |
| T1542 | Pre-OS Boot | Stealth |
| T1543 | Create or Modify System Process | Persistence |
| T1550 | Use Alternate Authentication Material | Lateral Movement |
| T1552 | Unsecured Credentials | Credential Access |
| T1553 | Subvert Trust Controls | Defense Impairment |
| T1554 | Compromise Host Software Binary | Persistence |
| T1555 | Credentials from Password Stores | Credential Access |
| T1556 | Modify Authentication Process | Defense Impairment |
| T1557 | Adversary-in-the-Middle | Credential Access |
| T1558 | Steal or Forge Kerberos Tickets | Credential Access |
| T1559 | Inter-Process Communication | Execution |
| T1560 | Archive Collected Data | Collection |
| T1561 | Disk Wipe | Impact |
| T1563 | Remote Service Session Hijacking | Lateral Movement |
| T1564 | Hide Artifacts | Stealth |
| T1565 | Data Manipulation | Impact |
| T1566 | Phishing | Initial Access |
| T1567 | Exfiltration Over Web Service | Exfiltration |
| T1568 | Dynamic Resolution | Command and Control |
| T1569 | System Services | Execution |
| T1570 | Lateral Tool Transfer | Lateral Movement |
| T1571 | Non-Standard Port | Command and Control |
| T1572 | Protocol Tunneling | Command and Control |
| T1573 | Encrypted Channel | Command and Control |
| T1574 | Hijack Execution Flow | Stealth |
| T1606 | Forge Web Credentials | Credential Access |
| T1611 | Escape to Host | Privilege Escalation |
| T1614 | System Location Discovery | Discovery |
| T1615 | Group Policy Discovery | Discovery |
| T1620 | Reflective Code Loading | Stealth |
| T1621 | Multi-Factor Authentication Request Generation | Credential Access |
| T1622 | Debugger Evasion | Stealth |
| T1649 | Steal or Forge Authentication Certificates | Credential Access |
| T1652 | Device Driver Discovery | Discovery |
| T1653 | Power Settings | Persistence |
| T1654 | Log Enumeration | Discovery |
| T1657 | Financial Theft | Impact |
| T1659 | Content Injection | Initial Access |
| T1665 | Hide Infrastructure | Command and Control |
| T1667 | Email Bombing | Impact |
| T1668 | Exclusive Control | Persistence |
| T1669 | Wi-Fi Networks | Initial Access |
| T1673 | Virtual Machine Discovery | Discovery |
| T1674 | Input Injection | Execution |
| T1678 | Delay Execution | Stealth |
| T1679 | Selective Exclusion | Stealth |
| T1680 | Local Storage Discovery | Discovery |
| T1684 | Social Engineering | Stealth |
| T1685 | Disable or Modify Tools | Defense Impairment |
| T1686 | Disable or Modify System Firewall | Defense Impairment |
| T1687 | Exploitation for Defense Impairment | Defense Impairment |
| T1688 | Safe Mode Boot | Defense Impairment |
| T1689 | Downgrade Attack | Defense Impairment |
| T1690 | Prevent Command History Logging | Defense Impairment |
