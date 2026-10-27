# MITRE ATT&CK Mapping

Mappings below are hypotheses to guide investigation, not proof that a technique occurred. Map only after validating supporting telemetry.

| Scenario | Potential ATT&CK technique | Evidence to validate |
|---|---|---|
| Phishing | T1566.001 Spearphishing Attachment; T1566.002 Spearphishing Link | Email telemetry, delivered URL/file, user interaction |
| Brute force | T1110 Brute Force; T1110.003 Password Spraying | Failed/successful authentication patterns and account spread |
| Lateral movement | T1021.001 RDP; T1021.002 SMB/Windows Admin Shares; T1569.002 Service Execution | Logon type, source host, service/process evidence |
| Malware | T1204 User Execution; T1059 Command and Scripting Interpreter | Process ancestry, file evidence, command line |
| Exfiltration | T1041 Exfiltration Over C2 Channel; T1567 Exfiltration Over Web Service | Network/proxy/cloud/DLP transfer evidence |
| PowerShell | T1059.001 PowerShell | Script block, process, parent and network evidence |
| AD account compromise | T1078 Valid Accounts; T1098 Account Manipulation | Auth history, account/group changes, identity audit logs |
| Service/task persistence | T1543.003 Windows Service; T1053.005 Scheduled Task | Service/task creation and resulting execution |
| RDP/remote access | T1021.001 Remote Desktop Protocol; T1133 External Remote Services | RDP logons plus VPN/jump-host context |
| Log tampering | T1685.001 Disable or Modify Tools (validate exact technique applicability); T1070.001 Clear Windows Event Logs | Event 1102/104, wevtutil and logging gaps |
| Kerberoasting | T1558.003 Kerberoasting | DC 4769 events, service account/SPN context, encryption type and requester baseline |
| Ransomware | T1486 Data Encrypted for Impact; T1490 Inhibit System Recovery | File changes, ransom notes, recovery deletion, corroborating endpoint evidence |

References: https://attack.mitre.org/
