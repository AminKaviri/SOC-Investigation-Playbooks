# MITRE ATT&CK Mapping

This is an investigative navigation aid, not proof that a technique occurred. Verify current technique IDs/names against the ATT&CK version used by your organization. Record confidence and map only behavior supported by evidence.

| Playbook | Primary technique IDs (hypotheses to validate) |
|---|---|
| [01 Phishing Triage](playbooks/01-phishing-triage.md) | T1566.001, T1566.002, T1204.001, T1204.002 |
| [02 Brute Force Investigation](playbooks/02-brute-force-investigation.md) | T1110.001, T1110.003 |
| [03 Lateral Movement](playbooks/03-lateral-movement-investigation.md) | T1021.001, T1021.002, T1021.006, T1550.002, T1550.003 |
| [04 Malware Alert](playbooks/04-malware-alert-investigation.md) | T1059.001, T1055, T1547.001, T1053.005, T1071 |
| [05 Data Exfiltration](playbooks/05-data-exfiltration-investigation.md) | T1048, T1041, T1567, T1567.002, T1020 |
| [06 Suspicious PowerShell](playbooks/06-suspicious-powershell-investigation.md) | T1059.001, T1027, T1105 |
| [07 AD Account Compromise](playbooks/07-active-directory-account-compromise.md) | T1078.002, T1098, T1003 |
| [08 Service / Scheduled Task](playbooks/08-suspicious-service-and-scheduled-task.md) | T1543.003, T1053.005 |
| [09 RDP / Remote Access](playbooks/09-suspicious-rdp-and-remote-access.md) | T1021.001, T1133, T1078 |
| [10 Event Log Tampering](playbooks/10-windows-event-log-tampering.md) | T1070.001, T1562.002 |
| [11 Kerberoasting](playbooks/11-kerberoasting-investigation.md) | T1558.003 |
| [12 Ransomware Early Triage](playbooks/12-ransomware-early-triage.md) | T1486, T1490, T1489 |
| [13 Cloud Identity Compromise](playbooks/13-cloud-identity-compromise.md) | T1078.004, T1098, T1528, T1621 |
| [14 Business Email Compromise](playbooks/14-business-email-compromise.md) | T1566, T1114.003, T1098, T1078 |
| [15 C2 Beaconing](playbooks/15-command-and-control-beaconing.md) | T1071, T1095, T1105, T1573 |
| [16 DNS / DGA / Tunneling](playbooks/16-suspicious-dns-and-dga.md) | T1071.004, T1568.002, T1048 |
| [17 Privilege Escalation / Admin Abuse](playbooks/17-privilege-escalation-and-admin-abuse.md) | T1098, T1068, T1548, T1078 |
| [18 WMI / WinRM / Remote Execution](playbooks/18-suspicious-wmi-winrm-remote-execution.md) | T1021.006, T1047, T1059, T1569.002 |
| [19 Sensitive Data Access / Staging](playbooks/19-sensitive-data-access-and-collection.md) | T1005, T1039, T1119, T1560 |
| [20 OAuth / Service Principal Abuse](playbooks/20-suspicious-oauth-app-consent.md) | T1098, T1528, T1078.004 |
| [21 VPN / Remote Access Anomaly](playbooks/21-vpn-and-remote-access-anomaly.md) | T1133, T1078, T1110 |
| [22 Insider Threat / Policy Violation](playbooks/22-insider-threat-and-policy-violation.md) | T1530, T1005, T1020, T1567 |
| [23 Web Exploitation](playbooks/23-vulnerability-exploitation-and-web-attack.md) | T1190, T1059, T1505.003 |
| [24 Linux Host Compromise](playbooks/24-linux-suspicious-activity.md) | T1059.004, T1543.002, T1053.003, T1078 |
| [25 Cloud Control-Plane Abuse](playbooks/25-cloud-control-plane-abuse.md) | T1078.004, T1098, T1578, T1537 |
| [26 Endpoint Defense Evasion](playbooks/26-endpoint-defense-evasion.md) | T1562.001, T1070, T1059 |

## Coverage notes
- A detection or mapped technique is not proof of successful compromise.
- Distinguish observations from hypotheses and record the source event supporting each mapping.
- Technique IDs and names can change between ATT&CK versions; validate before formal reporting.
