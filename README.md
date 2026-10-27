# SOC Investigation Playbooks

A practical collection of SOC Tier 1 / Tier 2 investigation playbooks for Windows, Active Directory, Sysmon, and Splunk environments.

## Scenarios

1. [Phishing Triage](playbooks/01-phishing-triage.md)
2. [Brute Force Investigation](playbooks/02-brute-force-investigation.md)
3. [Lateral Movement Investigation](playbooks/03-lateral-movement-investigation.md)
4. [Malware Alert Investigation](playbooks/04-malware-alert-investigation.md)
5. [Data Exfiltration Investigation](playbooks/05-data-exfiltration-investigation.md)
6. [Suspicious PowerShell Investigation](playbooks/06-suspicious-powershell-investigation.md)
7. [Active Directory Account Compromise](playbooks/07-active-directory-account-compromise.md)
8. [Suspicious Service and Scheduled Task](playbooks/08-suspicious-service-and-scheduled-task.md)
9. [Suspicious RDP and Remote Access](playbooks/09-suspicious-rdp-and-remote-access.md)
10. [Windows Event Log Tampering](playbooks/10-windows-event-log-tampering.md)
11. [Kerberoasting Investigation](playbooks/11-kerberoasting-investigation.md)
12. [Ransomware Early Triage](playbooks/12-ransomware-early-triage.md)

## Repository structure

- `playbooks/` — investigation workflows, Splunk SPL pivots, evidence collection, escalation and closure criteria
- `spl/README.md` — SPL assumptions and environment adaptation notes
- `templates/incident-report-template.md` — incident report template
- `templates/escalation-template.md` — Tier 1 to Tier 2 escalation template
- `mitre-mapping.md` — ATT&CK technique mapping

## Important usage notes

The SPL examples are starting points, not validated production detections. Adapt indexes, sourcetypes, field names, and time windows to your Splunk data model. A zero-result query does not prove that activity did not occur; verify telemetry coverage and ingestion first. Correlate alerts with endpoint, identity, network, and other available evidence before assigning a final disposition.

Do not perform disruptive containment actions (such as disabling accounts, isolating hosts, or deleting artifacts) without following your organization's incident-response authorization process.

## License and disclaimer

Use and adapt these playbooks to your environment. They are operational investigation aids, not a substitute for validated detection engineering, incident-response policy, or expert judgment.
