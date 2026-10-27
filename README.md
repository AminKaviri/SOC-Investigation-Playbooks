# SOC Investigation & Incident Response Playbooks

![Focus](https://img.shields.io/badge/Focus-SOC%20Tier--1%20%2F%20Tier--2-1f6feb)
![Framework](https://img.shields.io/badge/Mapping-MITRE%20ATT%26CK-orange)
![Playbooks](https://img.shields.io/badge/Playbooks-26-blue)
![Status](https://img.shields.io/badge/Status-Active-brightgreen)

An evidence-led SOC investigation library for Windows, Active Directory, endpoints, network security, email, Linux, cloud identity and cloud control-plane incidents.

The reference project's practical triage-first pattern informed the structure, but the scenario text and expanded catalog here are written for this repository, not copied from the reference. Each scenario includes Splunk SPL as a starting point; adapt and test it against your own indexes, sourcetypes and field extractions.

## Playbook Index

| ID | Scenario | Default priority | Primary focus |
|---|---|---|---|
| 01 | [Phishing Triage](playbooks/01-phishing-triage.md) | Medium–High | User interaction, email evidence, endpoint/identity follow-up |
| 02 | [Brute Force Investigation](playbooks/02-brute-force-investigation.md) | Medium–Critical | Password guessing/spraying, success after failure |
| 03 | [Lateral Movement Investigation](playbooks/03-lateral-movement-investigation.md) | High–Critical | Origin-to-target graph and remote services |
| 04 | [Malware Alert Investigation](playbooks/04-malware-alert-investigation.md) | High–Critical | Execution, process tree, persistence, C2 |
| 05 | [Data Exfiltration Investigation](playbooks/05-data-exfiltration-investigation.md) | High–Critical | Volume, channel, sensitive data and transfer status |
| 06 | [Suspicious PowerShell](playbooks/06-suspicious-powershell-investigation.md) | Medium–Critical | Script execution, obfuscation, download/execute |
| 07 | [Active Directory Account Compromise](playbooks/07-active-directory-account-compromise.md) | High–Critical | Identity abuse, persistence, credential access |
| 08 | [Suspicious Service and Scheduled Task](playbooks/08-suspicious-service-and-scheduled-task.md) | High–Critical | Persistence via services/tasks |
| 09 | [Suspicious RDP and Remote Access](playbooks/09-suspicious-rdp-and-remote-access.md) | Medium–Critical | Interactive logons and remote access |
| 10 | [Windows Event Log Tampering](playbooks/10-windows-event-log-tampering.md) | High–Critical | Log clearing, audit changes, telemetry gaps |
| 11 | [Kerberoasting Investigation](playbooks/11-kerberoasting-investigation.md) | High | Service-ticket anomalies and service-account risk |
| 12 | [Ransomware Early Triage](playbooks/12-ransomware-early-triage.md) | Critical | Encryption, spread, backup/restore risks |
| 13 | [Cloud Identity Compromise](playbooks/13-cloud-identity-compromise.md) | High–Critical | Cloud sign-ins, MFA and roles |
| 14 | [Business Email Compromise](playbooks/14-business-email-compromise.md) | High–Critical | Mailbox abuse, forwarding and payment fraud |
| 15 | [C2 Beaconing](playbooks/15-command-and-control-beaconing.md) | High–Critical | Repeated outbound traffic, endpoint correlation |
| 16 | [Suspicious DNS / DGA / Tunneling](playbooks/16-suspicious-dns-and-dga.md) | Medium–Critical | Rare domains and DNS tunneling |
| 17 | [Privilege Escalation / Admin Abuse](playbooks/17-privilege-escalation-and-admin-abuse.md) | High–Critical | Privileged changes and admin misuse |
| 18 | [WMI / WinRM / Remote Execution](playbooks/18-suspicious-wmi-winrm-remote-execution.md) | High–Critical | Remote execution and host-to-host scope |
| 19 | [Sensitive Data Access / Staging](playbooks/19-sensitive-data-access-and-collection.md) | Medium–Critical | Bulk access and data staging |
| 20 | [OAuth Consent / Service Principal Abuse](playbooks/20-suspicious-oauth-app-consent.md) | High–Critical | App grants, credentials and persistence |
| 21 | [VPN / Remote Access Anomaly](playbooks/21-vpn-and-remote-access-anomaly.md) | Medium–Critical | Remote sessions and follow-on access |
| 22 | [Potential Insider Threat / Policy Violation](playbooks/22-insider-threat-and-policy-violation.md) | Medium–Critical | Data behavior with privacy safeguards |
| 23 | [Web Exploitation / Application Attack](playbooks/23-vulnerability-exploitation-and-web-attack.md) | Medium–Critical | WAF, application, host and DB correlation |
| 24 | [Linux Host Compromise](playbooks/24-linux-suspicious-activity.md) | High–Critical | SSH, sudo, persistence and network behavior |
| 25 | [Cloud Control-Plane Abuse](playbooks/25-cloud-control-plane-abuse.md) | High–Critical | IAM, keys, resources and audit changes |
| 26 | [Endpoint Defense Evasion](playbooks/26-endpoint-defense-evasion.md) | High–Critical | EDR/AV tampering and logging gaps |

## How to use a playbook
1. Capture alert/ticket ID, UTC timestamps, affected entities and initial severity.
2. Complete the pre-triage checklist and record which telemetry is available or missing.
3. Follow triage steps in order; distinguish observed facts from hypotheses.
4. Adapt SPL to your index, sourcetype, CIM fields and event IDs; validate against known-good and authorized test events.
5. Contain only under approved authority. Coordinate high-impact actions with owners and incident command.
6. Escalate at stated thresholds. Record why a case was closed, escalated or left inconclusive.

## Common incident lifecycle
**Preparation → Identification and Analysis → Containment → Eradication → Recovery → Post-Incident Review**

## Severity and escalation baseline
- **Critical:** active ransomware/destructive activity, privileged identity compromise, critical infrastructure impact, credible ongoing sensitive-data exfiltration or broad compromise. Notify incident command immediately.
- **High:** confirmed malicious execution, persistence, lateral movement, or compromise of a critical identity/asset. Contain and escalate promptly.
- **Medium:** suspicious attempts without evidence of successful compromise, with enough telemetry to scope.
- **Low / benign:** evidence supports expected activity or false positive and no unresolved indicators remain.

Severity is a starting point, not a substitute for the organization's impact model or incident commander.

## Templates and mapping
- [MITRE ATT&CK mapping](mitre-mapping.md)
- [Incident report](templates/incident-report-template.md)
- [Tier 1 → Tier 2 escalation](templates/escalation-template.md)
- [Splunk SPL validation guide](spl/README.md)

## Engineering and validation principles
- Evidence before attribution: mappings are hypotheses until supported by observed behavior.
- SPL blocks are investigation pivots, not certified detections; field and event sources vary.
- No results means “not observed in searched telemetry,” not “did not happen.”
- Preserve evidence before disruptive action when feasible; containment follows approved authority.
- Minimize sensitive/employee data and restrict case access to authorized responders.

## Validation status
The sample SPL queries have not been executed against a live Splunk instance. Validate indexes, sourcetypes, fields, thresholds, event IDs, output semantics and benign scenarios before operational use.
