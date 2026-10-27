# 26 — Endpoint Defense Evasion and Security Tool Tampering

**Default severity:** High–Critical  
**Initial response target:** Initial triage: 10 minutes; escalate immediately if protection is disabled on multiple or critical hosts.  
**MITRE ATT&CK:** T1562.001 (Disable or Modify Tools), T1070 (Indicator Removal), T1059 (Command and Scripting Interpreter)

## Objective
Determine whether endpoint protection, logging, backups or monitoring were intentionally disabled and identify actor and follow-on actions.

## Indicators that trigger this playbook
- EDR/AV agent stopped, tamper-protection alert, service or driver change.
- Audit/logging configuration modified, event channels cleared, security agent uninstalled or exclusion added.
- Backup/restore service disabled, sensor heartbeat lost after suspicious execution.
- PowerShell/admin utility modifies Defender, firewall, audit or sensor configuration.

## Pre-triage evidence checklist
- [ ] Host, user, service/agent, process tree, configuration before/after, alert time and management-console state.
- [ ] Windows events 7036/7040/7045, Defender/EDR events, Sysmon process events and policy audit.
- [ ] Change ticket, management tool, maintenance, deployment identity and host criticality.
- [ ] Other controls still recording and whether agent outage correlates with suspicious activity.

## Tier 1 triage workflow
### Step 1 — Establish actual protection state
Confirm agent/service status from management console and endpoint; identify last healthy telemetry and sensor capabilities affected.

### Step 2 — Find actor and modification
Review ancestry, command line, service control, configuration changes, uninstall/exclusion operations and identity/session evidence.

### Step 3 — Correlate time window
Search execution, credential access, persistence, log clearing, backup tampering, remote access and outbound connections before/after change.

### Step 4 — Scope other hosts
Search management audit, same account/process/command and telemetry loss across endpoints.

### Step 5 — Contain under incident authority
Use trusted EDR/management plane to isolate or restore controls. If the control plane may be compromised, escalate to platform owner before trusting it.

### Step 6 — Validate recovery
Confirm agent check-in, policy/tamper protection, logs flowing, exclusions approved and no remaining malicious process/persistence.

## Splunk SPL investigation pivot
Adapt index, sourcetype, field names, event codes and time ranges to your environment. This is an investigation starting point, not a validated production detection.

```spl
index=sysmon EventCode=1 earliest=-24h
| eval cmd=lower(CommandLine), image=lower(Image)
| search cmd="*disable*defender*" OR cmd="*Set-MpPreference*" OR cmd="*sc stop*windefend*" OR cmd="*wevtutil cl*" OR cmd="*auditpol*"
| table _time host user ParentImage Image CommandLine
| sort - _time
```

## Containment guidance
Use approved authority and incident procedures. Preserve relevant logs and evidence before disruptive action when feasible.

- Preserve endpoint and EDR management audit records; record last telemetry and missing collection window.
- Restore protection using trusted policy controls and investigate exclusions/service changes before blindly re-enabling.
- If multiple sensors fail together, suspect shared admin/control-plane abuse and escalate.
- Don't conclude tampering from maintenance without change validation and actor evidence.

## Escalation criteria
Escalate to Tier 2 / IR when any of the following apply:

- Monitoring or backup controls disabled by unauthorized activity.
- Telemetry loss aligns with ransomware, credential theft, lateral movement or evidence destruction.
- Multiple systems or management infrastructure affected.

## Closure criteria
Close only when the evidence supports a disposition, scope and remaining gaps are recorded, and actions are complete or assigned.

- Control state restored and verified from management telemetry.
- Actor, timeline, related execution and telemetry gaps documented.
- Approved configuration changes are distinguished from unauthorized changes.

## False-positive and validation notes
Command-line indicators are incomplete. Supplement with product-specific EDR, Defender and Service Control Manager audit sources.

Do not treat an alert name, rarity score, or single query result as proof of compromise. Correlate independent telemetry and document unavailable sources.
