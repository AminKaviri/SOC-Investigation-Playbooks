# 06 — Suspicious PowerShell

**Default severity:** Medium–Critical  
**Triage target:** 15 minutes  
**MITRE ATT&CK:** T1059.001, T1027, T1105

## Objective
Determine whether PowerShell activity is authorized automation or suspicious script execution, download, obfuscation or follow-on behavior.

## Indicators that trigger this playbook
- Encoded/obfuscated PowerShell, unexpected parent process, remote download, suspicious script block, or PowerShell from user-writable path.
- PowerShell is followed by persistence, credential access, outbound traffic or defense-evasion activity.

## Pre-triage evidence checklist
- [ ] Full command line, script block/transcription logs, parent process, user, host and process identifiers.
- [ ] Execution policy, encoded content safely decoded in an approved environment, downloads, child process and network pivots.
- [ ] EDR, PowerShell Operational, Sysmon and authentication events around the command.

## Tier 1 triage workflow
### Step 1 — Validate the command
Collect full command line, parent process, user, script block and execution policy context. Look for obfuscation, encoded content, download/execute or hidden windows.

### Step 2 — Reconstruct process ancestry
Identify Office/browser/service/remote tool parents, child processes and linked script hosts.

### Step 3 — Pivot on indicators
Search domains, URLs, hashes, paths, commands, process IDs and neighboring event times.

### Step 4 — Check follow-on behaviors
Review persistence, credential access, security-control changes, scheduled tasks, service installation and remote connections.

### Step 5 — Contain and remediate
Coordinate isolation, block indicators and remove persistence only with approved procedures; preserve script evidence.

## Splunk SPL investigation pivots

Adapt indexes, sourcetypes, field names, event codes and time range to your environment. These are investigation starting points, not production-certified detections.

```spl
index=sysmon EventCode=1 earliest=-24h
| eval proc=lower(Image), parent=lower(ParentImage), cmd=lower(CommandLine)
| search proc="*\powershell.exe" OR proc="*\pwsh.exe"
| table _time host user ParentImage Image CommandLine ProcessGuid ParentProcessGuid
| sort - _time
```

### Correlation pivot — build a compact timeline
```spl
(index=wineventlog OR index=sysmon OR index=edr) earliest=-24h
| eval entity=coalesce(user, TargetUserName, SubjectUserName, AccountName)
| eval event_detail=coalesce(CommandLine, Message, EventDescription, action)
| table _time host entity EventCode Image ParentImage CommandLine event_detail
| sort 0 _time
```

## Containment guidance
- Preserve original evidence (message, command line, process tree, relevant log events, network/session metadata) before cleanup when feasible.
- Use approved containment authority. Coordinate with system, identity, email, data or application owners when action may disrupt business services.
- Prefer targeted controls and verify collateral impact before blocking shared infrastructure or disabling shared service identities.
- Record exactly what action was taken, by whom, when, why, and what was observed afterward.

## Tier 2 / incident response workflow
- Reconstruct the incident timeline across relevant email, endpoint, identity, network and application sources.
- Hunt the strongest observed indicators across the environment; include negative results and data gaps.
- Assess persistence, credentials, lateral movement, data access and whether containment succeeded.
- Confirm remediation with the owning team and define targeted monitoring for residual risk.

## Escalation criteria
Escalate promptly when any of these apply:
- Confirmed execution, unauthorized access, persistence, successful compromise or ongoing harmful activity.
- A privileged identity, critical system, domain controller, security/backup control or sensitive data repository is involved.
- Multiple hosts/users, broad campaign activity, suspected exfiltration, ransomware behavior or evidence tampering.
- Required logs are missing around critical actions or impact cannot be safely scoped.

## Closure criteria
Close only when:
- Evidence supports a clear disposition (true positive, benign positive, false positive, or inconclusive with stated limitations).
- Scope, affected assets/identities, timeline and containment outcomes are documented.
- Required owner/IR handoff is completed and remaining risks have an explicit owner.
- Any false-positive/tuning follow-up is recorded separately from incident facts.

## False-positive considerations
- Check approved changes, scheduled tasks, scanners, service accounts, deployment systems, remote-management infrastructure and business workflows.
- Rarity, failure volume, a suspicious command string or one event ID is not proof by itself.
- Where corroborating telemetry is unavailable, document the result as inconclusive rather than asserting no compromise.

## Query validation and data gaps
Validate SPL against real field extraction and source coverage before operational use. Confirm the search's time range, event IDs, source indexes, field names, result semantics and benign test cases. The examples have not been run against a live Splunk instance.
