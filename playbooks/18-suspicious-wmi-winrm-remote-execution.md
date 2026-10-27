# 18 — Suspicious WMI, WinRM and Remote Execution

**Default severity:** High–Critical  
**Initial response target:** Triage: 15 minutes; immediate Tier 2 handoff for remote execution across multiple hosts.  
**MITRE ATT&CK:** T1021.006 (Windows Remote Management), T1047 (Windows Management Instrumentation), T1059 (Command and Scripting Interpreter), T1569.002 (Service Execution)

## Objective
Determine whether remote management is authorized administration or attacker-driven execution and map origin, targets, credentials and outcomes.

## Indicators that trigger this playbook
- WMI/WinRM activity from workstation or account not normally used for administration.
- PowerShell remoting, wmiprvse.exe child process, remote service creation, or unusual admin-share usage.
- One origin initiating remote command activity across many endpoints.
- Remote execution following suspicious authentication or credential access.

## Pre-triage evidence checklist
- [ ] Origin host/user, destination host, protocol, process tree/command line, time range and logon session.
- [ ] Windows Security, PowerShell, Sysmon process/network, WinRM/WMI operational logs and EDR data.
- [ ] Asset criticality, admin jump-host inventory, automation-account owners and maintenance tickets.
- [ ] Success/failure status and resulting process, service, task or file.

## Tier 1 triage workflow
### Step 1 — Identify the execution mechanism
Distinguish WinRM/PowerShell remoting, WMI, PsExec/service creation, SMB admin shares and legitimate endpoint-management tooling.

### Step 2 — Trace source to target
Build source-target timeline, including logon IDs, account, source IP, process parent and administrative share/service operations.

### Step 3 — Validate authorization
Compare origin, identity, target and command with approved admin paths, deployment tools and scheduled jobs.

### Step 4 — Inspect executed actions
Review commands, scripts, child processes, service/task creation, downloads, credential use and security-control changes on targets.

### Step 5 — Scope movement
Search all targets touched by origin/account and additional origins using the same command/tool/indicator.

### Step 6 — Contain and preserve
Coordinate source/target isolation, credential revocation and tool/indicator blocks when malicious. Preserve EDR, process, PowerShell and Windows logs.

## Splunk SPL investigation pivot
Adapt index, sourcetype, field names, event codes and time ranges to your environment. This is an investigation starting point, not a validated production detection.

```spl
index=sysmon EventCode=1 earliest=-24h
| eval image=lower(Image), parent=lower(ParentImage), cmd=lower(CommandLine)
| search (image="*wmiprvse.exe" OR image="*wsmprovhost.exe" OR parent="*wmiprvse.exe" OR cmd="*winrs *" OR cmd="*invoke-command*")
| table _time host user ParentImage Image CommandLine ProcessGuid ParentProcessGuid
| sort - _time
```

## Containment guidance
Use approved authority and incident procedures. Preserve relevant logs and evidence before disruptive action when feasible.

- Isolate endpoints only with approved EDR/IR authority and consider impact to critical servers.
- Rotate credentials only after mapping service dependencies and coordinating with identity/operations teams.
- Block the specific unauthorized route or tool indicators, not all WinRM globally.
- Preserve command lines and logon IDs; investigate downstream execution before declaring containment complete.

## Escalation criteria
Escalate to Tier 2 / IR when any of the following apply:

- Remote execution touches a domain controller, backup, security or critical server.
- Multiple hosts are targeted or credentials are reused across endpoints.
- Remote execution is linked to suspicious login, persistence, or ransomware preparation.

## Closure criteria
Close only when the evidence supports a disposition, scope and remaining gaps are recorded, and actions are complete or assigned.

- Origin, targets and executed actions are accounted for.
- Unauthorized access is contained and impacted systems reviewed.
- Known administration tooling is distinguished from malicious activity in findings/tuning.

## False-positive and validation notes
WMI/WinRM coverage needs Windows and Sysmon/EDR telemetry. String-based SPL pivots miss variants; supplement with normalized event fields.

Do not treat an alert name, rarity score, or single query result as proof of compromise. Correlate independent telemetry and document unavailable sources.
