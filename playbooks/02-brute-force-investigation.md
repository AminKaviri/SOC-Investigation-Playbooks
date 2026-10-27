# 02 — Brute Force Investigation

**Default severity:** Medium–Critical  
**Triage target:** 15–30 minutes, based on impact  
**MITRE ATT&CK:** T1110.001, T1110.003

## Objective
Distinguish password guessing, password spraying and expected authentication failure, then determine whether access succeeded.

## Indicators that trigger this playbook
- Many failed logons against one account or source, account lockouts, password-spray detections, or unfamiliar authentication origin.
- Failed attempts followed by a successful logon, especially to a privileged account or multiple hosts.

## Pre-triage evidence checklist
- [ ] Account(s), source IP/host, destination(s), result/status, authentication type and exact time window.
- [ ] Whether success followed failures, lockout behavior, MFA outcomes, and account privilege.
- [ ] Known VPN/NAT/proxy egress, scanners, service accounts and identity-provider logs.

## Tier 1 triage workflow
### Step 1 — Determine successful access first
Separate failed attempts from success and identify any successful logon after the failure burst; raise urgency when admin accounts or sensitive systems are involved.

### Step 2 — Classify attack pattern
Single account/many sources suggests targeted guessing; many accounts/one source may suggest spraying; distributed origin requires correlation, not simple IP counting.

### Step 3 — Validate source context
Check VPN, NAT, scanners, known identity-provider infrastructure and expected automation before attributing an IP.

### Step 4 — Scope subsequent activity
Search successful sessions, MFA events, password resets, privilege changes and access to additional hosts after the suspect window.

### Step 5 — Contain and monitor
Coordinate credential reset/session revocation or source controls when warranted; document lockout and service-account impact.

## Splunk SPL investigation pivots

Adapt indexes, sourcetypes, field names, event codes and time range to your environment. These are investigation starting points, not production-certified detections.

```spl
index=wineventlog EventCode=4625 earliest=-24h
| eval account=coalesce(TargetUserName, Account_Name, user), src_ip=coalesce(IpAddress, Source_Network_Address, src), dest_host=host
| stats count dc(dest_host) as hosts values(dest_host) as targets values(Status) as statuses by account src_ip
| sort - count
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
