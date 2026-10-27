# 27 — Credential Access and Dumping

**Default severity:** High–Critical  
**MITRE ATT&CK:** T1003 (OS Credential Dumping), T1555 (Credentials from Password Stores), T1552 (Unsecured Credentials)

## Objective
Determine whether credential access attempts succeeded, which credential stores/identities may be exposed, and whether the actor used the results elsewhere.

## Indicators that trigger this playbook
- EDR detects LSASS access, dump utility, suspicious minidump creation or credential-store access.
- Unexpected secrets/credential-file reads, browser credential access or access to password managers.
- Credential-access indicator followed by admin logon, ticket abuse or remote execution.

## Pre-triage evidence checklist
- [ ] Host, user, process tree, signer/hash, full command line, object/file path and exact UTC time.
- [ ] EDR alert details, Sysmon process/file events, security/audit logs and dump artifact metadata.
- [ ] Privileged accounts logged on to the host, exposed service accounts, privileged access workstation policy and asset criticality.
- [ ] Subsequent authentication from the same identity or source to additional systems.

## Tier 1 triage workflow
### Step 1 — Confirm access behavior
Determine whether telemetry shows an attempted open/access, a dump artifact, a completed tool execution, or only a heuristic alert.

### Step 2 — Establish privileged credential exposure
Identify accounts/sessions present on the host at the time, including administrators, service accounts and interactive users.

### Step 3 — Inspect process and artifact lineage
Review parent process, signer, path, command line, dump/file artifacts, security-control alerts and deletion attempts.

### Step 4 — Hunt for credential reuse
Search for logons, Kerberos/NTLM activity, new remote sessions, privileged group changes and access to sensitive hosts after the event.

### Step 5 — Contain and rotate proportionately
Coordinate endpoint isolation and credential/session rotation based on scope; prioritize privileged identities and avoid rotating shared secrets without service-owner coordination.

### Step 6 — Verify follow-on risk
Check related hosts, persistence, remote execution and whether credentials were used from a different device.

## Splunk SPL investigation pivot
Adapt the index, sourcetype, fields and time window. This is an investigation pivot, not a validated detection.

```spl
index=sysmon earliest=-24h (EventCode=1 OR EventCode=10 OR EventCode=11)
| eval proc=lower(coalesce(Image, process_name)), cmd=lower(coalesce(CommandLine, process_command_line))
| search proc="*procdump*" OR proc="*rundll32.exe" OR cmd="*lsass*" OR cmd="*sekurlsa*" OR cmd="*comsvcs.dll*"
| table _time host user ParentImage Image CommandLine TargetFilename GrantedAccess CallTrace
| sort - _time
```

## Containment guidance
Use approved incident authority, preserve evidence where feasible, and coordinate high-impact actions with service owners.

- Preserve process/access telemetry and suspected artifacts before cleanup when feasible.
- Isolate the endpoint under approved authority when credential dumping is credibly active.
- Rotate or revoke exposed privileged credentials/sessions using a clean admin plane; assess dependencies for service accounts.
- Hunt logons and privilege use for exposed identities across the environment.

## Escalation criteria
- Credible LSASS/credential-store access, dump artifact, privileged account exposure or subsequent suspicious logon.
- Credential access on domain controller, identity tier, backup, or security infrastructure.
- Multiple hosts/identities or evidence of Pass-the-Hash/Pass-the-Ticket behavior.

## Closure criteria
- Credential exposure scope and follow-on identity activity assessed.
- Required sessions/credentials are rotated or explicitly risk-accepted by owners.
- Evidence, containment, and related-host hunting recorded.

## False-positive and validation notes
Process names and access fields vary by EDR/Sysmon configuration; these strings are not comprehensive and should be treated as triage pivots.

Correlate independent telemetry. An alert name or isolated query result does not prove compromise. Record sources not searched, retention gaps and unresolved hypotheses.
