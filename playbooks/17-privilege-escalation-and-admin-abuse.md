# 17 — Privilege Escalation and Administrative Abuse

**Default severity:** High–Critical  
**Initial response target:** Initial triage: 15 minutes; immediate escalation for domain/tenant admin or security-control bypass.  
**MITRE ATT&CK:** T1098 (Account Manipulation), T1068 (Exploitation for Privilege Escalation), T1548 (Abuse Elevation Control Mechanism), T1078 (Valid Accounts)

## Objective
Determine whether a new privilege, elevated token, admin group change, service account change or administrative action is authorized.

## Indicators that trigger this playbook
- Unexpected addition to Domain Admins, local Administrators or privileged cloud roles.
- New privileged account, service account credential, delegation or group membership.
- Unusual UAC/elevation, access-control changes, security tool disablement or admin activity from atypical hosts.
- Privileged actions by non-admin account or outside approved change window.

## Pre-triage evidence checklist
- [ ] Actor and target accounts, source host/IP, group/role, operation, timestamp, ticket/change ID.
- [ ] Before/after membership or permissions, privilege level, logon session, command line and parent process.
- [ ] AD/Windows/Entra audit logs, EDR events, change records and account owner confirmation.
- [ ] Whether identity is privileged by design and whether use matches expected admin workstation patterns.

## Tier 1 triage workflow
### Step 1 — Validate the change
Compare operation against approved change request and contact the system owner through a trusted channel.

### Step 2 — Identify actor and access path
Correlate source logon, logon type, authentication events, process tree, remote tools and session timeline.

### Step 3 — Assess privilege scope
Enumerate related group membership, role assignments, delegated permissions, new accounts, service principals and secrets created by actor.

### Step 4 — Check follow-on activity
Search for persistence, credential access, logging changes, remote execution, sensitive data access and additional identity changes.

### Step 5 — Contain safely
Coordinate removal of unauthorized privileges and session invalidation with identity owners. Preserve before/after state and protect necessary break-glass accounts.

### Step 6 — Verify least privilege
Confirm unauthorized rights are removed, known-good admin access remains, and related identities/endpoints were reviewed.

## Splunk SPL investigation pivot
Adapt index, sourcetype, field names, event codes and time ranges to your environment. This is an investigation starting point, not a validated production detection.

```spl
index=wineventlog earliest=-7d (EventCode=4728 OR EventCode=4732 OR EventCode=4756 OR EventCode=4672 OR EventCode=4738)
| table _time host EventCode SubjectUserName MemberName TargetUserName GroupName Message
| sort - _time
```

## Containment guidance
Use approved authority and incident procedures. Preserve relevant logs and evidence before disruptive action when feasible.

- Capture exact group/role state and event details before altering membership when feasible.
- Use approved identity-admin procedures to remove malicious privileges and revoke sessions; preserve emergency access.
- If domain/tenant admin is involved, expand immediately to all privileged accounts and administrative endpoints.
- Do not remediate unknown group membership without owner validation; it may disrupt business-critical services.

## Escalation criteria
Escalate to Tier 2 / IR when any of the following apply:

- Any domain, enterprise, tenant, backup, identity-security or EDR administrator compromise.
- Privilege change has no approved ticket or comes from unexpected source.
- Actor disables controls, creates persistent access, or changes multiple identities.

## Closure criteria
Close only when the evidence supports a disposition, scope and remaining gaps are recorded, and actions are complete or assigned.

- Changes are matched to authorization or contained and attributed.
- Privileged identity inventory, adjacent hosts and follow-on actions are reviewed.
- Access restoration and emergency account handling are documented.

## False-positive and validation notes
Windows Event IDs and field names depend on forwarding/TA extraction. Validate event field extraction and include domain-controller logs.

Do not treat an alert name, rarity score, or single query result as proof of compromise. Correlate independent telemetry and document unavailable sources.
