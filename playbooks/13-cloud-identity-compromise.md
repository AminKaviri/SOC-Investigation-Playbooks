# 13 — Cloud Identity Compromise (Microsoft Entra ID / SaaS)

**Default severity:** High–Critical  
**Initial response target:** Initial triage: 15 minutes; immediate escalation for privileged identities or active abuse.  
**MITRE ATT&CK:** T1078.004 (Cloud Accounts), T1098 (Account Manipulation), T1528 (Steal Application Access Token), T1621 (Multi-Factor Authentication Request Generation)

## Objective
Determine whether a cloud identity or SaaS session is compromised, establish attacker access and persistence, and coordinate safe session revocation and access containment.

## Indicators that trigger this playbook
- Risky sign-in or impossible-travel alert backed by sign-in telemetry.
- MFA fatigue, unexpected MFA enrollment, unfamiliar device, or token/session anomaly.
- New OAuth consent, service principal credential, mailbox delegation, forwarding rule, or privileged role assignment.
- Successful sign-in after password spraying or from infrastructure inconsistent with normal account use.

## Pre-triage evidence checklist
- [ ] User, UPN, tenant, role, and business criticality.
- [ ] Sign-in event IDs, source IP/ASN, geo, user agent, device ID, app/resource, authentication and Conditional Access results.
- [ ] MFA methods, recent resets, OAuth grants, app registrations, role changes, refresh-token/session events where available.
- [ ] Known travel, VPN, managed-device and change-window context.

## Tier 1 triage workflow
### Step 1 — Confirm authentication outcome
Separate failed attempts from successful sign-ins. Identify authentication strength, MFA details, device compliance, Conditional Access result, and resource accessed.

### Step 2 — Establish baseline and scope
Compare source IP, ASN, location, device, user-agent, application, sign-in cadence and peers. Search related accounts from the same source and other sign-ins for the affected identity.

### Step 3 — Hunt for persistence and privilege changes
Review new MFA methods, authentication-method changes, OAuth consent grants, service principal secrets/certificates, application permissions, role assignments, mailbox rules and delegates.

### Step 4 — Assess actions and data access
Review audit logs for file downloads, mailbox access, admin changes, token-related anomalies, app access, sensitive resource operations, and the bounded interval from first suspicious sign-in to last activity.

### Step 5 — Contain under approved procedure
Coordinate password reset, session/token revocation, removal of malicious auth methods or grants, and temporary account disablement when policy permits. Preserve audit events first when practical.

### Step 6 — Validate recovery
Confirm access through a known-good device, trusted MFA configuration, reviewed grants/roles, and cessation of suspicious sessions.

## Splunk SPL investigation pivot
Adapt index, sourcetype, field names, event codes and time ranges to your environment. This is an investigation starting point, not a validated production detection.

```spl
index=azure_signin earliest=-24h
| eval principal=coalesce(userPrincipalName, user, UserPrincipalName)
| eval src_ip=coalesce(ipAddress, src, IPAddress)
| eval app=coalesce(appDisplayName, app, ResourceDisplayName)
| stats count values(resultDescription) values(status) values(app) values(deviceDetail.deviceId) values(deviceDetail.operatingSystem) values(conditionalAccessStatus) by principal src_ip
| sort - count
```

## Containment guidance
Use approved authority and incident procedures. Preserve relevant logs and evidence before disruptive action when feasible.

- For confirmed active compromise, coordinate session revocation and password reset with the identity owner and incident commander.
- Remove unrecognized MFA methods, OAuth grants, secrets and role changes only after recording objects and following change-control/IR policy.
- Block indicators only when collateral impact is understood; don't broadly block shared corporate egress IPs based on one sign-in.
- If privileged identity abuse is suspected, assess tenant-wide administrative activity and adjacent identities immediately.

## Escalation criteria
Escalate to Tier 2 / IR when any of the following apply:

- Privileged/admin identity, malicious OAuth permission, service principal credential abuse, or role assignment.
- Confirmed access to email/files or evidence of data extraction.
- Persistence survives password reset, multiple identities share infrastructure, or logging coverage is incomplete.

## Closure criteria
Close only when the evidence supports a disposition, scope and remaining gaps are recorded, and actions are complete or assigned.

- Suspicious sign-in sequence is explained or confirmed and its scope recorded.
- Sessions and persistence mechanisms are addressed, and the owner validates safe access.
- Audit gaps, residual risks, and all approved containment actions are documented.

## False-positive and validation notes
Entra sign-in index fields differ across native, CIM, and custom pipelines. Validate against the tenant's actual sign-in and audit schema.

Do not treat an alert name, rarity score, or single query result as proof of compromise. Correlate independent telemetry and document unavailable sources.
