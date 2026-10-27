# 25 — Cloud Control-Plane Abuse (AWS/Azure/GCP)

**Default severity:** High–Critical  
**Initial response target:** Initial triage: 15 minutes; immediate escalation for admin/production control-plane abuse.  
**MITRE ATT&CK:** T1078.004 (Cloud Accounts), T1098 (Account Manipulation), T1578 (Modify Cloud Compute Infrastructure), T1537 (Transfer Data to Cloud Account)

## Objective
Determine whether cloud API actions, infrastructure changes, role assumptions, key creation or storage policy changes are unauthorized and identify resources affected.

## Indicators that trigger this playbook
- Unexpected IAM role/policy/credential changes or access-key creation.
- Public storage exposure, snapshot/image sharing, security-group modification or unusual compute creation.
- Cloud audit anomaly from uncommon identity, region, IP or user agent.
- Large data export, key vault access, logging disablement or security-control modification.

## Pre-triage evidence checklist
- [ ] Provider, account/subscription/project, actor and assumed role, session ID, source IP/user-agent, region and event ID.
- [ ] API action, resource ID, before/after config, policy diff, key/session origin and change/ticket context.
- [ ] Cloud audit, identity sign-in, workload/flow, storage access, key management and billing/resource logs.
- [ ] Resource sensitivity, cross-account relationships and approved automation identities.

## Tier 1 triage workflow
### Step 1 — Validate API event
Identify action, actor, session/role chain, source and result. Verify success and whether it matches deployment/automation.

### Step 2 — Assess identity and persistence
Review new keys, roles, trust-policy changes, federated identities, service accounts, access policies and credential access.

### Step 3 — Inspect infrastructure and data impact
Check compute launch/modify, storage exposure, snapshot sharing, downloads, key vault use, network security and audit logging changes.

### Step 4 — Scope the session
Trace role assumptions and related calls by request ID, identity, source IP, region and adjacent accounts/projects.

### Step 5 — Contain through cloud owner
Preserve state then revoke compromised credentials/roles, restore secure policies and restrict resources after assessing dependencies.

### Step 6 — Validate control-plane integrity
Re-enable/protect logging, verify IAM and exposed resource state, review billing anomalies and hunt across related accounts.

## Splunk SPL investigation pivot
Adapt index, sourcetype, field names, event codes and time ranges to your environment. This is an investigation starting point, not a validated production detection.

```spl
index=cloud_audit earliest=-24h
| eval actor=coalesce(userIdentity.arn, user, principalId), action=coalesce(eventName, operationName, action), resource=coalesce(requestParameters.resourceId, resourceId, object)
| search action="*CreateAccessKey*" OR action="*PutBucketPolicy*" OR action="*AuthorizeSecurityGroupIngress*" OR action="*StopLogging*" OR action="*CreateRole*" OR action="*SetIamPolicy*"
| table _time actor action resource sourceIPAddress awsRegion errorCode userAgent
| sort - _time
```

## Containment guidance
Use approved authority and incident procedures. Preserve relevant logs and evidence before disruptive action when feasible.

- Preserve audit and configuration state before changing roles, policies, keys or resources.
- Use provider-native revocation through trusted admin identity; protect break-glass and service principals.
- Treat public storage/cross-account sharing as high priority and quantify data access separately from exposure config.
- If logging was disabled, restore it and identify missing windows and alternate logs.

## Escalation criteria
Escalate to Tier 2 / IR when any of the following apply:

- Privilege/identity changes, logging disablement or sensitive key/data access is confirmed.
- Production, cross-account resources, regulated data or public exposure involved.
- Resource deletion/destruction or cost-intensive resource creation is underway.

## Closure criteria
Close only when the evidence supports a disposition, scope and remaining gaps are recorded, and actions are complete or assigned.

- Affected identities, API calls, resources and changed configs are known.
- Credentials and permissions are remediated; data exposure and logging gaps assessed.
- Recovery is verified by cloud owner and residual posture issues tracked.

## False-positive and validation notes
Provider schemas vary; map this SPL separately for CloudTrail, Azure Activity Logs and GCP Audit Logs.

Do not treat an alert name, rarity score, or single query result as proof of compromise. Correlate independent telemetry and document unavailable sources.
