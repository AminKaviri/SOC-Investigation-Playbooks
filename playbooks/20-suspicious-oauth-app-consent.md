# 20 — Suspicious OAuth Application Consent and Service Principal Abuse

**Default severity:** High–Critical  
**Initial response target:** Triage: 15 minutes; urgent response for broad mail/file/admin permissions.  
**MITRE ATT&CK:** T1098 (Account Manipulation), T1528 (Steal Application Access Token), T1078.004 (Cloud Accounts)

## Objective
Determine whether an application grant, service principal, secret or certificate enables unauthorized persistence or data access.

## Indicators that trigger this playbook
- Unexpected user consent or tenant-wide admin consent.
- New service principal credential, redirect URI, app role assignment or privileged API scope.
- Unfamiliar publisher/application accessing mail, files or directory data.
- Unusual app activity after phishing or suspicious sign-in.

## Pre-triage evidence checklist
- [ ] Tenant/app/client ID, publisher, requesting user, consent scopes, grant type and timestamp.
- [ ] Audit actor, service-principal owner, credentials, certificate thumbprint/expiry and redirect URI.
- [ ] Sign-in/audit events, application activity, accessed resources and sanctioned-app baseline.
- [ ] Whether permission was user-level or admin-consented and which objects it can access.

## Tier 1 triage workflow
### Step 1 — Identify object and grant
Capture app/client ID, service principal object ID, publisher, scope/roles, consent actor and grant time.

### Step 2 — Determine effective permissions
Separate delegated permissions from application permissions; identify mail/file/directory/admin privileges and affected resources.

### Step 3 — Review credentials and ownership
Inspect new secrets/certificates, redirect URIs, owners, app role assignments and whether the app is sanctioned.

### Step 4 — Correlate app behavior
Review sign-ins/audit logs for API calls, mailbox/file access, directory enumeration and changes after consent.

### Step 5 — Contain the grant
Coordinate disabling the service principal, revoking grants/credentials or removing permissions after preserving object state and assessing dependencies.

### Step 6 — Hunt for adjacent compromise
Investigate consent-granting user, other grants, sign-ins, mailbox changes and other identities that approved the same app.

## Splunk SPL investigation pivot
Adapt index, sourcetype, field names, event codes and time ranges to your environment. This is an investigation starting point, not a validated production detection.

```spl
index=entra_audit earliest=-30d
| eval actor=coalesce(InitiatedBy.user.userPrincipalName, user, Actor)
| eval operation=coalesce(ActivityDisplayName, Operation, operation)
| search operation="*consent*" OR operation="*service principal*" OR operation="*credential*"
| table _time actor operation TargetResources Result
| sort - _time
```

## Containment guidance
Use approved authority and incident procedures. Preserve relevant logs and evidence before disruptive action when feasible.

- Record app IDs, grants, scopes, credentials and audit event IDs before changes.
- Use tenant identity administrators to disable/revoke malicious access after approval; check dependencies before disabling legitimate integrations.
- Rotate exposed app credentials and review other secrets accessible to the app.
- Review affected users/resources when delegated consent is involved; app-only permissions may have tenant-wide reach.

## Escalation criteria
Escalate to Tier 2 / IR when any of the following apply:

- Application permission grants broad mail, file, directory or privileged access.
- Unknown app credentials or malicious service-principal activity confirmed.
- Evidence indicates data access/exfiltration or grant followed compromised sign-in.

## Closure criteria
Close only when the evidence supports a disposition, scope and remaining gaps are recorded, and actions are complete or assigned.

- App permissions and credentials are reviewed; malicious grants are removed/disabled.
- Application activity and affected users/resources are documented.
- Sanctioned-app inventory is updated and adjacent identity compromise addressed.

## False-positive and validation notes
Use the tenant's actual audit operation names and field schema. Check ATT&CK technique IDs against the version you reference.

Do not treat an alert name, rarity score, or single query result as proof of compromise. Correlate independent telemetry and document unavailable sources.
