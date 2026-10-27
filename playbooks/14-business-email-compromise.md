# 14 — Business Email Compromise (BEC) and Mailbox Abuse

**Default severity:** High–Critical  
**Initial response target:** Triage: 15 minutes; contact finance and identity teams immediately for payment redirection or executive impersonation.  
**MITRE ATT&CK:** T1566 (Phishing), T1114.003 (Email Forwarding Rule), T1098 (Account Manipulation), T1078 (Valid Accounts)

## Objective
Determine whether mailbox access, email rules, delegation or impersonation are being used for fraud, data exposure or onward phishing.

## Indicators that trigger this playbook
- External forwarding or suspicious inbox rule created.
- Unusual mailbox sign-in, delegate grant, transport rule or consent grant.
- Vendor bank-detail change, urgent payment request, executive impersonation, or reply-chain hijack.
- Outbound phishing from a legitimate internal mailbox.

## Pre-triage evidence checklist
- [ ] Mailbox owner, tenant, mailbox type, VIP/finance role, incident and message IDs.
- [ ] Raw headers, sender/Reply-To, Message-ID, recipient list, forwarding destination, rule creation time.
- [ ] Authentication logs, MFA changes, OAuth grants, delegated access, sending activity, audit retention.
- [ ] For financial fraud: payment status and verified finance contact; don't validate requests by replying to the suspect thread.

## Tier 1 triage workflow
### Step 1 — Validate business action
Contact the supposed sender/approver through a separately verified phone number or internal directory. Ask finance whether funds were sent; do not use contact details inside the suspicious message.

### Step 2 — Establish mailbox access
Review successful/failed sign-ins, unfamiliar devices/IPs, session anomalies, MFA reset/enrollment, and mailbox access operations.

### Step 3 — Inspect persistence and message manipulation
Review inbox rules, forwarding, delegates, transport rules, send-as permissions and OAuth grants. Record creation/modification actor and timestamps.

### Step 4 — Scope campaigns
Search sent mail, message trace, recipients, similar subject/body/URL indicators, deleted/recovered items, and other mailboxes sharing indicators.

### Step 5 — Coordinate containment
Use identity/email administrators to revoke sessions, reset credentials, remove unauthorized rules/delegates/grants, block or purge the campaign, and notify finance/legal where required.

### Step 6 — Confirm recovery and fraud controls
Validate rule inventory, user authentication and mailbox access; contact recipients through trusted channels; record whether payment recall or legal escalation was initiated.

## Splunk SPL investigation pivot
Adapt index, sourcetype, field names, event codes and time ranges to your environment. This is an investigation starting point, not a validated production detection.

```spl
index=o365_audit earliest=-7d
| eval actor=coalesce(UserId, user, Actor)
| eval operation=coalesce(Operation, operation)
| search operation IN ("New-InboxRule","Set-InboxRule","UpdateInboxRules","Add-MailboxPermission","Add-RecipientPermission","Set-Mailbox")
| table _time actor operation ClientIP UserId ObjectId Parameters
| sort - _time
```

## Containment guidance
Use approved authority and incident procedures. Preserve relevant logs and evidence before disruptive action when feasible.

- Preserve message headers, mailbox audit events and payment-request evidence before cleanup where feasible.
- Revoke sessions and reset credentials through approved identity operations when compromise is credible.
- Remove malicious rules, delegates, grants and transport rules after preserving their configuration and audit history.
- Finance should independently verify pending transfers and invoke the organization's fraud/payment recall process; notify legal/privacy based on potential exposure.

## Escalation criteria
Escalate to Tier 2 / IR when any of the following apply:

- Any unauthorized money transfer, attempted payment redirection, or access to finance/executive mailboxes.
- Evidence of external forwarding, mass internal phishing, or malicious OAuth access.
- Multiple mailboxes, customer/partner data exposure, or uncertain scope due to logging gaps.

## Closure criteria
Close only when the evidence supports a disposition, scope and remaining gaps are recorded, and actions are complete or assigned.

- Mailbox identity and persistence findings are addressed and independently checked.
- Potentially affected recipients and finance are notified through trusted channels.
- Financial impact, data exposure, scope, and residual monitoring are documented.

## False-positive and validation notes
M365 audit operation names and fields vary by ingestion source; adapt operation filters and index. Legal/privacy reporting obligations are organization- and jurisdiction-specific.

Do not treat an alert name, rarity score, or single query result as proof of compromise. Correlate independent telemetry and document unavailable sources.
