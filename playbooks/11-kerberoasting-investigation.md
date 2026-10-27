# 11 — Kerberoasting Investigation

## Objective
Identify anomalous Kerberos service-ticket requests that may support offline password cracking. Event 4769 requires domain-controller audit coverage.

## Tier 1
- Identify requester, service account/SPN, domain controller, time range, ticket encryption type, and request volume.
- Compare against baseline for service accounts, scanners, and legitimate applications.
- Do not classify a single 4769 event as malicious without context.

## SPL pivot
```spl
index=wineventlog EventCode=4769 earliest=-24h
| stats count dc(ServiceName) as unique_services values(ServiceName) as services values(TicketEncryptionType) as encryption_types by ClientAddress TargetUserName
| sort - count
```

Focused review (field names vary by parser):
```spl
index=wineventlog EventCode=4769 earliest=-24h
| table _time host ClientAddress TargetUserName ServiceName TicketEncryptionType Status
| sort - _time
```

## Tier 2
- Validate SPNs and service-account privilege, password age, and whether legacy encryption is expected.
- Correlate with logon events, endpoint execution, and other directory reconnaissance.
- Consult the AD team before changing service-account configuration.

## Escalation
Escalate abnormal high-volume service-ticket requests, unusual requester-to-SPN patterns, and corroborating suspicious activity. Encryption-type field values vary; validate parsing before detection tuning.
