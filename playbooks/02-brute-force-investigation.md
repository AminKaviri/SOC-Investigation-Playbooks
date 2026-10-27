# 02 — Brute Force Investigation

## Objective
Distinguish password guessing, password spraying, and expected authentication failures from successful account compromise.

## Tier 1
- Identify affected accounts, source IPs, destination hosts, time window, and failure volume.
- Look for distributed attempts across many accounts and successful logons after failures.
- Check lockouts and whether source IPs belong to approved scanners, VPNs, or identity infrastructure.
- Escalate any suspicious success, privileged account targeting, or broad spray pattern.

## Splunk SPL
Windows failed logons (4625):
```spl
index=wineventlog EventCode=4625 earliest=-24h
| stats count dc(TargetUserName) as unique_users values(TargetUserName) as users values(WorkstationName) as workstations by IpAddress
| sort - count
```

Successful logons after failure activity (4624; tune by source and account):
```spl
index=wineventlog (EventCode=4624 OR EventCode=4625) earliest=-24h
| stats count(eval(EventCode=4625)) as failures count(eval(EventCode=4624)) as successes values(host) as hosts values(LogonType) as logon_types by IpAddress TargetUserName
| where failures>0 AND successes>0
| sort - failures
```

Account lockouts (4740):
```spl
index=wineventlog EventCode=4740 earliest=-24h
| table _time host TargetUserName CallerComputerName
| sort - _time
```

## Tier 2
- Correlate source IP reputation, VPN/NAT, host ownership, and authentication protocol.
- Validate success context, logon type, MFA, subsequent process activity, and privilege changes.
- Determine whether multiple accounts or systems are in scope.

## Escalation / closure
Escalate successful suspicious authentication, privileged account targeting, confirmed spray, or evidence of post-authentication activity. A high failure count alone is not proof of compromise.
