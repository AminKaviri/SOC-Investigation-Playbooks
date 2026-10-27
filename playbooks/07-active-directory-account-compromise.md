# 07 — Active Directory Account Compromise

## Tier 1
- Identify account, source workstation/IP, authentication type, time window, and privilege level.
- Review 4624/4625 events, password resets, lockouts, account creation, and group membership changes.
- Check for impossible or unusual access patterns against known VPN, service-account, and admin activity.

## SPL pivots
```spl
index=wineventlog (EventCode=4624 OR EventCode=4625) earliest=-24h
| stats count(eval(EventCode=4624)) as success count(eval(EventCode=4625)) as failure values(IpAddress) as ips values(WorkstationName) as workstations by TargetUserName
| sort - failure
```

```spl
index=wineventlog (EventCode=4720 OR EventCode=4728 OR EventCode=4732 OR EventCode=4756 OR EventCode=4724 OR EventCode=4723) earliest=-7d
| table _time host EventCode SubjectUserName TargetUserName MemberName GroupName
| sort - _time
```

```spl
index=wineventlog EventCode=4740 earliest=-7d
| table _time host TargetUserName CallerComputerName
| sort - _time
```

## Tier 2
- Correlate identity provider/MFA logs, mailbox rules, endpoint process events, and group changes.
- Determine whether privileges changed and what resources the account accessed.
- Coordinate credential resets or account disablement through approved response procedures.

## Escalation
Escalate confirmed unauthorized success, privileged-group change, suspicious password reset, or post-authentication activity. Distinguish account misuse from ordinary failed logons.
