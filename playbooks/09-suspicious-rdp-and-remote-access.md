# 09 — Suspicious RDP and Remote Access

## Tier 1
- Identify account, source IP/host, destination host, time, and logon type.
- For Windows 4624, logon type 10 commonly indicates RemoteInteractive/RDP; validate local event semantics.
- Correlate VPN, RD Gateway, jump-host, and MFA logs where available.

## SPL pivots
```spl
index=wineventlog EventCode=4624 LogonType=10 earliest=-7d
| stats count values(IpAddress) as source_ips values(host) as destinations by TargetUserName
| sort - count
```

```spl
index=wineventlog EventCode=4625 earliest=-24h
| stats count dc(TargetUserName) as users values(TargetUserName) as account_list by IpAddress host
| sort - count
```

```spl
index=wineventlog earliest=-7d (EventCode=1149 OR EventCode=4624 OR EventCode=4625)
| table _time host EventCode TargetUserName IpAddress Message
| sort - _time
```

## Tier 2
- Confirm whether access was expected, authorized, and within normal hours.
- Review preceding failed logons and subsequent process/service/task activity.
- Determine if the source is a VPN egress/NAT address before attribution.

## Escalation
Escalate unexplained access to critical servers, privileged accounts from unusual sources, or RDP followed by suspicious execution. Event 1149 availability depends on RDP log collection.
