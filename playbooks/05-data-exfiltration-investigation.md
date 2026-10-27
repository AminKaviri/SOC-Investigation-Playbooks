# 05 — Data Exfiltration Investigation

## Objective
Determine whether sensitive data was staged, accessed, or transferred outside approved boundaries.

## Tier 1
- Identify user, endpoint, data source, destination, time range, volume, and alert trigger.
- Separate evidence of archive/staging from evidence of actual transfer.
- Review proxy, firewall, DNS, cloud audit, DLP, file-share, and endpoint telemetry where available.
- Escalate sensitive data access plus suspicious outbound transfer, unusual destinations, or policy violations.

## Splunk SPL
Sysmon network connections:
```spl
index=sysmon EventCode=3 earliest=-24h
| stats count sum(bytes_out) as bytes_out values(DestinationPort) as ports values(Image) as processes by host User DestinationIp
| sort - bytes_out
```
Note: `bytes_out` is illustrative and may not exist in Sysmon events. Use proxy/firewall byte fields for volume.

Archive/staging commands:
```spl
index=sysmon EventCode=1 earliest=-24h
| search (CommandLine="*7z*" OR CommandLine="*rar*" OR CommandLine="*Compress-Archive*" OR CommandLine="*makecab*" OR CommandLine="*robocopy*")
| table _time host User ParentImage Image CommandLine
| sort - _time
```

DNS pivots:
```spl
index=sysmon EventCode=22 earliest=-24h
| stats count dc(QueryName) as unique_domains values(QueryName) as domains by host User
| sort - unique_domains
```

## Tier 2
- Verify the data classification and whether the user had a legitimate business reason.
- Correlate staging files with proxy/cloud logs and quantify confirmed transferred bytes.
- Identify recipient, destination ownership, and any related credential or endpoint compromise.

## Escalation / closure
Escalate only when supported by evidence of unauthorized access or transfer. Large outbound traffic or archive creation alone is not proof of exfiltration.
