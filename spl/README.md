# Splunk SPL Notes and Validation Guide

The SPL examples are **investigation starting points**, not certified detections. They have not been executed against a live Splunk instance.

## Before running a query
1. Replace illustrative index names (`wineventlog`, `sysmon`, `proxy`, `azure_signin`, `o365_audit`, `cloud_audit`, `dns`, `vpn`, `dlp`, `file_audit`) with your deployment's indexes.
2. Confirm field extraction/capitalization. Common variants include `src` / `src_ip`, `user` / `TargetUserName`, and `dest` / `dest_ip`.
3. Confirm sourcetype, timestamp/timezone, event IDs, lookup behavior and CIM normalization.
4. Inspect raw events, validate time range, and add normalization/aggregation incrementally.
5. Test against a known benign example and an authorized test event; record expected/observed results and false positives.
6. Corroborate significant results with source consoles and related endpoint, identity, email, network or cloud evidence.

## Query quality and safety
- Do not copy sample thresholds into production without baselining.
- Repeated connections, rare domains, failed-logon bursts, or suspicious command strings are not proof by themselves.
- Query syntax and field paths may differ across Splunk versions and TAs; test each block in your target environment.
- Record query text, UTC range, indexes, result count and relevant event IDs in the incident.
- No results means “not observed in searched telemetry,” not “did not occur.”
- Never commit production logs, credentials, sensitive customer data or unnecessary employee data.

## Schema inspection pattern
```spl
index=<your_index> earliest=-24h
| head 100
| table _time host user src dest action EventCode Message
| sort 0 - _time
```
Use `head` for quick schema inspection only. Remove it for full investigation searches.
