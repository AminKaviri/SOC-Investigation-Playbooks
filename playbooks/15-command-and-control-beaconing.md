# 15 — Command-and-Control (C2) Beaconing

**Default severity:** High–Critical  
**Initial response target:** Triage: 15 minutes; prompt containment decision if endpoint execution is linked.  
**MITRE ATT&CK:** T1071 (Application Layer Protocol), T1095 (Non-Application Layer Protocol), T1105 (Ingress Tool Transfer), T1573 (Encrypted Channel)

## Objective
Determine whether repeated network connections represent malicious command-and-control activity or benign periodic software, and correlate network evidence with endpoint execution.

## Indicators that trigger this playbook
- Periodic outbound connections to rare/new destinations.
- EDR alert for a process contacting suspicious infrastructure.
- High-entropy DNS names, repeated small outbound transfers, or unusual protocol/port usage.
- Threat-intelligence match combined with endpoint or identity anomalies.

## Pre-triage evidence checklist
- [ ] Host, user, process, destination IP/domain, port/protocol, DNS answer, proxy/firewall flow, time window.
- [ ] Connection interval, destination prevalence, duration, bytes, DNS history, TLS metadata if available and reputation context.
- [ ] EDR process tree, command line, signer/hash, parent process, file creation and persistence.
- [ ] Expected agents, update services, monitoring tools, cloud endpoints and sanctioned egress paths.

## Tier 1 triage workflow
### Step 1 — Verify periodicity and destination rarity
Measure frequency, interval consistency, prevalence, duration and bytes. Compare with known baselines and business-purpose allowlists.

### Step 2 — Identify initiating process
Correlate network events to process telemetry. Establish signer, path, hash, parent process, user context and whether process is expected.

### Step 3 — Pivot across telemetry
Search DNS, proxy, firewall, EDR and authentication logs for host and domain/IP. Look for downloads, encoded commands, credential theft, persistence or lateral activity.

### Step 4 — Scope the environment
Search destination indicators, certificate/SNI where available, file hash and process lineage across endpoints. Don't assume every connection to shared infrastructure is malicious.

### Step 5 — Contain based on evidence
If process-level evidence supports compromise, coordinate EDR isolation and controlled network blocks. Preserve process/network evidence and account for shared infrastructure.

### Step 6 — Validate cleanup
Confirm beaconing ceased, process and persistence were addressed, and endpoint passes approved recovery checks.

## Splunk SPL investigation pivot
Adapt index, sourcetype, field names, event codes and time ranges to your environment. This is an investigation starting point, not a validated production detection.

```spl
index=proxy earliest=-24h
| eval dest=coalesce(dest, dest_ip, dhost, url_domain)
| eval client=coalesce(src, src_ip, host)
| bin _time span=5m
| stats count sum(bytes_out) as bytes_out sum(bytes_in) as bytes_in values(url) as urls by _time client dest dest_port
| where count >= 3
| sort - count
```

## Containment guidance
Use approved authority and incident procedures. Preserve relevant logs and evidence before disruptive action when feasible.

- Block a domain/IP only after validating ownership, shared hosting risk and expected business use.
- Isolate host when C2 behavior is corroborated by suspicious process or file evidence, following incident policy.
- Preserve packet/flow records and EDR timelines before indicators expire.
- Expand hunting to related hosts and credential abuse when malware execution or remote command capability is likely.

## Escalation criteria
Escalate to Tier 2 / IR when any of the following apply:

- C2 evidence is tied to a suspicious process, malware, command execution or credential access.
- Multiple endpoints, privileged servers or critical infrastructure are involved.
- Beaconing continues after initial controls, or logs are insufficient to establish scope.

## Closure criteria
Close only when the evidence supports a disposition, scope and remaining gaps are recorded, and actions are complete or assigned.

- Destination and initiating process are understood with evidence-based disposition.
- Malicious indicators and persistence are addressed; related hosts have been searched.
- Detection gaps and false-positive tuning recommendations are recorded.

## False-positive and validation notes
This query groups events into 5-minute buckets; repetition alone does not establish C2. Correlate endpoint and network evidence.

Do not treat an alert name, rarity score, or single query result as proof of compromise. Correlate independent telemetry and document unavailable sources.
