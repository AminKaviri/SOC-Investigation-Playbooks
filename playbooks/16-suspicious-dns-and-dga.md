# 16 — Suspicious DNS, DGA and DNS Tunneling

**Default severity:** Medium–Critical  
**Initial response target:** Triage: 30 minutes; immediate escalation when DNS activity correlates with malware execution or data transfer.  
**MITRE ATT&CK:** T1071.004 (DNS), T1568.002 (Domain Generation Algorithms), T1048 (Exfiltration Over Alternative Protocol)

## Objective
Differentiate normal DNS noise from algorithmically generated domains, tunneling, fast-flux or attacker-controlled name resolution.

## Indicators that trigger this playbook
- High NXDOMAIN volume or many unique subdomains from one host.
- Long/high-entropy labels, abnormal TXT query volume, or unusually large DNS responses.
- Rare domains requested by hosts with suspicious processes or malware alerts.
- DNS requests bypass expected resolvers or use unexpected DoH/DoT paths.

## Pre-triage evidence checklist
- [ ] Client host/IP, resolver, qname, qtype, rcode, response size, time window, process attribution if available.
- [ ] Query rate, unique domains/labels, NXDOMAIN ratio, record types, TTL and destination IP prevalence.
- [ ] Proxy/firewall logs, EDR process tree, newly created files and adjacent DNS activity.
- [ ] Known internal zones, software telemetry, security scanners and sanctioned encrypted-DNS clients.

## Tier 1 triage workflow
### Step 1 — Quantify DNS behavior
Compute query count, unique names, NXDOMAIN ratio, dominant types, label length and per-host distribution. Compare to baseline.

### Step 2 — Inspect suspicious names
Review full query strings and record types; identify repeating encoded subdomains, long labels, unusual TXT requests, or rapidly rotating domains.

### Step 3 — Resolve client process and intent
Where EDR supports DNS attribution, connect queries to process, user, parent process and command line. Review domain prevalence and history.

### Step 4 — Correlate network and endpoint evidence
Search resolved IP connections, TLS/proxy events, file downloads, persistence and process alerts. Consider legitimate CDNs and security software before blocking.

### Step 5 — Contain carefully
Coordinate endpoint isolation or resolver/proxy blocking only when corroborated. Avoid broad blocks against shared hosting or legitimate external DNS services.

### Step 6 — Confirm scope
Search the same domain/label pattern across clients and resolvers; document retained query data and visibility gaps.

## Splunk SPL investigation pivot
Adapt index, sourcetype, field names, event codes and time ranges to your environment. This is an investigation starting point, not a validated production detection.

```spl
index=dns earliest=-24h
| eval client=coalesce(src, src_ip, client_ip)
| eval qname=lower(coalesce(query, query_name, domain))
| eval rcode=coalesce(rcode, reply_code, response_code)
| stats count dc(qname) as unique_names count(eval(rcode="NXDOMAIN")) as nxdomain values(qtype) as qtypes by client
| eval nxdomain_ratio=round(nxdomain/count,3)
| where unique_names > 50 OR nxdomain_ratio > 0.3
| sort - unique_names
```

## Containment guidance
Use approved authority and incident procedures. Preserve relevant logs and evidence before disruptive action when feasible.

- Preserve full query names and resolver logs because truncation removes tunnel indicators.
- Use targeted containment with resolver, network and endpoint teams; document approved DNS sinkhole/block.
- If tunneling is plausible, review volume and sensitivity of outbound data and escalate possible exfiltration.
- Do not classify a domain as DGA solely because it is rare or syntactically unusual.

## Escalation criteria
Escalate to Tier 2 / IR when any of the following apply:

- DNS patterns align with malware/C2 telemetry or suspicious endpoint process behavior.
- Evidence suggests DNS tunneling or sensitive data transfer.
- Multiple endpoints share the pattern or resolver logging has critical blind spots.

## Closure criteria
Close only when the evidence supports a disposition, scope and remaining gaps are recorded, and actions are complete or assigned.

- Domain/query behavior is explained or confirmed malicious with supporting evidence.
- Any blocks, endpoint actions and related-host searches are recorded.
- False-positive patterns and threshold tuning are documented.

## False-positive and validation notes
DNS fields vary. Normalize rcode values before relying on NXDOMAIN comparison. Unique-name thresholds require baseline tuning.

Do not treat an alert name, rarity score, or single query result as proof of compromise. Correlate independent telemetry and document unavailable sources.
