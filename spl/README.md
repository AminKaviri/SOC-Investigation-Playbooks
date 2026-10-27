# Splunk SPL Notes

The SPL examples in this project are investigation starting points and have not been validated against a live Splunk instance.

## Adapt before use
- Replace illustrative indexes such as `sysmon`, `wineventlog`, and `email` with your actual index names.
- Confirm sourcetypes, event ID fields, CIM mappings, and field naming in your environment.
- Use bounded time windows and the narrowest appropriate index.
- Verify Windows auditing, Sysmon configuration, PowerShell logging, and forwarder coverage.
- Some example fields (for example `bytes_out`) may come from proxy/firewall data and are not native to all Sysmon events.

## Interpretation
A zero-result search can mean no activity, missing telemetry, wrong field names, or parsing failures. Validate ingestion and field extraction before concluding an event did not occur. Correlate results across endpoint, identity, email, network, and cloud sources.
