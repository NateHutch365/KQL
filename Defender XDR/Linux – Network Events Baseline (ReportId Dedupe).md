## Linux – Network Events Baseline (ReportId Dedupe) – Last 24h

### Purpose

This is your **network hunting baseline**. It preserves fidelity while removing only *true* duplicate records.

### Query

```kql
let LinuxDeviceIds =
    DeviceInfo
    | where OSPlatform == "Linux"
    | distinct DeviceId;
DeviceNetworkEvents
| where Timestamp > ago(24h)
| where DeviceId in (LinuxDeviceIds)
| summarize arg_max(Timestamp, *) by DeviceId, ReportId
| order by Timestamp desc
```

### Use this for

* Identifying unexpected outbound connections
* Spotting command‑line driven egress (e.g. `curl`, `wget`)
* Detecting early C2‑like behaviour
* Validating Network Protection coverage

### Typical activity you’ll see

* HTTPS requests to public IPs
* Package repository traffic
* Script‑driven uploads / downloads
* Occasional inbound connections (SSH, services)