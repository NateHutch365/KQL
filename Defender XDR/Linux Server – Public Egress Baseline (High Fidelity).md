## Linux Server – Public Egress Baseline (High Fidelity)

### Query name

**`Linux Server – Public egress baseline (high fidelity) – last 24h`**

### Purpose

Provides a **high-fidelity view of outbound public network traffic** for Linux servers.

This baseline excludes **only Defender’s own traffic**, leaving all other activity visible for review. The assumption is that **servers should be quieter and more predictable** than desktops.

### Query

```kql
let LinuxDeviceIds =
    DeviceInfo
    | where OSPlatform == "Linux"
    | distinct DeviceId;
DeviceNetworkEvents
| where Timestamp > ago(24h)
| where DeviceId in (LinuxDeviceIds)
| where RemoteIPType == "Public"
| where RemoteIP !startswith "127."
| where InitiatingProcessFileName !in ("sensecm")
| project
    Timestamp,
    DeviceName,
    InitiatingProcessFileName,
    InitiatingProcessCommandLine,
    RemoteIP,
    RemotePort,
    Protocol
| order by Timestamp desc
```

### Why this is stricter

On servers:

* `networkmanager` is often unnecessary or suspicious
* `snapd` may not be expected at all
* `fwupdmgr` is uncommon
* Package management activity may be operationally relevant

Rather than excluding these by default, this query **keeps them visible** so they can be reviewed in context.

### Typical activity you might investigate

* Application services calling external APIs
* Backup agents or monitoring tools
* Unexpected outbound connections
* Misconfigurations (servers acting like desktops)

### When to use this query

* Server threat hunting
* Investigating suspected compromise
* Auditing server network behaviour
* Supply-chain or persistence investigations