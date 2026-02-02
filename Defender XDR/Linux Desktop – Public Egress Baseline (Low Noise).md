## Linux Desktop – Public Egress Baseline (Low Noise)

### Query name

**`Linux Desktop – Public egress baseline (low noise) – last 24h`**

### Purpose

Provides a **low-noise view of outbound public network traffic** on Linux desktop or workstation devices (for example, Ubuntu desktops, developer VMs, user laptops).

This baseline aggressively excludes:

* Operating system background services
* Package management traffic
* Defender agent traffic

The goal is to surface **user-initiated or tool-driven network activity** quickly, without drowning in expected OS behaviour.

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
| where InitiatingProcessFileName !in (
    "sensecm",
    "snapd",
    "networkmanager",
    "fwupdmgr"
)
| where InitiatingProcessFolderPath !startswith "/usr/lib/apt/"
| where InitiatingProcessCommandLine !contains "ubuntu-release-upgrader"
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

### Why these exclusions are appropriate on desktops

* **sensecm** – Defender for Endpoint agent (always safe to exclude)
* **snapd** – Canonical Snap infrastructure (very chatty on desktops)
* **networkmanager** – Connectivity checks, VPN, Wi‑Fi management
* **fwupdmgr** – Firmware metadata refresh
* **APT methods** – Package installation and updates
* **ubuntu-release-upgrader** – OS upgrade checks

On desktops, these processes are expected and rarely represent attacker tradecraft.

### Typical activity you will still see

* `curl`, `wget`, `python`, `node`
* Developer tools reaching external APIs
* Manual uploads/downloads
* Red team / EDR test traffic

### When to use this query

* Validating Linux EDR on workstations
* Hunting user-driven behaviour
* Reducing noise during investigations