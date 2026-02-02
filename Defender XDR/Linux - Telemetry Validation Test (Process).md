## Linux – Telemetry Validation Test (Process) – Last 1h

### Purpose

This is your **primary “is EDR alive?” query** for Linux. If this returns data, core Linux telemetry (eBPF → process execution) is flowing correctly.

### Query

```kql
// Adjust timestamp to expand time window
let LinuxDeviceIds =
    DeviceInfo
    | where OSPlatform == "Linux"
    | summarize arg_max(Timestamp, DeviceId, DeviceName) by DeviceId
    | project DeviceId, DeviceName;
DeviceProcessEvents
| where Timestamp > ago(1h)
| where DeviceId in (LinuxDeviceIds)
| project
    Timestamp,
    DeviceName,
    FileName,
    FolderPath,
    ProcessCommandLine,
    InitiatingProcessFileName,
    InitiatingProcessCommandLine,
    ReportId
| order by Timestamp desc
| take 100
```

### Use this for

* Validating a newly onboarded Linux device
* Confirming telemetry after agent upgrades
* Confirming kernel / eBPF support is functional
* Proving to yourself (or others) that Linux EDR is *actually* collecting data

### Typical activity you’ll see

* `bash`, `sh`, `zsh` executions
* Package managers (`apt`, `dnf`, `yum`)
* CLI tools (`curl`, `wget`, `python`, `node`)
* Parent/child execution chains