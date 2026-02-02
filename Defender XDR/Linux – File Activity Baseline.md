## Linux – File Activity Baseline – Last 24h

### Purpose

Provides **visibility into file system activity**, which is critical for Linux threat hunting due to heavy use of staging directories.

### Query

```kql
let LinuxDeviceIds =
    DeviceInfo
    | where OSPlatform == "Linux"
    | distinct DeviceId;
DeviceFileEvents
| where Timestamp > ago(24h)
| where DeviceId in (LinuxDeviceIds)
| project
    Timestamp,
    DeviceName,
    ActionType,
    FileName,
    FolderPath,
    InitiatingProcessFileName,
    InitiatingProcessCommandLine,
    ReportId
| order by Timestamp desc
| take 200
```

### Use this for

* Detecting file drops and clean‑up activity
* Identifying abuse of `/tmp`, `/var/tmp`, or home directories
* Correlating file writes with suspicious processes
* Hunting installer‑style malware or tooling

### Typical activity you’ll see

* File creation in `/tmp`
* Renames of staged binaries
* Script output files
* Temporary archive extraction