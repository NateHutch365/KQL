## Linux – Script Activity (ScriptContent) – Last 24h

### Purpose

High‑signal query for **script‑based execution**, one of the most common Linux attack techniques.

### Query

```kql
let LinuxDeviceIds =
    DeviceInfo
    | where OSPlatform == "Linux"
    | distinct DeviceId;
DeviceEvents
| where Timestamp > ago(24h)
| where DeviceId in (LinuxDeviceIds)
| where ActionType == "ScriptContent"
| project
    Timestamp,
    DeviceName,
    FileName,
    FolderPath,
    InitiatingProcessFileName,
    InitiatingProcessCommandLine,
    AdditionalFields,
    ReportId
| order by Timestamp desc
```

### Use this for

* Detecting `curl | bash` patterns
* Identifying inline or downloaded scripts
* Investigating admin misuse or credential harvesting scripts
* Understanding attacker intent (script logic is often exposed)

### Typical activity you’ll see

* Shell scripts executed by `bash`
* Scripts dropped to `/tmp`
* Inline script execution via CLI tools