## Linux – Logon Activity – Last 24h

### Purpose

Adds **user context** to Linux activity. Especially useful for SSH‑based investigations.

### Query

```kql
let LinuxDeviceIds =
    DeviceInfo
    | where OSPlatform == "Linux"
    | distinct DeviceId;
DeviceLogonEvents
| where Timestamp > ago(24h)
| where DeviceId in (LinuxDeviceIds)
| project
    Timestamp,
    DeviceName,
    ActionType,
    AccountName,
    AccountDomain,
    LogonType,
    InitiatingProcessFileName,
    InitiatingProcessCommandLine
| order by Timestamp desc
```

### Use this for

* Investigating SSH access
* Detecting unexpected interactive logons
* Correlating user sessions with process or network activity

### Typical activity you’ll see

* SSH logons
* Local user sessions
* Automation accounts