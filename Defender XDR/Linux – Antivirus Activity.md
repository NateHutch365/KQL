## Linux – Antivirus Activity – Last 7d

### Purpose

Provides **visibility into Defender AV enforcement**, including malware and PUA detections.

### Query

```kql
let LinuxDeviceIds =
    DeviceInfo
    | where OSPlatform == "Linux"
    | distinct DeviceId;
DeviceEvents
| where Timestamp > ago(7d)
| where DeviceId in (LinuxDeviceIds)
| where ActionType startswith "Antivirus"
| extend AF = parse_json(AdditionalFields)
| project
    Timestamp,
    DeviceName,
    ActionType,
    ThreatName = tostring(AF.ThreatName),
    FileName,
    FolderPath,
    WasRemediated = tostring(AF.WasRemediated),
    ReportId
| order by Timestamp desc
```

### Use this for

* Validating PUA block mode effectiveness
* Investigating why a binary was blocked
* Tracking AV detections across Linux hosts
* Supporting security exception decisions

### Typical activity you’ll see

* Malware detections
* PUA detections (block mode only)
* Scan reports