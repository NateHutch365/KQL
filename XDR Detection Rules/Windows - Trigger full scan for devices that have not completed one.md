```kql
// Initial full scan helper for MDE onboarded devices
// Use this in a custom detection rule with the "Run antivirus scan" (Full scan) action.
// Map AV mode codes to friendly names
// Will include Windows clients and servers - See client only query if you do not want ot include servers
let AvModeDescription = dynamic({"0":"Normal", "1":"Passive", "4":"EDR Block"});
let TimeRange = ago(1d);
// 1. Find devices in Normal AV mode that have NOT completed a full scan
let ScanCandidates =
    DeviceTvmInfoGathering
    | where Timestamp > TimeRange
    | extend AdditionalFields = parse_json(AdditionalFields)
    | extend AvMode = tostring(AvModeDescription[tostring(AdditionalFields.["AvMode"])])
    | extend FullScanStatus = coalesce(
        extractjson("$.Full.ScanStatus", tostring(AdditionalFields.AvScanResults)),
        "Not available"
      )
    | where isnotempty(AvMode) and AvMode has "Normal"
    | where FullScanStatus !has "Completed"
    // one latest TVM record per device
    | summarize arg_max(Timestamp, FullScanStatus) by DeviceId, DeviceName
    | project DeviceId, DeviceName, FullScanStatus;
// 2. Anchor on DeviceEvents to get a valid event (ReportId + Timestamp)
DeviceEvents
| where Timestamp > TimeRange
| summarize arg_max(Timestamp, ReportId) by DeviceId
// 3. Join event anchor to the TVM scan status
| join kind=inner ScanCandidates on DeviceId
// 4. Final output for custom detection + device action
| project
    DeviceName,
    DeviceId,
    FullScanStatus,
    ReportId,   // REQUIRED for custom detections
    Timestamp   // REQUIRED for custom detections
    | take 50
```