// All credit goes to Felix Brand - Taken from his post (https://www.linkedin.com/posts/felix-brand_defenderxdr-kql-microsoft-activity-7228749401849040896-0sNk)
// Microsoft now recommends (https://lnkd.in/ewBryvhF) to have one initial full scan when you onboard your system into MDE. But MDE does not trigger a full scan after onboarding, this KQL query combined with a custom detection rule can trigger a scan. 
// Once a scan is completed on an endpoint, it will not appear in this query again.

let AvModeDescription = dynamic({"0":"Normal", "1":"Passive", "4":"EDR Block"});
let TimeRange = ago(1d);
DeviceTvmInfoGathering
| where Timestamp > TimeRange
| extend AdditionalFields = parse_json(AdditionalFields)
| extend AvMode =  tostring(AvModeDescription[tostring(AdditionalFields.["AvMode"])])
| extend FullScanStatus = coalesce(extractjson("$.Full.ScanStatus", tostring(AdditionalFields.AvScanResults)),"Not available")
| where isnotempty( AvMode ) and AvMode has "Normal"
| where FullScanStatus !has "Completed"
| join DeviceEvents on DeviceName
| summarize arg_max(Timestamp, *) by DeviceName, DeviceId
| project DeviceName, DeviceId, FullScanStatus, ReportId, Timestamp
| take 50
