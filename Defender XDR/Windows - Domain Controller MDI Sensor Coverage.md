```kql
let DomainControllers =
    DeviceInfo
    | where Timestamp > ago(30d)
    | summarize arg_max(Timestamp, *) by DeviceId
    | where DeviceRoles has "DomainController"
    | extend DCShortName = toupper(tostring(split(DeviceName, ".")[0]))
    | project DeviceId, DeviceName, DCShortName,
              OSPlatform, OnboardingStatus;
let MDIInstalled =
    DeviceTvmSoftwareInventory
    | where SoftwareName contains "Defender for Identity"
        or SoftwareName contains "Azure Advanced Threat Protection Sensor"
    | summarize SensorSoftware =
        make_set(strcat(SoftwareName, " ", SoftwareVersion))
        by DeviceId;
let MDITelemetry =
    IdentityDirectoryEvents
    | where Timestamp > ago(7d)
    | where isnotempty(DestinationDeviceName)
    | extend DCShortName =
        toupper(tostring(split(DestinationDeviceName, ".")[0]))
    | summarize
        LastMDIEvent = max(Timestamp),
        MDIEvents7d = count()
        by DCShortName;
DomainControllers
| join kind=leftouter MDIInstalled on DeviceId
| join kind=leftouter MDITelemetry on DCShortName
| extend MDIStatus = case(
    array_length(SensorSoftware) > 0,
        "Sensor software detected",
    isnotempty(LastMDIEvent),
        "MDI telemetry observed - installation unverified",
    "Not confirmed"
)
| project
    DeviceName,
    OSPlatform,
    OnboardingStatus,
    MDIStatus,
    SensorSoftware,
    LastMDIEvent,
    MDIEvents7d
| order by MDIStatus asc, DeviceName asc
```
