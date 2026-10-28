```kql
// Confirm specific device is successfully onboarded to MDE (saves waiting for the portal to update)
DeviceInfo
| where Timestamp > ago(7d)
| where DeviceName startswith "DEVICE-NAME-HERE"
| summarize arg_max(Timestamp, *) by DeviceId
| project Timestamp, DeviceName, DeviceId,
          OnboardingStatus, SensorHealthState,
          MergedToDeviceId, ClientVersion
| order by Timestamp desc
```
