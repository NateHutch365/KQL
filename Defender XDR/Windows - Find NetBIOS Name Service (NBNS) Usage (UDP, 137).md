```kql
// Find NetBIOS Name Service usage on UDP port 137
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where toupper(Protocol) == "UDP"
| where RemotePort == 137
```
