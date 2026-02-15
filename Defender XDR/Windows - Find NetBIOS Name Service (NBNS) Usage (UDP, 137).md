```kql
// Find NetBIOS Name Service usage on UDP port 137
// Can be used to determine if NetBIOS can be disabled in environment
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where toupper(Protocol) == "UDP"
| where RemotePort == 137
```
