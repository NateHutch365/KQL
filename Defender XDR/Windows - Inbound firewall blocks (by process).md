```kql
// Find Windows Defender Firewall Inbound Blocks (per process)
// Replace spotify.exe with required process file name
// Limited to 100 results, adjust as necessary
DeviceEvents
| where ActionType == "FirewallInboundConnectionBlocked"
| where InitiatingProcessFileName =~ "spotify.exe"
| sort by Timestamp desc
| limit 100
```
