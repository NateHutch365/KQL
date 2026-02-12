```kql
// Find All Windows Defender Firewall Inbound Blocks
// Limited to 100 results, adjust as necessary
DeviceEvents 
| where ActionType == "FirewallInboundConnectionBlocked" 
| sort by Timestamp 
| limit 100
```
