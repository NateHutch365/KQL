```kql
DeviceEvents
| where ActionType == "FirewallOutboundConnectionBlocked"
| join kind=leftouter (
    DeviceNetworkInfo
    | mv-expand ParsedNetworks = parse_json(ConnectedNetworks)
    | extend NetworkCategory = tostring(ParsedNetworks.Category)
    | summarize Categories = make_set(NetworkCategory) by DeviceId, DeviceName
    | extend FirewallProfile = tostring(Categories[0])
) on DeviceId
| project Timestamp, DeviceName, FirewallProfile, RemoteIP, RemotePort, InitiatingProcessFileName
| sort by Timestamp desc
| limit 100
```
