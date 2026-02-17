```kql
DeviceEvents
| where ActionType == "FirewallOutboundConnectionBlocked"
| join kind=leftouter (
    DeviceNetworkInfo
    | mv-expand ParsedNetworks = parse_json(ConnectedNetworks)
    | extend NetworkCategory = tostring(ParsedNetworks.Category)
    | summarize Categories = make_set(NetworkCategory) by DeviceId
    | extend FirewallProfile = tostring(Categories[0])
) on DeviceId
| summarize 
    BlockCount = count(),
    Devices = dcount(DeviceName),
    UniqueDestinations = dcount(RemoteIP)
    by FirewallProfile
| sort by BlockCount desc
```
