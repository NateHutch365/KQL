```kql
// Find outbound firewall blocks based on firewall profile
// Change "where FirewallProfile == "Public" to desired profile you want to search
// To find the profile type of "null" leave the quote marks empty, e.g., ""
// Adjust limit to dertermine result count
DeviceEvents
| where ActionType == "FirewallOutboundConnectionBlocked"
| join kind=leftouter (
    DeviceNetworkInfo
    | mv-expand ParsedNetworks = parse_json(ConnectedNetworks)
    | extend NetworkCategory = tostring(ParsedNetworks.Category)
    | summarize Categories = make_set(NetworkCategory) by DeviceId, DeviceName
    | extend FirewallProfile = tostring(Categories[0])
) on DeviceId
| where FirewallProfile == "Public"
| project Timestamp, DeviceName, FirewallProfile, RemoteIP, RemotePort, InitiatingProcessFileName
| sort by Timestamp desc
```
