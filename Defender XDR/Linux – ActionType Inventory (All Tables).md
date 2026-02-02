## Linux – ActionType Inventory (All Tables) – Last 24h

### Purpose

This is your **capability discovery query**. It tells you *what Linux telemetry exists* in your tenant and *which tables back the device timeline*.

### Query

```kql
let LinuxDeviceIds = materialize(
    DeviceInfo
    | where OSPlatform == "Linux"
    | distinct DeviceId
);
union
(
    DeviceEvents
    | where Timestamp > ago(24h)
    | where DeviceId in (LinuxDeviceIds)
    | project ActionType, Table="DeviceEvents"
),
(
    DeviceProcessEvents
    | where Timestamp > ago(24h)
    | where DeviceId in (LinuxDeviceIds)
    | project ActionType, Table="DeviceProcessEvents"
),
(
    DeviceNetworkEvents
    | where Timestamp > ago(24h)
    | where DeviceId in (LinuxDeviceIds)
    | project ActionType, Table="DeviceNetworkEvents"
),
(
    DeviceLogonEvents
    | where Timestamp > ago(24h)
    | where DeviceId in (LinuxDeviceIds)
    | project ActionType, Table="DeviceLogonEvents"
),
(
    DeviceFileEvents
    | where Timestamp > ago(24h)
    | where DeviceId in (LinuxDeviceIds)
    | project ActionType, Table="DeviceFileEvents"
)
| summarize Events=count() by Table, ActionType
| order by Table asc, Events desc
```

### Use this for

* Reconciling timeline events with hunting tables
* Understanding Linux telemetry coverage
* Discovering new ActionTypes after agent updates
* Deciding where to hunt for specific behaviours