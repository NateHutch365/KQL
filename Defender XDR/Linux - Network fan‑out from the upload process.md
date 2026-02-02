### Pivot A – Network fan‑out from the upload process

## Follow‑up pivots (recommended)

Use this when pivoting from the **Linux – Archive Command Followed by Upload Egress** query. They are strongly recommended to understand scope and intent.

* **Update the device name** in the `Device` variable to match the Linux host you want to investigate.
* **Adjust the time window** `(datetime(2026-01-30T15:00:00Z) .. datetime(2026-01-30T15:10:00Z))` if you are looking at older activity or want to narrow the scope during triage.

Use this pivot to identify:

* Multiple upload destinations
* CDN or mirror fan‑out
* Additional data transfers

```kql
// Update DeviceName and time window as required
DeviceNetworkEvents
| where Timestamp between (datetime(2026-01-30T15:00:00Z) .. datetime(2026-01-30T15:10:00Z))
| where DeviceName =~ "DeviceNameHere"
| where InitiatingProcessCommandLine has "file=@"
| project Timestamp, RemoteIP, RemotePort, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc
```

(Adjust timestamps based on the initial hit.)