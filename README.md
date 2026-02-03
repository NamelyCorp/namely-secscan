# Namely SecScan

**Namely SecScan** is a read-only Linux security assessment tool designed for VPS, cloud servers, and self-hosted environments.

It performs a structured, transparent audit of common compromise vectors while remaining **non-invasive by default**.

> Built by **NamelyCorp**  
> https://NamelyCorp.com

---

## 🔐 Core Principles

- **Read-only by default**
- **No system modifications**
- **No auto-installs without consent**
- **Clear progress indicators**
- **Actionable summaries, not noise**

---

## ✨ Features

- System health overview (OS, uptime, disk, memory, reboots)
- User & SSH security inspection
- Network exposure review (ports, firewall state)
- Webroot exposure scan (`.env`, `.git`, backups)
- Log analysis (SSH + web probes)
- Persistence detection (cron + systemd)
- Optional malware & rootkit tooling
- Human-readable **summary report**
- Full raw data preserved for forensics

---

## 🧠 What SecScan Is (and Is Not)

### ✅ Is
- A security visibility and triage tool
- A compromise indicator finder
- A safe first step after suspected exposure

### ❌ Is Not
- An exploit framework
- A malware remover
- A replacement for incident response professionals

---

## 📦 Installation

```bash
curl -O https://github.com/NamelyCorp/namely-secscan/releases/latest/download/namely-secscan.sh
chmod +x namely-secscan.sh
sudo ./namely-secscan.sh
```

---

## ⚠️ Read-Only Safety

Namely SecScan **does not modify your system**.

The *only* time changes may occur is if you explicitly approve:
- Installing missing tools
- Running optional scanners (AIDE, ClamAV, rkhunter)

All installs are:
- Clearly explained
- Opt-in only
- Logged

---

## ⏳ AIDE Notice (Important)

AIDE initialization (`aideinit`) can take **5–30+ minutes** depending on disk size.

### v1.1.1 Improvements:
- Clear warning before execution
- Optional during install
- Can be skipped and run later:
  ```bash
  sudo aideinit
  ```

---

## 📊 Output Location

```
/var/reports/namely-secscan/<timestamp>_namely-secscan_v1.1.1/
```

Includes:
- `REPORT.md`
- `SUMMARY.txt`
- `REQUIREMENTS.txt`
- `raw/`

---

## 🆘 Need Help?

If you discover suspicious activity:
- Isolate the host
- Preserve logs
- Seek professional help

👉 **https://NamelyCorp.com**

---

## 📜 License

MIT License
