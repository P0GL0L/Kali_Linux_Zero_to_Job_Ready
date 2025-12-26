# Stage 02 — Linux System Administration
## Managing and Securing Linux Systems

**Kali Linux for Cybersecurity Learning Path**  
**Audience:** Learners who have completed Stage 01 (no system administration experience required)

Welcome to Stage 02. In Stage 01, you learned to navigate and work with Linux as a user. In this stage, you will learn to **manage and secure Linux systems as an administrator**. These skills are essential whether you're defending systems as a blue teamer or understanding them as a penetration tester.

---

## Prerequisites

Before starting Stage 02, you must have completed Stage 01:

- [ ] Can navigate the Linux filesystem confidently
- [ ] Can create, modify, and manage files and directories
- [ ] Understand Linux permissions and can modify them
- [ ] Can create and manage users and groups
- [ ] Can use text processing tools (grep, find, etc.)
- [ ] Can write basic shell scripts
- [ ] Have a working Ubuntu Server VM

If any of these are not checked, return to Stage 01 and complete it first.

---

## Why This Stage Matters

**System administration is the foundation of both offensive and defensive security:**

| If You Want To... | You Need To Understand... |
|-------------------|---------------------------|
| Defend systems | How services run, how to harden them, how to monitor them |
| Attack systems | How services are configured, where weaknesses hide, how to persist |
| Analyze incidents | How logs work, what normal looks like, where evidence lives |
| Automate security | How to schedule tasks, manage packages, configure services |

Security professionals who understand system administration are dramatically more effective than those who only know tools.

---

## What You Will Learn

By the end of this stage, you will be able to:

- Install, update, and remove software packages
- Manage system services (start, stop, enable, disable)
- Configure and secure SSH for remote access
- Analyze system logs for troubleshooting and security
- Configure basic firewall rules
- Schedule automated tasks
- Manage disk storage and filesystems
- Apply basic system hardening techniques

---

## What You Will Build

1. **A hardened SSH configuration** — Secure remote access setup
2. **A log monitoring script** — Automated security log analysis
3. **A system health check script** — Comprehensive system status report
4. **A firewall ruleset** — Basic but secure firewall configuration
5. **A hardening checklist** — Documented security baseline for your system

---

## Certification Alignment

This stage maps to objectives from:

| Certification | Relevant Domains |
|--------------|------------------|
| **CompTIA Linux+** | 1.0 System Management, 2.0 Security, 4.0 Troubleshooting |
| **CompTIA Security+** | 3.0 Security Architecture, 4.0 Security Operations |
| **CompTIA CySA+** | 1.0 Security Operations (infrastructure concepts) |

> **Certification Exam Currency Notice:** Certification objectives are updated periodically. Verify current exam objectives at the vendor's official website before beginning exam preparation. See `docs/CERTIFICATION_MAPPING.md` for detailed alignment information.

---

## Time Estimate

**Total: 35-40 hours**

| Section | Hours |
|---------|-------|
| Package Management | 4-5 |
| Service Management | 4-5 |
| System Logging | 5-6 |
| SSH Configuration and Security | 5-6 |
| Network Configuration | 4-5 |
| Firewall Configuration | 4-5 |
| Scheduled Tasks | 3-4 |
| Disk and Storage Management | 4-5 |
| System Hardening | 4-5 |
| Stage Assessment | 2-3 |

---

## The Milestones Approach

### Stage 02 Milestones

1. **Master package management** (apt, dpkg)
2. **Control system services** (systemctl)
3. **Understand and analyze logs** (journald, /var/log)
4. **Configure and secure SSH**
5. **Configure network settings**
6. **Implement firewall rules** (ufw)
7. **Schedule automated tasks** (cron)
8. **Manage disk storage**
9. **Apply system hardening**
10. **Complete the stage assessment**

---

## Part 1 — Package Management (Milestone 1)

### What is Package Management?

Think of packages like apps on your phone. A **package** is a bundle containing:
- Software program files
- Configuration files
- Documentation
- Information about dependencies (other packages it needs)

A **package manager** is a tool that:
- Installs packages from repositories (like app stores)
- Keeps track of what's installed
- Updates software to newer versions
- Removes software cleanly
- Handles dependencies automatically

**Why does this matter for security?**
- Outdated software contains known vulnerabilities
- Unnecessary software increases attack surface
- Understanding what's installed is fundamental to security auditing

### Ubuntu's Package Management System

Ubuntu uses two main package tools:

| Tool | Purpose | When to Use |
|------|---------|-------------|
| `apt` | High-level package manager | Most daily tasks |
| `dpkg` | Low-level package tool | Manual package handling |

### Understanding Repositories

**What is a repository?**

A repository (or "repo") is a server that stores packages. Think of it like an app store catalog. When you install software, your system downloads it from these repositories.

**Viewing configured repositories:**

```bash
cat /etc/apt/sources.list
```

You'll see lines like:
```
deb http://archive.ubuntu.com/ubuntu/ noble main restricted
deb http://archive.ubuntu.com/ubuntu/ noble-updates main restricted
deb http://security.ubuntu.com/ubuntu noble-security main restricted
```

**Understanding the format:**

```
deb http://archive.ubuntu.com/ubuntu/ noble main restricted
│   │                                  │     │    │
│   │                                  │     │    └── Component (restricted)
│   │                                  │     └─────── Component (main)
│   │                                  └───────────── Distribution (noble = 24.04)
│   └──────────────────────────────────────────────── Repository URL
└──────────────────────────────────────────────────── Package type (deb = binary)
```

**Components explained:**
- **main** — Officially supported open-source software
- **restricted** — Officially supported closed-source software (drivers)
- **universe** — Community-maintained open-source
- **multiverse** — Software with legal/licensing restrictions

### The APT Command

APT (Advanced Package Tool) is your primary interface for package management.

#### Updating Package Lists

**What it does:** Downloads the latest list of available packages from repositories. This doesn't install anything—it just updates your system's knowledge of what's available.

```bash
sudo apt update
```

**Example output:**
```
Hit:1 http://archive.ubuntu.com/ubuntu noble InRelease
Get:2 http://archive.ubuntu.com/ubuntu noble-updates InRelease [126 kB]
Get:3 http://security.ubuntu.com/ubuntu noble-security InRelease [126 kB]
...
Reading package lists... Done
Building dependency tree... Done
Reading state information... Done
15 packages can be upgraded. Run 'apt list --upgradable' to see them.
```

**When to run:** Before installing anything new or checking for updates.

#### Upgrading Installed Packages

**What it does:** Downloads and installs newer versions of packages you already have installed.

```bash
# See what would be upgraded
sudo apt list --upgradable

# Upgrade all packages
sudo apt upgrade
```

You'll be prompted to confirm. Read what's being upgraded before pressing `Y`.

**Full upgrade (handles dependencies more aggressively):**

```bash
sudo apt full-upgrade
```

Use `full-upgrade` when `upgrade` can't complete due to dependency issues.

#### Installing Packages

**Basic installation:**

```bash
sudo apt install package-name
```

**Example: Install the `htop` system monitor:**

```bash
sudo apt install htop
```

**Output explanation:**
```
Reading package lists... Done
Building dependency tree... Done
Reading state information... Done
The following NEW packages will be installed:
  htop
0 upgraded, 1 newly installed, 0 to remove and 0 not upgraded.
Need to get 128 kB of archives.
After this operation, 373 kB of additional disk space will be used.
```

APT tells you:
- What will be installed
- How much data to download
- How much disk space will be used

**Install multiple packages at once:**

```bash
sudo apt install htop net-tools curl wget
```

**Install without confirmation prompt (use carefully):**

```bash
sudo apt install -y package-name
```

#### Removing Packages

**Remove a package (keep configuration files):**

```bash
sudo apt remove package-name
```

**Remove package AND configuration files:**

```bash
sudo apt purge package-name
```

**When to use which:**
- Use `remove` if you might reinstall later (keeps your settings)
- Use `purge` for complete removal (fresh start if reinstalled)

#### Cleaning Up

Over time, downloaded package files accumulate. Clean them up:

```bash
# Remove downloaded package files that are no longer needed
sudo apt clean

# Remove only outdated downloaded packages
sudo apt autoclean

# Remove packages that were automatically installed as dependencies
# but are no longer needed
sudo apt autoremove
```

**Best practice:** Run `autoremove` after removing packages.

#### Searching for Packages

**Search by keyword:**

```bash
apt search network scanner
```

**Show detailed information about a package:**

```bash
apt show nmap
```

**Output includes:**
- Description
- Version
- Dependencies
- Size
- Maintainer

**Check if a package is installed:**

```bash
apt list --installed | grep package-name

# Or more simply:
dpkg -l | grep package-name
```

### The DPKG Command

`dpkg` is the lower-level tool that `apt` uses behind the scenes. You'll use it for:
- Installing local `.deb` files
- Querying package information
- Troubleshooting

#### Installing a Local .deb File

Sometimes you download a `.deb` file directly (like from a vendor website):

```bash
# Install a local .deb file
sudo dpkg -i package-file.deb

# If there are dependency errors, fix them:
sudo apt install -f
```

#### Querying Package Information

```bash
# List all installed packages
dpkg -l

# Check if specific package is installed
dpkg -l | grep openssh

# List files installed by a package
dpkg -L openssh-server

# Find which package owns a file
dpkg -S /usr/bin/ssh
```

### Security-Relevant Package Management

#### Finding Security Updates

```bash
# List only security updates
apt list --upgradable 2>/dev/null | grep -i security
```

#### Checking for Known Vulnerabilities

```bash
# Install the Debian Security Tracker tool (if available)
# Or check: https://security-tracker.debian.org/
```

#### Listing Packages by Installation Date

Useful for incident investigation—what was recently installed?

```bash
# View dpkg log for installation history
cat /var/log/dpkg.log | grep "install "

# Or with timestamps
grep " install " /var/log/dpkg.log | tail -20
```

#### Auditing Installed Packages

Create a list of installed packages for documentation:

```bash
dpkg --get-selections > installed_packages_$(date +%Y%m%d).txt
```

### Practical Exercises: Package Management

#### Exercise 1.1: Update and Upgrade

1. Update your package lists
2. Check how many packages can be upgraded
3. View the list of upgradable packages
4. Perform the upgrade
5. Run autoremove to clean up

```bash
sudo apt update
apt list --upgradable | wc -l
apt list --upgradable
sudo apt upgrade -y
sudo apt autoremove -y
```

#### Exercise 1.2: Install Security Tools

Install these useful security/administration tools:

```bash
sudo apt install -y \
    htop \
    net-tools \
    curl \
    wget \
    nmap \
    tcpdump \
    whois \
    dnsutils \
    tree
```

After installation:
- Verify each is installed with `which tool-name`
- Check the version of nmap: `nmap --version`

#### Exercise 1.3: Package Investigation

For the `openssh-server` package:
1. Check if it's installed
2. View its description
3. List the files it installed
4. Find where its configuration files are

```bash
dpkg -l openssh-server
apt show openssh-server
dpkg -L openssh-server
dpkg -L openssh-server | grep etc
```

---

### Milestone 1 Checkpoint

Before proceeding, verify:

- [ ] You understand what packages and repositories are
- [ ] You can update package lists with `apt update`
- [ ] You can upgrade packages with `apt upgrade`
- [ ] You can install packages with `apt install`
- [ ] You can remove packages with `apt remove` and `apt purge`
- [ ] You can search for packages with `apt search`
- [ ] You can query installed packages with `dpkg`
- [ ] You understand the security importance of keeping software updated

**[CERT CHECKPOINT - Linux+ 1.5]**: Package management is heavily tested. Know apt and dpkg operations.

---

## Part 2 — Service Management (Milestone 2)

### What is a Service?

A **service** (also called a **daemon**) is a program that runs in the background, waiting to do work. Services start automatically when the system boots and continue running without user interaction.

**Examples of services:**
- `sshd` — Waits for SSH connections
- `nginx` — Waits for web requests
- `cron` — Waits to run scheduled tasks
- `rsyslog` — Collects and stores log messages

**Why services matter for security:**
- Every running service is a potential attack surface
- Unnecessary services should be disabled
- Service configurations often contain security weaknesses
- Compromised services are common attack vectors

### Understanding systemd

Modern Linux systems use **systemd** to manage services. systemd is:
- The first process that runs (PID 1)
- Responsible for starting all other services
- The manager of the entire system lifecycle

**Key systemd concepts:**

| Term | Definition |
|------|------------|
| **Unit** | Any resource systemd manages (services, mounts, timers, etc.) |
| **Service** | A specific type of unit that manages a daemon |
| **Target** | A group of units (like runlevels in older systems) |
| **Socket** | Activates a service when a connection arrives |

### The systemctl Command

`systemctl` is your primary tool for managing services.

#### Viewing Service Status

**Check if a service is running:**

```bash
systemctl status ssh
```

**Example output:**
```
● ssh.service - OpenBSD Secure Shell server
     Loaded: loaded (/lib/systemd/system/ssh.service; enabled; vendor preset: enabled)
     Active: active (running) since Thu 2025-12-25 10:00:00 UTC; 2h ago
       Docs: man:sshd(8)
             man:sshd_config(5)
    Process: 1234 ExecStartPre=/usr/sbin/sshd -t (code=exited, status=0/SUCCESS)
   Main PID: 1235 (sshd)
      Tasks: 1 (limit: 4666)
     Memory: 2.8M
        CPU: 54ms
     CGroup: /system.slice/ssh.service
             └─1235 sshd: /usr/sbin/sshd -D [listener] 0 of 10-100 startups
```

**Understanding the output:**

| Field | Meaning |
|-------|---------|
| `Loaded` | Unit file found and loaded |
| `enabled` | Will start automatically at boot |
| `Active` | Current state (running, stopped, failed) |
| `Main PID` | Process ID of the main service process |
| `Memory` | RAM used by this service |
| `CGroup` | Control group containing service processes |

**Quick status check (less detail):**

```bash
systemctl is-active ssh       # Returns "active" or "inactive"
systemctl is-enabled ssh      # Returns "enabled" or "disabled"
systemctl is-failed ssh       # Returns "failed" if in failed state
```

#### Starting and Stopping Services

**Start a stopped service:**

```bash
sudo systemctl start service-name
```

**Stop a running service:**

```bash
sudo systemctl stop service-name
```

**Restart a service (stop then start):**

```bash
sudo systemctl restart service-name
```

**Reload configuration without full restart:**

```bash
sudo systemctl reload service-name
```

Some services support reload (re-reads config files without interrupting connections). If unsure:

```bash
# Reload if supported, otherwise restart
sudo systemctl reload-or-restart service-name
```

#### Enabling and Disabling Services

**Enable (start at boot):**

```bash
sudo systemctl enable service-name
```

**Disable (don't start at boot):**

```bash
sudo systemctl disable service-name
```

**Enable AND start immediately:**

```bash
sudo systemctl enable --now service-name
```

**Disable AND stop immediately:**

```bash
sudo systemctl disable --now service-name
```

#### Listing Services

**List all loaded services:**

```bash
systemctl list-units --type=service
```

**List all services (including not loaded):**

```bash
systemctl list-unit-files --type=service
```

**List only running services:**

```bash
systemctl list-units --type=service --state=running
```

**List failed services (important for troubleshooting):**

```bash
systemctl list-units --type=service --state=failed
```

### Service Unit Files

Each service has a **unit file** that defines how it runs.

**Location of unit files:**
- `/lib/systemd/system/` — Package-provided unit files
- `/etc/systemd/system/` — Administrator customizations (overrides)

**View a unit file:**

```bash
systemctl cat ssh
```

**Example unit file structure:**
```ini
[Unit]
Description=OpenBSD Secure Shell server
Documentation=man:sshd(8) man:sshd_config(5)
After=network.target

[Service]
Type=notify
ExecStart=/usr/sbin/sshd -D
ExecReload=/bin/kill -HUP $MAINPID
Restart=on-failure

[Install]
WantedBy=multi-user.target
```

**Understanding unit file sections:**

| Section | Purpose |
|---------|---------|
| `[Unit]` | Description and dependencies |
| `[Service]` | How to start/stop/reload the service |
| `[Install]` | How to enable the service |

### Security-Relevant Service Management

#### Auditing Running Services

```bash
# List all enabled services (will start at boot)
systemctl list-unit-files --type=service --state=enabled

# Count them
systemctl list-unit-files --type=service --state=enabled | wc -l
```

**Security principle:** Disable any service you don't need. Every running service is potential attack surface.

#### Identifying Network Services

Services that listen on network ports are especially important:

```bash
# Show services with network connections
sudo ss -tlnp

# Match to systemd services
sudo ss -tlnp | grep LISTEN
```

#### Finding Services Running as Root

```bash
# Find processes running as root
ps aux | grep "^root" | less
```

#### Checking Service Logs for Errors

```bash
# View recent logs for a specific service
sudo journalctl -u ssh --since "1 hour ago"

# Follow logs in real-time
sudo journalctl -u ssh -f
```

### Practical Exercises: Service Management

#### Exercise 2.1: Service Exploration

1. List all running services
2. Count how many services are enabled
3. Find any failed services
4. Check the status of the SSH service

```bash
systemctl list-units --type=service --state=running
systemctl list-unit-files --type=service --state=enabled | wc -l
systemctl list-units --type=service --state=failed
systemctl status ssh
```

#### Exercise 2.2: Service Control Practice

1. Check if the `cron` service is running
2. Stop the cron service
3. Verify it stopped
4. Start it again
5. Check if it's enabled to start at boot

```bash
systemctl status cron
sudo systemctl stop cron
systemctl is-active cron
sudo systemctl start cron
systemctl is-enabled cron
```

#### Exercise 2.3: Security Audit - Running Services

Create a script that documents all enabled services:

```bash
#!/bin/bash
# service_audit.sh - Document enabled services

OUTPUT="$HOME/security-lab/reports/services_$(date +%Y%m%d).txt"

echo "Service Audit Report" > "$OUTPUT"
echo "Generated: $(date)" >> "$OUTPUT"
echo "Host: $(hostname)" >> "$OUTPUT"
echo "================================" >> "$OUTPUT"
echo "" >> "$OUTPUT"

echo "=== Enabled Services ===" >> "$OUTPUT"
systemctl list-unit-files --type=service --state=enabled >> "$OUTPUT"
echo "" >> "$OUTPUT"

echo "=== Currently Running Services ===" >> "$OUTPUT"
systemctl list-units --type=service --state=running >> "$OUTPUT"
echo "" >> "$OUTPUT"

echo "=== Network Listening Services ===" >> "$OUTPUT"
sudo ss -tlnp >> "$OUTPUT"
echo "" >> "$OUTPUT"

echo "=== Failed Services ===" >> "$OUTPUT"
systemctl list-units --type=service --state=failed >> "$OUTPUT"

echo "Report saved to: $OUTPUT"
```

Save this to `~/security-lab/scripts/service_audit.sh` and make it executable.

---

### Milestone 2 Checkpoint

Before proceeding, verify:

- [ ] You understand what services/daemons are
- [ ] You can check service status with `systemctl status`
- [ ] You can start, stop, and restart services
- [ ] You can enable and disable services
- [ ] You can list all services and filter by state
- [ ] You understand unit files and their location
- [ ] You can audit running and enabled services for security

**[CERT CHECKPOINT - Linux+ 1.4 / Security+ 4.1]**: Service management is fundamental. Know how to control services and audit what's running.

---

## Part 3 — System Logging (Milestone 3)

### Why Logs Matter

Logs are your **eyes into the system**. They record:
- What happened
- When it happened
- Who (or what) did it
- Whether it succeeded or failed

**For security professionals, logs are critical for:**
- Detecting attacks and intrusions
- Investigating incidents
- Troubleshooting problems
- Auditing compliance
- Understanding normal vs. abnormal behavior

### Linux Logging Systems

Modern Ubuntu uses two logging systems that work together:

| System | Purpose | Tool |
|--------|---------|------|
| **journald** | Binary logs managed by systemd | `journalctl` |
| **rsyslog** | Traditional text logs in /var/log | `cat`, `grep`, `less` |

### The /var/log Directory

Traditional logs live in `/var/log/`:

```bash
ls -la /var/log/
```

**Key log files:**

| File | Contents |
|------|----------|
| `/var/log/syslog` | General system messages |
| `/var/log/auth.log` | Authentication events (logins, sudo, SSH) |
| `/var/log/kern.log` | Kernel messages |
| `/var/log/dpkg.log` | Package installation/removal |
| `/var/log/apt/` | APT package manager logs |
| `/var/log/ufw.log` | Firewall logs (if ufw enabled) |
| `/var/log/lastlog` | Last login info (binary, use `lastlog` command) |
| `/var/log/wtmp` | Login records (binary, use `last` command) |
| `/var/log/btmp` | Failed login attempts (binary, use `lastb` command) |

### Reading Traditional Logs

**View recent entries:**

```bash
# Last 50 lines
tail -50 /var/log/syslog

# Follow in real-time (Ctrl+C to stop)
tail -f /var/log/syslog

# Search for specific content
grep "error" /var/log/syslog

# Case-insensitive search
grep -i "error" /var/log/syslog
```

**View authentication logs (security-critical):**

```bash
# Recent authentication events
sudo tail -100 /var/log/auth.log

# Failed login attempts
sudo grep "Failed password" /var/log/auth.log

# Successful logins
sudo grep "Accepted" /var/log/auth.log

# Sudo usage
sudo grep "sudo:" /var/log/auth.log
```

### The journalctl Command

`journalctl` is the modern way to query logs from systemd's journal.

#### Basic Usage

```bash
# View all logs (oldest first)
journalctl

# View logs (newest first)
journalctl -r

# Follow in real-time
journalctl -f

# Show only recent entries
journalctl -n 50    # Last 50 entries
```

#### Filtering by Time

```bash
# Since a specific time
journalctl --since "2025-12-25 10:00:00"

# Since a relative time
journalctl --since "1 hour ago"
journalctl --since "yesterday"

# Time range
journalctl --since "2025-12-25" --until "2025-12-26"

# Today's logs
journalctl --since today
```

#### Filtering by Unit (Service)

```bash
# Logs for SSH service
journalctl -u ssh

# Logs for SSH since today
journalctl -u ssh --since today

# Multiple services
journalctl -u ssh -u cron
```

#### Filtering by Priority

Log priorities (severity levels):

| Priority | Name | Meaning |
|----------|------|---------|
| 0 | emerg | System is unusable |
| 1 | alert | Immediate action required |
| 2 | crit | Critical conditions |
| 3 | err | Error conditions |
| 4 | warning | Warning conditions |
| 5 | notice | Normal but significant |
| 6 | info | Informational |
| 7 | debug | Debug messages |

```bash
# Show only errors and above (priorities 0-3)
journalctl -p err

# Show only warnings and above
journalctl -p warning

# Specific priority only
journalctl -p err..err
```

#### Filtering by Boot

```bash
# Current boot only
journalctl -b

# Previous boot
journalctl -b -1

# List available boots
journalctl --list-boots
```

#### Output Formats

```bash
# JSON output (useful for scripting)
journalctl -o json

# Verbose output (all fields)
journalctl -o verbose

# Short output with timestamps
journalctl -o short-iso
```

### Security Log Analysis

#### Finding Failed Login Attempts

```bash
# Using auth.log
sudo grep "Failed password" /var/log/auth.log | tail -20

# Using journalctl
journalctl -u ssh | grep -i "failed"

# Count failed attempts by IP
sudo grep "Failed password" /var/log/auth.log | \
    grep -oE "[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+" | \
    sort | uniq -c | sort -rn | head -10
```

#### Finding Successful Logins

```bash
# SSH accepted connections
sudo grep "Accepted" /var/log/auth.log

# Using the last command (login history)
last

# Last 10 logins
last -10

# Logins for specific user
last username
```

#### Finding Sudo Usage

```bash
# All sudo commands
sudo grep "sudo:" /var/log/auth.log

# What commands were run with sudo
sudo grep "COMMAND=" /var/log/auth.log | tail -20
```

#### Detecting Potential Brute Force Attacks

```bash
#!/bin/bash
# brute_force_check.sh - Detect potential brute force attempts

echo "=== Potential Brute Force Detection ==="
echo "Checking for IPs with multiple failed login attempts..."
echo ""

# Count failed attempts per IP
sudo grep "Failed password" /var/log/auth.log 2>/dev/null | \
    grep -oE "[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+" | \
    sort | uniq -c | sort -rn | \
    while read count ip; do
        if [ "$count" -ge 5 ]; then
            echo "WARNING: $ip has $count failed attempts"
        fi
    done

echo ""
echo "=== Recent Failed Logins ==="
sudo grep "Failed password" /var/log/auth.log 2>/dev/null | tail -10
```

### Log Rotation

Logs don't grow forever—they get **rotated** (archived and compressed) automatically.

**The logrotate system:**
- Configuration: `/etc/logrotate.conf` and `/etc/logrotate.d/`
- Typically keeps 4-7 weeks of logs
- Old logs compressed with gzip (`.gz` extension)

**View rotated logs:**

```bash
# List rotated auth logs
ls -la /var/log/auth.log*

# Read a compressed log
zcat /var/log/auth.log.2.gz | head

# Search in compressed logs
zgrep "Failed" /var/log/auth.log.*.gz
```

### Practical Exercises: System Logging

#### Exercise 3.1: Log Exploration

1. List all files in /var/log
2. View the last 20 lines of syslog
3. Search for the word "error" in syslog
4. Count how many entries are in today's auth.log

```bash
ls -la /var/log/
tail -20 /var/log/syslog
grep -i "error" /var/log/syslog
sudo grep "$(date +%b\ %d)" /var/log/auth.log | wc -l
```

#### Exercise 3.2: journalctl Practice

1. View logs from the last hour
2. View only error-level messages
3. View SSH service logs from today
4. Find logs related to your current login session

```bash
journalctl --since "1 hour ago"
journalctl -p err
journalctl -u ssh --since today
journalctl _UID=$(id -u)
```

#### Exercise 3.3: Security Log Monitor Script

Create a comprehensive log monitoring script:

```bash
#!/bin/bash
# log_monitor.sh - Security-focused log analysis

OUTPUT="$HOME/security-lab/reports/log_analysis_$(date +%Y%m%d_%H%M%S).txt"

echo "Security Log Analysis Report" > "$OUTPUT"
echo "Generated: $(date)" >> "$OUTPUT"
echo "Host: $(hostname)" >> "$OUTPUT"
echo "======================================" >> "$OUTPUT"
echo "" >> "$OUTPUT"

echo "=== Failed Login Attempts (Last 24h) ===" >> "$OUTPUT"
sudo journalctl --since "24 hours ago" | grep -i "failed" | tail -50 >> "$OUTPUT"
echo "" >> "$OUTPUT"

echo "=== Successful SSH Logins (Last 24h) ===" >> "$OUTPUT"
sudo grep "Accepted" /var/log/auth.log 2>/dev/null | tail -20 >> "$OUTPUT"
echo "" >> "$OUTPUT"

echo "=== Sudo Commands (Last 24h) ===" >> "$OUTPUT"
sudo grep "COMMAND=" /var/log/auth.log 2>/dev/null | tail -30 >> "$OUTPUT"
echo "" >> "$OUTPUT"

echo "=== Error Messages (Last 24h) ===" >> "$OUTPUT"
journalctl -p err --since "24 hours ago" | tail -50 >> "$OUTPUT"
echo "" >> "$OUTPUT"

echo "=== Failed Login Count by IP ===" >> "$OUTPUT"
sudo grep "Failed password" /var/log/auth.log 2>/dev/null | \
    grep -oE "[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+" | \
    sort | uniq -c | sort -rn | head -10 >> "$OUTPUT"
echo "" >> "$OUTPUT"

echo "=== Recent Login History ===" >> "$OUTPUT"
last -20 >> "$OUTPUT"

echo "Report saved to: $OUTPUT"
cat "$OUTPUT"
```

Save to `~/security-lab/scripts/log_monitor.sh` and make executable.

---

### Milestone 3 Checkpoint

Before proceeding, verify:

- [ ] You understand the importance of logs for security
- [ ] You know the key log files in /var/log
- [ ] You can read and search traditional log files
- [ ] You can use journalctl with time, unit, and priority filters
- [ ] You can identify failed login attempts in logs
- [ ] You can track sudo usage through logs
- [ ] You understand log rotation
- [ ] You have created the log_monitor.sh script

**[CERT CHECKPOINT - Linux+ 4.1 / CySA+ 1.2]**: Log analysis is critical for security operations. Know where logs are and how to query them effectively.

---

## Part 4 — SSH Configuration and Security (Milestone 4)

### What is SSH?

SSH (Secure Shell) is a protocol for secure remote access to systems. It provides:
- Encrypted communication (protects against eavesdropping)
- Authentication (verifies identity)
- Integrity (detects tampering)

**Why SSH matters for security:**
- SSH is how you remotely manage Linux systems
- Misconfigured SSH is a common vulnerability
- SSH brute force attacks are extremely common
- Proper SSH hardening is a fundamental security skill

### SSH Components

| Component | Description |
|-----------|-------------|
| `sshd` | The SSH server (daemon) - listens for connections |
| `ssh` | The SSH client - connects to servers |
| `ssh-keygen` | Generates SSH key pairs |
| `ssh-copy-id` | Copies public keys to remote servers |
| `scp` | Secure file copy over SSH |
| `sftp` | Secure file transfer protocol |

### Installing and Starting SSH Server

Check if SSH server is installed:

```bash
dpkg -l | grep openssh-server
```

If not installed:

```bash
sudo apt update
sudo apt install openssh-server
```

Verify it's running:

```bash
sudo systemctl status ssh
```

### Connecting via SSH

**Basic connection:**

```bash
ssh username@hostname-or-ip
```

**First-time connection:**

```
The authenticity of host '192.168.1.100 (192.168.1.100)' can't be established.
ED25519 key fingerprint is SHA256:abcdef123456...
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])?
```

This is the **host key verification**—the server proves its identity. Type `yes` if you trust the server.

**Specify port (if not default 22):**

```bash
ssh -p 2222 username@hostname
```

**Verbose mode (for troubleshooting):**

```bash
ssh -v username@hostname
```

### SSH Key-Based Authentication

Password authentication is vulnerable to:
- Brute force attacks
- Shoulder surfing
- Keyloggers
- Password reuse

**Key-based authentication** is more secure:
- Uses cryptographic key pairs
- Private key stays on your machine (never transmitted)
- Much harder to brute force

#### Generating SSH Keys

```bash
ssh-keygen -t ed25519 -C "your-email@example.com"
```

**Options explained:**
- `-t ed25519` — Use the Ed25519 algorithm (modern, secure)
- `-C "comment"` — Add a comment (usually email) for identification

**Prompts:**

```
Generating public/private ed25519 key pair.
Enter file in which to save the key (/home/yourname/.ssh/id_ed25519):
```

Press Enter for default location.

```
Enter passphrase (empty for no passphrase):
```

**Strongly recommended:** Enter a passphrase. This encrypts your private key.

**Result:** Two files created:
- `~/.ssh/id_ed25519` — Private key (KEEP SECRET!)
- `~/.ssh/id_ed25519.pub` — Public key (can share freely)

#### Copying Your Public Key to a Server

**Using ssh-copy-id (easiest):**

```bash
ssh-copy-id username@remote-server
```

This adds your public key to `~/.ssh/authorized_keys` on the remote server.

**Manual method:**

```bash
# View your public key
cat ~/.ssh/id_ed25519.pub

# On the remote server, add to authorized_keys:
# mkdir -p ~/.ssh
# echo "paste-public-key-here" >> ~/.ssh/authorized_keys
# chmod 700 ~/.ssh
# chmod 600 ~/.ssh/authorized_keys
```

#### Testing Key Authentication

```bash
ssh username@remote-server
```

If keys are set up correctly, you'll either:
- Log in without password prompt (if no passphrase on key)
- Be prompted for your key's passphrase (not the server password)

### SSH Configuration File

The SSH server configuration lives at `/etc/ssh/sshd_config`.

**View current configuration:**

```bash
sudo cat /etc/ssh/sshd_config
```

**Important settings to understand:**

```bash
# Port SSH listens on
Port 22

# Allow root to log in?
PermitRootLogin prohibit-password

# Allow password authentication?
PasswordAuthentication yes

# Allow key authentication?
PubkeyAuthentication yes

# Maximum authentication attempts
MaxAuthTries 6

# Allow X11 forwarding (GUI applications)
X11Forwarding yes

# Connection timeout settings
ClientAliveInterval 300
ClientAliveCountMax 3
```

### Hardening SSH Configuration

Here's a secure SSH configuration. Apply these changes carefully:

```bash
# Backup the original config first!
sudo cp /etc/ssh/sshd_config /etc/ssh/sshd_config.backup

# Edit the configuration
sudo nano /etc/ssh/sshd_config
```

**Recommended security changes:**

```bash
# Change default port (obscurity, reduces automated attacks)
Port 2222

# Disable root login entirely (or use prohibit-password)
PermitRootLogin no

# Disable password authentication (after setting up keys!)
PasswordAuthentication no

# Ensure key authentication is enabled
PubkeyAuthentication yes

# Reduce max authentication attempts
MaxAuthTries 3

# Disable empty passwords
PermitEmptyPasswords no

# Limit users who can SSH (replace with actual usernames)
AllowUsers yourname admin

# Disable X11 forwarding (unless needed)
X11Forwarding no

# Set idle timeout (disconnect after 5 min idle)
ClientAliveInterval 300
ClientAliveCountMax 2
```

**After making changes:**

```bash
# Validate configuration syntax
sudo sshd -t

# If no errors, restart SSH
sudo systemctl restart ssh

# Verify it's still running
sudo systemctl status ssh
```

> **WARNING:** Before disabling password authentication, ensure key-based authentication works! You could lock yourself out.

### Testing Your SSH Hardening

From your host machine (or another system):

```bash
# Try connecting with password (should fail if disabled)
ssh -o PreferredAuthentications=password username@server

# Try connecting with keys (should work)
ssh username@server

# Try connecting as root (should fail if disabled)
ssh root@server
```

### Practical Exercises: SSH Security

#### Exercise 4.1: SSH Key Setup

On your Ubuntu VM:

1. Generate an Ed25519 key pair with a passphrase
2. View both the public and private keys
3. Note the difference in their contents

```bash
ssh-keygen -t ed25519 -C "security-lab"
cat ~/.ssh/id_ed25519.pub
head -2 ~/.ssh/id_ed25519
```

#### Exercise 4.2: SSH Configuration Audit

Create a script that audits SSH configuration:

```bash
#!/bin/bash
# ssh_audit.sh - Audit SSH configuration

CONFIG="/etc/ssh/sshd_config"
echo "=== SSH Security Audit ==="
echo ""

echo "Port:"
grep "^Port " $CONFIG || echo "Default (22)"

echo ""
echo "Root Login:"
grep "^PermitRootLogin" $CONFIG || echo "Not explicitly set"

echo ""
echo "Password Authentication:"
grep "^PasswordAuthentication" $CONFIG || echo "Not explicitly set (default: yes)"

echo ""
echo "Key Authentication:"
grep "^PubkeyAuthentication" $CONFIG || echo "Not explicitly set (default: yes)"

echo ""
echo "Max Auth Tries:"
grep "^MaxAuthTries" $CONFIG || echo "Not explicitly set (default: 6)"

echo ""
echo "Allowed Users:"
grep "^AllowUsers" $CONFIG || echo "Not set (all users allowed)"

echo ""
echo "=== Listening SSH Ports ==="
sudo ss -tlnp | grep ssh
```

Save to `~/security-lab/scripts/ssh_audit.sh`.

#### Exercise 4.3: Apply SSH Hardening

1. Backup your current SSH config
2. Change the port to 2222
3. Set MaxAuthTries to 3
4. Test the configuration
5. Restart SSH
6. Test connecting on the new port

```bash
sudo cp /etc/ssh/sshd_config /etc/ssh/sshd_config.backup
sudo sed -i 's/#Port 22/Port 2222/' /etc/ssh/sshd_config
sudo sed -i 's/#MaxAuthTries 6/MaxAuthTries 3/' /etc/ssh/sshd_config
sudo sshd -t
sudo systemctl restart ssh
ss -tlnp | grep 2222
```

---

### Milestone 4 Checkpoint

Before proceeding, verify:

- [ ] You understand what SSH is and why it matters for security
- [ ] You can generate SSH key pairs
- [ ] You understand the difference between public and private keys
- [ ] You can configure key-based authentication
- [ ] You know the important settings in sshd_config
- [ ] You can apply SSH hardening measures
- [ ] You understand the risks of common misconfigurations

**[CERT CHECKPOINT - Linux+ 2.5 / Security+ 4.1]**: SSH configuration is a core competency. Know how to secure remote access.

---

## Part 5 — Network Configuration (Milestone 5)

### Understanding Network Interfaces

A **network interface** is the connection between your system and a network. It can be:
- Physical hardware (Ethernet card, WiFi adapter)
- Virtual (VM network adapters, VPNs, containers)

### Viewing Network Configuration

#### The `ip` Command (Modern)

```bash
# Show all interfaces with addresses
ip addr show

# Shortened form
ip a

# Show specific interface
ip addr show eth0
```

**Understanding the output:**

```
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP
    link/ether 08:00:27:xx:xx:xx brd ff:ff:ff:ff:ff:ff
    inet 192.168.1.100/24 brd 192.168.1.255 scope global dynamic eth0
       valid_lft 86400sec preferred_lft 86400sec
    inet6 fe80::a00:27ff:fexx:xxxx/64 scope link
       valid_lft forever preferred_lft forever
```

| Field | Meaning |
|-------|---------|
| `eth0` | Interface name |
| `UP` | Interface is active |
| `link/ether` | MAC address |
| `inet` | IPv4 address and subnet mask |
| `/24` | Subnet mask (255.255.255.0) |
| `dynamic` | Address assigned via DHCP |
| `inet6` | IPv6 address |

#### Other Network Commands

```bash
# Show routing table
ip route show

# Show DNS servers
cat /etc/resolv.conf

# Show hostname
hostname

# Show all IP addresses (brief format)
ip -br addr

# Show network statistics
ip -s link
```

#### Legacy Commands (Still Useful)

```bash
# ifconfig (install: apt install net-tools)
ifconfig

# Show routing table
route -n
```

### Network Configuration in Ubuntu

Ubuntu uses **Netplan** to configure networking. Configuration files are in `/etc/netplan/`.

**View current Netplan config:**

```bash
cat /etc/netplan/*.yaml
```

**Example DHCP configuration:**

```yaml
network:
  version: 2
  ethernets:
    eth0:
      dhcp4: true
```

**Example static IP configuration:**

```yaml
network:
  version: 2
  ethernets:
    eth0:
      addresses:
        - 192.168.1.100/24
      gateway4: 192.168.1.1
      nameservers:
        addresses:
          - 8.8.8.8
          - 8.8.4.4
```

**Apply Netplan changes:**

```bash
sudo netplan apply
```

### DNS Resolution

DNS (Domain Name System) translates hostnames to IP addresses.

**Test DNS resolution:**

```bash
# Using dig (detailed)
dig google.com

# Using nslookup
nslookup google.com

# Using host (simple)
host google.com
```

**View DNS configuration:**

```bash
cat /etc/resolv.conf
```

### Testing Network Connectivity

```bash
# Ping a host
ping -c 4 google.com

# Trace route to destination
traceroute google.com
# Or:
tracepath google.com

# Check if port is open
nc -zv google.com 443

# Test HTTP connectivity
curl -I https://google.com
```

### Practical Exercises: Network Configuration

#### Exercise 5.1: Network Discovery

Document your network configuration:

```bash
#!/bin/bash
# network_info.sh - Document network configuration

echo "=== Hostname ==="
hostname

echo ""
echo "=== Network Interfaces ==="
ip -br addr

echo ""
echo "=== Detailed Interface Info ==="
ip addr show

echo ""
echo "=== Routing Table ==="
ip route show

echo ""
echo "=== DNS Configuration ==="
cat /etc/resolv.conf

echo ""
echo "=== Active Connections ==="
ss -tuln
```

Save to `~/security-lab/scripts/network_info.sh`.

#### Exercise 5.2: Connectivity Testing

Test connectivity to various destinations:

```bash
# Test local gateway
ping -c 2 $(ip route | grep default | awk '{print $3}')

# Test external connectivity
ping -c 2 8.8.8.8

# Test DNS resolution
ping -c 2 google.com

# Trace route to external host
tracepath -m 15 google.com
```

---

### Milestone 5 Checkpoint

Before proceeding, verify:

- [ ] You can view network interface configuration with `ip`
- [ ] You understand IP addresses, subnet masks, and gateways
- [ ] You know where network configuration files are
- [ ] You can test connectivity with ping and traceroute
- [ ] You understand DNS resolution

**[CERT CHECKPOINT - Network+ / Linux+]**: Basic networking is fundamental. Know how to view and interpret network configuration.

---

## Part 6 — Firewall Configuration (Milestone 6)

### What is a Firewall?

A **firewall** controls network traffic based on rules. It can:
- Allow or block connections
- Filter traffic by port, IP, protocol
- Log connection attempts

**Why firewalls matter:**
- First line of network defense
- Reduces attack surface
- Prevents unauthorized access
- Provides visibility into connection attempts

### UFW (Uncomplicated Firewall)

Ubuntu includes **UFW**, a user-friendly interface for iptables (the underlying firewall).

#### Check UFW Status

```bash
sudo ufw status
```

If inactive:
```
Status: inactive
```

#### Enable UFW

> **WARNING:** Before enabling UFW, ensure you have a rule to allow SSH, or you could lock yourself out!

```bash
# Allow SSH first!
sudo ufw allow ssh

# Or if using non-standard port:
sudo ufw allow 2222/tcp

# Now enable UFW
sudo ufw enable
```

```
Firewall is active and enabled on system startup
```

#### Basic UFW Commands

```bash
# Check status with rules
sudo ufw status verbose

# Allow a service by name
sudo ufw allow ssh
sudo ufw allow http
sudo ufw allow https

# Allow a specific port
sudo ufw allow 8080/tcp
sudo ufw allow 53/udp

# Allow from specific IP
sudo ufw allow from 192.168.1.50

# Allow from specific IP to specific port
sudo ufw allow from 192.168.1.50 to any port 22

# Deny a port
sudo ufw deny 23/tcp

# Delete a rule (by rule)
sudo ufw delete allow 8080/tcp

# Delete a rule (by number)
sudo ufw status numbered
sudo ufw delete 3

# Reset to defaults
sudo ufw reset

# Disable firewall
sudo ufw disable
```

### Default Policies

UFW has default policies for incoming and outgoing traffic:

```bash
# View defaults
sudo ufw status verbose
```

```
Default: deny (incoming), allow (outgoing), disabled (routed)
```

**Change default policies:**

```bash
# Deny all incoming by default (recommended)
sudo ufw default deny incoming

# Allow all outgoing by default
sudo ufw default allow outgoing
```

### UFW Logging

```bash
# Enable logging
sudo ufw logging on

# Set log level (low, medium, high, full)
sudo ufw logging medium
```

View firewall logs:

```bash
sudo grep UFW /var/log/syslog | tail -20

# Or
sudo journalctl | grep UFW | tail -20
```

### Creating a Secure Firewall Ruleset

Here's a basic secure configuration:

```bash
# Reset to clean state (careful if remote!)
sudo ufw reset

# Set default policies
sudo ufw default deny incoming
sudo ufw default allow outgoing

# Allow SSH (change port if needed)
sudo ufw allow ssh

# Allow specific services as needed
# sudo ufw allow http
# sudo ufw allow https

# Enable firewall
sudo ufw enable

# Verify
sudo ufw status verbose
```

### Practical Exercises: Firewall Configuration

#### Exercise 6.1: Basic Firewall Setup

1. Check current firewall status
2. Allow SSH
3. Enable the firewall
4. Verify the rules

```bash
sudo ufw status
sudo ufw allow ssh
sudo ufw enable
sudo ufw status verbose
```

#### Exercise 6.2: Firewall Audit Script

```bash
#!/bin/bash
# firewall_audit.sh - Document firewall configuration

echo "=== UFW Firewall Audit ==="
echo "Generated: $(date)"
echo ""

echo "=== Status ==="
sudo ufw status verbose

echo ""
echo "=== Rules (Numbered) ==="
sudo ufw status numbered

echo ""
echo "=== Recent Firewall Logs ==="
sudo grep UFW /var/log/syslog 2>/dev/null | tail -20
```

Save to `~/security-lab/scripts/firewall_audit.sh`.

---

### Milestone 6 Checkpoint

Before proceeding, verify:

- [ ] You understand what a firewall does
- [ ] You can enable and disable UFW
- [ ] You can create allow and deny rules
- [ ] You understand default policies
- [ ] You can enable and view firewall logging
- [ ] You have created a basic secure firewall configuration

**[CERT CHECKPOINT - Linux+ 2.4 / Security+]**: Firewall configuration is essential. Know how to implement basic access control.

---

## Part 7 — Scheduled Tasks (Milestone 7)

### Why Schedule Tasks?

Many administrative and security tasks should run automatically:
- Log rotation
- Backups
- Security scans
- System updates
- Monitoring scripts

### Cron: The Classic Scheduler

**Cron** runs commands on a schedule. Each user has a **crontab** (cron table).

#### Viewing and Editing Crontabs

```bash
# View your crontab
crontab -l

# Edit your crontab
crontab -e

# View root's crontab
sudo crontab -l

# View another user's crontab
sudo crontab -u username -l
```

#### Crontab Syntax

```
* * * * * command to run
│ │ │ │ │
│ │ │ │ └── Day of week (0-7, where 0 and 7 are Sunday)
│ │ │ └──── Month (1-12)
│ │ └────── Day of month (1-31)
│ └──────── Hour (0-23)
└────────── Minute (0-59)
```

**Examples:**

| Schedule | Meaning |
|----------|---------|
| `* * * * *` | Every minute |
| `0 * * * *` | Every hour (at minute 0) |
| `0 0 * * *` | Every day at midnight |
| `0 0 * * 0` | Every Sunday at midnight |
| `0 0 1 * *` | First day of every month at midnight |
| `30 6 * * 1-5` | 6:30 AM, Monday through Friday |
| `0 */2 * * *` | Every 2 hours |
| `0 9-17 * * *` | Every hour from 9 AM to 5 PM |

#### Creating Cron Jobs

```bash
# Edit crontab
crontab -e

# Add a job (example: run backup script daily at 2 AM)
0 2 * * * /home/yourname/scripts/backup.sh >> /home/yourname/logs/backup.log 2>&1
```

**Best practices:**
- Always use full paths
- Redirect output to a log file
- Use `2>&1` to capture errors too

#### System Cron Directories

Besides user crontabs, there are system-wide cron directories:

```bash
/etc/cron.d/        # Package-managed cron jobs
/etc/cron.daily/    # Scripts run daily
/etc/cron.hourly/   # Scripts run hourly
/etc/cron.weekly/   # Scripts run weekly
/etc/cron.monthly/  # Scripts run monthly
```

To add a system script, just place an executable script in the appropriate directory.

### Practical Exercise: Create a Security Scan Cron Job

1. Create a daily security scan script
2. Schedule it to run at 6 AM daily

```bash
#!/bin/bash
# /home/yourname/security-lab/scripts/daily_security_scan.sh

LOGDIR="$HOME/security-lab/logs"
mkdir -p "$LOGDIR"
LOGFILE="$LOGDIR/security_scan_$(date +%Y%m%d).log"

echo "Daily Security Scan - $(date)" > "$LOGFILE"
echo "================================" >> "$LOGFILE"

echo "" >> "$LOGFILE"
echo "=== Failed Login Attempts ===" >> "$LOGFILE"
sudo grep "Failed password" /var/log/auth.log 2>/dev/null | wc -l >> "$LOGFILE"

echo "" >> "$LOGFILE"
echo "=== Listening Ports ===" >> "$LOGFILE"
sudo ss -tlnp >> "$LOGFILE"

echo "" >> "$LOGFILE"
echo "=== Disk Usage ===" >> "$LOGFILE"
df -h >> "$LOGFILE"

echo "" >> "$LOGFILE"
echo "Scan complete" >> "$LOGFILE"
```

Add to crontab:
```bash
crontab -e
# Add:
0 6 * * * /home/yourname/security-lab/scripts/daily_security_scan.sh
```

---

### Milestone 7 Checkpoint

Before proceeding, verify:

- [ ] You understand why scheduled tasks are important
- [ ] You can read and write cron schedule syntax
- [ ] You can create and edit crontabs
- [ ] You know about system cron directories
- [ ] You have created a scheduled security scan

**[CERT CHECKPOINT - Linux+ 1.4]**: Know cron syntax and how to schedule administrative tasks.

---

## Part 8 — Disk and Storage Management (Milestone 8)

### Understanding Linux Storage

Linux sees storage devices as files in `/dev/`:

| Device | Description |
|--------|-------------|
| `/dev/sda` | First SATA/SCSI disk |
| `/dev/sda1` | First partition on sda |
| `/dev/sdb` | Second disk |
| `/dev/nvme0n1` | First NVMe SSD |
| `/dev/vda` | Virtual disk (VMs) |

### Viewing Disk Information

```bash
# List block devices
lsblk

# Show disk partitions
sudo fdisk -l

# Show disk usage
df -h

# Show directory size
du -sh /var/log

# Show inodes (file metadata)
df -i
```

### Understanding df Output

```bash
df -h
```

```
Filesystem      Size  Used Avail Use% Mounted on
/dev/sda1        20G   5G   14G  27% /
tmpfs           2.0G     0  2.0G   0% /dev/shm
/dev/sda2       100G  10G   85G  11% /home
```

| Column | Meaning |
|--------|---------|
| Filesystem | Device or filesystem |
| Size | Total capacity |
| Used | Space used |
| Avail | Space available |
| Use% | Percentage used |
| Mounted on | Where it's accessible |

### Finding Large Files and Directories

```bash
# Find largest directories
du -h --max-depth=1 / 2>/dev/null | sort -rh | head -10

# Find files larger than 100MB
find / -type f -size +100M 2>/dev/null

# Find largest files in a directory
find /var -type f -exec du -h {} + 2>/dev/null | sort -rh | head -10
```

### Practical Exercise: Disk Usage Audit

```bash
#!/bin/bash
# disk_audit.sh - Audit disk usage

echo "=== Disk Usage Report ==="
echo "Generated: $(date)"
echo ""

echo "=== Filesystem Usage ==="
df -h

echo ""
echo "=== Largest Directories ==="
du -h --max-depth=1 / 2>/dev/null | sort -rh | head -10

echo ""
echo "=== Large Files (>50MB) ==="
find / -type f -size +50M -exec ls -lh {} \; 2>/dev/null | head -20
```

Save to `~/security-lab/scripts/disk_audit.sh`.

---

### Milestone 8 Checkpoint

Before proceeding, verify:

- [ ] You understand Linux storage device naming
- [ ] You can view disk usage with df and du
- [ ] You can find large files and directories
- [ ] You understand mount points

**[CERT CHECKPOINT - Linux+ 1.3]**: Know how to view and manage disk storage.

---

## Part 9 — System Hardening (Milestone 9)

System hardening reduces attack surface by:
- Disabling unnecessary services
- Applying security configurations
- Removing unused software
- Implementing access controls

### Hardening Checklist

#### 1. Keep System Updated

```bash
sudo apt update && sudo apt upgrade -y
```

#### 2. Remove Unnecessary Packages

```bash
# List installed packages
dpkg -l | wc -l

# Remove unnecessary packages (example)
sudo apt purge telnet ftp
sudo apt autoremove
```

#### 3. Disable Unnecessary Services

```bash
# List enabled services
systemctl list-unit-files --type=service --state=enabled

# Disable unused services (examples)
sudo systemctl disable bluetooth
sudo systemctl disable cups
```

#### 4. Configure Firewall

(Already covered in Part 6)

#### 5. Secure SSH

(Already covered in Part 4)

#### 6. Set Password Policies

View password policies:
```bash
cat /etc/login.defs
```

Key settings:
```
PASS_MAX_DAYS   90      # Maximum password age
PASS_MIN_DAYS   7       # Minimum days between changes
PASS_WARN_AGE   14      # Days warning before expiry
```

#### 7. Restrict Root Access

```bash
# Ensure root login is disabled in SSH
grep PermitRootLogin /etc/ssh/sshd_config

# Use sudo instead of su
# Remove direct root access
```

#### 8. Enable Audit Logging

```bash
# Install auditd
sudo apt install auditd

# Start and enable
sudo systemctl enable --now auditd

# View audit logs
sudo ausearch -m USER_LOGIN
```

### Create a Hardening Report

```bash
#!/bin/bash
# hardening_check.sh - Basic system hardening audit

echo "=== System Hardening Audit ==="
echo "Generated: $(date)"
echo "Host: $(hostname)"
echo "================================"
echo ""

echo "=== System Updates ==="
apt list --upgradable 2>/dev/null | wc -l
echo "packages can be upgraded"
echo ""

echo "=== SSH Configuration ==="
echo "Root Login: $(grep PermitRootLogin /etc/ssh/sshd_config | grep -v '#')"
echo "Password Auth: $(grep PasswordAuthentication /etc/ssh/sshd_config | grep -v '#')"
echo ""

echo "=== Firewall Status ==="
sudo ufw status | head -5
echo ""

echo "=== Enabled Services Count ==="
systemctl list-unit-files --type=service --state=enabled | wc -l
echo ""

echo "=== Users with Login Shells ==="
grep -v "nologin\|false" /etc/passwd | cut -d: -f1
echo ""

echo "=== SUID Files ==="
find /usr -perm -4000 -type f 2>/dev/null | wc -l
echo "SUID files found"
echo ""

echo "=== World-Writable Files in /etc ==="
find /etc -perm -0002 -type f 2>/dev/null | wc -l
echo "world-writable files in /etc"
```

Save to `~/security-lab/scripts/hardening_check.sh`.

---

### Milestone 9 Checkpoint

Before proceeding, verify:

- [ ] You understand the principles of system hardening
- [ ] You can identify and disable unnecessary services
- [ ] You know how to audit system security
- [ ] You have created the hardening_check.sh script

**[CERT CHECKPOINT - Linux+ 2.1 / Security+ 3.0]**: System hardening is essential for security. Know how to reduce attack surface.

---

## Stage 02 Assessment

### Written Assessment

Answer these questions in `~/security-lab/reports/stage02_assessment.txt`:

1. What is the difference between `apt update` and `apt upgrade`?

2. Explain the difference between enabling and starting a service.

3. What are three important SSH hardening measures?

4. What is the purpose of `/var/log/auth.log`?

5. Explain the cron schedule: `30 2 * * 0`

6. What does the UFW command `sudo ufw default deny incoming` do?

7. Why is it important to disable unnecessary services?

8. How would you find all files larger than 100MB on the system?

### Practical Assessment

1. **Service Management:** Install nginx, start it, enable it at boot, then verify it's listening on port 80. Finally, stop and disable it.

2. **Log Analysis:** Create a script that counts failed SSH login attempts per IP address and identifies the top 5 offenders.

3. **Firewall Configuration:** Configure UFW to:
   - Allow SSH on port 2222
   - Allow HTTP and HTTPS
   - Deny all other incoming traffic
   - Document the rules

4. **Scheduled Task:** Create a cron job that runs your hardening_check.sh script weekly and saves output to a timestamped log file.

---

## Stage 02 Completion Checklist

### Package Management
- [ ] Can use apt to update, upgrade, install, remove packages
- [ ] Can use dpkg to query package information
- [ ] Understand security importance of updates

### Service Management
- [ ] Can start, stop, restart, enable, disable services
- [ ] Can check service status and logs
- [ ] Can audit running and enabled services

### System Logging
- [ ] Know key log file locations
- [ ] Can use journalctl with filters
- [ ] Can analyze auth.log for security events
- [ ] Created log_monitor.sh

### SSH Security
- [ ] Can generate and use SSH keys
- [ ] Understand sshd_config settings
- [ ] Can apply SSH hardening
- [ ] Created ssh_audit.sh

### Network Configuration
- [ ] Can view network configuration with ip command
- [ ] Understand basic network settings
- [ ] Created network_info.sh

### Firewall
- [ ] Can configure UFW rules
- [ ] Understand default policies
- [ ] Created secure firewall configuration
- [ ] Created firewall_audit.sh

### Scheduled Tasks
- [ ] Can create and edit crontabs
- [ ] Understand cron syntax
- [ ] Created scheduled security scan

### Disk Management
- [ ] Can view disk usage with df and du
- [ ] Can find large files
- [ ] Created disk_audit.sh

### System Hardening
- [ ] Understand hardening principles
- [ ] Created hardening_check.sh
- [ ] Applied basic hardening to VM

### Assessment
- [ ] Written assessment completed
- [ ] Practical assessment completed

### Git Workflow
- [ ] Stage 02 committed
- [ ] Stage 02 pushed

---

## Definition of Done

Stage 02 is complete when:

1. All checklist items are checked
2. All scripts are created and functional
3. Your Ubuntu VM has basic hardening applied
4. Assessment is complete
5. Work is committed and pushed

---

## What's Next: Stage 03 Preview

In Stage 03 — Networking Fundamentals for Security, you will learn:

- TCP/IP and OSI models in depth
- Common network protocols (HTTP, DNS, SSH, etc.)
- Wireshark packet analysis
- Network troubleshooting
- Advanced firewall concepts
- Network security principles

These networking fundamentals are essential before diving into Kali Linux and security tools.

---

## Supplementary Resources

### Practice
- **TryHackMe:** "Linux Fundamentals Part 3" room (free)
- **OverTheWire:** Bandit wargame levels 15-25

### Reading
- Ubuntu Server Guide: https://ubuntu.com/server/docs
- Linux+ Study Guide (XK0-005)
- Red Hat System Administration guides (concepts apply)

---

**Commit your work and proceed to Stage 03 when ready:**

```bash
cd ~/path-to-repo
git add .
git commit -m "Complete Stage 02 - Linux System Administration"
git push
```
