# Stage 04 — Kali Linux Setup and Security Methodology
## Your Security Testing Platform and Professional Framework

**Kali Linux for Cybersecurity Learning Path**  
**Audience:** Learners who have completed Stages 01-03 (ready for security-specific tools)

Welcome to Stage 04. In Stages 01-03, you built a solid foundation in Linux and networking. Now you're ready to set up your primary security testing platform: **Kali Linux**. More importantly, you'll learn the **methodology and ethical framework** that separates professional security work from hacking.

---

## Prerequisites

Before starting Stage 04, you must have completed Stages 01-03:

- [ ] Comfortable with Linux command line and administration
- [ ] Understand network protocols and can analyze traffic
- [ ] Can perform basic network reconnaissance
- [ ] Have VirtualBox installed and working
- [ ] Understand TCP/IP, ports, and common services

If any of these are not checked, return to the previous stages first.

---

## Why This Stage Matters

**Kali Linux is the industry-standard penetration testing platform:**

| What Kali Provides | Why It Matters |
|-------------------|----------------|
| 600+ security tools pre-installed | No setup overhead for testing |
| Purpose-built for security work | Optimized configurations |
| Regular updates | Latest tools and exploits |
| Industry recognition | Expected knowledge for security roles |
| Documentation and community | Extensive learning resources |

**But tools without methodology are dangerous:**

| Without Methodology | With Methodology |
|---------------------|------------------|
| Random tool execution | Structured approach |
| Missed vulnerabilities | Comprehensive coverage |
| Legal liability | Protected engagement |
| Unprofessional reports | Actionable deliverables |
| Ethical violations | Responsible disclosure |

This stage teaches you both the platform AND the professional framework.

---

## What You Will Learn

By the end of this stage, you will be able to:

- Install and configure Kali Linux as a VM
- Understand the penetration testing methodology
- Explain the legal and ethical requirements for security testing
- Set up a safe, isolated lab environment
- Navigate Kali's tool categories
- Create proper documentation for security engagements
- Understand rules of engagement and scope

---

## What You Will Build

1. **Kali Linux VM** — Fully configured security testing platform
2. **Vulnerable target VMs** — Safe practice environment
3. **Lab network documentation** — Network diagram and configuration
4. **Engagement checklist template** — Professional documentation
5. **Rules of engagement template** — Legal protection framework
6. **Tool reference guide** — Personal notes on Kali tools

---

## Certification Alignment

This stage maps to objectives from:

| Certification | Relevant Domains |
|--------------|------------------|
| **CompTIA PenTest+** | 1.0 Planning and Scoping |
| **CompTIA Security+** | 5.0 Security Program Management |
| **CEH** | Module 1: Introduction to Ethical Hacking |
| **eJPT** | Assessment Methodologies |

> **Certification Exam Currency Notice:** Certification objectives are updated periodically. Verify current exam objectives at the vendor's official website before beginning exam preparation. See `docs/CERTIFICATION_MAPPING.md` for detailed alignment information.

---

## Time Estimate

**Total: 25-30 hours**

| Section | Hours |
|---------|-------|
| Kali Linux Installation | 3-4 |
| Initial Configuration | 2-3 |
| Penetration Testing Methodology | 4-5 |
| Legal and Ethical Framework | 3-4 |
| Lab Environment Setup | 4-5 |
| Kali Tool Categories | 4-5 |
| Documentation Templates | 2-3 |
| Stage Assessment | 2-3 |

---

## The Milestones Approach

### Stage 04 Milestones

1. **Install Kali Linux VM**
2. **Configure Kali for security work**
3. **Understand penetration testing methodology**
4. **Master the legal and ethical framework**
5. **Set up vulnerable target VMs**
6. **Explore Kali tool categories**
7. **Create professional documentation templates**
8. **Complete the stage assessment**

---

## Part 1 — Installing Kali Linux (Milestone 1)

### What is Kali Linux?

**Kali Linux** is a Debian-based Linux distribution designed specifically for:
- Penetration testing
- Security auditing
- Digital forensics
- Reverse engineering

**Key characteristics:**
- Maintained by Offensive Security (creators of OSCP certification)
- Over 600 pre-installed security tools
- Regular rolling updates
- Multiple platform support (VM, bare metal, ARM, containers, WSL)

### Kali vs. Your Ubuntu Server

| Aspect | Ubuntu Server (Stages 01-03) | Kali Linux (Stage 04+) |
|--------|------------------------------|------------------------|
| Purpose | General server/learning | Security testing |
| Desktop | Optional/none | Full desktop included |
| Tools | Minimal, add as needed | 600+ security tools |
| Updates | Stable releases | Rolling release |
| Default user | Regular user + sudo | `kali` user |
| Use case | Production servers, learning | Penetration testing |

**Important:** Kali is designed for security testing, not as a daily-use OS. Keep your Ubuntu VM for general learning.

### Download Kali Linux

1. Go to: https://www.kali.org/get-kali/

2. Select **Virtual Machines** (pre-built VMs are easiest)

3. Download the **VirtualBox 64-bit** version
   - File will be named like: `kali-linux-2024.4-virtualbox-amd64.7z`
   - Size: approximately 3-4 GB compressed

4. Extract the downloaded file:
   - Windows: Use 7-Zip (free: https://www.7-zip.org/)
   - macOS: Use Keka or The Unarchiver
   - Linux: `7z x kali-linux-*.7z`

### Import Kali into VirtualBox

1. **Open VirtualBox**

2. **Import the appliance:**
   - File → Import Appliance
   - Browse to the extracted `.vbox` file
   - Click "Import"

3. **Wait for import** (may take several minutes)

4. **Review settings before first boot:**
   - Select the Kali VM
   - Click "Settings"

### Configure VM Settings

#### Memory (RAM)

- **Minimum:** 2 GB (2048 MB)
- **Recommended:** 4 GB (4096 MB)
- **Optimal:** 8 GB (8192 MB) if available

```
Settings → System → Motherboard → Base Memory: 4096 MB
```

#### Processors

- **Minimum:** 1 CPU
- **Recommended:** 2 CPUs
- **Optimal:** 4 CPUs if available

```
Settings → System → Processor → Processor(s): 2
```

#### Storage

The pre-built VM comes with adequate storage. If you need more:

```
Settings → Storage → Controller: SATA → Kali disk
```

The default 80 GB virtual disk is usually sufficient.

#### Network

For initial setup, use NAT (default). We'll configure additional networks later.

```
Settings → Network → Adapter 1 → Attached to: NAT
```

#### Display

Enable 3D acceleration for better performance:

```
Settings → Display → Screen → Video Memory: 128 MB
Settings → Display → Screen → Enable 3D Acceleration: ✓
```

### First Boot

1. **Start the Kali VM:**
   - Select Kali in VirtualBox
   - Click "Start"

2. **Default credentials:**
   - Username: `kali`
   - Password: `kali`

3. **Login to the desktop environment**

### Immediate Post-Installation Tasks

#### Change the Default Password

**Critical security step!** Never keep default credentials.

```bash
# Open a terminal (click terminal icon or right-click desktop)
passwd
```

Enter current password (`kali`), then your new strong password twice.

#### Update the System

Kali uses rolling releases—always update before use:

```bash
# Update package lists
sudo apt update

# Upgrade all packages
sudo apt full-upgrade -y

# Clean up
sudo apt autoremove -y
sudo apt clean
```

This may take 15-30 minutes depending on how recent the image is.

#### Install VirtualBox Guest Additions

Guest Additions enable:
- Shared clipboard
- Drag and drop
- Shared folders
- Better display resolution
- Improved performance

```bash
# Install guest additions package
sudo apt install -y virtualbox-guest-x11

# Reboot to apply
sudo reboot
```

After reboot:
- View → Auto-resize Guest Display (in VirtualBox menu)
- Devices → Shared Clipboard → Bidirectional

#### Create a Snapshot

**Before making more changes, snapshot your clean installation:**

1. In VirtualBox: Machine → Take Snapshot
2. Name it: "Clean Install - Updated"
3. Description: "Fresh Kali install with updates and guest additions"

**Snapshots are your safety net.** If something breaks, you can restore.

### Practical Exercise: Verify Installation

Run these commands to verify your Kali installation:

```bash
# Check Kali version
cat /etc/os-release

# Check kernel version
uname -a

# Verify you're running as kali user
whoami

# Check available disk space
df -h

# Verify network connectivity
ping -c 3 google.com

# Check if common tools are present
which nmap
which metasploit-framework
which burpsuite

# List number of installed packages
dpkg -l | wc -l
```

Create a verification script:

```bash
#!/bin/bash
# kali_verify.sh - Verify Kali installation

echo "=== Kali Linux Installation Verification ==="
echo ""

echo "=== System Information ==="
echo "Kali Version: $(grep VERSION_ID /etc/os-release | cut -d= -f2)"
echo "Kernel: $(uname -r)"
echo "Architecture: $(uname -m)"
echo "Hostname: $(hostname)"
echo ""

echo "=== User Information ==="
echo "Current User: $(whoami)"
echo "User Groups: $(groups)"
echo ""

echo "=== Network Information ==="
ip -4 addr show | grep inet | head -2
echo "Gateway: $(ip route | grep default | awk '{print $3}')"
echo ""

echo "=== Resource Status ==="
echo "Memory: $(free -h | grep Mem | awk '{print $2}') total, $(free -h | grep Mem | awk '{print $3}') used"
echo "Disk: $(df -h / | tail -1 | awk '{print $2}') total, $(df -h / | tail -1 | awk '{print $3}') used"
echo ""

echo "=== Key Tools Verification ==="
tools=("nmap" "nikto" "dirb" "sqlmap" "hydra" "john" "hashcat" "burpsuite" "metasploit-framework" "wireshark")
for tool in "${tools[@]}"; do
    if command -v "$tool" &>/dev/null || dpkg -l | grep -q "$tool"; then
        echo "[✓] $tool"
    else
        echo "[✗] $tool (not found)"
    fi
done
echo ""

echo "=== Packages Installed ==="
echo "Total packages: $(dpkg -l | grep -c '^ii')"
echo ""

echo "=== Verification Complete ==="
```

Save to `~/scripts/kali_verify.sh` and make executable.

---

### Milestone 1 Checkpoint

Before proceeding, verify:

- [ ] Kali Linux VM imported and running
- [ ] Default password changed
- [ ] System fully updated
- [ ] Guest additions installed
- [ ] Snapshot created
- [ ] Network connectivity verified
- [ ] Common tools present

**[CERT CHECKPOINT - PenTest+ / CEH]**: Know how to set up your testing environment properly.

---

## Part 2 — Configuring Kali for Security Work (Milestone 2)

### Essential Configuration Tasks

#### Configure Terminal

Kali uses the XFCE desktop by default. Let's configure the terminal:

**Open Terminal Preferences:**
- Right-click in terminal → Preferences

**Recommended settings:**
- Font: Monospace 11 or 12
- Background: Slightly transparent (80-90%)
- Scrollback: 10000 lines or unlimited
- Colors: Your preference (Solarized Dark is popular)

#### Set Up Directory Structure

Create an organized workspace:

```bash
# Create working directories
mkdir -p ~/engagements
mkdir -p ~/tools
mkdir -p ~/wordlists
mkdir -p ~/scripts
mkdir -p ~/notes
mkdir -p ~/evidence

# Create a template engagement structure
mkdir -p ~/templates/engagement/{recon,scanning,exploitation,post-exploitation,evidence,reports}

# Set permissions
chmod 700 ~/engagements ~/evidence
```

#### Configure Bash History

Preserve command history for documentation:

```bash
# Edit .bashrc
nano ~/.bashrc

# Add these lines at the end:
# History configuration
HISTSIZE=50000
HISTFILESIZE=100000
HISTTIMEFORMAT="%Y-%m-%d %H:%M:%S  "
HISTCONTROL=ignoredups:erasedups
shopt -s histappend

# Save after each command
PROMPT_COMMAND="history -a; $PROMPT_COMMAND"
```

Apply changes:

```bash
source ~/.bashrc
```

Now your history will include timestamps—valuable for engagement documentation.

#### Install Additional Useful Tools

Some useful tools not in the default installation:

```bash
# General utilities
sudo apt install -y \
    terminator \
    tmux \
    tree \
    jq \
    golang-go \
    python3-pip \
    pipx \
    seclists \
    feroxbuster

# Ensure pipx path is set
pipx ensurepath
source ~/.bashrc
```

#### Configure Git

You'll use Git for notes and scripts:

```bash
git config --global user.name "Your Name"
git config --global user.email "your.email@example.com"
git config --global init.defaultBranch main
```

#### Set Up Aliases

Add useful aliases to `~/.bash_aliases`:

```bash
# Create aliases file
cat << 'EOF' > ~/.bash_aliases
# Navigation
alias ll='ls -la'
alias la='ls -A'
alias l='ls -CF'
alias ..='cd ..'
alias ...='cd ../..'

# Safety
alias rm='rm -i'
alias mv='mv -i'
alias cp='cp -i'

# Network
alias myip='curl -s ifconfig.me'
alias ports='ss -tulanp'
alias listening='ss -tlnp'

# Quick tools
alias serve='python3 -m http.server 8000'
alias clip='xclip -selection clipboard'
alias timestamp='date +%Y%m%d_%H%M%S'

# Engagement shortcuts
alias newengagement='mkdir -p $(date +%Y%m%d)_{recon,scanning,exploitation,evidence,reports}'

# Quick references
alias ports-common='cat /usr/share/nmap/nmap-services | grep -v "^#" | sort -k3 -rn | head -20'

# History search
alias hg='history | grep'
EOF

source ~/.bashrc
```

### Configure Network Interfaces

#### Understanding Kali's Network Modes

For security testing, you'll use different network configurations:

| Mode | Use Case | Configuration |
|------|----------|---------------|
| NAT | Internet access, updates | Default adapter |
| Host-Only | Isolated lab network | Additional adapter |
| Bridged | Same network as host | Testing on local network |
| Internal | VM-only network | Isolated VM communication |

#### Add a Host-Only Network

For your lab environment:

1. **In VirtualBox (not the VM):**
   - File → Host Network Manager
   - Click "Create"
   - Note the name (e.g., `vboxnet0`)
   - Configure: DHCP enabled, or set static range

2. **Add adapter to Kali VM:**
   - Settings → Network → Adapter 2
   - Enable Network Adapter: ✓
   - Attached to: Host-only Adapter
   - Name: vboxnet0

3. **Start Kali and verify:**

```bash
# See all interfaces
ip addr show

# You should see two interfaces (besides lo):
# eth0 - NAT (internet)
# eth1 - Host-only (lab)
```

### Configure Metasploit Database

Metasploit uses a PostgreSQL database. Initialize it:

```bash
# Start PostgreSQL service
sudo systemctl start postgresql
sudo systemctl enable postgresql

# Initialize the Metasploit database
sudo msfdb init

# Verify database connection
msfconsole -q -x "db_status; exit"
```

Expected output: `[*] Connected to msf. Connection type: postgresql.`

### Customize the Desktop (Optional)

#### Panel Configuration

Right-click the panel → Panel → Panel Preferences:
- Add: Workspace Switcher
- Add: System Load Monitor
- Adjust size and position

#### Workspaces

Set up multiple workspaces for organization:
- Settings → Workspaces → Number of workspaces: 4

Example workspace organization:
1. **Workspace 1:** Terminals and reconnaissance
2. **Workspace 2:** Web browser and web tools
3. **Workspace 3:** Burp Suite and web testing
4. **Workspace 4:** Documentation and reporting

### Create Configuration Backup Script

```bash
#!/bin/bash
# backup_config.sh - Backup Kali configuration

BACKUP_DIR="$HOME/backups"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
BACKUP_NAME="kali_config_$TIMESTAMP"

mkdir -p "$BACKUP_DIR"

echo "Creating configuration backup..."

# Create backup directory
mkdir -p "$BACKUP_DIR/$BACKUP_NAME"

# Backup important configs
cp ~/.bashrc "$BACKUP_DIR/$BACKUP_NAME/"
cp ~/.bash_aliases "$BACKUP_DIR/$BACKUP_NAME/" 2>/dev/null
cp ~/.bash_history "$BACKUP_DIR/$BACKUP_NAME/"
cp -r ~/.config "$BACKUP_DIR/$BACKUP_NAME/" 2>/dev/null
cp -r ~/.ssh "$BACKUP_DIR/$BACKUP_NAME/" 2>/dev/null
cp -r ~/scripts "$BACKUP_DIR/$BACKUP_NAME/" 2>/dev/null
cp -r ~/templates "$BACKUP_DIR/$BACKUP_NAME/" 2>/dev/null

# Create archive
cd "$BACKUP_DIR"
tar -czf "$BACKUP_NAME.tar.gz" "$BACKUP_NAME"
rm -rf "$BACKUP_NAME"

echo "Backup created: $BACKUP_DIR/$BACKUP_NAME.tar.gz"
ls -lh "$BACKUP_DIR/$BACKUP_NAME.tar.gz"
```

Save to `~/scripts/backup_config.sh`.

---

### Milestone 2 Checkpoint

Before proceeding, verify:

- [ ] Terminal configured to your preferences
- [ ] Directory structure created
- [ ] Bash history configured with timestamps
- [ ] Additional tools installed
- [ ] Aliases set up
- [ ] Network interfaces configured (NAT + Host-only)
- [ ] Metasploit database initialized
- [ ] Configuration backup script created

**[CERT CHECKPOINT - PenTest+]**: Proper environment configuration is part of professional testing.

---

## Part 3 — Penetration Testing Methodology (Milestone 3)

### Why Methodology Matters

Random tool execution is not penetration testing. A methodology provides:

| Benefit | Description |
|---------|-------------|
| **Consistency** | Same quality regardless of tester |
| **Completeness** | No areas missed |
| **Reproducibility** | Results can be verified |
| **Professionalism** | Meets industry standards |
| **Legal protection** | Documented scope and approach |

### Industry-Standard Methodologies

#### PTES (Penetration Testing Execution Standard)

The most comprehensive methodology, with 7 phases:

```
┌─────────────────────────────────────────────────────────────────┐
│                    PTES Methodology                              │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  1. Pre-engagement    ─► Define scope, rules, objectives        │
│         │                                                        │
│         ▼                                                        │
│  2. Intelligence      ─► Gather information about target        │
│     Gathering              (OSINT, passive recon)               │
│         │                                                        │
│         ▼                                                        │
│  3. Threat Modeling   ─► Identify assets, threats, attack       │
│                            vectors                               │
│         │                                                        │
│         ▼                                                        │
│  4. Vulnerability     ─► Identify and validate                  │
│     Analysis               vulnerabilities                       │
│         │                                                        │
│         ▼                                                        │
│  5. Exploitation      ─► Attempt to exploit vulnerabilities     │
│         │                                                        │
│         ▼                                                        │
│  6. Post-Exploitation ─► Determine value, maintain access,      │
│                            pivot                                 │
│         │                                                        │
│         ▼                                                        │
│  7. Reporting         ─► Document findings and recommendations  │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

#### OWASP Testing Guide

Focused on web application security:

- Information Gathering
- Configuration and Deployment Management Testing
- Identity Management Testing
- Authentication Testing
- Authorization Testing
- Session Management Testing
- Input Validation Testing
- Error Handling Testing
- Cryptography Testing
- Business Logic Testing
- Client-Side Testing

#### NIST SP 800-115

Government standard for technical security testing:

1. Planning
2. Discovery
3. Attack
4. Reporting

#### Cyber Kill Chain (Lockheed Martin)

Understanding attacker methodology:

```
1. Reconnaissance    ─► Research target
2. Weaponization     ─► Create exploit/payload
3. Delivery          ─► Transmit to target
4. Exploitation      ─► Execute code
5. Installation      ─► Install malware/backdoor
6. Command & Control ─► Establish remote control
7. Actions on Objectives ─► Achieve goals
```

### Our Methodology Framework

For this course, we'll use a simplified, practical framework:

```
┌────────────────────────────────────────────────────────────────┐
│               Security Assessment Framework                     │
├────────────────────────────────────────────────────────────────┤
│                                                                 │
│  PHASE 0: PRE-ENGAGEMENT                                       │
│  ├── Scope definition                                          │
│  ├── Rules of engagement                                       │
│  ├── Authorization documentation                               │
│  └── Communication plan                                        │
│                                                                 │
│  PHASE 1: RECONNAISSANCE                                       │
│  ├── Passive reconnaissance (OSINT)                            │
│  ├── Active reconnaissance (scanning)                          │
│  └── Target profiling                                          │
│                                                                 │
│  PHASE 2: SCANNING & ENUMERATION                               │
│  ├── Port scanning                                             │
│  ├── Service enumeration                                       │
│  ├── Vulnerability scanning                                    │
│  └── Web application scanning                                  │
│                                                                 │
│  PHASE 3: VULNERABILITY ANALYSIS                               │
│  ├── Identify vulnerabilities                                  │
│  ├── Research exploits                                         │
│  ├── Validate findings                                         │
│  └── Prioritize by risk                                        │
│                                                                 │
│  PHASE 4: EXPLOITATION                                         │
│  ├── Attempt exploitation                                      │
│  ├── Document success/failure                                  │
│  ├── Capture evidence                                          │
│  └── Avoid disruption                                          │
│                                                                 │
│  PHASE 5: POST-EXPLOITATION                                    │
│  ├── Privilege escalation                                      │
│  ├── Lateral movement                                          │
│  ├── Data identification                                       │
│  └── Persistence (if in scope)                                 │
│                                                                 │
│  PHASE 6: REPORTING                                            │
│  ├── Executive summary                                         │
│  ├── Technical findings                                        │
│  ├── Risk ratings                                              │
│  ├── Recommendations                                           │
│  └── Evidence appendix                                         │
│                                                                 │
│  PHASE 7: REMEDIATION SUPPORT                                  │
│  ├── Clarification                                             │
│  ├── Retesting                                                 │
│  └── Knowledge transfer                                        │
│                                                                 │
└────────────────────────────────────────────────────────────────┘
```

### Phase Details

#### Phase 0: Pre-Engagement

**This phase happens BEFORE any testing.**

**Key deliverables:**
- Signed authorization (contract/statement of work)
- Scope document (what's included and excluded)
- Rules of engagement (what's allowed)
- Emergency contacts
- Testing timeline

**Critical questions to answer:**
- What systems/networks are in scope?
- What's explicitly OUT of scope?
- What testing is allowed (DoS? Social engineering?)
- What hours can testing occur?
- Who do I contact if something breaks?
- Where do I report critical findings immediately?

#### Phase 1: Reconnaissance

**Goal:** Gather as much information as possible about the target.

**Passive reconnaissance (no direct contact):**
- WHOIS lookups
- DNS enumeration
- Search engine research
- Social media investigation
- Job posting analysis
- Public document review

**Active reconnaissance (direct contact):**
- DNS zone transfers
- Network scanning
- Banner grabbing
- Web spidering

**Output:** Target profile document

#### Phase 2: Scanning & Enumeration

**Goal:** Identify live systems, open ports, and running services.

**Activities:**
- Host discovery
- Port scanning
- Service version detection
- Operating system fingerprinting
- Web application discovery
- Vulnerability scanning

**Output:** Asset inventory with services

#### Phase 3: Vulnerability Analysis

**Goal:** Identify and validate security weaknesses.

**Activities:**
- Automated vulnerability scanning
- Manual verification
- Research known vulnerabilities
- Identify misconfigurations
- Analyze for logic flaws

**Output:** Validated vulnerability list with severity

#### Phase 4: Exploitation

**Goal:** Demonstrate real-world impact of vulnerabilities.

**Activities:**
- Attempt exploitation
- Document all attempts (success and failure)
- Capture screenshots/evidence
- Avoid system disruption
- Stay within scope

**Output:** Exploitation evidence, access achieved

#### Phase 5: Post-Exploitation

**Goal:** Demonstrate potential damage and attack paths.

**Activities:**
- Privilege escalation attempts
- Internal network reconnaissance
- Sensitive data identification
- Lateral movement attempts
- Persistence mechanisms (if authorized)

**Output:** Impact assessment, attack path documentation

#### Phase 6: Reporting

**Goal:** Communicate findings clearly and actionably.

**Report components:**
- Executive summary (non-technical)
- Methodology overview
- Findings with severity ratings
- Step-by-step reproduction
- Evidence (screenshots, logs)
- Recommendations
- Risk ratings (CVSS or custom)

**Output:** Professional penetration test report

#### Phase 7: Remediation Support

**Goal:** Help the client fix issues.

**Activities:**
- Answer questions about findings
- Provide additional context
- Retest fixed vulnerabilities
- Verify remediation effectiveness

**Output:** Retest report, closure

### Create Methodology Cheat Sheet

```bash
#!/bin/bash
# Create methodology reference

cat << 'EOF' > ~/notes/methodology_reference.md
# Penetration Testing Methodology Reference

## Phase 0: Pre-Engagement
- [ ] Authorization signed
- [ ] Scope defined
- [ ] Rules of engagement agreed
- [ ] Emergency contacts documented
- [ ] Timeline confirmed

## Phase 1: Reconnaissance
### Passive
- [ ] WHOIS lookup
- [ ] DNS records
- [ ] Search engine recon
- [ ] Social media review
- [ ] Job postings analysis
- [ ] Public documents

### Active
- [ ] DNS zone transfer attempt
- [ ] Subdomain enumeration
- [ ] Network range identification

## Phase 2: Scanning & Enumeration
- [ ] Host discovery
- [ ] Port scanning (TCP)
- [ ] Port scanning (UDP - top ports)
- [ ] Service version detection
- [ ] OS fingerprinting
- [ ] Web server discovery
- [ ] Default credentials check

## Phase 3: Vulnerability Analysis
- [ ] Vulnerability scan
- [ ] Manual verification
- [ ] CVE research
- [ ] Exploit availability check
- [ ] Risk prioritization

## Phase 4: Exploitation
- [ ] Create exploitation plan
- [ ] Test exploits (controlled)
- [ ] Document all attempts
- [ ] Capture evidence
- [ ] Note any system impact

## Phase 5: Post-Exploitation
- [ ] Document access level
- [ ] Privilege escalation
- [ ] Sensitive data search
- [ ] Network pivoting
- [ ] Persistence (if authorized)

## Phase 6: Reporting
- [ ] Executive summary
- [ ] Technical findings
- [ ] CVSS/risk ratings
- [ ] Reproduction steps
- [ ] Recommendations
- [ ] Evidence appendix

## Phase 7: Remediation Support
- [ ] Client Q&A
- [ ] Retesting
- [ ] Closure documentation
EOF

echo "Created: ~/notes/methodology_reference.md"
```

---

### Milestone 3 Checkpoint

Before proceeding, verify:

- [ ] You understand why methodology matters
- [ ] You can name the phases of penetration testing
- [ ] You understand what happens in each phase
- [ ] You know the difference between reconnaissance types
- [ ] You understand the importance of pre-engagement
- [ ] You have created your methodology reference

**[CERT CHECKPOINT - PenTest+ 1.0 / CEH]**: Methodology is heavily tested. Know the phases and their purposes.

---

## Part 4 — Legal and Ethical Framework (Milestone 4)

### The Critical Importance of Authorization

**UNAUTHORIZED SECURITY TESTING IS A CRIME.**

This cannot be overstated. Without proper authorization:

| Activity | Legal Status |
|----------|--------------|
| Port scanning someone's server | Potentially illegal |
| Running vulnerability scans | Illegal in many jurisdictions |
| Attempting exploitation | Definitely illegal |
| Accessing systems | Computer fraud, felony charges |

**With written authorization, the same activities become:**
- Legal
- Professional
- Valuable security work

### Relevant Laws (United States)

#### Computer Fraud and Abuse Act (CFAA)

The primary U.S. federal law covering computer crimes:

- Unauthorized access to computers
- Exceeding authorized access
- Damage to protected computers
- Trafficking in passwords
- Extortion via computer

**Penalties:** Fines and imprisonment (up to 20 years for some offenses)

#### State Laws

Most states have additional computer crime laws. Some are more restrictive than federal law.

#### International Considerations

- **EU:** Computer Misuse Directive, GDPR implications
- **UK:** Computer Misuse Act 1990
- **Other countries:** Various cybercrime laws

**If testing internationally:** Understand local laws and get legal advice.

### Ethical Guidelines

#### The EC-Council Code of Ethics (CEH)

1. Keep private and confidential information obtained in professional work
2. Protect the intellectual property of others
3. Disclose to appropriate persons or authorities potential dangers to any e-commerce clients, the Internet community, or the public
4. Provide service in areas of competence, being honest about limitations
5. Never knowingly use software or process that is obtained or retained illegally
6. Not engage in deceptive financial practices
7. Use the property of a client or employer only in authorized ways
8. Not take part in or contribute to any harmful actions
9. Ensure ethical conduct in professional life

#### Core Ethical Principles

```
┌────────────────────────────────────────────────────────────────┐
│                  Security Professional Ethics                   │
├────────────────────────────────────────────────────────────────┤
│                                                                 │
│  1. AUTHORIZATION                                              │
│     Never test without explicit written permission             │
│                                                                 │
│  2. SCOPE ADHERENCE                                            │
│     Stay within defined boundaries                             │
│                                                                 │
│  3. CONFIDENTIALITY                                            │
│     Protect client data and findings                           │
│                                                                 │
│  4. INTEGRITY                                                  │
│     Report all findings honestly                               │
│                                                                 │
│  5. NON-DISRUPTION                                             │
│     Minimize impact on operations                              │
│                                                                 │
│  6. RESPONSIBLE DISCLOSURE                                     │
│     Report vulnerabilities appropriately                       │
│                                                                 │
│  7. PROFESSIONALISM                                            │
│     Maintain professional standards                            │
│                                                                 │
│  8. CONTINUOUS LEARNING                                        │
│     Stay current, admit limitations                            │
│                                                                 │
└────────────────────────────────────────────────────────────────┘
```

### Authorization Documentation

#### Key Documents

1. **Master Service Agreement (MSA)**
   - Overall relationship between parties
   - General terms and conditions
   - Liability and indemnification

2. **Statement of Work (SOW)**
   - Specific engagement details
   - Scope
   - Timeline
   - Deliverables

3. **Rules of Engagement (ROE)**
   - What's allowed and forbidden
   - Testing windows
   - Emergency procedures
   - Communication protocols

4. **Get Out of Jail Free Letter**
   - Explicit authorization
   - Emergency contact info
   - Carry during physical testing

### Rules of Engagement Template

Create a template for future use:

```bash
cat << 'EOF' > ~/templates/rules_of_engagement.md
# Rules of Engagement

## Engagement Information

| Field | Value |
|-------|-------|
| **Client Name** | [CLIENT] |
| **Engagement Type** | [Penetration Test / Vulnerability Assessment / Red Team] |
| **Start Date** | [DATE] |
| **End Date** | [DATE] |
| **Primary Contact** | [NAME, EMAIL, PHONE] |
| **Emergency Contact** | [NAME, EMAIL, PHONE] |
| **Tester(s)** | [NAME(S)] |

## Scope

### In Scope
- [IP ranges, domains, applications]
- [Specific systems]
- [Testing types allowed]

### Out of Scope
- [Excluded systems]
- [Excluded activities]
- [Production systems restrictions]

## Authorized Testing Activities

| Activity | Authorized | Notes |
|----------|------------|-------|
| Port scanning | [ ] Yes  [ ] No | |
| Vulnerability scanning | [ ] Yes  [ ] No | |
| Web application testing | [ ] Yes  [ ] No | |
| Exploitation | [ ] Yes  [ ] No | |
| Social engineering | [ ] Yes  [ ] No | |
| Physical testing | [ ] Yes  [ ] No | |
| Denial of service | [ ] Yes  [ ] No | |
| Wireless testing | [ ] Yes  [ ] No | |

## Testing Windows

| Day | Allowed Hours | Restrictions |
|-----|---------------|--------------|
| Monday-Friday | [TIME-TIME] | [Any] |
| Saturday-Sunday | [TIME-TIME] | [Any] |
| Holidays | [ ] Yes  [ ] No | [Details] |

## Communication Protocol

### Regular Updates
- Frequency: [Daily/Weekly]
- Method: [Email/Phone/Portal]
- Recipient: [Contact]

### Critical Finding Notification
- Notification within: [X hours]
- Method: [Phone call required]
- Recipient: [Contact]

### Emergency Procedures
- If system becomes unresponsive: [Action]
- If data breach discovered: [Action]
- If testing causes disruption: [Action]

## Evidence Handling

- Evidence stored: [Location]
- Encryption required: [ ] Yes  [ ] No
- Retention period: [X days/months]
- Destruction method: [Method]

## Signatures

**Client Authorization:**

Name: ________________________
Title: ________________________
Signature: ________________________
Date: ________________________

**Tester Acknowledgment:**

Name: ________________________
Signature: ________________________
Date: ________________________

EOF

echo "Created: ~/templates/rules_of_engagement.md"
```

### Safe Harbor for Learning

#### What You CAN Test Legally

1. **Your own systems**
   - VMs on your own computer
   - Your own network devices
   - Websites you own

2. **Authorized practice environments**
   - TryHackMe (https://tryhackme.com)
   - HackTheBox (https://hackthebox.com)
   - VulnHub VMs (https://vulnhub.com)
   - DVWA, WebGoat, other intentionally vulnerable apps

3. **Bug bounty programs (with terms)**
   - HackerOne
   - Bugcrowd
   - Company-specific programs

#### What You CANNOT Test

- Any system you don't own without written permission
- Your employer's systems (without authorization)
- Public websites (even for "practice")
- Your neighbor's WiFi
- Government systems
- Critical infrastructure

### Practical Exercise: Create Engagement Folder

```bash
#!/bin/bash
# new_engagement.sh - Create new engagement structure

if [ -z "$1" ]; then
    echo "Usage: $0 <engagement_name>"
    exit 1
fi

ENGAGEMENT_NAME="$1"
ENGAGEMENT_DIR="$HOME/engagements/$(date +%Y%m%d)_${ENGAGEMENT_NAME}"

mkdir -p "$ENGAGEMENT_DIR"/{00_preengagement,01_recon,02_scanning,03_vulnerability,04_exploitation,05_postexploit,06_evidence,07_reports}

# Create tracking files
cat << EOF > "$ENGAGEMENT_DIR/README.md"
# Engagement: $ENGAGEMENT_NAME

## Quick Info
- **Created:** $(date)
- **Status:** Planning
- **Client:** [TBD]

## Folder Structure
- 00_preengagement/ - Authorization, scope, ROE
- 01_recon/ - Reconnaissance data
- 02_scanning/ - Scan results
- 03_vulnerability/ - Vulnerability analysis
- 04_exploitation/ - Exploitation attempts
- 05_postexploit/ - Post-exploitation
- 06_evidence/ - Screenshots, logs, proof
- 07_reports/ - Draft and final reports

## Important Notes

[Add notes here]
EOF

# Copy templates
cp ~/templates/rules_of_engagement.md "$ENGAGEMENT_DIR/00_preengagement/"

# Create activity log
cat << EOF > "$ENGAGEMENT_DIR/activity_log.md"
# Activity Log

| Date | Time | Activity | Notes |
|------|------|----------|-------|
| $(date +%Y-%m-%d) | $(date +%H:%M) | Engagement created | Initial setup |

EOF

echo "Created engagement: $ENGAGEMENT_DIR"
ls -la "$ENGAGEMENT_DIR"
```

Save to `~/scripts/new_engagement.sh`.

---

### Milestone 4 Checkpoint

Before proceeding, verify:

- [ ] You understand that unauthorized testing is illegal
- [ ] You know key laws (CFAA, etc.)
- [ ] You understand ethical obligations
- [ ] You can explain what authorization documents are needed
- [ ] You have created the ROE template
- [ ] You have created the new_engagement.sh script

**[CERT CHECKPOINT - PenTest+ 1.1-1.3 / CEH]**: Legal and ethical requirements are heavily tested. Know authorization requirements.

---

## Part 5 — Setting Up Vulnerable Target VMs (Milestone 5)

### Why Vulnerable VMs?

You need legal, safe targets to practice on. Vulnerable VMs are:
- Intentionally insecure
- Designed for learning
- Legal to attack (on your own network)
- Realistic practice

### Recommended Practice Environments

#### Metasploitable 2

The classic vulnerable target:

**Download:** https://sourceforge.net/projects/metasploitable/

**Installation:**
1. Download the zip file
2. Extract (creates Metasploitable.vmdk)
3. Create new VM in VirtualBox:
   - Name: Metasploitable2
   - Type: Linux
   - Version: Debian (64-bit)
   - Memory: 512 MB minimum
   - Use existing virtual hard disk → select .vmdk file

**Configuration:**
- Network: Host-only adapter (same as Kali's second adapter)
- Don't connect to internet (it's very vulnerable!)

**Default credentials:** msfadmin / msfadmin

**What it includes:**
- Vulnerable services (FTP, SSH, Telnet, HTTP, etc.)
- Vulnerable web applications
- Multiple exploitation paths

#### DVWA (Damn Vulnerable Web Application)

For web application testing:

**Option 1: Docker (recommended)**
```bash
# On Kali
sudo apt install docker.io
sudo systemctl start docker
sudo systemctl enable docker

# Run DVWA
sudo docker run --rm -it -p 80:80 vulnerables/web-dvwa
```

Access at: http://localhost

**Option 2: Manual installation on separate VM**

**Default credentials:** admin / password

**What it includes:**
- SQL injection
- XSS (reflected and stored)
- Command injection
- File upload vulnerabilities
- CSRF
- And more, with adjustable difficulty levels

#### Other Recommended VMs

| VM | Focus | Source |
|------|-------|--------|
| **Metasploitable 3** | Modern Windows/Linux | Rapid7 GitHub |
| **VulnHub VMs** | Various challenges | vulnhub.com |
| **OWASP WebGoat** | Web app security | OWASP |
| **HackTheBox** | Online platform | hackthebox.com |
| **TryHackMe** | Guided learning | tryhackme.com |

### Lab Network Architecture

Set up an isolated network:

```
┌─────────────────────────────────────────────────────────────────┐
│                     Your Host Computer                          │
│                                                                 │
│  ┌─────────────┐                                                │
│  │  Internet   │                                                │
│  └──────┬──────┘                                                │
│         │                                                       │
│  ┌──────┴──────┐                                                │
│  │ VirtualBox  │                                                │
│  │   NAT       │ (192.168.x.x - Internet access)               │
│  └──────┬──────┘                                                │
│         │                                                       │
│  ┌──────┴────────────────────────────────────────────────┐     │
│  │                                                        │     │
│  │  ┌─────────────┐                                       │     │
│  │  │ Host-Only   │ (192.168.56.0/24 - Lab Network)      │     │
│  │  │  Network    │                                       │     │
│  │  └──────┬──────┘                                       │     │
│  │         │                                              │     │
│  │    ┌────┴────┬────────────┬────────────┐              │     │
│  │    │         │            │            │              │     │
│  │ ┌──┴───┐ ┌───┴────┐ ┌─────┴─────┐ ┌───┴────┐         │     │
│  │ │ Kali │ │Metaspl │ │   DVWA    │ │ Other  │         │     │
│  │ │ eth1 │ │ oitable│ │           │ │  VMs   │         │     │
│  │ │.56.x │ │ .56.x  │ │  .56.x    │ │ .56.x  │         │     │
│  │ └──────┘ └────────┘ └───────────┘ └────────┘         │     │
│  │                                                        │     │
│  └────────────────────────────────────────────────────────┘     │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

### Setting Up Metasploitable 2

#### Download and Import

1. Download from SourceForge
2. Extract the zip file
3. In VirtualBox: New → Name: Metasploitable2, Type: Linux, Version: Debian

4. Memory: 512 MB

5. Hard disk: Use existing → Browse to Metasploitable.vmdk

6. Network configuration:
   - Adapter 1: Host-only Adapter
   - Select your vboxnet0

7. Start the VM

8. Login: msfadmin / msfadmin

9. Find IP address:
```bash
ifconfig
# Note the IP (should be 192.168.56.x)
```

#### Verify Connectivity from Kali

```bash
# On Kali, ping Metasploitable
ping -c 3 192.168.56.x

# Quick scan to see services
nmap -sV 192.168.56.x
```

You should see many open ports!

### Lab Documentation

Create documentation for your lab:

```bash
cat << 'EOF' > ~/notes/lab_network.md
# Security Lab Network Documentation

## Network Details

| Network | Type | Range | Purpose |
|---------|------|-------|---------|
| NAT | Internet access | 10.0.2.0/24 | Updates, research |
| Host-only | Lab network | 192.168.56.0/24 | Testing |

## Virtual Machines

| VM Name | Role | IP Address | Credentials | Notes |
|---------|------|------------|-------------|-------|
| Kali | Attacker | 192.168.56.X | kali/[changed] | Main testing platform |
| Metasploitable2 | Target | 192.168.56.X | msfadmin/msfadmin | Intentionally vulnerable |
| DVWA | Web Target | Docker/192.168.56.X | admin/password | Web app testing |
| Ubuntu Server | Victim/Tools | 192.168.56.X | [user]/[pass] | From Stages 01-03 |

## Quick Reference

### Start Lab
1. Start VirtualBox
2. Start Kali VM
3. Start target VMs as needed
4. Verify connectivity with ping

### Stop Lab
1. Shutdown target VMs
2. Shutdown Kali
3. Verify all VMs stopped

### Reset Lab
1. Restore VMs from snapshots
2. Verify clean state

## Network Diagram

[Your Host]
     |
[VirtualBox Host-Only: 192.168.56.0/24]
     |
     +-- Kali (192.168.56.X)
     |
     +-- Metasploitable2 (192.168.56.X)
     |
     +-- DVWA (192.168.56.X or Docker)
     |
     +-- Other targets as needed

EOF

echo "Created: ~/notes/lab_network.md"
```

### Lab Connectivity Test Script

```bash
#!/bin/bash
# lab_check.sh - Verify lab connectivity

echo "=== Lab Environment Check ==="
echo ""

# Define targets (update IPs as needed)
declare -A TARGETS
TARGETS=(
    ["Kali (self)"]="127.0.0.1"
    ["Gateway"]="192.168.56.1"
    ["Metasploitable2"]="192.168.56.101"
    # Add more targets as needed
)

echo "Checking network connectivity..."
echo ""

for name in "${!TARGETS[@]}"; do
    ip="${TARGETS[$name]}"
    if ping -c 1 -W 2 "$ip" &>/dev/null; then
        echo "[✓] $name ($ip) - REACHABLE"
    else
        echo "[✗] $name ($ip) - UNREACHABLE"
    fi
done

echo ""
echo "=== Quick Port Check on Reachable Targets ==="

for name in "${!TARGETS[@]}"; do
    ip="${TARGETS[$name]}"
    if [ "$ip" != "127.0.0.1" ] && [ "$ip" != "192.168.56.1" ]; then
        if ping -c 1 -W 2 "$ip" &>/dev/null; then
            echo ""
            echo "Open ports on $name ($ip):"
            nmap -F --open "$ip" 2>/dev/null | grep "open"
        fi
    fi
done
```

Save to `~/scripts/lab_check.sh`.

---

### Milestone 5 Checkpoint

Before proceeding, verify:

- [ ] Metasploitable 2 installed and running
- [ ] Host-only network configured
- [ ] Kali can reach vulnerable targets
- [ ] Lab network documented
- [ ] Connectivity test script created
- [ ] Snapshots taken for all VMs

**[CERT CHECKPOINT - PenTest+ / CEH]**: Lab setup is essential. Know how to configure isolated test networks.

---

## Part 6 — Kali Tool Categories (Milestone 6)

### Understanding Kali's Organization

Kali organizes its 600+ tools into categories. You don't need to know every tool—focus on mastering core tools in each category.

### Tool Categories Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                    Kali Linux Tool Categories                    │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  01. Information Gathering                                       │
│      └── DNS, OSINT, network scanning, route analysis           │
│                                                                  │
│  02. Vulnerability Analysis                                      │
│      └── Vulnerability scanners, fuzzers, analyzers             │
│                                                                  │
│  03. Web Application Analysis                                    │
│      └── CMS scanners, proxies, web vulnerability tools         │
│                                                                  │
│  04. Database Assessment                                         │
│      └── SQL injection, database clients, dumpers               │
│                                                                  │
│  05. Password Attacks                                            │
│      └── Cracking, brute force, hash analysis                   │
│                                                                  │
│  06. Wireless Attacks                                            │
│      └── WiFi analysis, Bluetooth, SDR tools                    │
│                                                                  │
│  07. Reverse Engineering                                         │
│      └── Disassemblers, debuggers, binary analysis              │
│                                                                  │
│  08. Exploitation Tools                                          │
│      └── Metasploit, exploit frameworks, payload generators     │
│                                                                  │
│  09. Sniffing & Spoofing                                        │
│      └── Packet capture, MITM, network spoofing                 │
│                                                                  │
│  10. Post Exploitation                                           │
│      └── Privilege escalation, persistence, tunneling           │
│                                                                  │
│  11. Forensics                                                   │
│      └── Disk analysis, memory forensics, carving               │
│                                                                  │
│  12. Reporting Tools                                             │
│      └── Documentation, evidence management                      │
│                                                                  │
│  13. Social Engineering Tools                                    │
│      └── Phishing, pretexting, SET                              │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

### Core Tools by Category

#### Information Gathering

| Tool | Purpose | Usage |
|------|---------|-------|
| **nmap** | Port scanning, service detection | `nmap -sV target` |
| **dnsrecon** | DNS enumeration | `dnsrecon -d domain.com` |
| **theHarvester** | Email/subdomain OSINT | `theHarvester -d domain.com -b google` |
| **recon-ng** | OSINT framework | Interactive framework |
| **maltego** | Visual OSINT | GUI tool |
| **whois** | Domain registration | `whois domain.com` |

**Start with:** nmap, theHarvester, dnsrecon

#### Vulnerability Analysis

| Tool | Purpose | Usage |
|------|---------|-------|
| **nikto** | Web server scanner | `nikto -h http://target` |
| **openvas** | Full vulnerability scanner | GUI/web interface |
| **nmap scripts** | NSE vulnerability checks | `nmap --script vuln target` |
| **legion** | Network scanning framework | GUI tool |

**Start with:** nikto, nmap NSE scripts

#### Web Application Analysis

| Tool | Purpose | Usage |
|------|---------|-------|
| **burpsuite** | Web proxy/scanner | GUI tool |
| **OWASP ZAP** | Web app scanner | GUI tool |
| **dirb/dirbuster** | Directory brute force | `dirb http://target` |
| **gobuster** | Directory/DNS brute force | `gobuster dir -u http://target -w wordlist` |
| **wpscan** | WordPress scanner | `wpscan --url http://target` |
| **sqlmap** | SQL injection automation | `sqlmap -u "http://target?id=1"` |

**Start with:** Burp Suite, dirb, sqlmap

#### Password Attacks

| Tool | Purpose | Usage |
|------|---------|-------|
| **john** | Password cracker | `john --wordlist=rockyou.txt hash.txt` |
| **hashcat** | GPU password cracker | `hashcat -m 0 hash.txt rockyou.txt` |
| **hydra** | Online brute force | `hydra -l user -P passwords.txt ssh://target` |
| **medusa** | Online brute force | Similar to hydra |
| **cewl** | Custom wordlist generator | `cewl http://target` |

**Start with:** john, hydra, hashcat

#### Exploitation Tools

| Tool | Purpose | Usage |
|------|---------|-------|
| **metasploit** | Exploitation framework | `msfconsole` |
| **searchsploit** | Exploit database search | `searchsploit apache 2.4` |
| **msfvenom** | Payload generator | `msfvenom -p payload LHOST=ip LPORT=port` |

**Start with:** metasploit, searchsploit

#### Sniffing & Spoofing

| Tool | Purpose | Usage |
|------|---------|-------|
| **wireshark** | Packet analysis | GUI tool |
| **tcpdump** | Command-line capture | `tcpdump -i eth0` |
| **ettercap** | MITM attacks | `ettercap -G` |
| **bettercap** | Modern MITM framework | Interactive |
| **responder** | LLMNR/NBT-NS poisoning | `responder -I eth0` |

**Start with:** wireshark, tcpdump, bettercap

#### Post Exploitation

| Tool | Purpose | Usage |
|------|---------|-------|
| **mimikatz** | Windows credential extraction | `sekurlsa::logonpasswords` |
| **linpeas/winpeas** | Privilege escalation enum | `./linpeas.sh` |
| **empire** | Post-exploitation framework | Interactive |
| **chisel** | TCP tunneling | Tunneling |
| **proxychains** | Proxy chaining | `proxychains nmap target` |

**Start with:** linpeas/winpeas, basic Metasploit post modules

### Exploring Tools on Kali

#### Using the Application Menu

1. Click the Kali menu (dragon icon)
2. Browse categories: Applications → [Category]
3. Explore available tools

#### Command-Line Discovery

```bash
# List all installed packages
dpkg -l | wc -l

# Search for security tools
apt search penetration | head -20
apt search scanner | head -20

# Find where a tool is
which nmap
whereis burpsuite

# Get tool help
nmap --help
nikto -H
```

#### Quick Tool Reference

```bash
#!/bin/bash
# tool_reference.sh - Quick reference for common tools

cat << 'EOF'
=== Quick Tool Reference ===

RECONNAISSANCE:
  nmap -sn 192.168.1.0/24              # Ping sweep
  nmap -sV -sC target                  # Version and default scripts
  nmap -A target                       # Aggressive scan
  theHarvester -d domain.com -b all    # OSINT gathering

WEB TESTING:
  nikto -h http://target               # Web server scan
  dirb http://target                   # Directory brute force
  gobuster dir -u http://target -w /usr/share/wordlists/dirb/common.txt
  wpscan --url http://target           # WordPress scan
  sqlmap -u "http://target?id=1" --dbs # SQL injection

PASSWORD ATTACKS:
  john --wordlist=/usr/share/wordlists/rockyou.txt hashes.txt
  hashcat -m 0 hash.txt /usr/share/wordlists/rockyou.txt
  hydra -l admin -P passwords.txt ssh://target
  hydra -l admin -P passwords.txt http-post-form "/login:user=^USER^&pass=^PASS^:Invalid"

EXPLOITATION:
  msfconsole                           # Start Metasploit
  searchsploit apache                  # Search for exploits
  msfvenom -p linux/x86/shell_reverse_tcp LHOST=IP LPORT=4444 -f elf > shell

PACKET CAPTURE:
  tcpdump -i eth0 -w capture.pcap
  wireshark &
  tshark -i eth0 -Y "http"

USEFUL WORDLISTS:
  /usr/share/wordlists/rockyou.txt
  /usr/share/wordlists/dirb/common.txt
  /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
  /usr/share/seclists/                 # SecLists collection

EOF
```

Save to `~/scripts/tool_reference.sh`.

### Practice: First Tool Exploration

Run these on your Metasploitable target:

```bash
# Set target IP
TARGET="192.168.56.101"  # Adjust to your Metasploitable IP

# 1. Basic nmap scan
nmap $TARGET

# 2. Service version detection
nmap -sV $TARGET

# 3. Web server scan (if port 80 open)
nikto -h http://$TARGET

# 4. Directory enumeration
dirb http://$TARGET

# 5. Quick vulnerability scan
nmap --script vuln $TARGET
```

**Document what you find!**

---

### Milestone 6 Checkpoint

Before proceeding, verify:

- [ ] You understand Kali's tool organization
- [ ] You can navigate the application menu
- [ ] You know core tools in each category
- [ ] You can find tool documentation
- [ ] You have practiced basic scans on Metasploitable
- [ ] You have created the tool_reference.sh script

**[CERT CHECKPOINT - CEH / PenTest+]**: Know tool categories and when to use which tools.

---

## Part 7 — Professional Documentation Templates (Milestone 7)

### Why Documentation Matters

Professional security work requires thorough documentation:

| Purpose | Why It Matters |
|---------|----------------|
| Legal protection | Proves you stayed in scope |
| Client deliverable | What they're paying for |
| Reproducibility | Others can verify findings |
| Knowledge retention | Reference for future work |
| Quality assurance | Consistent methodology |

### Essential Templates

#### Pre-Engagement Checklist

```bash
cat << 'EOF' > ~/templates/pre_engagement_checklist.md
# Pre-Engagement Checklist

## Client Information
- [ ] Client name: ________________
- [ ] Primary contact: ________________
- [ ] Contact email: ________________
- [ ] Contact phone: ________________
- [ ] Emergency contact: ________________

## Authorization
- [ ] Master Service Agreement signed
- [ ] Statement of Work signed
- [ ] Rules of Engagement signed
- [ ] Authorization letter obtained
- [ ] NDA signed (if applicable)

## Scope Definition
- [ ] IP ranges defined
- [ ] Domains defined
- [ ] Excluded systems listed
- [ ] Testing types agreed
- [ ] Social engineering scope (if applicable)

## Schedule
- [ ] Start date confirmed
- [ ] End date confirmed
- [ ] Testing windows defined
- [ ] Blackout periods identified
- [ ] Reporting deadline set

## Logistics
- [ ] VPN access (if needed)
- [ ] Credentials (if authenticated testing)
- [ ] Testing accounts created
- [ ] Access to documentation/architecture

## Communication
- [ ] Communication channels established
- [ ] Reporting frequency agreed
- [ ] Critical finding notification process
- [ ] Status meeting schedule

## Technical Preparation
- [ ] Kali VM ready
- [ ] Tools updated
- [ ] Wordlists prepared
- [ ] Network connectivity tested
- [ ] Engagement folder created

EOF
```

#### Daily Activity Log

```bash
cat << 'EOF' > ~/templates/activity_log_template.md
# Daily Activity Log

**Date:** [DATE]
**Engagement:** [NAME]
**Tester:** [NAME]

## Summary
[Brief summary of day's activities]

## Activities

### Time: [HH:MM - HH:MM]
**Activity:** [Description]
**Target:** [System/IP]
**Tools Used:** [List]
**Findings:** [Brief findings]
**Evidence:** [Screenshots/files saved]

### Time: [HH:MM - HH:MM]
**Activity:** [Description]
**Target:** [System/IP]
**Tools Used:** [List]
**Findings:** [Brief findings]
**Evidence:** [Screenshots/files saved]

## Issues/Blockers
- [Any issues encountered]

## Tomorrow's Plan
- [Planned activities]

## Notes
[Additional notes]
EOF
```

#### Finding Template

```bash
cat << 'EOF' > ~/templates/finding_template.md
# Finding Report

## Finding ID: [VULN-001]

### Summary
| Field | Value |
|-------|-------|
| **Title** | [Descriptive title] |
| **Severity** | [Critical/High/Medium/Low/Informational] |
| **CVSS Score** | [0.0 - 10.0] |
| **Affected System(s)** | [IP/hostname] |
| **Affected Component** | [Application/service] |

### Description
[Detailed description of the vulnerability]

### Impact
[What an attacker could do if this is exploited]

### Steps to Reproduce
1. [Step 1]
2. [Step 2]
3. [Step 3]

### Evidence
[Screenshots, command output, etc.]

### Recommendation
[How to fix this vulnerability]

### References
- [CVE if applicable]
- [Vendor advisory if available]
- [Other relevant references]
EOF
```

#### Executive Summary Template

```bash
cat << 'EOF' > ~/templates/executive_summary.md
# Executive Summary

## Engagement Overview

| Field | Value |
|-------|-------|
| **Client** | [Name] |
| **Assessment Type** | [Penetration Test / Vulnerability Assessment] |
| **Testing Period** | [Start Date] - [End Date] |
| **Tester(s)** | [Names] |

## Scope
[Brief description of what was tested]

## Key Findings

| Severity | Count |
|----------|-------|
| Critical | [X] |
| High | [X] |
| Medium | [X] |
| Low | [X] |
| Informational | [X] |

## Critical Findings Summary
[1-2 sentences on each critical finding]

## Overall Risk Rating
[Low / Medium / High / Critical]

[Brief justification for rating]

## Key Recommendations
1. [Most important recommendation]
2. [Second recommendation]
3. [Third recommendation]

## Conclusion
[Brief summary and next steps]
EOF
```

### Screenshot and Evidence Guidelines

**Every finding needs evidence:**

1. **Screenshots**
   - Show the vulnerability clearly
   - Include timestamps if possible
   - Redact sensitive data if needed
   - Name files descriptively: `VULN-001_sqli_proof_01.png`

2. **Command Output**
   - Save to text files
   - Include the full command used
   - Timestamp the output

3. **Network Captures**
   - Save relevant packets
   - Filter to show only relevant traffic
   - Document what you captured

**Evidence Script:**

```bash
#!/bin/bash
# evidence.sh - Capture and timestamp evidence

ENGAGEMENT_DIR="${1:-.}"
EVIDENCE_DIR="$ENGAGEMENT_DIR/06_evidence"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)

mkdir -p "$EVIDENCE_DIR"

case "$2" in
    screenshot)
        OUTPUT="$EVIDENCE_DIR/screenshot_$TIMESTAMP.png"
        gnome-screenshot -f "$OUTPUT"
        echo "Screenshot saved: $OUTPUT"
        ;;
    
    command)
        shift 2
        CMD="$*"
        OUTPUT="$EVIDENCE_DIR/command_$TIMESTAMP.txt"
        echo "Timestamp: $(date)" > "$OUTPUT"
        echo "Command: $CMD" >> "$OUTPUT"
        echo "Output:" >> "$OUTPUT"
        eval "$CMD" >> "$OUTPUT" 2>&1
        echo "Command output saved: $OUTPUT"
        ;;
    
    note)
        OUTPUT="$EVIDENCE_DIR/note_$TIMESTAMP.txt"
        echo "Timestamp: $(date)" > "$OUTPUT"
        echo "Note:" >> "$OUTPUT"
        cat >> "$OUTPUT"
        echo "Note saved: $OUTPUT"
        ;;
    
    *)
        echo "Usage: $0 <engagement_dir> <screenshot|command|note> [args]"
        echo "Examples:"
        echo "  $0 . screenshot"
        echo "  $0 . command nmap -sV target"
        echo "  $0 . note"
        ;;
esac
```

Save to `~/scripts/evidence.sh`.

---

### Milestone 7 Checkpoint

Before proceeding, verify:

- [ ] Pre-engagement checklist template created
- [ ] Activity log template created
- [ ] Finding template created
- [ ] Executive summary template created
- [ ] Evidence script created
- [ ] You understand documentation requirements

**[CERT CHECKPOINT - PenTest+ 5.0]**: Professional documentation is a major exam topic.

---

## Stage 04 Assessment

### Written Assessment

Answer these questions in `~/notes/stage04_assessment.txt`:

1. Why should you never use Kali Linux for unauthorized testing?

2. List the 7 phases of penetration testing methodology.

3. What documents should be signed before a penetration test begins?

4. What is the difference between passive and active reconnaissance?

5. Name 5 tool categories in Kali Linux and give one example tool for each.

6. What should you do if you discover a critical vulnerability during testing?

7. Why are VirtualBox snapshots important for security testing?

8. What is the purpose of a Rules of Engagement document?

9. What information should be included in a finding report?

10. Why is documentation important during penetration testing?

### Practical Assessment

1. **Environment Verification:**
   - Verify your Kali VM is properly configured
   - Run the kali_verify.sh script
   - Save the output as evidence

2. **Lab Connectivity:**
   - Verify connectivity to Metasploitable
   - Perform a basic nmap scan
   - Document open ports and services

3. **Documentation:**
   - Create a new engagement folder for "Assessment Practice"
   - Complete the pre-engagement checklist (mark as lab exercise)
   - Document the Metasploitable scan in the activity log format

4. **Tool Exploration:**
   - Use three different reconnaissance tools on Metasploitable
   - Document findings using the finding template format
   - Take screenshots as evidence

---

## Stage 04 Completion Checklist

### Kali Installation
- [ ] Kali VM imported and running
- [ ] Default password changed
- [ ] System updated
- [ ] Guest additions installed
- [ ] Snapshot created
- [ ] kali_verify.sh script created

### Configuration
- [ ] Directory structure created
- [ ] Bash history configured
- [ ] Additional tools installed
- [ ] Aliases set up
- [ ] Network interfaces configured
- [ ] Metasploit database initialized
- [ ] backup_config.sh created

### Methodology
- [ ] Understand penetration testing phases
- [ ] Can explain each phase's purpose
- [ ] methodology_reference.md created

### Legal/Ethical
- [ ] Understand authorization requirements
- [ ] Know relevant laws (CFAA)
- [ ] Understand ethical obligations
- [ ] rules_of_engagement.md template created
- [ ] new_engagement.sh script created

### Lab Environment
- [ ] Metasploitable 2 installed
- [ ] Host-only network configured
- [ ] Lab connectivity verified
- [ ] Lab documentation created
- [ ] lab_check.sh script created
- [ ] All VM snapshots taken

### Tool Knowledge
- [ ] Understand tool categories
- [ ] Know core tools in each category
- [ ] Can find tool documentation
- [ ] Practiced basic scans
- [ ] tool_reference.sh created

### Documentation
- [ ] Pre-engagement checklist template
- [ ] Activity log template
- [ ] Finding template
- [ ] Executive summary template
- [ ] evidence.sh script created

### Assessment
- [ ] Written assessment completed
- [ ] Practical assessment completed

### Git Workflow
- [ ] Stage 04 committed
- [ ] Stage 04 pushed

---

## Definition of Done

Stage 04 is complete when:

1. All checklist items are checked
2. Kali and vulnerable VMs are working
3. All templates and scripts are created
4. You understand methodology and ethics
5. Assessment is complete
6. Work is committed and pushed

---

## What's Next: Stage 05 Preview

In Stage 05 — Reconnaissance and Information Gathering, you will:

- Master passive reconnaissance (OSINT)
- Learn active reconnaissance techniques
- Use professional reconnaissance tools
- Build target profiles
- Automate reconnaissance workflows

This is where you start actively using your security tools!

---

## Supplementary Resources

### Practice
- **TryHackMe:** "Pentesting Fundamentals" room (free)
- **TryHackMe:** "Intro to Offensive Security" pathway
- **HackTheBox:** Starting Point machines

### Reading
- PTES: http://www.pentest-standard.org/
- OWASP Testing Guide: https://owasp.org/www-project-web-security-testing-guide/
- Kali Documentation: https://www.kali.org/docs/

### Ethical Guidelines
- EC-Council Code of Ethics
- ISC² Code of Ethics
- SANS Ethics Policy

---

**Commit your work and proceed to Stage 05 when ready:**

```bash
cd ~/path-to-repo
git add .
git commit -m "Complete Stage 04 - Kali Linux Setup and Security Methodology"
git push
```
