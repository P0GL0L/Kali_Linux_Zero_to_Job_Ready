# Kali Linux for Cybersecurity Learning Path

[![License: CC BY-NC-SA 4.0](https://img.shields.io/badge/License-CC%20BY--NC--SA%204.0-lightgrey.svg)](https://creativecommons.org/licenses/by-nc-sa/4.0/)
[![Kali Linux](https://img.shields.io/badge/Kali-Linux-557C94?logo=kalilinux&logoColor=white)](https://www.kali.org/)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](CONTRIBUTING.md)
[![NICE Framework](https://img.shields.io/badge/NICE-Framework%20Aligned-purple)](https://www.nist.gov/itl/applied-cybersecurity/nice/nice-framework-resource-center)

> A comprehensive, hands-on learning path from Linux fundamentals to professional penetration testing.  
> Aligned with industry certifications including PenTest+, CEH, eJPT, and OSCP.  
> **340-395 hours of structured, practical cybersecurity education.**

---

## 🚦 Quick Start

- **New learners:** Start with [`docs/START_HERE.md`](docs/START_HERE.md)
- **Track progress:** Use [`docs/LEARNER_PROGRESS_CHECKLIST.md`](docs/LEARNER_PROGRESS_CHECKLIST.md)
- **Certification prep:** See [`docs/CERTIFICATION_MAPPING.md`](docs/CERTIFICATION_MAPPING.md)

**Workflow rule:** Complete each stage in order, then **commit and push** before moving on.

---

## 📌 What This Course Is

This is a **complete, beginner-to-professional cybersecurity learning path** that teaches:

- Linux system administration and security
- Network fundamentals and analysis
- Penetration testing methodology
- Vulnerability assessment and exploitation
- Professional reporting and career development

**This is NOT:**
- A collection of random hacking scripts
- A "become a hacker in 30 days" shortcut
- Material for illegal activities

**This IS:**
- Structured, progressive skill development
- Hands-on, lab-based learning
- Ethical, professional security education
- Career-focused with certification alignment

---

## 🗺️ Learning Path Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                    LEARNING PATH PROGRESSION                     │
└─────────────────────────────────────────────────────────────────┘

    FOUNDATIONS                ASSESSMENT               OPERATIONS
   ┌───────────┐             ┌───────────┐            ┌───────────┐
   │ Stage 01  │             │ Stage 05  │            │ Stage 07  │
   │  Linux    │────────────▶│  Recon &  │───────────▶│Exploitation│
   │   CLI     │             │   OSINT   │            │           │
   └───────────┘             └───────────┘            └───────────┘
        │                          │                        │
        ▼                          ▼                        ▼
   ┌───────────┐             ┌───────────┐            ┌───────────┐
   │ Stage 02  │             │ Stage 06  │            │ Stage 08  │
   │  System   │             │   Vuln    │            │   Post-   │
   │  Admin    │             │ Scanning  │            │  Exploit  │
   └───────────┘             └───────────┘            └───────────┘
        │                                                   │
        ▼                                                   ▼
   ┌───────────┐                                      ┌───────────┐
   │ Stage 03  │                                      │ Stage 09  │
   │ Networking│                                      │ Reporting │
   └───────────┘                                      │ & Career  │
        │                                             └───────────┘
        ▼                                                   │
   ┌───────────┐                                           ▼
   │ Stage 04  │                                    ┌───────────┐
   │Kali Setup │                                    │  🎓 DONE  │
   │& Methodology                                   └───────────┘
   └───────────┘
```

---

## 📚 Stage Breakdown

### Phase 1: Foundations (Stages 01-03)

| Stage | Title | Hours | What You'll Learn |
|-------|-------|-------|-------------------|
| **01** | Linux Foundations & CLI Mastery | 35-45 | Command line, file system, text processing, shell scripting |
| **02** | Linux System Administration | 35-45 | Users, permissions, services, security hardening, logging |
| **03** | Networking Fundamentals | 35-45 | TCP/IP, protocols, Wireshark, firewalls, network security |

### Phase 2: Kali & Assessment (Stages 04-06)

| Stage | Title | Hours | What You'll Learn |
|-------|-------|-------|-------------------|
| **04** | Kali Linux & Security Methodology | 35-45 | Kali installation, tool categories, pentest methodology, lab setup |
| **05** | Reconnaissance & Information Gathering | 40-50 | OSINT, passive/active recon, DNS, subdomain enumeration |
| **06** | Vulnerability Scanning & Analysis | 35-45 | Nmap NSE, OpenVAS, Nikto, vulnerability validation |

### Phase 3: Exploitation & Reporting (Stages 07-09)

| Stage | Title | Hours | What You'll Learn |
|-------|-------|-------|-------------------|
| **07** | Exploitation Fundamentals | 40-50 | Metasploit, payloads, shells, network/web exploitation |
| **08** | Post-Exploitation & Privilege Escalation | 45-55 | Enumeration, Linux/Windows privesc, credentials, persistence |
| **09** | Reporting & Professional Practice | 35-45 | Report writing, documentation, ethics, certifications, career |

---

## 🎯 Certification Alignment

This course prepares you for major industry certifications:

| Certification | Coverage | Notes |
|--------------|----------|-------|
| **CompTIA PenTest+** | ~85% | Strong alignment with all domains |
| **EC-Council CEH** | ~75% | Methodology and tools coverage |
| **eLearnSecurity eJPT** | ~90% | Excellent preparation for practical exam |
| **Offensive Security OSCP** | ~60% | Foundation; additional practice needed |
| **CompTIA Security+** | Foundation | Stages 01-04 provide strong base |
| **CompTIA CySA+** | Partial | Defensive concepts throughout |

> **Note:** Certification exam objectives change. Always verify current requirements at official vendor websites.

---

## 📋 Prerequisites

### Required
- Computer with 16GB+ RAM (for virtual machines)
- 100GB+ free storage
- Internet connection
- Willingness to learn

### Recommended
- Basic computer literacy
- Comfort with command line (or patience to learn)
- 10-15 hours per week available

### Technical Requirements

| Component | Minimum | Recommended |
|-----------|---------|-------------|
| **RAM** | 8GB | 16GB+ |
| **Storage** | 50GB free | 100GB+ SSD |
| **CPU** | 4 cores | 8+ cores |
| **Virtualization** | VirtualBox | VMware Workstation Pro |
| **OS** | Windows 10/11, macOS, Linux | Any with virtualization support |

---

## 🚀 Getting Started

### 1. Clone the Repository

```bash
git clone https://github.com/YOUR-USERNAME/kali-linux-learning-path.git
cd kali-linux-learning-path
```

### 2. Read the Onboarding Guide

```bash
# Start here - read this first!
cat docs/START_HERE.md
```

### 3. Begin Stage 01

```bash
cd stage-starters/stage_01_Linux_Foundations_CLI_Mastery
# Read the README and begin learning
```

### 4. Track Your Progress

Use [`docs/LEARNER_PROGRESS_CHECKLIST.md`](docs/LEARNER_PROGRESS_CHECKLIST.md) to track completion.

---

## 📁 Repository Structure

```
kali-linux-learning-path/
│
├── README.md                          # This file
├── LICENSE                            # CC BY-NC-SA 4.0
│
├── docs/
│   ├── START_HERE.md                  # Onboarding guide
│   ├── LEARNER_PROGRESS_CHECKLIST.md  # Progress tracking
│   ├── CERTIFICATION_MAPPING.md       # Cert alignment details
│   └── index.html                     # Web landing page
│
└── stage-starters/
    ├── stage_01_Linux_Foundations_CLI_Mastery/
    │   └── README.md                  # Stage 01 content
    ├── stage_02_Linux_System_Administration/
    │   └── README.md                  # Stage 02 content
    ├── stage_03_Networking_Fundamentals/
    │   └── README.md                  # Stage 03 content
    ├── stage_04_Kali_Linux_Security_Methodology/
    │   └── README.md                  # Stage 04 content
    ├── stage_05_Reconnaissance_Information_Gathering/
    │   └── README.md                  # Stage 05 content
    ├── stage_06_Vulnerability_Scanning_Analysis/
    │   └── README.md                  # Stage 06 content
    ├── stage_07_Exploitation_Fundamentals/
    │   └── README.md                  # Stage 07 content
    ├── stage_08_Post_Exploitation_Privilege_Escalation/
    │   └── README.md                  # Stage 08 content
    └── stage_09_Reporting_Professional_Practice/
        └── README.md                  # Stage 09 content
```

---

## 🛠️ Tools You'll Master

### Linux & System Tools
`bash` `grep` `awk` `sed` `find` `systemctl` `iptables` `ssh` `cron`

### Network Analysis
`Wireshark` `tcpdump` `netstat` `ss` `nmap` `netcat`

### Reconnaissance
`theHarvester` `Maltego` `Recon-ng` `Shodan` `Amass` `Sublist3r`

### Vulnerability Scanning
`Nmap NSE` `OpenVAS` `Nikto` `WPScan` `SQLMap`

### Exploitation
`Metasploit` `Msfvenom` `Burp Suite` `Hydra` `John the Ripper`

### Post-Exploitation
`LinPEAS` `WinPEAS` `Mimikatz` `BloodHound` `PowerShell Empire`

---

## ⏱️ Time Investment

| Phase | Stages | Hours | Focus |
|-------|--------|-------|-------|
| Foundations | 01-03 | 105-135 | Linux, networking basics |
| Assessment | 04-06 | 110-140 | Kali, recon, scanning |
| Operations | 07-09 | 120-150 | Exploitation, reporting |
| **Total** | **01-09** | **335-425** | **Complete path** |

**Recommended pace:** 10-15 hours per week = 6-10 months to completion

---

## 🎓 What You'll Achieve

After completing this course, you will be able to:

✅ Navigate and administer Linux systems confidently  
✅ Analyze network traffic and understand protocols  
✅ Set up professional penetration testing environments  
✅ Perform comprehensive reconnaissance and OSINT  
✅ Scan for and validate security vulnerabilities  
✅ Exploit common vulnerabilities ethically  
✅ Escalate privileges on Linux and Windows systems  
✅ Write professional penetration test reports  
✅ Prepare for industry certifications  
✅ Begin a career in cybersecurity  

---

## ⚠️ Legal & Ethical Notice

**This course is for educational purposes only.**

- Only test systems you own or have explicit written permission to test
- Unauthorized access to computer systems is illegal
- This material is intended for defensive security professionals
- Always follow responsible disclosure practices
- Respect privacy and data protection laws

**By using this material, you agree to use it ethically and legally.**

---

## 🤝 Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Submit a pull request

See [CONTRIBUTING.md](CONTRIBUTING.md) for details.

---

## 📜 License

This work is licensed under [Creative Commons Attribution-NonCommercial-ShareAlike 4.0 International (CC BY-NC-SA 4.0)](LICENSE).

**You are free to:**
- Share — copy and redistribute the material
- Adapt — remix, transform, and build upon the material

**Under these terms:**
- **Attribution** — Give appropriate credit
- **NonCommercial** — No commercial use without permission
- **ShareAlike** — Distribute contributions under the same license

For commercial licensing inquiries, contact the repository owner.

---

## 🙏 Acknowledgments

- The Kali Linux team at Offensive Security
- The open-source security community
- OWASP, NIST, and MITRE for frameworks and resources
- All contributors and learners

---

## 📞 Support

- **Issues:** Open a GitHub issue for bugs or suggestions
- **Discussions:** Use GitHub Discussions for questions
- **Updates:** Watch/star the repo for updates

---

<p align="center">
  <strong>Ready to begin your cybersecurity journey?</strong><br>
  Start with <a href="docs/START_HERE.md">docs/START_HERE.md</a>
</p>

<p align="center">
  <em>Learn • Practice • Secure</em>
</p>
