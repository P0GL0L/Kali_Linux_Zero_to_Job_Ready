# Learner Progress Checklist
Kali Linux for Cybersecurity Learning Path

This checklist is your **single source of truth** for tracking progress through the learning path.  
A stage is **not complete** until every box in that stage is checked **and** changes are committed and pushed to GitHub.

---

## How to Use This Checklist

- Complete stages **in order**
- Do **not** skip stages
- Treat each stage like a real deliverable
- Commit and push **after every stage**
- Use this checklist to self-audit before moving forward

---

## Global Requirements (Apply to Every Stage)

Before advancing past any stage, confirm:

- [ ] All exercises completed hands-on (not just read)
- [ ] Stage assessment finished
- [ ] README instructions followed completely
- [ ] Scripts and outputs saved in appropriate directories
- [ ] Changes committed to Git
- [ ] Changes pushed to GitHub
- [ ] `git status` shows a clean working tree

---

## Stage 01 — Linux Foundations & CLI Mastery

**Focus:** Filesystem navigation, file operations, permissions, users, text processing, shell basics

**Time Estimate:** 35-40 hours

### Lab Environment
- [ ] VirtualBox (or alternative) installed
- [ ] Ubuntu Server VM created
- [ ] VM boots and login works
- [ ] Clean snapshot created

### Filesystem Navigation
- [ ] Understand Linux directory hierarchy
- [ ] Fluent with `pwd`, `ls`, `cd`
- [ ] Understand absolute vs relative paths
- [ ] Can use navigation shortcuts (~, .., -)

### File Operations
- [ ] Can create files and directories
- [ ] Can copy, move, rename files/directories
- [ ] Can safely delete files/directories
- [ ] Can view file contents (cat, less, head, tail)

### Permissions
- [ ] Can read permission strings
- [ ] Can use chmod (symbolic and numeric)
- [ ] Can use chown and chgrp
- [ ] Understand SUID, SGID, sticky bit
- [ ] Can perform basic permission audit

### Users and Groups
- [ ] Understand /etc/passwd and /etc/group
- [ ] Can create and manage users
- [ ] Can manage group membership
- [ ] Understand su vs sudo

### Text Processing
- [ ] Proficient with grep (including regex)
- [ ] Can use find with various criteria
- [ ] Can use cut, sort, uniq, wc
- [ ] Basic familiarity with awk and sed

### Redirection and Pipelines
- [ ] Understand stdin, stdout, stderr
- [ ] Can redirect output to files
- [ ] Can build multi-stage pipelines

### Process Management
- [ ] Can view and interpret process information
- [ ] Can send signals to processes
- [ ] Can manage background jobs

### Scripting
- [ ] Can create and execute bash scripts
- [ ] Can use variables, conditionals, loops
- [ ] Created system_info.sh
- [ ] Created security_audit.sh

### Assessment
- [ ] Written assessment completed
- [ ] Practical assessment completed
- [ ] Reflection document created

### Commit and Push
- [ ] Stage 01 committed
- [ ] Stage 01 pushed

---

## Stage 02 — Linux System Administration

**Focus:** Package management, services, logging, SSH, networking basics, cron, disk management

**Time Estimate:** 35-40 hours

### Package Management
- [ ] Can use apt (update, upgrade, install, remove)
- [ ] Understand package repositories
- [ ] Can query package information

### Service Management
- [ ] Can use systemctl (start, stop, enable, disable)
- [ ] Understand service status
- [ ] Can view service logs with journalctl

### System Logging
- [ ] Understand syslog and journald
- [ ] Can analyze logs in /var/log
- [ ] Can filter logs by time and service

### SSH
- [ ] SSH server configured
- [ ] Can generate SSH keys
- [ ] Understand SSH key authentication
- [ ] Basic SSH hardening applied

### Network Configuration
- [ ] Understand network interfaces
- [ ] Can configure static/DHCP addressing
- [ ] Can use ip, ss, netstat commands

### Scheduled Tasks
- [ ] Understand cron syntax
- [ ] Can create cron jobs
- [ ] Understand systemd timers

### Disk Management
- [ ] Understand disk partitions
- [ ] Can view disk usage (df, du)
- [ ] Basic understanding of LVM

### System Hardening Basics
- [ ] Firewall configured (ufw)
- [ ] Unnecessary services disabled
- [ ] Basic hardening checklist completed

### Commit and Push
- [ ] Stage 02 committed
- [ ] Stage 02 pushed

---

## Stage 03 — Networking Fundamentals for Security

**Focus:** TCP/IP, protocols, routing, Wireshark basics, firewall concepts

**Time Estimate:** 30-35 hours

### Network Theory
- [ ] Understand OSI model layers
- [ ] Understand TCP/IP model
- [ ] Know common protocols (HTTP, HTTPS, DNS, SSH, FTP, etc.)
- [ ] Understand TCP vs UDP

### IP Addressing
- [ ] Understand IPv4 addressing
- [ ] Understand subnetting basics
- [ ] Understand private vs public IPs
- [ ] Basic IPv6 awareness

### Routing and Switching
- [ ] Understand default gateway
- [ ] Can read routing tables
- [ ] Understand basic switching concepts

### DNS
- [ ] Understand DNS resolution process
- [ ] Can query DNS (dig, nslookup)
- [ ] Know common DNS record types

### Packet Analysis
- [ ] Wireshark installed and functional
- [ ] Can capture traffic
- [ ] Can apply basic filters
- [ ] Can follow TCP streams

### Firewall Concepts
- [ ] Understand stateful vs stateless
- [ ] Understand iptables basics
- [ ] Can configure ufw/iptables rules

### Network Troubleshooting
- [ ] Can use ping, traceroute
- [ ] Can use ss, netstat, lsof
- [ ] Can diagnose basic connectivity issues

### Commit and Push
- [ ] Stage 03 committed
- [ ] Stage 03 pushed

---

## Stage 04 — Kali Linux Setup & Security Methodology

**Focus:** Kali installation, tool organization, methodology, legal/ethical framework

**Time Estimate:** 25-30 hours

### Kali Linux Setup
- [ ] Kali Linux VM installed
- [ ] VM configured appropriately
- [ ] Snapshot created
- [ ] Basic customization completed

### Tool Familiarization
- [ ] Understand tool categories in Kali menu
- [ ] Know how to update Kali and tools
- [ ] Understand tool documentation sources

### Penetration Testing Methodology
- [ ] Understand phases (recon, scanning, exploitation, post-exploitation, reporting)
- [ ] Know common methodologies (OWASP, PTES, OSSTMM)
- [ ] Understand scope and rules of engagement

### Legal and Ethical Framework
- [ ] Understand computer crime laws
- [ ] Understand authorization requirements
- [ ] Know responsible disclosure principles
- [ ] Signed ethical commitment document

### Documentation Standards
- [ ] Understand reporting requirements
- [ ] Know evidence handling basics
- [ ] Practiced structured note-taking

### Lab Environment Complete
- [ ] Metasploitable VM installed
- [ ] DVWA installed
- [ ] Isolated lab network configured

### Commit and Push
- [ ] Stage 04 committed
- [ ] Stage 04 pushed

---

## Stage 05 — Reconnaissance & Information Gathering

**Focus:** OSINT, passive/active recon, Nmap, enumeration

**Time Estimate:** 35-40 hours

### OSINT Techniques
- [ ] Understand passive reconnaissance
- [ ] Can use theHarvester
- [ ] Can use Recon-ng
- [ ] Understand Maltego basics
- [ ] Know Shodan fundamentals

### Network Scanning
- [ ] Nmap mastery (host discovery, port scanning)
- [ ] Understand scan types (SYN, Connect, UDP)
- [ ] Can use Nmap scripts (NSE)
- [ ] Can interpret Nmap output

### Service Enumeration
- [ ] Can enumerate common services
- [ ] Can identify versions and vulnerabilities
- [ ] Practiced banner grabbing

### Web Reconnaissance
- [ ] Can enumerate web technologies
- [ ] Directory enumeration (gobuster, dirb)
- [ ] Subdomain enumeration

### Documentation
- [ ] Recon findings documented
- [ ] Target profiles created
- [ ] Evidence properly organized

### Commit and Push
- [ ] Stage 05 committed
- [ ] Stage 05 pushed

---

## Stage 06 — Vulnerability Assessment & Exploitation

**Focus:** Vulnerability scanning, Metasploit, web app testing, password attacks

**Time Estimate:** 40-45 hours

### Vulnerability Scanning
- [ ] Can use Nikto
- [ ] Understand OpenVAS/GVM
- [ ] Can use Searchsploit
- [ ] Can prioritize vulnerabilities

### Metasploit Framework
- [ ] Understand Metasploit architecture
- [ ] Can search and select exploits
- [ ] Can configure payloads
- [ ] Can use meterpreter

### Web Application Testing
- [ ] Burp Suite basics
- [ ] SQL injection (manual and SQLmap)
- [ ] XSS identification
- [ ] Directory traversal

### Password Attacks
- [ ] Can use Hydra
- [ ] Can use John the Ripper
- [ ] Understand hashcat basics
- [ ] Know password attack strategies

### Exploitation Practice
- [ ] Successfully exploited Metasploitable targets
- [ ] Successfully exploited DVWA vulnerabilities
- [ ] Documented exploitation steps

### Commit and Push
- [ ] Stage 06 committed
- [ ] Stage 06 pushed

---

## Stage 07 — Defensive Operations & Blue Team Tools

**Focus:** Log analysis, IDS/IPS, threat hunting, incident response basics

**Time Estimate:** 35-40 hours

### Log Analysis
- [ ] Can analyze Linux logs
- [ ] Can identify suspicious activity
- [ ] Can correlate events across logs
- [ ] Understand SIEM concepts

### IDS/IPS
- [ ] Snort or Suricata configured
- [ ] Can write basic rules
- [ ] Can interpret alerts

### Threat Hunting
- [ ] Understand threat hunting methodology
- [ ] Can use YARA rules
- [ ] Can identify IOCs

### Incident Response
- [ ] Understand IR phases
- [ ] Can perform initial triage
- [ ] Can preserve evidence

### Forensics Introduction
- [ ] Understand forensic principles
- [ ] Volatility basics
- [ ] Autopsy basics

### Commit and Push
- [ ] Stage 07 committed
- [ ] Stage 07 pushed

---

## Stage 08 — Active Directory & Windows Integration

**Focus:** AD enumeration, BloodHound, common attacks, Windows logs

**Time Estimate:** 30-35 hours

### Active Directory Concepts
- [ ] Understand AD structure
- [ ] Know key AD objects
- [ ] Understand authentication (Kerberos, NTLM)

### AD Enumeration
- [ ] Can enumerate with BloodHound
- [ ] Can use CrackMapExec
- [ ] Understand Impacket tools

### Common AD Attacks
- [ ] Understand Kerberoasting
- [ ] Understand Pass-the-Hash
- [ ] Know common misconfigurations

### Windows Event Logs
- [ ] Can analyze Windows logs
- [ ] Know critical event IDs
- [ ] Can identify attack patterns

### PowerShell for Security
- [ ] Basic PowerShell commands
- [ ] Security-relevant cmdlets
- [ ] Script analysis basics

### Commit and Push
- [ ] Stage 08 committed
- [ ] Stage 08 pushed

---

## Stage 09 — Professional Documentation & Reporting

**Focus:** Report writing, executive summaries, evidence handling

**Time Estimate:** 25-30 hours

### Report Writing
- [ ] Understand report structure
- [ ] Can write technical findings
- [ ] Can explain vulnerabilities and impact

### Executive Communication
- [ ] Can write executive summaries
- [ ] Can present findings to non-technical audience
- [ ] Understand risk ratings

### Evidence Handling
- [ ] Proper evidence organization
- [ ] Screenshot best practices
- [ ] Chain of custody awareness

### Portfolio Preparation
- [ ] Sample report created
- [ ] Work samples organized
- [ ] GitHub profile polished

### Commit and Push
- [ ] Stage 09 committed
- [ ] Stage 09 pushed

---

## Capstone — Integrated Security Assessment

**Focus:** Complete penetration test, security monitoring toolkit, professional deliverables

**Time Estimate:** 50-60 hours

### Offensive Assessment
- [ ] Full reconnaissance completed
- [ ] Vulnerabilities discovered and documented
- [ ] Exploitation attempts documented
- [ ] Findings prioritized

### Defensive Assessment
- [ ] Monitoring toolkit built
- [ ] Log analysis performed
- [ ] Detection rules created
- [ ] Incident response plan drafted

### Professional Deliverables
- [ ] Complete penetration test report
- [ ] Executive summary
- [ ] Technical appendices
- [ ] Remediation recommendations

### Portfolio Ready
- [ ] All work organized in repository
- [ ] README files complete
- [ ] Demo/walkthrough prepared
- [ ] Ready for employer review

### Final Commit
- [ ] Capstone committed
- [ ] Capstone pushed
- [ ] All stages complete

---

## Certification Readiness

By completing this course, you should feel prepared to pursue:

- [ ] CompTIA Security+ — Ready to study for exam
- [ ] CompTIA CySA+ — Ready to study for exam  
- [ ] CompTIA PenTest+ — Ready to study for exam
- [ ] CompTIA Linux+ — Ready to study for exam
- [ ] eLearnSecurity eJPT — Ready to attempt
- [ ] EC-Council CEH — Foundational knowledge complete

---

## Final Certification

By checking every item above, you certify that:

- You completed all stages in order
- You performed all hands-on exercises
- You treated learning like professional work
- You are ready to explain and demonstrate your skills

**Signature (optional):** ________________________  
**Date:** ________________________

---

## Navigation

- Start here: `docs/START_HERE.md`
- First stage: `stage-starters/stage_01_Linux_Foundations_CLI_Mastery/`
- Certification mapping: `docs/CERTIFICATION_MAPPING.md`
