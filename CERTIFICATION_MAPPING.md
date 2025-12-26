# Certification Mapping Guide
Kali Linux for Cybersecurity Learning Path

This document maps course content to industry certification exam objectives, helping you understand how your learning aligns with recognized credentials.

---

## Important Disclaimer

> **Certification Exam Currency Notice**
>
> This mapping is based on certification exam objectives available at the time of course development. Certification bodies (CompTIA, EC-Council, eLearnSecurity, etc.) periodically update their exam objectives, domains, and question pools.
>
> **Before pursuing any certification:**
> 1. Visit the official certification website for current exam objectives
> 2. Compare current objectives against this mapping
> 3. Supplement your study with official exam preparation materials
> 4. Verify exam version numbers (e.g., Security+ SY0-701 vs SY0-601)
>
> This course provides **foundational knowledge and practical skills** aligned with certification domains. It is **not a substitute** for dedicated exam preparation using official study materials.
>
> **Last mapping update:** December 2025
> **Exam versions referenced:**
> - CompTIA Security+ SY0-701
> - CompTIA CySA+ CS0-003
> - CompTIA PenTest+ PT0-002
> - CompTIA Linux+ XK0-005
> - CompTIA Network+ N10-009
> - EC-Council CEH v12
> - eLearnSecurity eJPTv2

---

## How to Use This Document

### Certification Checkpoint Markers

Throughout each stage, you'll see markers like:

```
[CERT CHECKPOINT - Security+ 1.2 / CySA+ 1.3]
```

These indicate that the current content maps to specific certification domains. The format is:

```
[CERT CHECKPOINT - Certification Domain.Objective]
```

### Coverage Levels

| Level | Meaning |
|-------|---------|
| **Full** | Comprehensive coverage sufficient for exam preparation |
| **Substantial** | Strong coverage; some supplemental study recommended |
| **Foundational** | Introduces concepts; dedicated study required for exam |
| **Awareness** | Basic exposure; significant additional study required |

---

## Certification Overview

### Certifications Aligned with This Course

| Certification | Vendor | Focus | Course Coverage |
|--------------|--------|-------|-----------------|
| **Security+** | CompTIA | Security fundamentals | Substantial |
| **CySA+** | CompTIA | Security analyst skills | Substantial |
| **PenTest+** | CompTIA | Penetration testing | Substantial |
| **Linux+** | CompTIA | Linux administration | Full |
| **Network+** | CompTIA | Networking fundamentals | Foundational |
| **CEH** | EC-Council | Ethical hacking | Substantial |
| **eJPT** | eLearnSecurity | Junior penetration testing | Full |
| **Linux Essentials** | LPI | Linux basics | Full |

---

## CompTIA Security+ (SY0-701)

**Exam Details:**
- 90 questions (multiple choice + performance-based)
- 90 minutes
- Passing score: 750/900
- Recommended experience: 2 years IT with security focus

### Domain Mapping

| Domain | Weight | Course Stages | Coverage |
|--------|--------|---------------|----------|
| 1.0 General Security Concepts | 12% | 04, 07 | Substantial |
| 2.0 Threats, Vulnerabilities & Mitigations | 22% | 05, 06, 07 | Substantial |
| 3.0 Security Architecture | 18% | 02, 03, 07 | Foundational |
| 4.0 Security Operations | 28% | 05, 06, 07, 08 | Substantial |
| 5.0 Security Program Management | 20% | 04, 09 | Foundational |

### Detailed Objective Mapping

#### Domain 1.0: General Security Concepts (12%)

| Objective | Description | Stage(s) | Notes |
|-----------|-------------|----------|-------|
| 1.1 | Compare security control types | 04, 07 | Control categories, implementation |
| 1.2 | Summarize fundamental security concepts | 01, 04 | CIA triad, authentication, authorization |
| 1.3 | Explain importance of change management | 02, 09 | Documentation, procedures |
| 1.4 | Explain cryptographic solutions | 03 | Covered at awareness level |

#### Domain 2.0: Threats, Vulnerabilities & Mitigations (22%)

| Objective | Description | Stage(s) | Notes |
|-----------|-------------|----------|-------|
| 2.1 | Compare threat actors and motivations | 04, 05 | Threat landscape overview |
| 2.2 | Explain threat vectors and attack surfaces | 05, 06 | Reconnaissance, enumeration |
| 2.3 | Explain vulnerability types | 06 | Web app, system vulnerabilities |
| 2.4 | Analyze indicators of malicious activity | 07 | Log analysis, IOCs |
| 2.5 | Explain mitigation techniques | 06, 07 | Remediation strategies |

#### Domain 3.0: Security Architecture (18%)

| Objective | Description | Stage(s) | Notes |
|-----------|-------------|----------|-------|
| 3.1 | Compare security architectures | 03, 07 | Network segmentation, defense in depth |
| 3.2 | Apply security principles to infrastructure | 02, 03 | Hardening, secure configuration |
| 3.3 | Compare secure data concepts | 02, 07 | Data protection, encryption at rest |
| 3.4 | Explain resilience and recovery | 02 | Backup concepts, disaster recovery awareness |

#### Domain 4.0: Security Operations (28%)

| Objective | Description | Stage(s) | Notes |
|-----------|-------------|----------|-------|
| 4.1 | Apply security techniques to computing resources | 01, 02 | Hardening, secure configuration |
| 4.2 | Explain security implications of asset management | 02, 05 | Inventory, discovery |
| 4.3 | Explain vulnerability management activities | 05, 06 | Scanning, assessment, remediation |
| 4.4 | Explain alerting and monitoring concepts | 07 | SIEM, log analysis, IDS/IPS |
| 4.5 | Modify enterprise capabilities for security | 07, 08 | Detection engineering |
| 4.6 | Implement identity and access management | 01, 08 | Authentication, authorization, AD |
| 4.7 | Explain automation and orchestration | 01, 07 | Scripting for security |

#### Domain 5.0: Security Program Management (20%)

| Objective | Description | Stage(s) | Notes |
|-----------|-------------|----------|-------|
| 5.1 | Summarize governance, risk, and compliance | 04, 09 | Framework awareness, policies |
| 5.2 | Explain risk management processes | 04, 09 | Risk assessment, prioritization |
| 5.3 | Summarize data protection and compliance | 04, 09 | Legal requirements, data handling |
| 5.4 | Summarize security awareness practices | 04 | Training concepts |

---

## CompTIA CySA+ (CS0-003)

**Exam Details:**
- 85 questions (multiple choice + performance-based)
- 165 minutes
- Passing score: 750/900
- Recommended experience: 4 years hands-on security

### Domain Mapping

| Domain | Weight | Course Stages | Coverage |
|--------|--------|---------------|----------|
| 1.0 Security Operations | 33% | 02, 07, 08 | Substantial |
| 2.0 Vulnerability Management | 30% | 05, 06 | Substantial |
| 3.0 Incident Response | 22% | 07 | Substantial |
| 4.0 Reporting and Communication | 15% | 09 | Full |

### Detailed Objective Mapping

#### Domain 1.0: Security Operations (33%)

| Objective | Description | Stage(s) | Notes |
|-----------|-------------|----------|-------|
| 1.1 | Explain importance of system/network architecture | 02, 03 | Infrastructure concepts |
| 1.2 | Analyze indicators of potentially malicious activity | 07 | Log analysis, threat hunting |
| 1.3 | Use tools/techniques to determine malicious activity | 07, 08 | SIEM, IDS/IPS, forensics |
| 1.4 | Compare threat intelligence and threat hunting | 07 | IOCs, threat feeds, hunting methodology |
| 1.5 | Explain importance of efficiency and process improvement | 07, 09 | Automation, SOPs |

#### Domain 2.0: Vulnerability Management (30%)

| Objective | Description | Stage(s) | Notes |
|-----------|-------------|----------|-------|
| 2.1 | Implement vulnerability scanning methods | 05, 06 | Nmap, Nikto, OpenVAS |
| 2.2 | Analyze vulnerability scan output | 06 | Prioritization, false positives |
| 2.3 | Analyze data to prioritize vulnerabilities | 06, 09 | Risk-based prioritization |
| 2.4 | Recommend controls to mitigate vulnerabilities | 06, 09 | Remediation strategies |
| 2.5 | Explain vulnerability response and remediation | 06, 09 | Patching, compensating controls |

#### Domain 3.0: Incident Response (22%)

| Objective | Description | Stage(s) | Notes |
|-----------|-------------|----------|-------|
| 3.1 | Explain incident response processes | 07 | IR phases, procedures |
| 3.2 | Apply incident response procedures | 07 | Containment, eradication, recovery |
| 3.3 | Analyze potential IOCs | 07 | Network, host, application indicators |
| 3.4 | Use forensic techniques | 07 | Evidence handling, analysis |

#### Domain 4.0: Reporting and Communication (15%)

| Objective | Description | Stage(s) | Notes |
|-----------|-------------|----------|-------|
| 4.1 | Explain importance of vulnerability management reporting | 09 | Metrics, dashboards |
| 4.2 | Explain importance of incident response reporting | 09 | Documentation, lessons learned |
| 4.3 | Communicate vulnerability and incident information | 09 | Executive summaries, technical reports |

---

## CompTIA PenTest+ (PT0-002)

**Exam Details:**
- 85 questions (multiple choice + performance-based)
- 165 minutes
- Passing score: 750/900
- Recommended experience: 3-4 years hands-on security

### Domain Mapping

| Domain | Weight | Course Stages | Coverage |
|--------|--------|---------------|----------|
| 1.0 Planning and Scoping | 14% | 04 | Full |
| 2.0 Information Gathering | 22% | 05 | Full |
| 3.0 Vulnerability Scanning | 18% | 05, 06 | Substantial |
| 4.0 Attacks and Exploits | 30% | 06, 08 | Substantial |
| 5.0 Reporting and Communication | 16% | 09 | Full |

### Detailed Objective Mapping

#### Domain 1.0: Planning and Scoping (14%)

| Objective | Description | Stage(s) | Notes |
|-----------|-------------|----------|-------|
| 1.1 | Compare governance, risk, compliance | 04 | Legal, compliance awareness |
| 1.2 | Explain scoping and organizational requirements | 04 | Rules of engagement, scope definition |
| 1.3 | Demonstrate ethical hacking mindset | 04 | Ethics, professionalism |

#### Domain 2.0: Information Gathering (22%)

| Objective | Description | Stage(s) | Notes |
|-----------|-------------|----------|-------|
| 2.1 | Perform passive reconnaissance | 05 | OSINT, public information |
| 2.2 | Perform active reconnaissance | 05 | Scanning, enumeration |
| 2.3 | Analyze reconnaissance results | 05 | Target profiling, attack surface |

#### Domain 3.0: Vulnerability Scanning (18%)

| Objective | Description | Stage(s) | Notes |
|-----------|-------------|----------|-------|
| 3.1 | Compare scanning methods and tools | 05, 06 | Nmap, Nikto, web scanners |
| 3.2 | Analyze scan output | 06 | Interpretation, validation |
| 3.3 | Explain vulnerability scanning concepts | 06 | Credentialed vs non-credentialed |

#### Domain 4.0: Attacks and Exploits (30%)

| Objective | Description | Stage(s) | Notes |
|-----------|-------------|----------|-------|
| 4.1 | Research attack vectors | 06 | Exploit databases, CVE research |
| 4.2 | Perform network attacks | 06 | Various network-based attacks |
| 4.3 | Perform application-based attacks | 06 | Web application attacks |
| 4.4 | Perform attacks on cloud technologies | - | Limited coverage |
| 4.5 | Explain common attacks and vulnerabilities | 06, 08 | Including AD attacks |
| 4.6 | Perform post-exploitation techniques | 06 | Persistence, lateral movement |

#### Domain 5.0: Reporting and Communication (16%)

| Objective | Description | Stage(s) | Notes |
|-----------|-------------|----------|-------|
| 5.1 | Analyze findings and recommend remediation | 09 | Risk-based recommendations |
| 5.2 | Explain report components | 09 | Executive summary, technical details |
| 5.3 | Explain post-report delivery activities | 09 | Debrief, retesting |

---

## CompTIA Linux+ (XK0-005)

**Exam Details:**
- 90 questions (multiple choice + performance-based)
- 90 minutes
- Passing score: 720/900

### Domain Mapping

| Domain | Weight | Course Stages | Coverage |
|--------|--------|---------------|----------|
| 1.0 System Management | 32% | 01, 02 | Full |
| 2.0 Security | 21% | 01, 02, 07 | Full |
| 3.0 Scripting, Containers, Automation | 19% | 01, 02 | Substantial |
| 4.0 Troubleshooting | 28% | 01, 02, 03 | Substantial |

### Detailed Objective Mapping

#### Domain 1.0: System Management (32%)

| Objective | Description | Stage(s) | Notes |
|-----------|-------------|----------|-------|
| 1.1 | Summarize Linux fundamentals | 01 | Filesystem, shells, commands |
| 1.2 | Manage files and directories | 01 | cp, mv, rm, permissions |
| 1.3 | Configure and manage storage | 02 | Partitions, LVM, mounts |
| 1.4 | Configure and use processes and services | 01, 02 | systemctl, process management |
| 1.5 | Use package managers | 02 | apt, dpkg |
| 1.6 | Configure localization options | 02 | Locale, timezone |

#### Domain 2.0: Security (21%)

| Objective | Description | Stage(s) | Notes |
|-----------|-------------|----------|-------|
| 2.1 | Summarize security best practices | 01, 02 | Hardening, least privilege |
| 2.2 | Implement identity management | 01 | Users, groups, PAM |
| 2.3 | Implement authorization and access controls | 01 | Permissions, ACLs, sudo |
| 2.4 | Configure and apply firewall rules | 02, 03 | iptables, ufw |
| 2.5 | Configure and apply remote connectivity | 02 | SSH configuration, keys |
| 2.6 | Apply appropriate security settings | 02 | SELinux awareness, AppArmor |

#### Domain 3.0: Scripting, Containers, Automation (19%)

| Objective | Description | Stage(s) | Notes |
|-----------|-------------|----------|-------|
| 3.1 | Create simple shell scripts | 01 | Variables, loops, conditionals |
| 3.2 | Perform basic container operations | 02 | Awareness level |
| 3.3 | Perform version control using Git | All | Workflow throughout course |

#### Domain 4.0: Troubleshooting (28%)

| Objective | Description | Stage(s) | Notes |
|-----------|-------------|----------|-------|
| 4.1 | Analyze system properties and remediate | 01, 02 | Logs, performance |
| 4.2 | Troubleshoot user issues | 01 | Account problems, permissions |
| 4.3 | Troubleshoot application and hardware issues | 02 | Service failures, resource issues |
| 4.4 | Troubleshoot network issues | 03 | Connectivity, DNS, routing |

---

## CompTIA Network+ (N10-009)

**Exam Details:**
- 90 questions (multiple choice + performance-based)
- 90 minutes
- Passing score: 720/900

### Domain Mapping

| Domain | Weight | Course Stages | Coverage |
|--------|--------|---------------|----------|
| 1.0 Networking Concepts | 23% | 03 | Foundational |
| 2.0 Network Implementation | 19% | 03 | Awareness |
| 3.0 Network Operations | 18% | 02, 03 | Foundational |
| 4.0 Network Security | 20% | 03, 07 | Foundational |
| 5.0 Network Troubleshooting | 20% | 03 | Foundational |

> **Note:** This course provides foundational networking knowledge required for security work. For full Network+ preparation, dedicated networking study is recommended.

---

## EC-Council CEH (v12)

**Exam Details:**
- 125 questions
- 4 hours
- Passing score: 60-85% (varies by exam form)

### Domain Mapping

| Domain | Course Stages | Coverage |
|--------|---------------|----------|
| 1. Introduction to Ethical Hacking | 04 | Full |
| 2. Footprinting and Reconnaissance | 05 | Full |
| 3. Scanning Networks | 05 | Full |
| 4. Enumeration | 05 | Full |
| 5. Vulnerability Analysis | 06 | Substantial |
| 6. System Hacking | 06 | Substantial |
| 7. Malware Threats | 07 | Foundational |
| 8. Sniffing | 03, 07 | Substantial |
| 9. Social Engineering | 04 | Awareness |
| 10. Denial of Service | 06 | Awareness |
| 11. Session Hijacking | 06 | Foundational |
| 12. Hacking Web Servers | 06 | Substantial |
| 13. Hacking Web Applications | 06 | Substantial |
| 14. SQL Injection | 06 | Substantial |
| 15. Hacking Wireless Networks | 06 | Foundational |
| 16. Hacking Mobile Platforms | - | Not covered |
| 17. IoT and OT Hacking | - | Not covered |
| 18. Cloud Computing | - | Limited coverage |
| 19. Cryptography | 03 | Foundational |

---

## eLearnSecurity eJPT (v2)

**Exam Details:**
- Practical exam (35 questions based on penetration test)
- 48 hours
- Passing score: 70%

### Domain Mapping

| Domain | Course Stages | Coverage |
|--------|---------------|----------|
| Assessment Methodologies | 04 | Full |
| Host & Networking Auditing | 03, 05 | Full |
| Host & Network Penetration Testing | 05, 06 | Full |
| Web Application Penetration Testing | 06 | Substantial |

> **Note:** This course provides comprehensive preparation for eJPTv2. The practical, hands-on nature of our capstone project closely mirrors the eJPT exam format.

---

## LPI Linux Essentials (010-160)

**Exam Details:**
- 40 questions
- 60 minutes
- Passing score: 500/800

### Domain Mapping

| Domain | Weight | Course Stages | Coverage |
|--------|--------|---------------|----------|
| 1. The Linux Community | 10% | 01, 04 | Full |
| 2. Finding Your Way on Linux | 26% | 01 | Full |
| 3. The Power of the Command Line | 24% | 01 | Full |
| 4. The Linux Operating System | 20% | 01, 02 | Full |
| 5. Security and File Permissions | 20% | 01 | Full |

> **Note:** Stage 01 of this course provides complete coverage of Linux Essentials objectives.

---

## Stage-by-Stage Certification Mapping Quick Reference

| Stage | Primary Certifications | Secondary Certifications |
|-------|----------------------|-------------------------|
| **01** | Linux+, Linux Essentials | Security+ (foundations) |
| **02** | Linux+ | CySA+ (foundations), Security+ |
| **03** | Network+ | Security+, CySA+ |
| **04** | PenTest+, CEH | Security+, eJPT |
| **05** | PenTest+, CEH, eJPT | CySA+ |
| **06** | PenTest+, CEH, eJPT | CySA+, Security+ |
| **07** | CySA+, Security+ | CEH |
| **08** | CySA+, PenTest+ | CEH |
| **09** | All | Professional competency |
| **Capstone** | eJPT, PenTest+ | Portfolio demonstration |

---

## Recommended Certification Path

Based on this course content, here is a suggested certification progression:

### Entry Level (After Stages 01-03)
1. **LPI Linux Essentials** — Validate Linux fundamentals
2. **CompTIA Linux+** — Demonstrate Linux administration skills

### Security Foundations (After Stages 04-06)
3. **CompTIA Security+** — Industry-standard security baseline
4. **eLearnSecurity eJPT** — Practical penetration testing validation

### Specialization (After Complete Course)
5. **CompTIA CySA+** — If pursuing analyst/defensive path
6. **CompTIA PenTest+** — If pursuing offensive security path
7. **EC-Council CEH** — Additional penetration testing credential

### Timeline Suggestion

| Timeframe | Certification | Prerequisites |
|-----------|--------------|---------------|
| After Stage 02 | Linux Essentials | Stages 01-02 complete |
| After Stage 03 | Linux+ | Additional study recommended |
| After Stage 06 | Security+ | Stages 01-06 complete |
| After Stage 06 | eJPT | Strong hands-on practice |
| After Capstone | CySA+ or PenTest+ | Full course + exam prep |

---

## Additional Study Resources

For dedicated certification exam preparation, supplement this course with:

### Official Resources
- CompTIA CertMaster (official practice)
- EC-Council official courseware
- eLearnSecurity INE training platform

### Practice Exams
- CompTIA official practice tests
- Kaplan IT Training
- Pearson practice tests

### Study Guides
- CompTIA study guides (Sybex, Pearson)
- Official certification study guides
- Community-created study materials

---

## Disclaimer Reminder

This mapping represents our best effort to align course content with certification objectives as of the document date. Always verify current exam objectives with the certification vendor before beginning exam preparation.

**Certification vendors:**
- CompTIA: https://www.comptia.org
- EC-Council: https://www.eccouncil.org
- eLearnSecurity/INE: https://ine.com

---

## Navigation

- Return to course: `README.md`
- Start learning: `docs/START_HERE.md`
- Track progress: `docs/LEARNER_PROGRESS_CHECKLIST.md`
