# START HERE — Kali Linux for Cybersecurity Learning Path

Welcome.  
This document is the **operational entry point** for this repository.

If you are new here, **do not skip this file**.

This guide tells you:
- What you need installed
- How to open and navigate the repository
- Where to start learning
- How stages work
- When a stage is complete
- When you are allowed to move forward

---

> Looking for the project overview, learning stages, and certification alignment? See the root `README.md`.

---

## 1. What You Need Before Starting

### Hardware Requirements

**Minimum (Will work, but may be slow):**
- 8GB RAM
- 100GB free disk space
- Dual-core processor with virtualization support

**Recommended (Smooth experience):**
- 16GB RAM or more
- 200GB free disk space (SSD preferred)
- Quad-core processor

**To check if your CPU supports virtualization:**

**Windows:**
1. Open Task Manager (Ctrl+Shift+Esc)
2. Go to Performance → CPU
3. Look for "Virtualization: Enabled"

**macOS:**
- All Intel Macs support virtualization
- Apple Silicon (M1/M2/M3): Use UTM instead of VirtualBox

**Linux:**
```bash
grep -E "(vmx|svm)" /proc/cpuinfo
```
If output appears, virtualization is supported.

### Software Requirements

You will install these as you progress through Stage 01:

1. **Virtualization Software** (choose one):
   - VirtualBox (free, cross-platform) — Recommended for beginners
   - VMware Workstation Player (free for personal use)
   - UTM (macOS Apple Silicon)

2. **Git** — For version control and submitting your work
   - Windows: https://git-scm.com/download/win
   - macOS: `xcode-select --install`
   - Linux: `sudo apt install git`

3. **Text Editor** (for notes and documentation):
   - VS Code (recommended)
   - Any editor you're comfortable with

### Operating Systems

You can complete this course from:
- Windows 10/11
- macOS (Intel or Apple Silicon)
- Linux

All hands-on work happens inside virtual machines, so your host OS doesn't matter much.

---

## 2. Clone the Repository

Open a terminal (PowerShell on Windows, Terminal on macOS/Linux):

```bash
git clone https://github.com/yourusername/kali-linux-learning-path.git
cd kali-linux-learning-path
```

### 3. Open the Repository in Your Editor

If using VS Code:
1. Open VS Code
2. File → Open Folder
3. Select the `kali-linux-learning-path` folder
4. Click Select Folder / Open

You should see the folder structure on the left panel.

---

## 4. Understand the Repository Structure

You will work in three main areas:

### `docs/` — READ HERE
- Explanations, concepts, and guidance
- This document lives here
- Reference materials

### `stage-starters/` — START LEARNING HERE
- One folder per stage
- Each stage has a README with complete instructions
- This is where your hands-on work happens

### `audience-docs/` — REVIEW WHEN COMPLETE
- Documentation for specific audiences
- Interview preparation
- Employer-facing materials

---

## 5. How This Learning Path Works

This repository is structured as **progressive stages** that must be completed in order.

### Rules:

1. **Complete stages in order** — Do not skip ahead
2. **Do all hands-on exercises** — Reading is not enough
3. **Commit and push after every stage** — This is required
4. **Each stage builds on the previous** — Skipping creates gaps

### What Each Stage Contains:

- **README.md** — Complete instructions and content
- **Learning objectives** — What you will achieve
- **Hands-on exercises** — Practice activities
- **Certification checkpoints** — Exam alignment markers
- **Assessment** — Verify your understanding
- **Definition of Done** — Checklist before moving on

---

## 6. Start Stage 01

Your learning begins in **Stage 01 — Linux Foundations & CLI Mastery**.

Navigate to:
```
stage-starters/stage_01_Linux_Foundations_CLI_Mastery/
```

Open `README.md` and follow it from beginning to end.

**Do not skip to Kali Linux!** Stage 01 builds the foundation that everything else requires. Without it, you will struggle with every tool in Kali.

---

## 7. Definition of "Stage Complete"

A stage is **only complete** when ALL of the following are true:

1. ✅ You have read the entire stage README
2. ✅ You have completed all hands-on exercises
3. ✅ You have completed the stage assessment
4. ✅ You have checked off all items in the completion checklist
5. ✅ Your work is committed to Git
6. ✅ Your work is pushed to GitHub
7. ✅ `git status` shows a clean working tree

### Required Git Workflow (After Each Stage)

From the repository root:

```bash
git status
git add .
git commit -m "Complete Stage XX - [Stage Title]"
git push
```

**Do not proceed to the next stage without a clean commit and push.**

This workflow:
- Mirrors professional development practices
- Creates an audit trail of your learning
- Demonstrates disciplined work habits to employers

---

## 8. Moving to the Next Stage

You may move forward **only after**:
- The current stage is fully complete (all checklist items)
- You have committed and pushed your work
- You feel confident in the skills covered

Then:
1. Open the next stage folder
2. Read its README completely
3. Begin the exercises

---

## 9. How Much Time Should This Take?

This course is designed for **self-paced learning** over several months.

**Realistic expectations:**

| Commitment | Total Time | Timeline |
|-----------|------------|----------|
| 10 hrs/week | 340-395 hrs | 8-10 months |
| 15 hrs/week | 340-395 hrs | 6-7 months |
| 20 hrs/week | 340-395 hrs | 4-5 months |
| Full-time | 340-395 hrs | 2-3 months |

**Quality matters more than speed.** Take the time to truly understand each concept.

---

## 10. Common Troubleshooting

### "My VM won't start"
- Enable virtualization in BIOS/UEFI settings
- Disable Hyper-V on Windows (conflicts with VirtualBox)
- Allocate less RAM if your host is running low

### "I'm stuck on an exercise"
1. Re-read the relevant section
2. Check man pages (`man command`)
3. Try the command yourself with variations
4. Search online (this is a real skill!)
5. Take a break and come back fresh

### "Git says 'nothing to commit'"
- You may not have saved your files
- You may be in the wrong directory
- Run `git status` to check what Git sees

### "I feel overwhelmed"
- This is normal — you're learning a lot
- Focus on one section at a time
- It's okay to repeat exercises
- Everyone starts as a beginner

---

## 11. When to Start the Capstone

You may begin the capstone **only after**:
- All 9 stages are completed
- Each stage has its own commit
- You can explain the concepts from each stage
- You feel ready to demonstrate your skills

The capstone location:
```
stage-starters/capstone/
```

---

## 12. Supplementary Practice Resources

These **optional** third-party platforms complement your learning:

| Platform | Best For | Cost |
|----------|----------|------|
| TryHackMe | Guided Linux/security rooms | Free tier available |
| OverTheWire | CLI practice challenges | Free |
| HackTheBox | Advanced challenges | Free tier available |
| VulnHub | Downloadable vulnerable VMs | Free |

These are **not required** but provide additional practice opportunities.

---

## 13. Ethical and Legal Reminder

**Throughout this course, you will learn powerful techniques.**

You must:
- ✅ Only test systems you own or have explicit written permission to test
- ✅ Understand that unauthorized access is illegal
- ✅ Follow responsible disclosure if you find real vulnerabilities
- ✅ Use your skills ethically and professionally

Violation of computer crime laws can result in:
- Criminal prosecution
- Civil liability
- Career destruction

**"With great power comes great responsibility."**

---

## 14. What to Do Right Now

1. Verify your hardware meets minimum requirements
2. Install VirtualBox (or your chosen hypervisor)
3. Install Git if not already present
4. Navigate to `stage-starters/stage_01_Linux_Foundations_CLI_Mastery/`
5. Open `README.md`
6. Begin Stage 01

---

## What to Read Next

- Begin: `stage-starters/stage_01_Linux_Foundations_CLI_Mastery/README.md`
- Track progress: `docs/LEARNER_PROGRESS_CHECKLIST.md`
- Certification mapping: `docs/CERTIFICATION_MAPPING.md`

---

## Final Note

This repository is designed to build **real cybersecurity skills** through disciplined, progressive learning.

If something feels strict, that is intentional. Professional cybersecurity work demands:
- Attention to detail
- Methodical approaches
- Documentation discipline
- Ethical conduct

Start now. Take your time. Master each stage.

Your future in cybersecurity begins here.
