# Stage 01 — Linux Foundations & CLI Mastery
## Your First Steps into the Linux Operating System

**Kali Linux for Cybersecurity Learning Path**  
**Audience:** Complete beginners (no prior Linux or command-line experience required)

Welcome. In this stage you will learn the fundamental building blocks of Linux and use them to confidently navigate, manipulate, and understand a Linux system. By the end of this stage, you will have the foundational skills that every cybersecurity professional relies on daily.

---

## Why This Stage Matters

Every tool in Kali Linux runs on Linux. Every penetration test happens through a Linux terminal. Every security analyst must read logs, navigate filesystems, and automate tasks using Linux commands.

**Without Linux fundamentals, you cannot:**
- Run security tools effectively
- Understand what those tools are doing
- Troubleshoot when things break
- Work in enterprise security environments

This stage is not optional background—it is the foundation everything else builds upon.

---

## What You Will Learn and Why It Matters

### Skills You Will Gain

| Skill | Why It Matters for Security |
|-------|----------------------------|
| **Navigating the filesystem** | Security tools output to specific locations; logs live in specific directories; you must know where things are |
| **File and directory manipulation** | Creating scripts, organizing evidence, managing tool outputs |
| **Understanding permissions** | Linux permissions are the first line of defense; misconfigurations are common vulnerabilities |
| **User and group management** | Privilege escalation attacks target user/group weaknesses; you must understand the model |
| **Reading and searching files** | Log analysis, configuration review, and evidence gathering all require text manipulation |
| **Input/output redirection** | Capturing tool output, building pipelines, automating workflows |
| **Process management** | Understanding what's running, identifying suspicious processes, resource management |
| **Basic shell scripting** | Automation is essential; repetitive tasks must be scripted |
| **Getting help** | Man pages and documentation are how professionals solve problems independently |

---

## What You Will Build

By the end of this stage, you will have:

1. **A fully functional Linux lab environment** — Your personal practice system
2. **A command reference cheat sheet** — Built by you, for you, as you learn
3. **A system reconnaissance script** — Your first security-relevant automation
4. **Demonstrated competency** — Verified through hands-on exercises and a stage assessment

---

## Certification Alignment

This stage maps to objectives from:

| Certification | Relevant Domains |
|--------------|------------------|
| **CompTIA Linux+** | System Management, Security, Scripting |
| **CompTIA Security+** | 3.3 Secure Systems Design, 4.1 Security Assessment Tools |
| **CompTIA CySA+** | 1.3 Security Concepts, 4.2 Analysis Tools |
| **CompTIA PenTest+** | 1.1 Planning and Scoping (Environment Setup) |
| **LPI Linux Essentials** | All domains |

### Certification Checkpoint Mapping

Throughout this stage, you'll see **[CERT CHECKPOINT]** markers that indicate specific skills mapping to certification exam objectives. These are not exhaustive but highlight key alignments.

---

## Time Estimate

**Total: 35-40 hours**

| Section | Hours |
|---------|-------|
| Lab Environment Setup | 3-4 |
| Filesystem Navigation | 4-5 |
| File & Directory Operations | 5-6 |
| Permissions & Ownership | 5-6 |
| Users & Groups | 3-4 |
| Text Processing & Searching | 5-6 |
| Redirection & Pipelines | 3-4 |
| Process Management | 3-4 |
| Basic Shell Scripting | 4-5 |
| Stage Assessment | 2-3 |

These estimates assume focused study with hands-on practice. Take the time you need—mastery matters more than speed.

---

## Prerequisites

### Required
- A computer capable of running virtual machines (8GB RAM minimum, 16GB recommended)
- At least 50GB of free disk space
- Internet connection for downloading software
- Patience and willingness to type commands (not just read about them)

### Not Required
- Prior Linux experience
- Programming knowledge
- Cybersecurity background

---

## The Milestones Approach

This stage is broken into milestones so you can track progress and build confidence incrementally.

### Stage 01 Milestones

1. **Set up your Linux lab environment** (VirtualBox + Ubuntu)
2. **Navigate the Linux filesystem with confidence**
3. **Create, move, copy, and delete files and directories**
4. **Understand and modify permissions**
5. **Manage users and groups**
6. **Search and process text files**
7. **Use redirection and pipelines**
8. **Manage running processes**
9. **Write your first shell scripts**
10. **Complete the stage assessment and commit your work**

---

## Part 1 — Lab Environment Setup (Milestone 1)

Before you can learn Linux, you need a Linux system to practice on. We will use virtualization—running Linux inside your existing operating system—so you can experiment freely without risk to your main computer.

### Why Virtualization?

- **Safety**: You can break things and simply rebuild
- **Isolation**: Your experiments don't affect your main OS
- **Snapshots**: Save your VM state and revert if needed
- **Industry Standard**: Security professionals use VMs constantly
- **Skill Building**: VM management is itself a valuable skill

### What We're Installing

1. **VirtualBox** — Free, open-source virtualization software
2. **Ubuntu Server 24.04 LTS** — A clean, stable Linux distribution for learning

> **Why Ubuntu Server, not Kali Linux yet?**
> 
> Kali Linux is a specialized distribution with 600+ pre-installed security tools. Starting with Kali would be like learning to drive in a Formula 1 car. Ubuntu Server gives you a clean environment to learn core Linux skills without distraction. You will install Kali in Stage 03 after you've built your foundation.

### Step-by-Step: Installing VirtualBox

#### Windows Installation

1. Download VirtualBox from: https://www.virtualbox.org/wiki/Downloads
2. Click "Windows hosts" to download the installer
3. Run the downloaded `.exe` file
4. Click **Next** through the installation wizard
5. Accept default settings (they are fine for our purposes)
6. Click **Yes** when asked about network interfaces (brief network interruption)
7. Click **Install**
8. Click **Finish**

#### macOS Installation

1. Download VirtualBox from: https://www.virtualbox.org/wiki/Downloads
2. Click "macOS / Intel hosts" (or ARM if you have M1/M2/M3 chip)
3. Open the downloaded `.dmg` file
4. Double-click "VirtualBox.pkg"
5. Follow the installation prompts
6. Go to **System Preferences → Security & Privacy → General**
7. Click **Allow** next to the Oracle message (if present)
8. Restart your Mac if prompted

> **Apple Silicon (M1/M2/M3) Users**: VirtualBox has limited ARM support. Consider UTM (free) or VMware Fusion (free for personal use) as alternatives. The commands you learn will be identical.

#### Linux Installation

```bash
# Debian/Ubuntu
sudo apt update
sudo apt install virtualbox virtualbox-ext-pack

# Fedora
sudo dnf install VirtualBox

# Arch
sudo pacman -S virtualbox virtualbox-host-modules-arch
```

### Step-by-Step: Creating Your Ubuntu VM

#### 1. Download Ubuntu Server

1. Go to: https://ubuntu.com/download/server
2. Download **Ubuntu Server 24.04 LTS** (approximately 2.5GB)
3. Save the `.iso` file somewhere you can find it

#### 2. Create the Virtual Machine

1. Open VirtualBox
2. Click **New**
3. Configure the VM:
   - **Name**: `Ubuntu-Lab` (or any name you prefer)
   - **Machine Folder**: Leave default or choose your preferred location
   - **Type**: Linux
   - **Version**: Ubuntu (64-bit)
4. Click **Next**

#### 3. Allocate Resources

**Memory (RAM):**
- Minimum: 2048 MB (2GB)
- Recommended: 4096 MB (4GB)
- If your host has 16GB+: 8192 MB (8GB)

**Processors:**
- Minimum: 1 CPU
- Recommended: 2 CPUs

**Hard Disk:**
- Select "Create a virtual hard disk now"
- Click **Create**
- Choose **VDI (VirtualBox Disk Image)**
- Choose **Dynamically allocated** (saves space)
- Set size to at least **25GB** (50GB recommended)
- Click **Create**

#### 4. Attach the Ubuntu ISO

1. Select your new VM in the list
2. Click **Settings**
3. Go to **Storage**
4. Click the **Empty** disk icon under "Controller: IDE"
5. Click the disk icon on the right → **Choose a disk file**
6. Select the Ubuntu Server `.iso` you downloaded
7. Click **OK**

#### 5. Install Ubuntu Server

1. Select your VM and click **Start**
2. The Ubuntu installer will boot
3. Select your language using arrow keys, press **Enter**
4. Select **Install Ubuntu Server**
5. Follow the prompts:
   - **Keyboard**: Choose your layout
   - **Network**: Accept defaults (will auto-configure)
   - **Proxy**: Leave blank unless you need one
   - **Mirror**: Accept default
   - **Storage**: Use entire disk (accept defaults)
   - **Confirm destructive action**: Yes (this is the VM disk, not your real disk!)
6. **Profile setup**:
   - **Your name**: Your actual name
   - **Server name**: `ubuntu-lab`
   - **Username**: `yourname` (lowercase, no spaces)
   - **Password**: Choose something memorable but secure

   > **IMPORTANT**: Remember this username and password! You will use them constantly.

7. **SSH Setup**: Check "Install OpenSSH server" (press Space to select)
8. **Featured Server Snaps**: Skip (press Tab to highlight Done, press Enter)
9. Wait for installation to complete
10. Select **Reboot Now**
11. Press **Enter** when prompted to remove installation medium

#### 6. First Login

After reboot, you'll see a login prompt:

```
ubuntu-lab login: _
```

1. Type your username, press **Enter**
2. Type your password (characters won't display—this is normal), press **Enter**

You should see something like:

```
Welcome to Ubuntu 24.04 LTS (GNU/Linux 6.x.x-xx-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

yourname@ubuntu-lab:~$ _
```

**Congratulations!** You are now at a Linux command prompt.

### Creating Your First Snapshot

Before doing anything else, let's save this clean state:

1. In VirtualBox menu: **Machine → Take Snapshot**
2. Name it: `Fresh Install - Clean State`
3. Click **OK**

You can always return to this snapshot if you break something.

---

### Milestone 1 Checkpoint

Before proceeding, verify:

- [ ] VirtualBox is installed and runs without errors
- [ ] Ubuntu Server VM is created with appropriate resources
- [ ] Ubuntu Server is installed and boots successfully
- [ ] You can log in with your username and password
- [ ] You have created a "Clean State" snapshot

**[CERT CHECKPOINT - Linux+ / Security+]**: Setting up isolated lab environments is a fundamental skill tested across certifications. You've just demonstrated environment preparation and virtualization competency.

---

## Part 2 — Understanding the Linux Environment

Before diving into commands, let's understand what you're looking at.

### The Shell

When you log in, you interact with **the shell**—a program that interprets your commands and communicates with the operating system. Your default shell is **Bash** (Bourne Again SHell).

### The Command Prompt

Your prompt looks something like:

```
yourname@ubuntu-lab:~$
```

Let's decode this:

| Part | Meaning |
|------|---------|
| `yourname` | Your username |
| `@` | Separator (at) |
| `ubuntu-lab` | Hostname (computer name) |
| `:` | Separator |
| `~` | Current directory (`~` means your home directory) |
| `$` | You are a regular user (would be `#` for root/superuser) |

### Your First Commands

Let's start with the simplest possible commands. Type each one exactly, then press **Enter**.

#### 1. `whoami` — Who am I?

```bash
whoami
```

Output:
```
yourname
```

This confirms which user you're logged in as.

#### 2. `hostname` — What computer am I on?

```bash
hostname
```

Output:
```
ubuntu-lab
```

#### 3. `date` — What's the date and time?

```bash
date
```

Output (example):
```
Thu Dec 25 14:30:00 UTC 2025
```

#### 4. `uptime` — How long has this system been running?

```bash
uptime
```

Output (example):
```
 14:30:05 up 5 min,  1 user,  load average: 0.00, 0.02, 0.00
```

#### 5. `clear` — Clear the screen

```bash
clear
```

This clears all previous output. Useful when your screen gets cluttered.

> **Keyboard Shortcut**: `Ctrl + L` does the same thing as `clear`

### Command Structure

Most Linux commands follow this pattern:

```
command [options] [arguments]
```

- **command**: The program you want to run
- **options**: Modify how the command behaves (usually start with `-` or `--`)
- **arguments**: What the command acts upon (files, directories, etc.)

Example:
```bash
ls -l /home
```
- `ls` = command (list directory contents)
- `-l` = option (use long format)
- `/home` = argument (the directory to list)

---

## Part 3 — Filesystem Navigation (Milestone 2)

The Linux filesystem is a hierarchical tree structure. Everything starts at the **root** directory, represented by `/`.

### The Linux Directory Structure

```
/                       ← Root (top of the tree)
├── bin                 ← Essential user binaries (ls, cp, mv, etc.)
├── boot                ← Boot loader files (kernel, initramfs)
├── dev                 ← Device files (disks, terminals, etc.)
├── etc                 ← System configuration files
├── home                ← User home directories
│   └── yourname        ← YOUR home directory
├── lib                 ← Essential shared libraries
├── media               ← Mount points for removable media
├── mnt                 ← Temporary mount points
├── opt                 ← Optional/third-party software
├── proc                ← Virtual filesystem (process/kernel info)
├── root                ← Root user's home directory
├── run                 ← Runtime data
├── sbin                ← System binaries (admin commands)
├── srv                 ← Service data
├── sys                 ← Virtual filesystem (system info)
├── tmp                 ← Temporary files
├── usr                 ← User programs and data
│   ├── bin             ← User binaries
│   ├── lib             ← Libraries
│   ├── local           ← Locally installed software
│   └── share           ← Shared data (docs, icons)
└── var                 ← Variable data (logs, caches, mail)
    ├── log             ← System logs
    └── www             ← Web server files
```

### Security-Relevant Directories

As a security professional, pay special attention to:

| Directory | Security Relevance |
|-----------|-------------------|
| `/etc` | Configuration files—misconfigurations are vulnerabilities |
| `/etc/passwd` | User account information |
| `/etc/shadow` | Password hashes (restricted access) |
| `/var/log` | System and application logs—your evidence source |
| `/tmp` | Temporary files—malware often hides here |
| `/home` | User data—target for data exfiltration |
| `/root` | Root's home—high-value target |
| `/proc` | Process information—system reconnaissance |

### Navigation Commands

#### `pwd` — Print Working Directory

Where am I right now?

```bash
pwd
```

Output:
```
/home/yourname
```

#### `ls` — List Directory Contents

What's in this directory?

```bash
ls
```

If your home directory is empty (likely for a fresh install), you'll see no output. That's okay!

**Common `ls` options:**

```bash
# Long format (detailed information)
ls -l

# Show hidden files (start with .)
ls -a

# Both long format AND hidden files
ls -la

# Human-readable sizes
ls -lh

# Sort by time (newest first)
ls -lt

# Recursive (show subdirectories too)
ls -R
```

**Example: List the root directory**

```bash
ls -l /
```

Output (truncated):
```
total 64
drwxr-xr-x   2 root root  4096 Dec 20 10:00 bin
drwxr-xr-x   3 root root  4096 Dec 20 10:05 boot
drwxr-xr-x  19 root root  4000 Dec 25 14:30 dev
drwxr-xr-x  92 root root  4096 Dec 25 14:30 etc
drwxr-xr-x   3 root root  4096 Dec 20 10:05 home
...
```

#### Understanding `ls -l` Output

```
drwxr-xr-x   2 root root  4096 Dec 20 10:00 bin
```

| Field | Meaning |
|-------|---------|
| `d` | File type (d=directory, -=file, l=link) |
| `rwxr-xr-x` | Permissions (we'll cover this in detail later) |
| `2` | Number of hard links |
| `root` | Owner |
| `root` | Group |
| `4096` | Size in bytes |
| `Dec 20 10:00` | Last modification time |
| `bin` | Name |

#### `cd` — Change Directory

Move to a different directory.

```bash
# Go to the root directory
cd /

# Verify where you are
pwd
```

Output:
```
/
```

**Navigation shortcuts:**

```bash
# Go to your home directory (three equivalent ways)
cd
cd ~
cd /home/yourname

# Go to the previous directory (back)
cd -

# Go up one level (parent directory)
cd ..

# Go up two levels
cd ../..
```

**Practice navigation:**

```bash
# Start in home directory
cd ~
pwd                    # Shows /home/yourname

# Go to /var/log
cd /var/log
pwd                    # Shows /var/log

# List what's here
ls -l

# Go back home
cd ~
pwd                    # Shows /home/yourname
```

### Absolute vs. Relative Paths

**Absolute path**: Starts from root (`/`), always works regardless of current location
```bash
cd /var/log
```

**Relative path**: Starts from current directory
```bash
# If you're in /var
cd log          # Takes you to /var/log

# If you're in /var/log
cd ..           # Takes you to /var
cd ../..        # Takes you to /
```

### The `tree` Command

`tree` shows directory structure visually. It may not be installed by default:

```bash
# Install tree
sudo apt update
sudo apt install tree -y

# Show directory tree (limit depth to 2 levels)
tree -L 2 /home
```

Output:
```
/home
└── yourname

1 directory, 0 files
```

> **Note**: `sudo` runs a command as the superuser (administrator). We'll cover this in detail later.

---

### Milestone 2 Exercises

Complete these exercises to verify your understanding:

#### Exercise 2.1: Exploration

Navigate to each of these directories, list their contents with `ls -l`, and note what you find:

1. `/etc`
2. `/var/log`
3. `/usr/bin`
4. `/tmp`

#### Exercise 2.2: Path Practice

Starting from your home directory:

1. Navigate to `/var/log` using an absolute path
2. Navigate to `/var` using a relative path (from /var/log)
3. Navigate to `/etc` using an absolute path
4. Return home using the `~` shortcut
5. Use `cd -` to go back to `/etc`

#### Exercise 2.3: Hidden Files

1. Go to your home directory
2. Run `ls` — note what you see
3. Run `ls -a` — note the additional files starting with `.`
4. Examine `.bashrc` and `.profile` — these are configuration files

---

### Milestone 2 Checkpoint

Before proceeding, verify:

- [ ] You understand the Linux directory hierarchy
- [ ] You can use `pwd` to display your current location
- [ ] You can use `ls` with various options (-l, -a, -la, -lh)
- [ ] You can navigate using `cd` with absolute and relative paths
- [ ] You understand the difference between absolute and relative paths
- [ ] You can use navigation shortcuts (~, .., -, .)

**[CERT CHECKPOINT - Linux+]**: Filesystem navigation is tested extensively. Know the purpose of standard directories and demonstrate fluent navigation.

---

## Part 4 — File and Directory Operations (Milestone 3)

Now that you can navigate, let's learn to create, copy, move, and remove files and directories.

### Creating Directories

#### `mkdir` — Make Directory

```bash
# Create a single directory
mkdir projects

# Verify it was created
ls -l

# Create nested directories (with -p for "parents")
mkdir -p projects/stage01/exercises

# Verify the structure
tree projects
```

Output:
```
projects
└── stage01
    └── exercises

2 directories, 0 files
```

### Creating Files

#### `touch` — Create Empty Files or Update Timestamps

```bash
# Create an empty file
touch myfile.txt

# Create multiple files at once
touch file1.txt file2.txt file3.txt

# Verify
ls -l
```

#### Creating Files with Content

**Method 1: `echo` with redirection**
```bash
# Create file with one line of content
echo "Hello, this is my first file" > hello.txt

# View the file
cat hello.txt
```

**Method 2: `cat` with redirection**
```bash
# Create file with multiple lines
cat > notes.txt << EOF
This is line 1
This is line 2
This is line 3
EOF

# View the file
cat notes.txt
```

**Method 3: Text editor (nano)**
```bash
# Open nano editor
nano myfile.txt
```

In nano:
- Type your content
- Press `Ctrl + O` to save (Write Out)
- Press `Enter` to confirm filename
- Press `Ctrl + X` to exit

### Viewing File Contents

#### `cat` — Concatenate and Display

```bash
# Display entire file
cat hello.txt

# Display multiple files
cat file1.txt file2.txt

# Display with line numbers
cat -n notes.txt
```

#### `less` — Page Through Files

For longer files, `less` lets you scroll:

```bash
less /var/log/syslog
```

Navigation in `less`:
- **Space** or **Page Down**: Next page
- **b** or **Page Up**: Previous page
- **g**: Go to beginning
- **G**: Go to end
- **/searchterm**: Search forward
- **n**: Next search result
- **q**: Quit

#### `head` and `tail` — View File Beginnings/Endings

```bash
# First 10 lines
head /var/log/syslog

# First 20 lines
head -n 20 /var/log/syslog

# Last 10 lines
tail /var/log/syslog

# Last 20 lines
tail -n 20 /var/log/syslog

# Follow file in real-time (great for monitoring logs!)
tail -f /var/log/syslog
```

Press `Ctrl + C` to stop `tail -f`.

### Copying Files and Directories

#### `cp` — Copy

```bash
# Copy a file
cp hello.txt hello_backup.txt

# Copy a file to a directory
cp hello.txt projects/

# Copy multiple files to a directory
cp file1.txt file2.txt file3.txt projects/

# Copy a directory (requires -r for recursive)
cp -r projects/ projects_backup/

# Copy with verbose output
cp -v hello.txt another_copy.txt
```

### Moving and Renaming

#### `mv` — Move (also used to rename)

```bash
# Rename a file
mv hello.txt greeting.txt

# Move a file to a directory
mv greeting.txt projects/

# Move and rename simultaneously
mv projects/greeting.txt projects/stage01/hello.txt

# Move a directory
mv projects_backup/ old_projects/
```

### Removing Files and Directories

#### `rm` — Remove

> ⚠️ **WARNING**: Linux has no recycle bin. `rm` deletes permanently. Be careful!

```bash
# Remove a file
rm file1.txt

# Remove multiple files
rm file2.txt file3.txt

# Remove with confirmation prompt
rm -i myfile.txt

# Remove a directory (must be empty)
rmdir empty_directory

# Remove a directory and all contents (DANGEROUS!)
rm -r directory_name

# Remove forcefully without prompts (VERY DANGEROUS!)
rm -rf directory_name
```

> **Best Practice**: Always use `rm -i` or at minimum `ls` the files first to verify what you're deleting.

### Practical Exercises: File Operations

#### Exercise 3.1: Create a Project Structure

Create this directory structure:

```
~/security-lab/
├── logs/
├── scripts/
├── reports/
│   ├── daily/
│   └── weekly/
└── README.txt (containing "Security Lab - Created by [your name]")
```

**Solution:**
```bash
cd ~
mkdir -p security-lab/{logs,scripts,reports/{daily,weekly}}
echo "Security Lab - Created by $(whoami)" > security-lab/README.txt
tree security-lab
```

#### Exercise 3.2: File Operations Practice

1. Create a file called `test.txt` with the content "This is a test file"
2. Copy it to `test_backup.txt`
3. Create a directory called `archive`
4. Move `test_backup.txt` into `archive/`
5. Rename `archive/test_backup.txt` to `archive/old_test.txt`
6. Verify with `tree` and `cat`

#### Exercise 3.3: Safe Deletion Practice

1. Create 5 files: `delete1.txt` through `delete5.txt`
2. Create a directory `to_delete` and move all files into it
3. List the contents to verify
4. Remove everything using `rm -ri to_delete` (note the prompts)

---

### Milestone 3 Checkpoint

Before proceeding, verify:

- [ ] You can create directories with `mkdir` (including nested with `-p`)
- [ ] You can create files with `touch`, `echo`, and text editors
- [ ] You can view file contents with `cat`, `less`, `head`, and `tail`
- [ ] You can copy files and directories with `cp` (including `-r`)
- [ ] You can move and rename with `mv`
- [ ] You understand the danger of `rm` and use it carefully

**[CERT CHECKPOINT - Linux+ / CySA+]**: File operations are fundamental to evidence collection, log analysis, and system administration tasks tested on these exams.

---

## Part 5 — Permissions and Ownership (Milestone 4)

Linux permissions are one of the most important security concepts you'll learn. Misconfigurations in permissions are among the most common vulnerabilities in real systems.

### Understanding Permission Notation

When you run `ls -l`, you see permission strings like:

```
-rw-r--r-- 1 yourname yourname 1234 Dec 25 10:00 myfile.txt
drwxr-xr-x 2 yourname yourname 4096 Dec 25 10:00 mydir
```

Let's decode `-rw-r--r--`:

```
-    rw-    r--    r--
│    │      │      │
│    │      │      └── Others (everyone else)
│    │      └───────── Group
│    └──────────────── Owner
└───────────────────── File type (- = file, d = directory, l = link)
```

### Permission Types

| Symbol | Permission | For Files | For Directories |
|--------|-----------|-----------|-----------------|
| `r` | Read | View contents | List contents |
| `w` | Write | Modify contents | Create/delete files in directory |
| `x` | Execute | Run as program | Enter directory (cd into it) |
| `-` | None | No permission | No permission |

### Understanding Permission Groups

| Group | Who | Example |
|-------|-----|---------|
| Owner (u) | The user who owns the file | `yourname` |
| Group (g) | Members of the file's group | `yourname` group |
| Others (o) | Everyone else | Any other user |

### Numeric (Octal) Permissions

Permissions can also be represented as numbers:

| Permission | Value |
|-----------|-------|
| Read (r) | 4 |
| Write (w) | 2 |
| Execute (x) | 1 |
| None (-) | 0 |

Add values together for each group:

| Numeric | Symbolic | Meaning |
|---------|----------|---------|
| 7 | rwx | Read + Write + Execute |
| 6 | rw- | Read + Write |
| 5 | r-x | Read + Execute |
| 4 | r-- | Read only |
| 3 | -wx | Write + Execute |
| 2 | -w- | Write only |
| 1 | --x | Execute only |
| 0 | --- | No permission |

**Examples:**

| Numeric | Symbolic | Meaning |
|---------|----------|---------|
| 755 | rwxr-xr-x | Owner: full; Group & Others: read/execute |
| 644 | rw-r--r-- | Owner: read/write; Group & Others: read |
| 700 | rwx------ | Owner: full; Group & Others: nothing |
| 600 | rw------- | Owner: read/write; Group & Others: nothing |

### Changing Permissions

#### `chmod` — Change Mode

**Symbolic method:**
```bash
# Add execute permission for owner
chmod u+x script.sh

# Remove write permission from group
chmod g-w document.txt

# Set read-only for others
chmod o=r file.txt

# Add read for all (owner, group, others)
chmod a+r file.txt

# Multiple changes at once
chmod u+x,g-w,o-r file.txt
```

**Numeric method:**
```bash
# Set to 755 (rwxr-xr-x)
chmod 755 script.sh

# Set to 644 (rw-r--r--)
chmod 644 document.txt

# Set to 600 (rw-------)
chmod 600 private.txt
```

### Changing Ownership

#### `chown` — Change Owner

```bash
# Change owner
sudo chown newuser file.txt

# Change owner and group
sudo chown newuser:newgroup file.txt

# Change just the group
sudo chown :newgroup file.txt

# Recursive (directory and all contents)
sudo chown -R newuser:newgroup directory/
```

#### `chgrp` — Change Group

```bash
sudo chgrp newgroup file.txt
```

### Special Permissions

There are three special permission bits you should know about:

#### SUID (Set User ID) — 4000

When set on an executable, the program runs with the owner's permissions, not the user who ran it.

```bash
# Find SUID files (security audit!)
find / -perm -4000 -type f 2>/dev/null
```

#### SGID (Set Group ID) — 2000

On executables: runs with group's permissions.
On directories: new files inherit the directory's group.

```bash
# Find SGID files
find / -perm -2000 -type f 2>/dev/null
```

#### Sticky Bit — 1000

On directories: only file owners can delete their own files (used on `/tmp`).

```bash
# Check /tmp permissions
ls -ld /tmp
```

Output:
```
drwxrwxrwt 15 root root 4096 Dec 25 10:00 /tmp
```

The `t` at the end indicates the sticky bit.

### Security Implications of Permissions

| Vulnerability | What It Means | Risk |
|--------------|---------------|------|
| World-writable files | Anyone can modify | Data tampering, malware injection |
| World-readable sensitive files | Anyone can read | Data exposure |
| SUID on shell scripts | Can be exploited for privilege escalation | Critical |
| Weak /etc/shadow permissions | Password hashes exposed | Account compromise |
| World-writable directories | Anyone can create/delete files | File injection, DoS |

### Practical Permission Exercises

#### Exercise 4.1: Permission Practice

1. Create a file called `secret.txt` with content "Classified information"
2. Check its default permissions with `ls -l`
3. Make it readable only by the owner
4. Try to read it as another user (you'll need to create another user first—we'll cover this next)
5. Make it completely inaccessible to group and others

```bash
# Solution
echo "Classified information" > secret.txt
ls -l secret.txt
chmod 600 secret.txt
ls -l secret.txt
```

#### Exercise 4.2: Script Permissions

1. Create a simple script:
```bash
echo '#!/bin/bash' > myscript.sh
echo 'echo "Hello from script!"' >> myscript.sh
```
2. Try to run it: `./myscript.sh` — what happens?
3. Add execute permission: `chmod +x myscript.sh`
4. Run it again: `./myscript.sh`

#### Exercise 4.3: Security Audit (Important!)

Run these commands to find potential permission issues:

```bash
# Find world-writable files (excluding /proc and /sys)
sudo find / -perm -0002 -type f 2>/dev/null | grep -v "^/proc\|^/sys"

# Find SUID executables
sudo find / -perm -4000 -type f 2>/dev/null

# Find files with no owner
sudo find / -nouser -type f 2>/dev/null
```

Document what you find in your `~/security-lab/reports/` directory.

---

### Milestone 4 Checkpoint

Before proceeding, verify:

- [ ] You can read and interpret permission strings (e.g., `rwxr-xr--`)
- [ ] You understand the three permission groups (owner, group, others)
- [ ] You can convert between symbolic and numeric permissions
- [ ] You can use `chmod` to modify permissions (both methods)
- [ ] You can use `chown` and `chgrp` to change ownership
- [ ] You understand the security implications of SUID, SGID, and sticky bit
- [ ] You can perform a basic permission audit

**[CERT CHECKPOINT - Linux+ / Security+ / CySA+]**: Permission management and auditing are heavily tested. Know how to identify and remediate permission vulnerabilities.

---

## Part 6 — Users and Groups (Milestone 5)

Linux is a multi-user operating system. Understanding user and group management is essential for:
- Access control
- Privilege separation
- Security auditing
- Understanding privilege escalation attacks

### Important User-Related Files

| File | Purpose | Can You Read It? |
|------|---------|------------------|
| `/etc/passwd` | User account information | Yes (world-readable) |
| `/etc/shadow` | Password hashes | No (root only) |
| `/etc/group` | Group information | Yes (world-readable) |
| `/etc/gshadow` | Secure group information | No (root only) |

### Understanding /etc/passwd

```bash
cat /etc/passwd
```

Each line follows this format:
```
username:x:UID:GID:comment:home_directory:shell
```

Example:
```
yourname:x:1000:1000:Your Name:/home/yourname:/bin/bash
```

| Field | Meaning |
|-------|---------|
| `yourname` | Username |
| `x` | Password placeholder (actual hash in /etc/shadow) |
| `1000` | User ID (UID) |
| `1000` | Primary Group ID (GID) |
| `Your Name` | Comment (usually full name) |
| `/home/yourname` | Home directory |
| `/bin/bash` | Default shell |

**Important UIDs:**
- `0` = root (superuser)
- `1-999` = System accounts
- `1000+` = Regular users

### Understanding /etc/group

```bash
cat /etc/group
```

Format:
```
groupname:x:GID:members
```

Example:
```
sudo:x:27:yourname
```

### User Management Commands

#### Adding Users

```bash
# Add a user (interactive)
sudo adduser newusername

# Add a user (non-interactive, for scripting)
sudo useradd -m -s /bin/bash newusername
# -m creates home directory
# -s sets the shell
```

#### Setting/Changing Passwords

```bash
# Set password for another user (as root)
sudo passwd newusername

# Change your own password
passwd
```

#### Deleting Users

```bash
# Delete user (keep home directory)
sudo deluser username

# Delete user AND home directory
sudo deluser --remove-home username

# Alternative command
sudo userdel -r username
```

#### Modifying Users

```bash
# Change username
sudo usermod -l newname oldname

# Change home directory
sudo usermod -d /new/home -m username

# Change shell
sudo usermod -s /bin/zsh username

# Lock an account (disable login)
sudo usermod -L username

# Unlock an account
sudo usermod -U username

# Set account expiration
sudo usermod -e 2025-12-31 username
```

### Group Management Commands

#### Creating Groups

```bash
sudo groupadd developers
```

#### Adding Users to Groups

```bash
# Add user to a group (as secondary group)
sudo usermod -aG groupname username
# -a = append (don't remove from other groups)
# -G = groups

# Example: Add yourself to sudo group
sudo usermod -aG sudo yourname
```

#### Viewing Group Membership

```bash
# See your groups
groups

# See another user's groups
groups username

# See who's in a group
getent group groupname
```

### The `sudo` Command

`sudo` (SuperUser DO) allows permitted users to run commands as root.

```bash
# Run a single command as root
sudo command

# Open a root shell (use sparingly!)
sudo -i

# Run command as different user
sudo -u username command
```

**Who can use sudo?**

Check the `/etc/sudoers` file (don't edit directly!):
```bash
sudo cat /etc/sudoers
```

Or use `visudo` to edit it safely:
```bash
sudo visudo
```

Members of the `sudo` group (on Ubuntu) can use sudo for any command.

### The `su` Command

`su` (Switch User) allows you to become another user:

```bash
# Switch to root (requires root password)
su -

# Switch to another user
su - username

# Run single command as another user
su -c "command" username
```

**`su` vs `sudo`:**
- `su` requires the target user's password
- `sudo` requires YOUR password (and you must be in sudoers)
- `sudo` is logged and more auditable
- `sudo` is preferred in modern systems

### Practical User/Group Exercises

#### Exercise 5.1: Create a Test User

1. Create a new user called `testuser`
2. Set a password for `testuser`
3. Verify the user exists in `/etc/passwd`
4. Log in as `testuser` using `su - testuser`
5. Verify you're now `testuser` with `whoami`
6. Exit back to your user with `exit`

```bash
sudo adduser testuser
# Follow prompts to set password
grep testuser /etc/passwd
su - testuser
whoami
exit
```

#### Exercise 5.2: Group Management

1. Create a group called `security`
2. Add yourself and `testuser` to the `security` group
3. Verify group membership
4. Create a shared directory `/home/shared-security`
5. Set group ownership to `security`
6. Set permissions so only group members can access

```bash
sudo groupadd security
sudo usermod -aG security yourname
sudo usermod -aG security testuser
groups yourname
groups testuser
sudo mkdir /home/shared-security
sudo chown :security /home/shared-security
sudo chmod 770 /home/shared-security
ls -ld /home/shared-security
```

#### Exercise 5.3: Security Audit of Users

Create a script that reports:
- All users with UID 0 (should only be root)
- All users with login shells
- All users in the sudo group

```bash
echo "=== Users with UID 0 ==="
awk -F: '$3 == 0 {print $1}' /etc/passwd

echo ""
echo "=== Users with login shells ==="
grep -v "nologin\|false" /etc/passwd | cut -d: -f1,7

echo ""
echo "=== Members of sudo group ==="
getent group sudo
```

Save this to `~/security-lab/scripts/user_audit.sh` and make it executable.

---

### Milestone 5 Checkpoint

Before proceeding, verify:

- [ ] You can read and interpret `/etc/passwd` and `/etc/group`
- [ ] You can create users with `adduser` and `useradd`
- [ ] You can delete users with `deluser` and `userdel`
- [ ] You can create groups and add users to them
- [ ] You understand the difference between `su` and `sudo`
- [ ] You can perform a basic user security audit

**[CERT CHECKPOINT - Linux+ / Security+ / CySA+]**: User and group management is core to access control. Understand privilege separation and how to audit user configurations.

---

## Part 7 — Text Processing and Searching (Milestone 6)

Security analysts spend significant time analyzing logs, configurations, and data. Text processing skills are essential.

### The `grep` Command — Pattern Searching

`grep` searches for patterns in text. It's one of the most used commands in security work.

#### Basic grep Usage

```bash
# Search for "error" in a file
grep "error" /var/log/syslog

# Case-insensitive search
grep -i "error" /var/log/syslog

# Show line numbers
grep -n "error" /var/log/syslog

# Count matches
grep -c "error" /var/log/syslog

# Invert match (show lines that DON'T match)
grep -v "error" /var/log/syslog

# Search recursively in directories
grep -r "password" /etc/

# Show context (lines before/after match)
grep -B 2 -A 2 "error" /var/log/syslog  # 2 before, 2 after
grep -C 3 "error" /var/log/syslog       # 3 before and after
```

#### Regular Expressions with grep

```bash
# Match beginning of line
grep "^Dec" /var/log/syslog

# Match end of line
grep "failed$" /var/log/syslog

# Match any single character
grep "fail.d" /var/log/syslog  # matches "failed", "failad", etc.

# Match zero or more
grep "fail*" /var/log/syslog

# Extended regex (more features)
grep -E "error|warning|critical" /var/log/syslog

# Word boundaries
grep -w "the" file.txt  # matches "the" but not "there"
```

#### Security-Relevant grep Examples

```bash
# Find failed login attempts
grep "Failed password" /var/log/auth.log

# Find sudo usage
grep "sudo" /var/log/auth.log

# Find specific IP addresses
grep -E "192\.168\.[0-9]+\.[0-9]+" /var/log/auth.log

# Find SSH connections
grep "sshd" /var/log/auth.log

# Find potential attacks (brute force indicators)
grep -c "Failed password" /var/log/auth.log
```

### The `find` Command — File Searching

`find` searches for files based on various criteria.

```bash
# Find files by name
find /home -name "*.txt"

# Case-insensitive name search
find /home -iname "*.txt"

# Find files by type
find /var/log -type f  # files only
find /home -type d     # directories only

# Find files by size
find / -size +100M     # larger than 100MB
find / -size -1k       # smaller than 1KB

# Find files by modification time
find /var/log -mtime -1   # modified within last day
find /home -mtime +30     # modified more than 30 days ago

# Find files by permissions
find / -perm 777          # exact match
find / -perm -u+s         # SUID bit set

# Find and execute command
find /tmp -name "*.tmp" -exec rm {} \;
find /var/log -name "*.log" -exec ls -lh {} \;
```

#### Security-Relevant find Examples

```bash
# Find SUID files (potential privilege escalation)
sudo find / -perm -4000 -type f 2>/dev/null

# Find world-writable files
sudo find / -perm -0002 -type f 2>/dev/null

# Find files with no owner
sudo find / -nouser 2>/dev/null

# Find recently modified files (potential indicators of compromise)
sudo find / -mtime -1 -type f 2>/dev/null

# Find hidden files
find /home -name ".*" -type f

# Find large files (potential data exfiltration staging)
find /home -size +50M -type f
```

### Text Manipulation Tools

#### `cut` — Extract Columns

```bash
# Extract first field (delimiter = :)
cut -d: -f1 /etc/passwd

# Extract multiple fields
cut -d: -f1,3,7 /etc/passwd

# Extract by character position
echo "Hello World" | cut -c1-5
```

#### `sort` — Sort Lines

```bash
# Alphabetical sort
sort file.txt

# Numeric sort
sort -n numbers.txt

# Reverse sort
sort -r file.txt

# Sort by specific field
sort -t: -k3 -n /etc/passwd  # sort by UID
```

#### `uniq` — Filter Duplicates

```bash
# Remove adjacent duplicates (requires sorted input)
sort file.txt | uniq

# Count occurrences
sort file.txt | uniq -c

# Show only duplicates
sort file.txt | uniq -d
```

#### `wc` — Word/Line/Character Count

```bash
# Count lines
wc -l file.txt

# Count words
wc -w file.txt

# Count characters
wc -c file.txt

# All counts
wc file.txt
```

#### `awk` — Pattern Processing

`awk` is powerful for processing structured text:

```bash
# Print specific field
awk '{print $1}' file.txt           # first field (space-separated)
awk -F: '{print $1}' /etc/passwd    # first field (colon-separated)

# Print multiple fields
awk -F: '{print $1, $3}' /etc/passwd

# Filter by condition
awk -F: '$3 >= 1000 {print $1}' /etc/passwd  # users with UID >= 1000

# Print with formatting
awk -F: '{printf "User: %-15s UID: %s\n", $1, $3}' /etc/passwd
```

#### `sed` — Stream Editor

`sed` modifies text streams:

```bash
# Replace first occurrence per line
sed 's/old/new/' file.txt

# Replace all occurrences
sed 's/old/new/g' file.txt

# Delete lines matching pattern
sed '/pattern/d' file.txt

# Print only matching lines
sed -n '/pattern/p' file.txt

# In-place editing (careful!)
sed -i 's/old/new/g' file.txt
```

### Practical Text Processing Exercises

#### Exercise 6.1: Log Analysis

Using `/var/log/syslog` (or `/var/log/auth.log` if available):

1. Count total lines
2. Find all unique timestamps (dates)
3. Count occurrences of each service
4. Find any error messages

```bash
# Example approach
wc -l /var/log/syslog
grep -oE "^[A-Z][a-z]+ [0-9]+" /var/log/syslog | sort -u
awk '{print $5}' /var/log/syslog | cut -d: -f1 | sort | uniq -c | sort -rn | head -10
grep -i error /var/log/syslog
```

#### Exercise 6.2: User Analysis

Create a report showing:
1. All user accounts with UID >= 1000 (regular users)
2. All accounts with /bin/bash as their shell
3. All accounts sorted by UID

```bash
echo "=== Regular Users (UID >= 1000) ==="
awk -F: '$3 >= 1000 {print $1, $3}' /etc/passwd

echo ""
echo "=== Accounts with Bash Shell ==="
grep "/bin/bash$" /etc/passwd | cut -d: -f1

echo ""
echo "=== All Accounts Sorted by UID ==="
sort -t: -k3 -n /etc/passwd | awk -F: '{print $3, $1}'
```

#### Exercise 6.3: Security Search

Create a script that searches for:
1. Files containing "password" (case-insensitive) in /etc/
2. World-readable files in /etc/
3. Recently modified configuration files

Save to `~/security-lab/scripts/config_audit.sh`

---

### Milestone 6 Checkpoint

Before proceeding, verify:

- [ ] You can use `grep` with various options and regular expressions
- [ ] You can use `find` to locate files by name, size, permissions, and time
- [ ] You can use `cut`, `sort`, `uniq`, and `wc` for text processing
- [ ] You have basic familiarity with `awk` and `sed`
- [ ] You can combine commands to analyze logs and configurations

**[CERT CHECKPOINT - Linux+ / CySA+]**: Text processing and log analysis are core SOC analyst skills. Grep and find are tested extensively.

---

## Part 8 — Input/Output Redirection and Pipelines (Milestone 7)

Understanding redirection and pipelines transforms you from running single commands to building powerful command chains.

### Standard Streams

Every Linux process has three standard streams:

| Stream | Number | Default | Purpose |
|--------|--------|---------|---------|
| stdin | 0 | Keyboard | Input |
| stdout | 1 | Screen | Normal output |
| stderr | 2 | Screen | Error messages |

### Output Redirection

#### Redirect stdout to a file

```bash
# Overwrite file
ls -l > listing.txt

# Append to file
ls -l >> listing.txt
```

#### Redirect stderr to a file

```bash
# Redirect only errors
find / -name "secret" 2> errors.txt

# Redirect errors to /dev/null (discard)
find / -name "secret" 2>/dev/null
```

#### Redirect both stdout and stderr

```bash
# Both to same file
command > output.txt 2>&1

# Modern syntax (bash)
command &> output.txt

# Separate files
command > stdout.txt 2> stderr.txt
```

### Input Redirection

```bash
# Read input from file
wc -l < /etc/passwd

# Here document (multi-line input)
cat << EOF
Line 1
Line 2
Line 3
EOF

# Here string (single line)
grep "root" <<< "root:x:0:0:root:/root:/bin/bash"
```

### Pipelines

Pipelines (`|`) connect stdout of one command to stdin of another.

```bash
# Simple pipeline
ls -l | head -5

# Multi-stage pipeline
cat /etc/passwd | cut -d: -f1 | sort | head -10

# Common patterns
grep "pattern" file.txt | wc -l          # count matches
ps aux | grep nginx                       # find processes
history | grep "sudo"                     # search history
dmesg | tail -20                          # recent kernel messages
```

### The `tee` Command

`tee` writes to both stdout AND a file (like a T-junction):

```bash
# See output AND save to file
ls -l | tee listing.txt

# Append instead of overwrite
ls -l | tee -a listing.txt

# Use in middle of pipeline
cat /etc/passwd | tee users.txt | wc -l
```

### Command Substitution

Capture command output as input to another command:

```bash
# Using $()
echo "Current user: $(whoami)"
echo "Current date: $(date)"

# Create timestamped filename
cp file.txt "backup_$(date +%Y%m%d).txt"

# Use in conditionals
if [ $(whoami) = "root" ]; then
    echo "You are root"
fi
```

### Practical Pipeline Exercises

#### Exercise 7.1: Log Analysis Pipeline

Create a one-liner that:
1. Reads `/var/log/syslog`
2. Filters for the current month
3. Extracts the service name
4. Counts occurrences of each service
5. Sorts by frequency
6. Shows top 10

```bash
cat /var/log/syslog | grep "^$(date +%b)" | awk '{print $5}' | cut -d: -f1 | sort | uniq -c | sort -rn | head -10
```

#### Exercise 7.2: User Report Pipeline

Create a pipeline that produces a formatted list of regular users:

```bash
cat /etc/passwd | awk -F: '$3 >= 1000 {printf "%-20s UID: %s\n", $1, $3}' | sort
```

#### Exercise 7.3: Security Monitoring Pipeline

Create a command that monitors auth.log for failed login attempts in real-time:

```bash
sudo tail -f /var/log/auth.log | grep --line-buffered "Failed"
```

---

### Milestone 7 Checkpoint

Before proceeding, verify:

- [ ] You understand stdin, stdout, and stderr
- [ ] You can redirect output to files (overwrite and append)
- [ ] You can redirect stderr separately
- [ ] You can build multi-stage pipelines
- [ ] You can use `tee` to capture intermediate output
- [ ] You can use command substitution with `$()`

**[CERT CHECKPOINT - Linux+]**: I/O redirection and pipelines are fundamental to scripting and automation tested on Linux+.

---

## Part 9 — Process Management (Milestone 8)

Understanding running processes is critical for:
- Security monitoring
- Identifying suspicious activity
- Resource management
- Incident response

### Viewing Processes

#### `ps` — Process Status

```bash
# Your processes
ps

# All processes (full format)
ps aux

# All processes (alternative format)
ps -ef

# Process tree
ps auxf
# or
pstree
```

**Understanding `ps aux` output:**

```
USER       PID  %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND
root         1   0.0  0.1 168936 11244 ?        Ss   10:00   0:01 /sbin/init
yourname  1234   0.5  1.2 456789 98765 pts/0    S+   14:30   0:05 vim file.txt
```

| Column | Meaning |
|--------|---------|
| USER | Process owner |
| PID | Process ID |
| %CPU | CPU usage |
| %MEM | Memory usage |
| VSZ | Virtual memory size |
| RSS | Resident memory size |
| TTY | Terminal (? = no terminal) |
| STAT | Process state |
| START | Start time |
| TIME | CPU time used |
| COMMAND | Command that started process |

**Process States (STAT):**
| Code | Meaning |
|------|---------|
| R | Running |
| S | Sleeping (waiting) |
| D | Uninterruptible sleep |
| Z | Zombie |
| T | Stopped |
| + | Foreground process |
| s | Session leader |

#### `top` and `htop` — Interactive Process Viewers

```bash
# Standard top
top

# Install and use htop (better interface)
sudo apt install htop -y
htop
```

**Top keyboard commands:**
- `q` - Quit
- `k` - Kill a process
- `M` - Sort by memory
- `P` - Sort by CPU
- `u` - Filter by user
- `1` - Show individual CPUs

### Managing Processes

#### Signals

Processes communicate via signals. Common ones:

| Signal | Number | Meaning | Action |
|--------|--------|---------|--------|
| SIGTERM | 15 | Terminate | Graceful shutdown |
| SIGKILL | 9 | Kill | Immediate termination |
| SIGSTOP | 19 | Stop | Pause process |
| SIGCONT | 18 | Continue | Resume paused process |
| SIGHUP | 1 | Hang up | Often reload config |

#### `kill` — Send Signals

```bash
# Graceful termination (SIGTERM, default)
kill PID

# Forceful termination (SIGKILL)
kill -9 PID
kill -KILL PID

# Send specific signal
kill -HUP PID  # Reload config

# Kill by name
killall processname
pkill processname

# Kill all processes by user
pkill -u username
```

### Background and Foreground Jobs

```bash
# Run command in background
long_running_command &

# List background jobs
jobs

# Bring job to foreground
fg %1    # job number 1

# Send running process to background
# Press Ctrl+Z first (suspends process)
bg %1    # continue in background

# Keep process running after logout
nohup command &
```

### Finding Specific Processes

```bash
# Find by name
ps aux | grep nginx
pgrep nginx
pgrep -l nginx    # with names

# Find by user
ps -u username

# Find by port
sudo lsof -i :80    # processes using port 80
sudo netstat -tlnp  # listening ports
sudo ss -tlnp       # modern alternative
```

### Security-Relevant Process Analysis

```bash
# Find all LISTENING network services
sudo ss -tlnp

# Find processes with network connections
sudo lsof -i

# Find processes accessing a file
sudo lsof /path/to/file

# Find deleted files still open (potential malware hiding)
sudo lsof | grep deleted

# Find processes running from /tmp (suspicious!)
ps aux | grep '/tmp/'

# Find processes with no TTY (could be backdoors)
ps aux | awk '$7 == "?" {print}'
```

### Practical Process Exercises

#### Exercise 8.1: Process Monitoring

1. Open `top`, identify the top 3 processes by CPU usage
2. Sort by memory usage, note the top 3
3. Filter to show only your processes
4. Identify any zombie processes

#### Exercise 8.2: Background Jobs

1. Start a long-running process: `sleep 300 &`
2. List jobs with `jobs`
3. Bring it to foreground with `fg`
4. Suspend it with `Ctrl+Z`
5. Resume it in background with `bg`
6. Kill it with `kill`

#### Exercise 8.3: Network Process Audit

Create a script that reports:
1. All processes listening on network ports
2. All established network connections
3. Any processes running from unusual locations

```bash
#!/bin/bash
echo "=== Listening Ports ==="
sudo ss -tlnp

echo ""
echo "=== Established Connections ==="
sudo ss -tnp state established

echo ""
echo "=== Processes from /tmp ==="
ps aux | grep '/tmp/' | grep -v grep
```

Save to `~/security-lab/scripts/process_audit.sh`

---

### Milestone 8 Checkpoint

Before proceeding, verify:

- [ ] You can view processes with `ps`, `top`, and `htop`
- [ ] You understand process states and can interpret `ps` output
- [ ] You can kill processes gracefully and forcefully
- [ ] You can manage background and foreground jobs
- [ ] You can find processes by name, user, and port
- [ ] You can identify potentially suspicious processes

**[CERT CHECKPOINT - Linux+ / CySA+]**: Process management and analysis are critical for incident response. Understanding what's running on a system is fundamental to security monitoring.

---

## Part 10 — Basic Shell Scripting (Milestone 9)

Shell scripts automate repetitive tasks. Every security professional needs basic scripting skills.

### Script Basics

#### Creating Your First Script

```bash
#!/bin/bash
# My first script
# This is a comment

echo "Hello, $(whoami)!"
echo "Today is $(date)"
echo "You are in $(pwd)"
```

Save as `first_script.sh`:

```bash
nano first_script.sh
# Paste the content, save with Ctrl+O, exit with Ctrl+X

# Make it executable
chmod +x first_script.sh

# Run it
./first_script.sh
```

#### The Shebang

The first line `#!/bin/bash` tells Linux which interpreter to use.

| Shebang | Interpreter |
|---------|-------------|
| `#!/bin/bash` | Bash shell |
| `#!/bin/sh` | POSIX shell |
| `#!/usr/bin/env python3` | Python 3 |
| `#!/usr/bin/env perl` | Perl |

### Variables

```bash
#!/bin/bash

# Define variables (no spaces around =)
NAME="Security Lab"
VERSION=1.0
TODAY=$(date +%Y-%m-%d)

# Use variables with $
echo "Welcome to $NAME"
echo "Version: $VERSION"
echo "Date: $TODAY"

# Curly braces for clarity
echo "File: ${NAME}_backup.txt"
```

#### Special Variables

| Variable | Meaning |
|----------|---------|
| `$0` | Script name |
| `$1, $2, ...` | Arguments |
| `$#` | Number of arguments |
| `$@` | All arguments |
| `$?` | Exit status of last command |
| `$$` | Current process ID |
| `$USER` | Current username |
| `$HOME` | Home directory |
| `$PWD` | Current directory |

### User Input

```bash
#!/bin/bash

echo "What is your name?"
read NAME

echo "Hello, $NAME!"

# Read with prompt on same line
read -p "Enter your age: " AGE
echo "You are $AGE years old"

# Silent input (for passwords)
read -sp "Enter password: " PASS
echo ""  # New line after hidden input
```

### Conditionals

```bash
#!/bin/bash

# Basic if statement
if [ "$USER" = "root" ]; then
    echo "You are root!"
else
    echo "You are $USER"
fi

# Numeric comparison
AGE=25
if [ $AGE -ge 18 ]; then
    echo "Adult"
else
    echo "Minor"
fi

# File tests
if [ -f "/etc/passwd" ]; then
    echo "passwd file exists"
fi

if [ -d "/home" ]; then
    echo "/home is a directory"
fi

if [ -x "/bin/bash" ]; then
    echo "bash is executable"
fi
```

**Comparison Operators:**

| String | Numeric | File Test | Meaning |
|--------|---------|-----------|---------|
| `=` | `-eq` | | Equal |
| `!=` | `-ne` | | Not equal |
| | `-lt` | | Less than |
| | `-le` | | Less than or equal |
| | `-gt` | | Greater than |
| | `-ge` | | Greater than or equal |
| | | `-f` | Is a file |
| | | `-d` | Is a directory |
| | | `-e` | Exists |
| | | `-r` | Is readable |
| | | `-w` | Is writable |
| | | `-x` | Is executable |

### Loops

#### For Loop

```bash
#!/bin/bash

# Loop through list
for fruit in apple banana cherry; do
    echo "I like $fruit"
done

# Loop through files
for file in *.txt; do
    echo "Found: $file"
done

# Loop through command output
for user in $(cut -d: -f1 /etc/passwd); do
    echo "User: $user"
done

# C-style for loop
for ((i=1; i<=5; i++)); do
    echo "Number: $i"
done
```

#### While Loop

```bash
#!/bin/bash

# Counter loop
COUNT=1
while [ $COUNT -le 5 ]; do
    echo "Count: $COUNT"
    ((COUNT++))
done

# Read file line by line
while read line; do
    echo "Line: $line"
done < /etc/passwd
```

### Functions

```bash
#!/bin/bash

# Define function
greet() {
    echo "Hello, $1!"
}

# Call function
greet "World"
greet "Security"

# Function with return value
is_root() {
    if [ "$(whoami)" = "root" ]; then
        return 0  # success/true
    else
        return 1  # failure/false
    fi
}

# Use return value
if is_root; then
    echo "Running as root"
else
    echo "Not root"
fi
```

### Practical Script: System Information Report

```bash
#!/bin/bash
# system_info.sh - Basic system information report
# Usage: ./system_info.sh

echo "========================================"
echo "       SYSTEM INFORMATION REPORT"
echo "========================================"
echo ""

echo "--- System ---"
echo "Hostname: $(hostname)"
echo "OS: $(cat /etc/os-release | grep PRETTY_NAME | cut -d'"' -f2)"
echo "Kernel: $(uname -r)"
echo "Uptime: $(uptime -p)"
echo ""

echo "--- User ---"
echo "Current User: $(whoami)"
echo "User ID: $(id -u)"
echo "Groups: $(groups)"
echo ""

echo "--- Memory ---"
free -h | head -2
echo ""

echo "--- Disk Usage ---"
df -h | grep "^/dev"
echo ""

echo "--- Network ---"
ip addr show | grep "inet " | grep -v "127.0.0.1"
echo ""

echo "--- Logged In Users ---"
who
echo ""

echo "========================================"
echo "Report generated: $(date)"
echo "========================================"
```

Save this as `~/security-lab/scripts/system_info.sh` and make it executable.

### Practical Script: Security Audit Script

This is your first real security tool:

```bash
#!/bin/bash
# security_audit.sh - Basic security audit script
# Usage: ./security_audit.sh

OUTPUT_DIR="$HOME/security-lab/reports"
REPORT_FILE="$OUTPUT_DIR/audit_$(date +%Y%m%d_%H%M%S).txt"

# Create output directory if needed
mkdir -p "$OUTPUT_DIR"

echo "Security Audit Report" > "$REPORT_FILE"
echo "Generated: $(date)" >> "$REPORT_FILE"
echo "Host: $(hostname)" >> "$REPORT_FILE"
echo "======================================" >> "$REPORT_FILE"
echo "" >> "$REPORT_FILE"

echo "[*] Running security audit..."

# 1. Users with UID 0
echo "=== Users with UID 0 (should only be root) ===" >> "$REPORT_FILE"
awk -F: '$3 == 0 {print $1}' /etc/passwd >> "$REPORT_FILE"
echo "" >> "$REPORT_FILE"

# 2. Users with empty passwords
echo "=== Users with empty passwords ===" >> "$REPORT_FILE"
sudo awk -F: '($2 == "" || $2 == "!") {print $1}' /etc/shadow 2>/dev/null >> "$REPORT_FILE"
echo "" >> "$REPORT_FILE"

# 3. World-writable files in /etc
echo "=== World-writable files in /etc ===" >> "$REPORT_FILE"
find /etc -perm -0002 -type f 2>/dev/null >> "$REPORT_FILE"
echo "" >> "$REPORT_FILE"

# 4. SUID files
echo "=== SUID files ===" >> "$REPORT_FILE"
find / -perm -4000 -type f 2>/dev/null >> "$REPORT_FILE"
echo "" >> "$REPORT_FILE"

# 5. Listening ports
echo "=== Listening network ports ===" >> "$REPORT_FILE"
sudo ss -tlnp 2>/dev/null >> "$REPORT_FILE"
echo "" >> "$REPORT_FILE"

# 6. Failed login attempts (last 24h)
echo "=== Recent failed login attempts ===" >> "$REPORT_FILE"
grep "Failed password" /var/log/auth.log 2>/dev/null | tail -20 >> "$REPORT_FILE"
echo "" >> "$REPORT_FILE"

# 7. Sudo usage
echo "=== Recent sudo usage ===" >> "$REPORT_FILE"
grep "sudo:" /var/log/auth.log 2>/dev/null | tail -20 >> "$REPORT_FILE"
echo "" >> "$REPORT_FILE"

echo "[*] Audit complete: $REPORT_FILE"
```

Save as `~/security-lab/scripts/security_audit.sh` and make executable.

---

### Milestone 9 Checkpoint

Before proceeding, verify:

- [ ] You can create and execute bash scripts
- [ ] You can use variables and capture command output
- [ ] You can read user input
- [ ] You can use if/else conditionals
- [ ] You can use for and while loops
- [ ] You can create and call functions
- [ ] You have created the system_info.sh script
- [ ] You have created the security_audit.sh script

**[CERT CHECKPOINT - Linux+ / PenTest+]**: Scripting is essential for automation and is tested across certifications. Being able to write basic scripts distinguishes you from pure GUI users.

---

## Part 11 — Getting Help (Ongoing Skill)

Professional Linux users know how to find answers independently.

### Man Pages

Every command has a manual:

```bash
man ls
man grep
man chmod
```

**Navigating man pages:**
- Space: Next page
- b: Previous page
- /search: Search forward
- n: Next search result
- q: Quit

**Man page sections:**
| Section | Content |
|---------|---------|
| 1 | User commands |
| 2 | System calls |
| 3 | Library functions |
| 4 | Special files |
| 5 | File formats |
| 6 | Games |
| 7 | Misc |
| 8 | Admin commands |

```bash
# Specify section
man 5 passwd   # passwd file format
man 1 passwd   # passwd command
```

### Other Help Resources

```bash
# Brief description
whatis ls

# Search man pages by keyword
apropos permission
man -k permission

# Command help flag
ls --help
grep --help

# Info pages (more detailed than man)
info coreutils
```

### Online Resources

- **Linux man pages online**: https://man7.org/linux/man-pages/
- **Explain Shell**: https://explainshell.com/ (explains command strings)
- **Stack Overflow**: https://stackoverflow.com/
- **Unix Stack Exchange**: https://unix.stackexchange.com/

---

## Stage 01 Assessment

Before moving to Stage 02, complete this assessment to verify your understanding.

### Written Assessment

Answer these questions (write answers in `~/security-lab/reports/stage01_assessment.txt`):

1. What is the difference between absolute and relative paths? Give an example of each.

2. Explain the permission string `rwxr-x---`. Who can do what?

3. What is the difference between `su` and `sudo`?

4. What does this pipeline do?
   ```bash
   cat /etc/passwd | cut -d: -f1,3 | sort -t: -k2 -n | tail -5
   ```

5. Why are SUID files a security concern?

6. What command would you use to find all files modified in the last 24 hours?

7. Explain stdin, stdout, and stderr.

8. What does `2>/dev/null` do and why would you use it?

### Practical Assessment

Complete these tasks:

1. **Directory Structure**: Create this exact structure under `~/stage01_assessment/`:
   ```
   project/
   ├── src/
   │   ├── main.sh (executable)
   │   └── lib/
   ├── docs/
   │   └── README.txt (contains "Stage 01 Assessment")
   └── logs/
       └── .gitkeep (hidden empty file)
   ```

2. **Permissions**: Set permissions so that:
   - `main.sh` is executable by owner only
   - `docs/` is readable by everyone
   - `logs/` is writable only by owner

3. **Script**: Create `~/stage01_assessment/project/src/main.sh` that:
   - Takes a directory path as an argument
   - Lists all files in that directory
   - Counts and displays the total number of files
   - Reports any world-writable files found

4. **Search**: Create a file `~/stage01_assessment/find_results.txt` containing:
   - All `.conf` files in `/etc/`
   - All executable files in `/usr/bin/` starting with "net"

### Submission

Run your security_audit.sh script and save the output.

Document what you learned in `~/security-lab/reports/stage01_reflection.txt`:
- What was most challenging?
- What was most surprising?
- What do you want to learn more about?

---

## Stage 01 Completion Checklist

Check off each item before moving to Stage 02:

### Lab Environment
- [ ] VirtualBox installed and functioning
- [ ] Ubuntu Server VM created and running
- [ ] Snapshot of clean state created
- [ ] Can log in successfully

### Filesystem Navigation
- [ ] Understand Linux directory hierarchy
- [ ] Fluent with pwd, ls, cd
- [ ] Understand absolute vs relative paths

### File Operations
- [ ] Can create files and directories
- [ ] Can copy, move, and rename files/directories
- [ ] Can safely delete files/directories
- [ ] Can view file contents (cat, less, head, tail)

### Permissions
- [ ] Can read and interpret permission strings
- [ ] Can modify permissions with chmod (both methods)
- [ ] Can change ownership with chown
- [ ] Understand SUID, SGID, sticky bit

### Users and Groups
- [ ] Understand /etc/passwd and /etc/group
- [ ] Can create and delete users
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
- [ ] Can use command substitution

### Process Management
- [ ] Can view and interpret process information
- [ ] Can send signals to processes
- [ ] Can manage background jobs
- [ ] Can identify suspicious processes

### Scripting
- [ ] Can create and execute bash scripts
- [ ] Can use variables, conditionals, loops
- [ ] Have created system_info.sh
- [ ] Have created security_audit.sh

### Assessment
- [ ] Completed written assessment
- [ ] Completed practical assessment
- [ ] Created reflection document

### Git Workflow
- [ ] All scripts committed to repository
- [ ] Stage 01 complete and pushed

---

## Definition of Done

Stage 01 is complete when:

1. All checklist items above are checked
2. You can navigate the Linux filesystem without hesitation
3. You can create, modify, and manage files and permissions
4. You can write basic shell scripts that accomplish security tasks
5. Your security_audit.sh runs successfully and produces useful output
6. Your assessment is complete and documented
7. All work is committed and pushed to your repository

---

## What's Next: Stage 02 Preview

In Stage 02 — Linux System Administration, you will learn:

- Package management (apt, dpkg)
- Service management (systemctl)
- System logging and journald
- Network configuration
- SSH server setup and security
- Cron jobs and task scheduling
- Disk and filesystem management
- Basic system hardening

These skills transform you from a Linux user to a Linux administrator—a critical step before diving into security tools.

---

## Supplementary Resources

### Practice Platforms (Free Tiers)

> **Note**: These are third-party platforms with their own terms of service. They offer free tiers that complement this course but are not required.

- **TryHackMe** (https://tryhackme.com/) — Beginner-friendly "Linux Fundamentals" rooms
- **OverTheWire Bandit** (https://overthewire.org/wargames/bandit/) — Linux CLI practice through challenges
- **Linux Journey** (https://linuxjourney.com/) — Interactive Linux tutorials

### Recommended Reading

- "The Linux Command Line" by William Shotts (free PDF available)
- Linux man pages (always your first reference)
- Ubuntu Server documentation (https://ubuntu.com/server/docs)

---

## Getting Stuck?

If you're struggling:

1. **Re-read the relevant section** — Don't skip ahead
2. **Try the command yourself** — Hands-on practice is essential
3. **Use man pages** — `man command` is always your friend
4. **Check your syntax carefully** — Spaces and quotes matter
5. **Take a break** — Sometimes fresh eyes help
6. **Document your questions** — Write them down for future research

Remember: Every security professional started exactly where you are now. Persistence is more important than speed.

---

**Congratulations on completing Stage 01!** 🎉

You now have the Linux foundation that everything else builds upon. Commit your work, push to your repository, and move on to Stage 02 when ready.

```bash
cd ~/path-to-repo
git add .
git commit -m "Complete Stage 01 - Linux Foundations and CLI Mastery"
git push
```
