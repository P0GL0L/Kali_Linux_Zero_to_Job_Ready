# Stage 03 — Networking Fundamentals for Security
## Understanding How Networks Work and How They're Attacked

**Kali Linux for Cybersecurity Learning Path**  
**Audience:** Learners who have completed Stages 01-02 (no networking experience required)

Welcome to Stage 03. In Stages 01-02, you learned to work with Linux systems. In this stage, you will learn **how computers communicate over networks**. This knowledge is absolutely essential for cybersecurity—you cannot effectively attack or defend systems without understanding the protocols and technologies that connect them.

---

## Prerequisites

Before starting Stage 03, you must have completed Stages 01-02:

- [ ] Comfortable with Linux command line
- [ ] Can manage services with systemctl
- [ ] Can analyze logs with journalctl and grep
- [ ] Can configure basic firewall rules with UFW
- [ ] Have a working Ubuntu Server VM with network connectivity

If any of these are not checked, return to the previous stages first.

---

## Why This Stage Matters

**Every attack and defense happens over a network:**

| Security Activity | Networking Knowledge Required |
|-------------------|------------------------------|
| Port scanning | Understanding TCP/UDP, ports, services |
| Packet capture | Protocol analysis, network layers |
| Web application testing | HTTP protocol, request/response cycle |
| Network reconnaissance | DNS, WHOIS, routing concepts |
| Firewall configuration | Ports, protocols, traffic flow |
| Intrusion detection | Normal vs. abnormal traffic patterns |
| Incident response | Network forensics, traffic analysis |

A security professional without networking knowledge is like a mechanic who doesn't understand how engines work.

---

## What You Will Learn

By the end of this stage, you will be able to:

- Explain how data moves through network layers (OSI and TCP/IP models)
- Understand common protocols and their security implications
- Capture and analyze network traffic
- Perform basic network reconnaissance
- Understand IP addressing and subnetting
- Identify common network attacks and how they work
- Use essential networking tools (Wireshark, tcpdump, netcat, etc.)

---

## What You Will Build

1. **Network reconnaissance toolkit** — Scripts for network discovery
2. **Packet capture analysis** — Documented traffic analysis exercises
3. **Protocol reference guide** — Personal notes on common protocols
4. **Network diagram** — Documentation of your lab network
5. **Traffic analysis report** — Interpretation of captured packets

---

## Certification Alignment

This stage maps to objectives from:

| Certification | Relevant Domains |
|--------------|------------------|
| **CompTIA Network+** | 1.0 Networking Concepts, 5.0 Network Troubleshooting |
| **CompTIA Security+** | 1.0 General Security Concepts, 3.0 Security Architecture |
| **CompTIA CySA+** | 1.0 Security Operations (network analysis) |
| **CompTIA PenTest+** | 2.0 Information Gathering |
| **CEH** | Modules 3-4 (Scanning, Enumeration) |

> **Certification Exam Currency Notice:** Certification objectives are updated periodically. Verify current exam objectives at the vendor's official website before beginning exam preparation. See `docs/CERTIFICATION_MAPPING.md` for detailed alignment information.

---

## Time Estimate

**Total: 30-35 hours**

| Section | Hours |
|---------|-------|
| Network Models (OSI/TCP-IP) | 4-5 |
| IP Addressing and Subnetting | 4-5 |
| Common Network Protocols | 5-6 |
| Network Tools and Commands | 4-5 |
| Packet Capture with tcpdump | 4-5 |
| Wireshark Analysis | 5-6 |
| Network Reconnaissance | 4-5 |
| Stage Assessment | 2-3 |

---

## The Milestones Approach

### Stage 03 Milestones

1. **Understand the OSI and TCP/IP models**
2. **Master IP addressing and subnetting**
3. **Learn common network protocols**
4. **Use essential network commands**
5. **Capture packets with tcpdump**
6. **Analyze traffic with Wireshark**
7. **Perform network reconnaissance**
8. **Complete the stage assessment**

---

## Part 1 — Network Models: How Data Travels (Milestone 1)

### The Problem Networks Solve

Imagine you want to send a letter to a friend in another country. You don't just hand it to them directly—you:

1. Write the message on paper (data)
2. Put it in an envelope with their address (addressing)
3. Give it to the postal service (routing)
4. The postal service moves it through various hubs (transmission)
5. It arrives at their mailbox (delivery)
6. They open and read it (reception)

Computer networks work similarly, but with much more complexity. To manage this complexity, we use **layered models** that break down networking into organized steps.

### Why Layered Models Matter for Security

Understanding network layers helps you:

| Security Task | Layer Knowledge Needed |
|---------------|------------------------|
| Analyze malware traffic | Application layer (HTTP, DNS) |
| Detect ARP spoofing | Data link layer |
| Understand firewall rules | Network/Transport layers (IP, TCP/UDP) |
| Investigate packet captures | All layers |
| Identify protocol attacks | Specific layer understanding |

### The OSI Model (7 Layers)

The **Open Systems Interconnection (OSI)** model is a conceptual framework that describes how data moves through a network. Think of it as the "academic" model—detailed and comprehensive.

**The 7 Layers (top to bottom):**

```
Layer 7: Application    ─┐
Layer 6: Presentation   ─┤ "Upper Layers" (data)
Layer 5: Session        ─┘
Layer 4: Transport      ─┐
Layer 3: Network        ─┤ "Lower Layers" (delivery)
Layer 2: Data Link      ─┤
Layer 1: Physical       ─┘
```

**Memory trick:** "**A**ll **P**eople **S**eem **T**o **N**eed **D**ata **P**rocessing" (top to bottom)

Or bottom to top: "**P**lease **D**o **N**ot **T**hrow **S**ausage **P**izza **A**way"

#### Layer 7: Application Layer

**What it does:** Provides network services directly to user applications.

**Examples:** 
- HTTP/HTTPS (web browsing)
- SMTP/POP3/IMAP (email)
- FTP (file transfer)
- SSH (secure shell)
- DNS (name resolution)

**Security relevance:**
- Web application attacks target this layer (SQL injection, XSS)
- Phishing and malware often use application protocols
- Protocol-specific vulnerabilities (HTTP smuggling, DNS poisoning)

**What you see in Wireshark:** Website content, email data, file transfers

#### Layer 6: Presentation Layer

**What it does:** Translates data between network format and application format. Handles encryption, compression, and data formatting.

**Examples:**
- SSL/TLS encryption
- Data compression
- Character encoding (ASCII, Unicode)
- Image formatting (JPEG, PNG)

**Security relevance:**
- Encryption protects data confidentiality
- Cryptographic attacks target this layer
- Data format vulnerabilities (malformed files)

**What you see in Wireshark:** Encrypted data, encoded content

#### Layer 5: Session Layer

**What it does:** Manages connections (sessions) between applications. Establishes, maintains, and terminates sessions.

**Examples:**
- Session establishment in remote connections
- Authentication handshakes
- Session management in web applications

**Security relevance:**
- Session hijacking attacks
- Authentication vulnerabilities
- Cookie/token manipulation

**What you see in Wireshark:** Session setup/teardown, authentication sequences

#### Layer 4: Transport Layer

**What it does:** Provides end-to-end communication between applications. Ensures reliable (or unreliable) data delivery.

**Protocols:**
- **TCP (Transmission Control Protocol):** Reliable, connection-oriented
- **UDP (User Datagram Protocol):** Fast, connectionless

**Key concepts:**
- **Ports:** Numbers that identify specific applications (HTTP=80, SSH=22)
- **Segments:** Data units at this layer

**Security relevance:**
- Port scanning identifies services
- TCP flags manipulation (SYN flood, RST attacks)
- UDP amplification attacks

**What you see in Wireshark:** Port numbers, TCP flags, sequence numbers

#### Layer 3: Network Layer

**What it does:** Handles logical addressing and routing. Determines how data gets from source to destination across networks.

**Protocols:**
- **IP (Internet Protocol):** Addressing and routing
- **ICMP (Internet Control Message Protocol):** Error messages, ping
- **ARP (Address Resolution Protocol):** Maps IP to MAC addresses

**Key concepts:**
- **IP addresses:** Logical addresses (like 192.168.1.100)
- **Routing:** Path determination
- **Packets:** Data units at this layer

**Security relevance:**
- IP spoofing attacks
- Routing attacks (BGP hijacking)
- ICMP-based reconnaissance (ping sweeps)
- ARP spoofing/poisoning

**What you see in Wireshark:** Source/destination IP addresses, TTL, protocol type

#### Layer 2: Data Link Layer

**What it does:** Provides node-to-node data transfer on the same network segment. Handles physical addressing.

**Components:**
- **MAC addresses:** Physical hardware addresses (like 08:00:27:ab:cd:ef)
- **Switches:** Forward frames based on MAC addresses
- **Frames:** Data units at this layer

**Security relevance:**
- MAC spoofing
- ARP poisoning (actually layer 2/3)
- VLAN hopping
- Switch attacks (CAM table overflow)

**What you see in Wireshark:** Source/destination MAC addresses, frame type

#### Layer 1: Physical Layer

**What it does:** Transmits raw bits over physical media. Deals with cables, signals, voltages.

**Components:**
- Ethernet cables (Cat5e, Cat6)
- Fiber optic cables
- Wireless radio signals
- Network interface cards (NICs)

**Security relevance:**
- Physical access attacks (wiretapping)
- Signal interception
- Jamming attacks (wireless)

**What you see in Wireshark:** Nothing directly—this is below packet capture

### The TCP/IP Model (4 Layers)

The **TCP/IP model** is the practical model used on the Internet. It's simpler and more commonly referenced in real-world work.

```
Layer 4: Application    (OSI 5-7)
Layer 3: Transport      (OSI 4)
Layer 2: Internet       (OSI 3)
Layer 1: Network Access (OSI 1-2)
```

**Comparison:**

| TCP/IP Layer | OSI Layers | Protocols |
|--------------|------------|-----------|
| Application | 5, 6, 7 | HTTP, FTP, SSH, DNS, SMTP |
| Transport | 4 | TCP, UDP |
| Internet | 3 | IP, ICMP, ARP |
| Network Access | 1, 2 | Ethernet, WiFi |

### Data Encapsulation

As data moves down through layers, each layer adds its own **header** (and sometimes trailer). This process is called **encapsulation**.

```
Application Layer:  [DATA]
Transport Layer:    [TCP Header][DATA] = Segment
Internet Layer:     [IP Header][TCP Header][DATA] = Packet
Network Access:     [Eth Header][IP Header][TCP Header][DATA][Eth Trailer] = Frame
```

When data is received, this process reverses (**decapsulation**)—each layer removes its header and passes data up.

**Data units at each layer:**

| Layer | Data Unit Name |
|-------|----------------|
| Application | Data / Message |
| Transport | Segment (TCP) / Datagram (UDP) |
| Internet/Network | Packet |
| Network Access/Data Link | Frame |
| Physical | Bits |

### Practical Exercise: Visualizing Layers

Let's see encapsulation in action using Wireshark (we'll install it shortly):

1. When you browse to a website, your browser creates an HTTP request (Layer 7)
2. The request is wrapped in a TCP segment with port numbers (Layer 4)
3. The segment is wrapped in an IP packet with addresses (Layer 3)
4. The packet is wrapped in an Ethernet frame with MAC addresses (Layer 2)
5. The frame is converted to electrical signals on the cable (Layer 1)

We'll capture this process and examine each layer in Part 6.

### Knowledge Check: Network Models

Answer these questions in `~/security-lab/notes/stage03_notes.txt`:

1. What are the 7 layers of the OSI model (top to bottom)?
2. What layer do port numbers belong to?
3. What's the difference between a packet and a frame?
4. Which layer handles IP addressing?
5. Which layer would you analyze to investigate a web application attack?

---

### Milestone 1 Checkpoint

Before proceeding, verify:

- [ ] You can name all 7 OSI layers in order
- [ ] You understand the 4 TCP/IP layers
- [ ] You know which protocols operate at each layer
- [ ] You understand data encapsulation
- [ ] You know what data units are called at each layer

**[CERT CHECKPOINT - Network+ 1.1 / Security+ 1.0]**: Network models are foundational. Expect questions about layers and protocols.

---

## Part 2 — IP Addressing and Subnetting (Milestone 2)

### What is an IP Address?

An **IP address** is a logical address that identifies a device on a network. Think of it like a street address for computers.

There are two versions:
- **IPv4:** 32-bit addresses (like 192.168.1.100) — still most common
- **IPv6:** 128-bit addresses (like 2001:0db8:85a3::8a2e:0370:7334) — the future

We'll focus primarily on IPv4, as it's what you'll encounter most often in security work.

### IPv4 Address Structure

An IPv4 address consists of 4 numbers (octets) separated by dots:

```
192.168.1.100
 │   │   │  │
 │   │   │  └── Fourth octet (0-255)
 │   │   └───── Third octet (0-255)
 │   └───────── Second octet (0-255)
 └───────────── First octet (0-255)
```

Each octet is 8 bits, so an IPv4 address is 32 bits total.

**Binary representation:**

```
192.168.1.100 in binary:
192     = 11000000
168     = 10101000
1       = 00000001
100     = 01100100

Full: 11000000.10101000.00000001.01100100
```

### Network and Host Portions

Every IP address has two parts:
- **Network portion:** Identifies which network the device is on
- **Host portion:** Identifies the specific device on that network

The **subnet mask** determines where the split occurs.

**Example:**

```
IP Address:    192.168.1.100
Subnet Mask:   255.255.255.0

Network:       192.168.1.0    (first three octets)
Host:          100            (last octet)
```

### Subnet Masks Explained

A subnet mask is a 32-bit number that "masks" the network portion of an IP address.

**Common subnet masks:**

| Mask | CIDR | Network Bits | Host Bits | # of Hosts |
|------|------|--------------|-----------|------------|
| 255.0.0.0 | /8 | 8 | 24 | 16,777,214 |
| 255.255.0.0 | /16 | 16 | 16 | 65,534 |
| 255.255.255.0 | /24 | 24 | 8 | 254 |
| 255.255.255.128 | /25 | 25 | 7 | 126 |
| 255.255.255.192 | /26 | 26 | 6 | 62 |
| 255.255.255.224 | /27 | 27 | 5 | 30 |
| 255.255.255.240 | /28 | 28 | 4 | 14 |
| 255.255.255.248 | /29 | 29 | 3 | 6 |
| 255.255.255.252 | /30 | 30 | 2 | 2 |

**CIDR Notation:** `/24` means "24 bits for network, 8 bits for hosts"

### Calculating Network Addresses

To find the network address, perform a bitwise AND between the IP and subnet mask:

**Example:**
```
IP Address:    192.168.1.100   = 11000000.10101000.00000001.01100100
Subnet Mask:   255.255.255.0   = 11111111.11111111.11111111.00000000
               ─────────────────────────────────────────────────────
Network:       192.168.1.0     = 11000000.10101000.00000001.00000000
```

### Special IP Addresses

| Address Type | Example | Purpose |
|--------------|---------|---------|
| Network address | 192.168.1.0/24 | Identifies the network (not usable by hosts) |
| Broadcast address | 192.168.1.255/24 | Sends to all hosts on network |
| Loopback | 127.0.0.1 | Refers to the local machine |
| Default gateway | (varies) | Router that leads to other networks |

### Private vs. Public IP Addresses

**Private addresses** are used within internal networks and are not routable on the Internet:

| Class | Range | CIDR | Typical Use |
|-------|-------|------|-------------|
| A | 10.0.0.0 – 10.255.255.255 | 10.0.0.0/8 | Large enterprises |
| B | 172.16.0.0 – 172.31.255.255 | 172.16.0.0/12 | Medium networks |
| C | 192.168.0.0 – 192.168.255.255 | 192.168.0.0/16 | Home/small office |

**Public addresses** are globally unique and routable on the Internet.

**Why this matters for security:**
- Private networks are "hidden" behind NAT (Network Address Translation)
- Internal reconnaissance reveals private addresses
- Public addresses are directly attackable from the Internet
- Many attacks exploit the trust between internal systems

### IPv4 Address Classes (Historical)

Originally, IP addresses were divided into classes:

| Class | First Octet | Default Mask | Purpose |
|-------|-------------|--------------|---------|
| A | 1-126 | /8 | Very large networks |
| B | 128-191 | /16 | Large networks |
| C | 192-223 | /24 | Small networks |
| D | 224-239 | N/A | Multicast |
| E | 240-255 | N/A | Experimental |

**Note:** 127.x.x.x is reserved for loopback (127.0.0.1 = localhost)

Modern networks use **CIDR (Classless Inter-Domain Routing)** instead of rigid classes.

### Subnetting Basics

**Subnetting** divides a network into smaller subnetworks. This:
- Improves network organization
- Enhances security (isolation)
- Reduces broadcast traffic
- Allows efficient IP address allocation

**Example: Subnetting a /24 into four /26 networks:**

Original: 192.168.1.0/24 (254 hosts)

After subnetting:
```
192.168.1.0/26    (hosts: .1 - .62,   broadcast: .63)
192.168.1.64/26   (hosts: .65 - .126, broadcast: .127)
192.168.1.128/26  (hosts: .129 - .190, broadcast: .191)
192.168.1.192/26  (hosts: .193 - .254, broadcast: .255)
```

Each subnet now has 62 usable hosts instead of 254.

### Quick Subnet Calculation Method

For /24 and larger, use this shortcut:

1. Subtract the CIDR from 32: `32 - CIDR = host bits`
2. Calculate hosts: `2^(host bits) - 2` (subtract 2 for network and broadcast)
3. Calculate subnets: `2^(borrowed bits)`

**Example: /27**
- Host bits: 32 - 27 = 5
- Hosts per subnet: 2^5 - 2 = 30
- Subnet increment: 2^5 = 32 (subnets at .0, .32, .64, .96, .128, etc.)

### Practical Exercise: IP and Subnet Calculation

#### Exercise 2.1: Identify Network Information

For the IP address 172.16.50.100/22:

1. What is the subnet mask in dotted decimal?
2. What is the network address?
3. What is the broadcast address?
4. What is the range of usable host addresses?
5. How many usable hosts are possible?

**Solution:**

```bash
# Install ipcalc for easy calculation
sudo apt install ipcalc

# Calculate
ipcalc 172.16.50.100/22
```

**Manual calculation:**

1. /22 mask = 255.255.252.0
2. Network: 172.16.48.0
3. Broadcast: 172.16.51.255
4. Usable range: 172.16.48.1 - 172.16.51.254
5. Usable hosts: 2^10 - 2 = 1022

#### Exercise 2.2: Subnet Planning

Your organization has the network 10.10.0.0/16 and needs to create subnets for:
- Engineering: 500 hosts
- Sales: 100 hosts
- IT: 25 hosts
- Guest WiFi: 50 hosts

Calculate appropriate subnet sizes for each department.

**Approach:**

| Department | Hosts Needed | Host Bits | Subnet | Hosts Available |
|------------|--------------|-----------|--------|-----------------|
| Engineering | 500 | 9 (2^9=512) | /23 | 510 |
| Sales | 100 | 7 (2^7=128) | /25 | 126 |
| Guest WiFi | 50 | 6 (2^6=64) | /26 | 62 |
| IT | 25 | 5 (2^5=32) | /27 | 30 |

### Viewing Network Configuration on Linux

```bash
# Show IP addresses
ip addr show

# Show only IPv4 addresses
ip -4 addr show

# Show routing table
ip route show

# Show ARP cache (IP to MAC mappings)
ip neigh show

# Using older tools
ifconfig        # Requires net-tools package
route -n        # Show routing table
arp -a          # Show ARP cache
```

### Create a Network Documentation Script

```bash
#!/bin/bash
# network_doc.sh - Document network configuration

OUTPUT="$HOME/security-lab/reports/network_config_$(date +%Y%m%d).txt"

echo "Network Configuration Report" > "$OUTPUT"
echo "Generated: $(date)" >> "$OUTPUT"
echo "Hostname: $(hostname)" >> "$OUTPUT"
echo "========================================" >> "$OUTPUT"
echo "" >> "$OUTPUT"

echo "=== IP Addresses ===" >> "$OUTPUT"
ip -4 addr show >> "$OUTPUT"
echo "" >> "$OUTPUT"

echo "=== Default Gateway ===" >> "$OUTPUT"
ip route show default >> "$OUTPUT"
echo "" >> "$OUTPUT"

echo "=== Full Routing Table ===" >> "$OUTPUT"
ip route show >> "$OUTPUT"
echo "" >> "$OUTPUT"

echo "=== DNS Servers ===" >> "$OUTPUT"
cat /etc/resolv.conf | grep nameserver >> "$OUTPUT"
echo "" >> "$OUTPUT"

echo "=== ARP Cache ===" >> "$OUTPUT"
ip neigh show >> "$OUTPUT"
echo "" >> "$OUTPUT"

echo "=== Network Interfaces (Detailed) ===" >> "$OUTPUT"
ip -s link show >> "$OUTPUT"

echo "Report saved to: $OUTPUT"
cat "$OUTPUT"
```

Save to `~/security-lab/scripts/network_doc.sh`.

---

### Milestone 2 Checkpoint

Before proceeding, verify:

- [ ] You understand the structure of IPv4 addresses
- [ ] You can identify network and host portions using subnet masks
- [ ] You know the private IP address ranges
- [ ] You can perform basic subnet calculations
- [ ] You can use ipcalc or calculate manually
- [ ] You can view network configuration on Linux

**[CERT CHECKPOINT - Network+ 1.4 / Security+]**: IP addressing and subnetting are heavily tested. Practice calculations until they're second nature.

---

## Part 3 — Common Network Protocols (Milestone 3)

Understanding protocols is critical for security work. Each protocol has its own characteristics, ports, and potential vulnerabilities.

### Protocol Reference Format

For each protocol, we'll cover:
- **What it does**
- **How it works (briefly)**
- **Default port(s)**
- **Security considerations**
- **What to look for in packet captures**

---

### TCP vs. UDP: The Transport Layer Protocols

Before diving into application protocols, understand the two main transport protocols:

#### TCP (Transmission Control Protocol)

**Characteristics:**
- **Connection-oriented:** Establishes connection before sending data
- **Reliable:** Guarantees delivery, order, and error-checking
- **Slower:** Has overhead for reliability features

**The TCP Three-Way Handshake:**

```
Client                          Server
   |                               |
   |  ──── SYN ──────────────────► |  "I want to connect"
   |                               |
   |  ◄──── SYN-ACK ────────────── |  "OK, I acknowledge"
   |                               |
   |  ──── ACK ──────────────────► |  "Connection established"
   |                               |
   |  ◄════ DATA TRANSFER ════════►|
   |                               |
   |  ──── FIN ──────────────────► |  "I'm done"
   |  ◄──── ACK ────────────────── |
   |  ◄──── FIN ────────────────── |
   |  ──── ACK ──────────────────► |  "Connection closed"
```

**TCP Flags (important for security):**

| Flag | Name | Purpose |
|------|------|---------|
| SYN | Synchronize | Initiate connection |
| ACK | Acknowledge | Confirm receipt |
| FIN | Finish | Close connection |
| RST | Reset | Abort connection |
| PSH | Push | Send data immediately |
| URG | Urgent | Priority data |

**Security relevance:**
- SYN flood attacks exploit the handshake
- RST attacks can terminate connections
- TCP flags are used in port scanning techniques
- Sequence number prediction enables session hijacking

#### UDP (User Datagram Protocol)

**Characteristics:**
- **Connectionless:** No handshake, just sends data
- **Unreliable:** No guarantee of delivery or order
- **Fast:** Minimal overhead

**Used for:**
- DNS queries (quick lookups)
- Streaming media (speed over reliability)
- Gaming (real-time updates)
- VoIP (voice calls)

**Security relevance:**
- UDP amplification attacks (DNS, NTP, SSDP)
- Easy to spoof source IP (no handshake to verify)
- Often overlooked in firewall rules

---

### Application Layer Protocols

#### HTTP/HTTPS (Web Traffic)

**What it does:** Transfers web pages and web application data.

**Ports:**
- HTTP: TCP 80
- HTTPS: TCP 443

**How it works:**
1. Client sends HTTP request (GET, POST, etc.)
2. Server processes request
3. Server sends HTTP response with status code and content

**HTTP Methods:**

| Method | Purpose | Security Concern |
|--------|---------|------------------|
| GET | Retrieve data | Parameters visible in URL/logs |
| POST | Submit data | Hidden in body, but not encrypted (HTTP) |
| PUT | Upload/replace | Can overwrite files if misconfigured |
| DELETE | Remove resource | Dangerous if exposed |
| HEAD | Get headers only | Information disclosure |
| OPTIONS | List allowed methods | Reveals attack surface |

**HTTP Status Codes:**

| Code Range | Meaning | Example |
|------------|---------|---------|
| 1xx | Informational | 100 Continue |
| 2xx | Success | 200 OK, 201 Created |
| 3xx | Redirect | 301 Moved, 302 Found |
| 4xx | Client Error | 400 Bad Request, 403 Forbidden, 404 Not Found |
| 5xx | Server Error | 500 Internal Error, 503 Service Unavailable |

**Security considerations:**
- HTTP transmits data in cleartext (no encryption)
- HTTPS encrypts with TLS but doesn't prevent application attacks
- Look for: SQL injection, XSS, sensitive data in URLs
- Headers reveal server information (Server, X-Powered-By)

**In packet captures, look for:**
```
GET /login.php?user=admin HTTP/1.1
Host: target.com
User-Agent: Mozilla/5.0...
Cookie: session=abc123...
```

---

#### DNS (Domain Name System)

**What it does:** Translates domain names (google.com) to IP addresses (142.250.80.46).

**Ports:**
- UDP 53 (most queries)
- TCP 53 (zone transfers, large responses)

**How it works (simplified):**

```
1. You type "google.com" in browser
2. Your computer asks DNS resolver "What's the IP for google.com?"
3. Resolver may ask root servers → TLD servers → authoritative servers
4. Answer returns: "google.com is 142.250.80.46"
5. Browser connects to that IP
```

**DNS Record Types:**

| Type | Purpose | Example |
|------|---------|---------|
| A | IPv4 address | google.com → 142.250.80.46 |
| AAAA | IPv6 address | google.com → 2607:f8b0:4004:... |
| MX | Mail server | google.com → mail.google.com |
| NS | Name server | google.com → ns1.google.com |
| CNAME | Alias | www.google.com → google.com |
| TXT | Text data | Often used for verification |
| PTR | Reverse lookup | IP → domain name |
| SOA | Zone authority | Administrative info |

**Security considerations:**
- DNS queries are usually unencrypted (DNS over HTTPS/TLS changing this)
- DNS poisoning/spoofing redirects users to malicious sites
- DNS tunneling exfiltrates data
- Zone transfers can leak internal hostnames

**DNS reconnaissance commands:**

```bash
# Basic lookup
nslookup google.com
dig google.com

# Specific record types
dig google.com MX
dig google.com NS
dig google.com TXT

# Reverse lookup
dig -x 8.8.8.8

# Attempt zone transfer (usually blocked)
dig axfr @ns1.example.com example.com
```

---

#### SSH (Secure Shell)

**What it does:** Provides encrypted remote access and file transfer.

**Port:** TCP 22

**How it works:**
1. Client initiates TCP connection to port 22
2. Server sends its public key
3. Client verifies key (or trusts on first connection)
4. Encrypted session established (key exchange)
5. User authenticates (password or key)
6. Secure shell access granted

**Security considerations:**
- SSH is secure if configured properly
- Password authentication vulnerable to brute force
- Key-based auth much stronger
- SSH version 1 is broken (ensure version 2)
- Keep SSH software updated

**What attackers target:**
- Weak passwords
- Default credentials
- Known vulnerabilities (specific versions)
- SSH key files left on compromised systems

---

#### FTP (File Transfer Protocol)

**What it does:** Transfers files between systems.

**Ports:**
- TCP 21 (control connection)
- TCP 20 (data connection - active mode)
- High ports (data connection - passive mode)

**Security considerations:**
- **FTP transmits everything in cleartext including passwords!**
- Anonymous FTP can expose sensitive files
- Active FTP has issues with firewalls
- Use SFTP (SSH) or FTPS (FTP over TLS) instead

**In packet captures:**
```
USER administrator
PASS password123     ← Password visible in cleartext!
```

---

#### SMTP/POP3/IMAP (Email)

**What they do:**
- **SMTP:** Sends email (TCP 25, 587, 465)
- **POP3:** Retrieves email, downloads to client (TCP 110, 995)
- **IMAP:** Retrieves email, keeps on server (TCP 143, 993)

**Security considerations:**
- Email often unencrypted (especially internal)
- Email spoofing is trivial without SPF/DKIM/DMARC
- Phishing is the #1 attack vector
- Email headers reveal routing information

**Email header analysis:**

```
Received: from mail.attacker.com (192.168.1.100)
    by target.com (192.168.1.50)
From: ceo@legitimate-company.com    ← Can be forged!
To: employee@target.com
Subject: Urgent Wire Transfer
```

---

#### DHCP (Dynamic Host Configuration Protocol)

**What it does:** Automatically assigns IP addresses and network configuration.

**Ports:** UDP 67 (server), UDP 68 (client)

**How it works (DORA):**

```
1. DISCOVER: Client broadcasts "I need an IP"
2. OFFER: Server offers an IP address
3. REQUEST: Client requests the offered IP
4. ACKNOWLEDGE: Server confirms the assignment
```

**Security considerations:**
- Rogue DHCP servers can MitM entire networks
- DHCP starvation exhausts available addresses
- DHCP can assign malicious DNS servers/gateways
- No authentication by default

---

#### ARP (Address Resolution Protocol)

**What it does:** Maps IP addresses to MAC addresses on local network.

**Layer:** Network/Data Link (Layer 2-3)

**How it works:**
```
1. Computer A wants to send to 192.168.1.50
2. A broadcasts: "Who has 192.168.1.50? Tell 192.168.1.100"
3. B (192.168.1.50) replies: "I have it, my MAC is XX:XX:XX:XX:XX:XX"
4. A caches this mapping and sends directly to that MAC
```

**Security considerations:**
- **ARP has no authentication**
- ARP spoofing/poisoning is trivial
- Attacker can claim any IP address
- Enables man-in-the-middle attacks
- Defense: Static ARP entries, dynamic ARP inspection (switches)

**View ARP cache:**
```bash
ip neigh show
# or
arp -a
```

---

#### ICMP (Internet Control Message Protocol)

**What it does:** Sends error messages and operational information.

**Layer:** Network (Layer 3)

**Common ICMP types:**

| Type | Code | Description |
|------|------|-------------|
| 0 | 0 | Echo Reply (ping response) |
| 3 | 0 | Destination Unreachable: Network |
| 3 | 1 | Destination Unreachable: Host |
| 3 | 3 | Destination Unreachable: Port |
| 8 | 0 | Echo Request (ping) |
| 11 | 0 | Time Exceeded (traceroute) |

**Security considerations:**
- Ping sweeps for host discovery
- Traceroute for network mapping
- ICMP tunneling for covert channels
- ICMP flood attacks (ping of death)
- Many networks block ICMP at the firewall

**ICMP tools:**
```bash
ping -c 4 target.com
traceroute target.com
```

---

### Protocol Summary Table

| Protocol | Port(s) | Transport | Encrypted | Security Risk |
|----------|---------|-----------|-----------|---------------|
| HTTP | 80 | TCP | No | High |
| HTTPS | 443 | TCP | Yes | Medium |
| SSH | 22 | TCP | Yes | Low (if configured) |
| FTP | 21, 20 | TCP | No | High |
| FTPS | 990 | TCP | Yes | Low |
| SFTP | 22 | TCP | Yes | Low |
| Telnet | 23 | TCP | No | Critical |
| SMTP | 25, 587 | TCP | Sometimes | Medium-High |
| POP3 | 110 | TCP | No | High |
| POP3S | 995 | TCP | Yes | Low |
| IMAP | 143 | TCP | No | High |
| IMAPS | 993 | TCP | Yes | Low |
| DNS | 53 | UDP/TCP | No | Medium |
| DHCP | 67, 68 | UDP | No | Medium |
| SNMP | 161, 162 | UDP | No | High |
| RDP | 3389 | TCP | Partial | High |
| MySQL | 3306 | TCP | Optional | High |
| SMB | 445 | TCP | Optional | High |

---

### Practical Exercise: Protocol Identification

#### Exercise 3.1: Port to Protocol Matching

For each port, identify the protocol and whether it's typically encrypted:

1. TCP 22
2. TCP 80
3. TCP 443
4. UDP 53
5. TCP 21
6. TCP 25
7. TCP 3389
8. TCP 445
9. UDP 161
10. TCP 3306

#### Exercise 3.2: Protocol Analysis Script

Create a script that checks which common services are listening:

```bash
#!/bin/bash
# service_detector.sh - Detect common services on target

TARGET="${1:-127.0.0.1}"

echo "=== Service Detection for $TARGET ==="
echo ""

declare -A ports
ports=(
    [21]="FTP"
    [22]="SSH"
    [23]="Telnet"
    [25]="SMTP"
    [53]="DNS"
    [80]="HTTP"
    [110]="POP3"
    [143]="IMAP"
    [443]="HTTPS"
    [445]="SMB"
    [3306]="MySQL"
    [3389]="RDP"
)

for port in "${!ports[@]}"; do
    timeout 1 bash -c "echo >/dev/tcp/$TARGET/$port" 2>/dev/null
    if [ $? -eq 0 ]; then
        echo "[OPEN] Port $port - ${ports[$port]}"
    fi
done
```

Save to `~/security-lab/scripts/service_detector.sh`.

---

### Milestone 3 Checkpoint

Before proceeding, verify:

- [ ] You understand the difference between TCP and UDP
- [ ] You can explain the TCP three-way handshake
- [ ] You know common protocols and their default ports
- [ ] You understand security implications of each protocol
- [ ] You can identify which protocols transmit data in cleartext

**[CERT CHECKPOINT - Network+ 1.5 / Security+ / CEH]**: Protocol knowledge is essential. Know ports, behaviors, and security risks.

---

## Part 4 — Essential Network Commands and Tools (Milestone 4)

### Network Diagnostic Commands

Every security professional needs these commands at their fingertips.

#### ip (Network Configuration)

The `ip` command is the modern replacement for `ifconfig`, `route`, and `arp`.

```bash
# Show all interfaces and addresses
ip addr show
ip a                    # Shorthand

# Show only IPv4
ip -4 addr show

# Show specific interface
ip addr show eth0

# Show routing table
ip route show
ip r                    # Shorthand

# Show ARP/neighbor cache
ip neigh show
ip n                    # Shorthand

# Show link information
ip link show
ip l                    # Shorthand

# Show network statistics
ip -s link show
```

#### ping (ICMP Echo)

Tests basic connectivity to a host.

```bash
# Ping 4 times
ping -c 4 google.com

# Continuous ping (Ctrl+C to stop)
ping google.com

# Set interval between pings (1 = 1 second, 0.2 = 200ms)
ping -i 0.2 google.com

# Specify packet size
ping -s 1000 google.com

# Flood ping (requires root, use carefully)
sudo ping -f google.com
```

**Security notes:**
- Many hosts block ICMP, so no response doesn't mean host is down
- Ping can be used for host discovery (ping sweeps)
- Flood ping can be used for DoS

#### traceroute/tracepath (Route Discovery)

Shows the path packets take to reach a destination.

```bash
# Basic traceroute
traceroute google.com

# Alternative (usually pre-installed)
tracepath google.com

# TCP traceroute (useful when ICMP is blocked)
sudo traceroute -T google.com

# Limit hops
traceroute -m 15 google.com
```

**Understanding output:**
```
 1  router.home (192.168.1.1)  1.234 ms  1.456 ms  1.567 ms
 2  isp-gateway (10.0.0.1)  5.678 ms  5.789 ms  5.890 ms
 3  * * *                                              ← No response (filtered)
 4  backbone.isp.net (203.0.113.1)  15.123 ms  15.234 ms  15.345 ms
```

Each line shows:
- Hop number
- Router name/IP
- Three round-trip times (TTL exceeded responses)

#### ss (Socket Statistics)

Modern replacement for `netstat`. Shows network connections.

```bash
# Show all listening TCP ports
ss -tln

# Show all listening UDP ports
ss -uln

# Show all listening ports with process names
sudo ss -tlnp

# Show all established connections
ss -t state established

# Show connections to specific port
ss -t '( dport = :443 )'

# Show socket memory usage
ss -m
```

**Flag meanings:**
- `-t` — TCP
- `-u` — UDP
- `-l` — Listening
- `-n` — Numeric (don't resolve names)
- `-p` — Show process using socket
- `-a` — All sockets

#### netstat (Legacy but Still Useful)

```bash
# Install if not present
sudo apt install net-tools

# Show all listening ports with programs
sudo netstat -tlnp
sudo netstat -ulnp

# Show all connections
netstat -an

# Show routing table
netstat -r

# Show interface statistics
netstat -i
```

#### dig/nslookup (DNS Queries)

```bash
# Basic DNS lookup
dig google.com
nslookup google.com

# Specific record types
dig google.com MX
dig google.com NS
dig google.com AAAA

# Use specific DNS server
dig @8.8.8.8 google.com

# Short output
dig +short google.com

# Reverse DNS lookup
dig -x 8.8.8.8

# Trace DNS resolution
dig +trace google.com
```

#### host (Simple DNS Lookup)

```bash
# Basic lookup
host google.com

# Reverse lookup
host 8.8.8.8

# Find mail servers
host -t MX google.com
```

#### whois (Domain Registration Info)

```bash
# Install whois
sudo apt install whois

# Query domain information
whois google.com

# Query IP information
whois 8.8.8.8
```

**Security use:** Find domain owner, registration dates, name servers, and sometimes contact information.

#### curl/wget (HTTP Clients)

```bash
# Fetch web page
curl http://example.com
wget http://example.com

# Show only headers
curl -I http://example.com

# Follow redirects
curl -L http://example.com

# Verbose output (shows connection details)
curl -v http://example.com

# Save output to file
curl -o output.html http://example.com
wget -O output.html http://example.com

# Send POST request
curl -X POST -d "user=admin&pass=test" http://example.com/login

# Custom headers
curl -H "User-Agent: CustomAgent" http://example.com
```

#### nc/netcat (Network Swiss Army Knife)

Netcat is incredibly versatile—reading, writing, and manipulating network connections.

```bash
# Install
sudo apt install netcat-openbsd

# Test if port is open
nc -zv target.com 80

# Scan port range
nc -zv target.com 20-25

# Connect to port and interact
nc target.com 80

# Listen on a port
nc -l 4444

# Transfer file (receiver)
nc -l 4444 > received_file

# Transfer file (sender)
nc target.com 4444 < file_to_send

# Simple chat (server)
nc -l 4444

# Simple chat (client)
nc server.com 4444

# Banner grabbing
echo "" | nc -v target.com 22
```

**Security uses:**
- Port scanning
- Banner grabbing
- File transfer (during penetration tests)
- Reverse shells (we'll cover this later)
- Testing firewall rules

### Create a Network Toolkit Script

```bash
#!/bin/bash
# network_toolkit.sh - Network reconnaissance toolkit

TARGET="${1:-}"

if [ -z "$TARGET" ]; then
    echo "Usage: $0 <target>"
    exit 1
fi

OUTPUT="$HOME/security-lab/reports/recon_${TARGET}_$(date +%Y%m%d_%H%M%S).txt"

echo "Network Reconnaissance Report" > "$OUTPUT"
echo "Target: $TARGET" >> "$OUTPUT"
echo "Generated: $(date)" >> "$OUTPUT"
echo "========================================" >> "$OUTPUT"
echo "" >> "$OUTPUT"

echo "[*] Running reconnaissance on $TARGET..."

echo "=== Ping Test ===" >> "$OUTPUT"
ping -c 4 "$TARGET" >> "$OUTPUT" 2>&1
echo "" >> "$OUTPUT"

echo "=== DNS Lookup ===" >> "$OUTPUT"
dig +short "$TARGET" >> "$OUTPUT" 2>&1
dig "$TARGET" ANY +noall +answer >> "$OUTPUT" 2>&1
echo "" >> "$OUTPUT"

echo "=== Traceroute ===" >> "$OUTPUT"
tracepath -m 20 "$TARGET" >> "$OUTPUT" 2>&1
echo "" >> "$OUTPUT"

echo "=== WHOIS ===" >> "$OUTPUT"
whois "$TARGET" 2>/dev/null | head -50 >> "$OUTPUT"
echo "" >> "$OUTPUT"

echo "=== Quick Port Check (common ports) ===" >> "$OUTPUT"
for port in 21 22 23 25 53 80 110 143 443 445 3306 3389; do
    timeout 1 bash -c "echo >/dev/tcp/$TARGET/$port" 2>/dev/null
    if [ $? -eq 0 ]; then
        echo "  Port $port: OPEN" >> "$OUTPUT"
    fi
done 2>/dev/null
echo "" >> "$OUTPUT"

echo "[*] Report saved to: $OUTPUT"
```

Save to `~/security-lab/scripts/network_toolkit.sh`.

---

### Milestone 4 Checkpoint

Before proceeding, verify:

- [ ] You can use ip, ping, traceroute, ss, netstat
- [ ] You can perform DNS lookups with dig/nslookup
- [ ] You can use curl/wget for HTTP requests
- [ ] You understand what netcat can do
- [ ] You have created the network_toolkit.sh script

**[CERT CHECKPOINT - Network+ 5.0 / Linux+]**: Know these troubleshooting commands cold. They're tested and used daily.

---

## Part 5 — Packet Capture with tcpdump (Milestone 5)

### What is Packet Capture?

**Packet capture** (also called "sniffing" or "packet analysis") is the process of intercepting and logging network traffic. It's essential for:

- Troubleshooting network issues
- Security monitoring and incident response
- Protocol analysis
- Penetration testing reconnaissance
- Malware analysis

### Introduction to tcpdump

`tcpdump` is the command-line packet capture tool. It's lightweight, powerful, and available on almost every Unix system.

#### Installing tcpdump

```bash
sudo apt install tcpdump
```

#### Basic Usage

```bash
# Capture all traffic on default interface (requires root)
sudo tcpdump

# Capture on specific interface
sudo tcpdump -i eth0

# List available interfaces
tcpdump -D

# Capture with verbose output
sudo tcpdump -v
sudo tcpdump -vv      # More verbose
sudo tcpdump -vvv     # Maximum verbosity

# Limit number of packets
sudo tcpdump -c 10    # Capture only 10 packets

# Don't resolve hostnames (faster, shows IPs)
sudo tcpdump -n

# Don't resolve ports to service names
sudo tcpdump -nn

# Show packet contents in hex and ASCII
sudo tcpdump -X

# Show packet contents in hex only
sudo tcpdump -x
```

#### Writing and Reading Capture Files

```bash
# Save capture to file (PCAP format)
sudo tcpdump -w capture.pcap

# Read from capture file
tcpdump -r capture.pcap

# Save with limited packets
sudo tcpdump -c 100 -w capture.pcap

# Save specific traffic only
sudo tcpdump -w ssh_traffic.pcap port 22
```

**Important:** PCAP files can be opened in Wireshark for detailed analysis.

### tcpdump Filters

Filters are how you capture only the traffic you're interested in.

#### Filter by Host

```bash
# Traffic to/from specific host
sudo tcpdump host 192.168.1.100

# Traffic from specific host (source)
sudo tcpdump src host 192.168.1.100

# Traffic to specific host (destination)
sudo tcpdump dst host 192.168.1.100
```

#### Filter by Network

```bash
# Traffic on a network
sudo tcpdump net 192.168.1.0/24

# Source network
sudo tcpdump src net 10.0.0.0/8
```

#### Filter by Port

```bash
# Traffic on specific port
sudo tcpdump port 80

# Source port
sudo tcpdump src port 443

# Destination port
sudo tcpdump dst port 22

# Port range
sudo tcpdump portrange 20-25
```

#### Filter by Protocol

```bash
# TCP only
sudo tcpdump tcp

# UDP only
sudo tcpdump udp

# ICMP only
sudo tcpdump icmp

# ARP only
sudo tcpdump arp
```

#### Combining Filters

Use `and`, `or`, `not` (or `&&`, `||`, `!`):

```bash
# HTTP traffic to specific host
sudo tcpdump tcp port 80 and host 192.168.1.100

# SSH or HTTPS
sudo tcpdump port 22 or port 443

# Everything except SSH
sudo tcpdump not port 22

# Complex filter
sudo tcpdump 'tcp port 80 and (host 192.168.1.100 or host 192.168.1.101)'
```

#### Filter by TCP Flags

```bash
# SYN packets only
sudo tcpdump 'tcp[tcpflags] & tcp-syn != 0'

# SYN-ACK packets
sudo tcpdump 'tcp[tcpflags] & (tcp-syn|tcp-ack) == (tcp-syn|tcp-ack)'

# RST packets
sudo tcpdump 'tcp[tcpflags] & tcp-rst != 0'
```

### Understanding tcpdump Output

**Example output:**
```
10:15:32.123456 IP 192.168.1.100.54321 > 93.184.216.34.80: Flags [S], seq 12345, win 65535, length 0
```

| Field | Meaning |
|-------|---------|
| `10:15:32.123456` | Timestamp |
| `IP` | Protocol |
| `192.168.1.100.54321` | Source IP and port |
| `>` | Direction indicator |
| `93.184.216.34.80` | Destination IP and port |
| `Flags [S]` | TCP flags (S=SYN, .=ACK, P=PSH, F=FIN, R=RST) |
| `seq 12345` | Sequence number |
| `win 65535` | Window size |
| `length 0` | Payload length |

**TCP flag abbreviations:**
- `S` = SYN
- `.` = ACK (just a dot)
- `P` = PSH
- `F` = FIN
- `R` = RST
- `S.` = SYN+ACK

### Practical Exercises: tcpdump

#### Exercise 5.1: Basic Capture

Capture your first packets:

```bash
# Start capture (run in one terminal)
sudo tcpdump -i eth0 -c 20 -nn

# In another terminal, generate traffic
ping -c 3 google.com
curl -I http://example.com
```

#### Exercise 5.2: Capture HTTP Traffic

```bash
# Capture HTTP traffic and save to file
sudo tcpdump -i eth0 -w http_traffic.pcap port 80

# In another terminal
curl http://example.com

# Stop capture (Ctrl+C), then analyze
tcpdump -r http_traffic.pcap -A | head -50
```

The `-A` flag shows ASCII content—you can see HTTP requests!

#### Exercise 5.3: Capture DNS Queries

```bash
# Capture DNS traffic
sudo tcpdump -i eth0 -nn port 53

# In another terminal
nslookup google.com
dig microsoft.com
```

You'll see the DNS queries and responses.

#### Exercise 5.4: Create Capture Script

```bash
#!/bin/bash
# packet_capture.sh - Automated packet capture

INTERFACE="${1:-eth0}"
DURATION="${2:-60}"
OUTPUT="$HOME/security-lab/captures/capture_$(date +%Y%m%d_%H%M%S).pcap"

mkdir -p "$(dirname $OUTPUT)"

echo "Starting packet capture..."
echo "Interface: $INTERFACE"
echo "Duration: $DURATION seconds"
echo "Output: $OUTPUT"
echo ""

sudo timeout "$DURATION" tcpdump -i "$INTERFACE" -w "$OUTPUT" -nn

echo ""
echo "Capture complete!"
echo "Packets captured: $(tcpdump -r $OUTPUT 2>/dev/null | wc -l)"
echo ""
echo "To analyze: tcpdump -r $OUTPUT"
echo "Or open in Wireshark: wireshark $OUTPUT"
```

Save to `~/security-lab/scripts/packet_capture.sh`.

---

### Milestone 5 Checkpoint

Before proceeding, verify:

- [ ] You can capture packets with tcpdump
- [ ] You can write captures to PCAP files
- [ ] You can filter by host, port, and protocol
- [ ] You can combine filters with and/or/not
- [ ] You can read and interpret tcpdump output
- [ ] You have created the packet_capture.sh script

**[CERT CHECKPOINT - CySA+ 1.3 / PenTest+]**: Packet capture is core to security operations. Know tcpdump well.

---

## Part 6 — Traffic Analysis with Wireshark (Milestone 6)

### What is Wireshark?

**Wireshark** is the world's most popular network protocol analyzer. It provides:
- Graphical interface for packet analysis
- Deep protocol dissection
- Powerful filtering
- Statistics and visualization
- Export capabilities

### Installing Wireshark

On your Ubuntu VM:

```bash
sudo apt install wireshark

# Allow non-root capture (optional, adds your user to wireshark group)
sudo usermod -aG wireshark $USER

# Log out and back in for group change to take effect
```

**Note:** For this stage, we'll mainly analyze capture files. Running Wireshark's GUI requires a graphical environment (desktop Ubuntu or X11 forwarding).

### Wireshark on Desktop

If you have a desktop environment:

```bash
wireshark &
```

### Command-Line Alternative: tshark

`tshark` is Wireshark's command-line version:

```bash
# Install
sudo apt install tshark

# Capture packets
sudo tshark -i eth0

# Read PCAP file
tshark -r capture.pcap

# Apply display filter
tshark -r capture.pcap -Y "http"

# Specific fields
tshark -r capture.pcap -Y "http.request" -T fields -e http.host -e http.request.uri
```

### Wireshark Display Filters

Display filters are different from capture filters (BPF). They're more powerful and readable.

#### Basic Display Filters

```
# By IP address
ip.addr == 192.168.1.100
ip.src == 192.168.1.100
ip.dst == 10.0.0.1

# By port
tcp.port == 80
tcp.dstport == 443
udp.port == 53

# By protocol
http
dns
ssh
tcp
udp
icmp
arp

# TCP flags
tcp.flags.syn == 1
tcp.flags.ack == 1
tcp.flags.fin == 1
tcp.flags.rst == 1
```

#### HTTP Filters

```
# All HTTP traffic
http

# HTTP requests only
http.request

# HTTP responses only
http.response

# Specific methods
http.request.method == "GET"
http.request.method == "POST"

# Specific URLs
http.request.uri contains "login"
http.host contains "google"

# Status codes
http.response.code == 200
http.response.code >= 400
```

#### DNS Filters

```
# All DNS
dns

# DNS queries
dns.flags.response == 0

# DNS responses
dns.flags.response == 1

# Specific query types
dns.qry.type == 1    # A record
dns.qry.type == 28   # AAAA record
dns.qry.type == 15   # MX record

# Query for specific domain
dns.qry.name contains "google"
```

#### Combining Filters

```
# HTTP to specific host
http and ip.dst == 192.168.1.100

# DNS or HTTP
dns or http

# Not ARP
!arp

# Complex example
(http.request or http.response) and ip.addr == 192.168.1.100
```

### Analyzing the TCP Handshake

In Wireshark, find a TCP connection and look for:

1. **Packet 1 - SYN:** `Flags: 0x002 (SYN)`
   - Client initiates
   - Sequence number set

2. **Packet 2 - SYN-ACK:** `Flags: 0x012 (SYN, ACK)`
   - Server responds
   - Acknowledges client's sequence

3. **Packet 3 - ACK:** `Flags: 0x010 (ACK)`
   - Client confirms
   - Connection established

**tshark command to see handshakes:**

```bash
tshark -r capture.pcap -Y "tcp.flags.syn == 1" -T fields -e ip.src -e ip.dst -e tcp.dstport
```

### Following TCP Streams

One of Wireshark's most powerful features is reconstructing conversations.

**In GUI:**
1. Right-click a packet
2. Select "Follow" → "TCP Stream"
3. See the entire conversation reconstructed

**With tshark:**

```bash
# Show all TCP streams
tshark -r capture.pcap -z conv,tcp

# Follow specific stream
tshark -r capture.pcap -z follow,tcp,ascii,0
```

### Extracting Data from Captures

#### Export HTTP Objects (Files)

In Wireshark GUI:
1. File → Export Objects → HTTP
2. See list of transferred files
3. Save files for analysis

**With tshark:**

```bash
tshark -r capture.pcap --export-objects http,./extracted_files/
```

### Practical Exercises: Wireshark/tshark

#### Exercise 6.1: Analyze HTTP Traffic

1. Generate some HTTP traffic and capture it:

```bash
# Start capture
sudo tcpdump -i eth0 -w http_analysis.pcap port 80 &

# Generate traffic
curl http://example.com
curl http://httpbin.org/get
curl http://httpbin.org/headers

# Stop capture
sudo killall tcpdump
```

2. Analyze with tshark:

```bash
# Show HTTP requests
tshark -r http_analysis.pcap -Y "http.request" -T fields -e http.host -e http.request.method -e http.request.uri

# Show HTTP response codes
tshark -r http_analysis.pcap -Y "http.response" -T fields -e http.response.code

# Follow HTTP stream
tshark -r http_analysis.pcap -z follow,tcp,ascii,0
```

#### Exercise 6.2: Analyze DNS Traffic

```bash
# Capture DNS
sudo tcpdump -i eth0 -w dns_analysis.pcap -c 50 port 53 &

# Generate queries
dig google.com
dig microsoft.com MX
nslookup amazon.com

sudo killall tcpdump

# Analyze
tshark -r dns_analysis.pcap -Y "dns" -T fields -e dns.qry.name -e dns.resp.addr
```

#### Exercise 6.3: Identify Three-Way Handshakes

```bash
# Create capture with connections
sudo tcpdump -i eth0 -w handshakes.pcap -c 100 &

curl http://example.com
curl http://httpbin.org

sudo killall tcpdump

# Find SYN packets (connection initiations)
tshark -r handshakes.pcap -Y "tcp.flags.syn == 1 and tcp.flags.ack == 0"

# Find complete handshakes
tshark -r handshakes.pcap -Y "tcp.flags.syn == 1" -T fields -e ip.src -e ip.dst -e tcp.dstport -e tcp.flags
```

#### Exercise 6.4: Create Analysis Script

```bash
#!/bin/bash
# pcap_analyzer.sh - Analyze PCAP files

PCAP="${1:-}"

if [ -z "$PCAP" ] || [ ! -f "$PCAP" ]; then
    echo "Usage: $0 <pcap_file>"
    exit 1
fi

echo "=== PCAP Analysis Report ==="
echo "File: $PCAP"
echo "Generated: $(date)"
echo "========================================"
echo ""

echo "=== Capture Statistics ==="
capinfos "$PCAP" 2>/dev/null || tshark -r "$PCAP" -q -z io,stat,0
echo ""

echo "=== Protocol Hierarchy ==="
tshark -r "$PCAP" -q -z io,phs
echo ""

echo "=== Top Talkers (IP Conversations) ==="
tshark -r "$PCAP" -q -z conv,ip | head -20
echo ""

echo "=== DNS Queries ==="
tshark -r "$PCAP" -Y "dns.flags.response == 0" -T fields -e dns.qry.name 2>/dev/null | sort | uniq -c | sort -rn | head -10
echo ""

echo "=== HTTP Hosts ==="
tshark -r "$PCAP" -Y "http.request" -T fields -e http.host 2>/dev/null | sort | uniq -c | sort -rn | head -10
echo ""

echo "=== TCP Ports Used ==="
tshark -r "$PCAP" -Y "tcp" -T fields -e tcp.dstport 2>/dev/null | sort | uniq -c | sort -rn | head -10
echo ""

echo "=== Potential Issues ==="
echo "TCP Retransmissions:"
tshark -r "$PCAP" -Y "tcp.analysis.retransmission" 2>/dev/null | wc -l

echo "TCP RST Packets:"
tshark -r "$PCAP" -Y "tcp.flags.rst == 1" 2>/dev/null | wc -l
```

Save to `~/security-lab/scripts/pcap_analyzer.sh`.

---

### Milestone 6 Checkpoint

Before proceeding, verify:

- [ ] You understand Wireshark/tshark basics
- [ ] You can apply display filters
- [ ] You can filter by protocol, IP, port
- [ ] You can identify TCP handshakes
- [ ] You can follow TCP streams
- [ ] You can extract useful data from captures
- [ ] You have created the pcap_analyzer.sh script

**[CERT CHECKPOINT - CySA+ 1.3 / CEH]**: Wireshark skills are essential. Practice analyzing various traffic types.

---

## Part 7 — Network Reconnaissance (Milestone 7)

### What is Network Reconnaissance?

**Reconnaissance** (recon) is the first phase of penetration testing and security assessment. It's about gathering information about targets before testing.

**Types of reconnaissance:**
- **Passive:** Gathering info without directly interacting with target (OSINT)
- **Active:** Directly scanning/probing the target

### Passive Reconnaissance

Passive recon gathers publicly available information without alerting the target.

#### WHOIS Lookups

```bash
# Domain information
whois example.com

# IP information
whois 8.8.8.8

# Key information to extract:
# - Registrar
# - Creation/expiration dates
# - Name servers
# - Registrant info (sometimes)
```

#### DNS Enumeration

```bash
# Find all DNS records
dig example.com ANY

# Find mail servers
dig example.com MX

# Find name servers
dig example.com NS

# Find text records (often have interesting info)
dig example.com TXT

# Attempt zone transfer (usually blocked)
dig axfr @ns1.example.com example.com
```

#### Online Tools (Reference)

These websites provide passive reconnaissance:
- **Shodan.io** — Search engine for internet-connected devices
- **Censys.io** — Similar to Shodan
- **dnsdumpster.com** — DNS recon
- **crt.sh** — Certificate transparency logs
- **builtwith.com** — Technology profiler

### Active Reconnaissance

Active recon involves direct interaction with targets. This can be detected!

#### Host Discovery

Find live hosts on a network:

```bash
# Ping sweep using ping
for ip in $(seq 1 254); do
    ping -c 1 -W 1 192.168.1.$ip &>/dev/null && echo "192.168.1.$ip is up"
done

# Using nmap (we'll install this)
sudo apt install nmap
nmap -sn 192.168.1.0/24
```

#### Port Scanning Concepts

Port scanning determines which services are running on a target.

**Scan types:**

| Scan Type | Description | Detectability |
|-----------|-------------|---------------|
| TCP Connect | Full TCP handshake | High (logged) |
| SYN Scan | Half-open (SYN only) | Medium |
| FIN Scan | Sends FIN flag | Low |
| NULL Scan | No flags set | Low |
| XMAS Scan | FIN+PSH+URG flags | Low |
| UDP Scan | UDP packets | Slow, but important |

#### Basic Port Scanning with nmap

```bash
# Scan single host, common ports
nmap 192.168.1.100

# Scan specific ports
nmap -p 22,80,443 192.168.1.100

# Scan port range
nmap -p 1-1000 192.168.1.100

# Scan all ports
nmap -p- 192.168.1.100

# Fast scan (top 100 ports)
nmap -F 192.168.1.100

# Service version detection
nmap -sV 192.168.1.100

# Operating system detection
sudo nmap -O 192.168.1.100

# Aggressive scan (OS, versions, scripts, traceroute)
nmap -A 192.168.1.100

# UDP scan (slow but important)
sudo nmap -sU 192.168.1.100
```

#### Understanding nmap Output

```
Starting Nmap 7.80 ( https://nmap.org )
Nmap scan report for 192.168.1.100
Host is up (0.00050s latency).

PORT     STATE  SERVICE     VERSION
22/tcp   open   ssh         OpenSSH 8.9
80/tcp   open   http        Apache httpd 2.4.52
443/tcp  open   ssl/http    Apache httpd 2.4.52
3306/tcp closed mysql
```

**Port states:**
- **open** — Service accepting connections
- **closed** — Port reachable but no service
- **filtered** — Firewall blocking, can't determine state
- **open|filtered** — Can't determine if open or filtered

#### Banner Grabbing

Get service information by reading connection banners:

```bash
# Using netcat
nc -v target.com 22

# Using telnet
telnet target.com 80
GET / HTTP/1.0
[press Enter twice]

# Using nmap
nmap -sV --script=banner target.com
```

### Practical Exercises: Network Reconnaissance

#### Exercise 7.1: Passive Recon Script

```bash
#!/bin/bash
# passive_recon.sh - Passive reconnaissance

TARGET="${1:-}"

if [ -z "$TARGET" ]; then
    echo "Usage: $0 <domain>"
    exit 1
fi

OUTPUT="$HOME/security-lab/reports/passive_recon_${TARGET}_$(date +%Y%m%d).txt"

echo "Passive Reconnaissance Report" > "$OUTPUT"
echo "Target: $TARGET" >> "$OUTPUT"
echo "Date: $(date)" >> "$OUTPUT"
echo "========================================" >> "$OUTPUT"
echo "" >> "$OUTPUT"

echo "[*] Running passive reconnaissance..."

echo "=== WHOIS Information ===" >> "$OUTPUT"
whois "$TARGET" 2>/dev/null | head -50 >> "$OUTPUT"
echo "" >> "$OUTPUT"

echo "=== DNS Records ===" >> "$OUTPUT"
echo "A Records:" >> "$OUTPUT"
dig +short "$TARGET" A >> "$OUTPUT"
echo "" >> "$OUTPUT"

echo "MX Records:" >> "$OUTPUT"
dig +short "$TARGET" MX >> "$OUTPUT"
echo "" >> "$OUTPUT"

echo "NS Records:" >> "$OUTPUT"
dig +short "$TARGET" NS >> "$OUTPUT"
echo "" >> "$OUTPUT"

echo "TXT Records:" >> "$OUTPUT"
dig +short "$TARGET" TXT >> "$OUTPUT"
echo "" >> "$OUTPUT"

echo "=== Subdomain Enumeration (basic) ===" >> "$OUTPUT"
for sub in www mail ftp vpn remote admin portal api dev staging; do
    result=$(dig +short "$sub.$TARGET" 2>/dev/null)
    if [ -n "$result" ]; then
        echo "$sub.$TARGET: $result" >> "$OUTPUT"
    fi
done
echo "" >> "$OUTPUT"

echo "[*] Report saved to: $OUTPUT"
```

Save to `~/security-lab/scripts/passive_recon.sh`.

#### Exercise 7.2: Active Recon Script

```bash
#!/bin/bash
# active_recon.sh - Active reconnaissance (only use on authorized targets!)

TARGET="${1:-}"

if [ -z "$TARGET" ]; then
    echo "Usage: $0 <target_ip_or_hostname>"
    echo "WARNING: Only use on systems you have permission to scan!"
    exit 1
fi

echo "============================================"
echo "WARNING: Active scanning can be detected!"
echo "Only proceed if you have authorization!"
echo "============================================"
read -p "Do you have permission to scan $TARGET? (yes/no): " confirm

if [ "$confirm" != "yes" ]; then
    echo "Aborting."
    exit 1
fi

OUTPUT="$HOME/security-lab/reports/active_recon_${TARGET}_$(date +%Y%m%d_%H%M%S).txt"

echo "Active Reconnaissance Report" > "$OUTPUT"
echo "Target: $TARGET" >> "$OUTPUT"
echo "Date: $(date)" >> "$OUTPUT"
echo "========================================" >> "$OUTPUT"
echo "" >> "$OUTPUT"

echo "[*] Checking if host is up..."
ping -c 2 "$TARGET" >> "$OUTPUT" 2>&1

echo "[*] Running quick port scan..."
echo "" >> "$OUTPUT"
echo "=== Quick Port Scan (Top 1000) ===" >> "$OUTPUT"
nmap -T4 "$TARGET" >> "$OUTPUT" 2>&1

echo "" >> "$OUTPUT"
echo "[*] Running service detection on open ports..."
echo "=== Service Detection ===" >> "$OUTPUT"
nmap -sV -T4 "$TARGET" >> "$OUTPUT" 2>&1

echo "" >> "$OUTPUT"
echo "[*] Report saved to: $OUTPUT"
```

Save to `~/security-lab/scripts/active_recon.sh`.

#### Exercise 7.3: Network Discovery Script

```bash
#!/bin/bash
# network_discovery.sh - Discover hosts on local network

NETWORK="${1:-192.168.1.0/24}"

echo "============================================"
echo "Network Discovery"
echo "Target Network: $NETWORK"
echo "============================================"
echo ""

echo "[*] Method 1: ARP Scan (if available)"
if command -v arp-scan &>/dev/null; then
    sudo arp-scan "$NETWORK"
fi

echo ""
echo "[*] Method 2: Nmap Ping Sweep"
nmap -sn "$NETWORK"

echo ""
echo "[*] Method 3: Current ARP Cache"
ip neigh show
```

Save to `~/security-lab/scripts/network_discovery.sh`.

---

### Milestone 7 Checkpoint

Before proceeding, verify:

- [ ] You understand passive vs. active reconnaissance
- [ ] You can perform WHOIS and DNS enumeration
- [ ] You understand port scanning concepts
- [ ] You can use nmap for basic scanning
- [ ] You understand nmap output (port states)
- [ ] You have created reconnaissance scripts
- [ ] You understand the legal and ethical implications

**[CERT CHECKPOINT - PenTest+ 2.0 / CEH]**: Reconnaissance is Phase 1 of penetration testing. Know these techniques well.

---

## Stage 03 Assessment

### Written Assessment

Answer these questions in `~/security-lab/reports/stage03_assessment.txt`:

1. What are the 7 layers of the OSI model? Give one example protocol for layers 3, 4, and 7.

2. What is the difference between TCP and UDP? Give two examples of protocols that use each.

3. Explain what happens during a TCP three-way handshake.

4. A host has IP 172.16.50.25 with subnet mask 255.255.240.0. What is the network address?

5. What ports do HTTP, HTTPS, SSH, and DNS use?

6. Explain the difference between a display filter in Wireshark and a capture filter in tcpdump.

7. What is the difference between passive and active reconnaissance?

8. What do the nmap port states "open," "closed," and "filtered" mean?

9. Why is ARP considered a security risk?

10. What information can you learn from a WHOIS query?

### Practical Assessment

1. **Packet Capture Challenge:**
   - Capture 60 seconds of traffic on your VM
   - Save to a PCAP file
   - Use tshark to identify:
     - Number of unique IP addresses
     - Top 5 ports used
     - Any DNS queries made
     - Any HTTP traffic

2. **Network Documentation:**
   - Document your lab network completely:
     - Your VM's IP, subnet mask, gateway
     - DNS servers configured
     - All routes in the routing table
     - Create a simple network diagram (text-based is fine)

3. **Reconnaissance Exercise:**
   - Perform passive recon on a domain you own (or use example.com)
   - Document: WHOIS info, DNS records, any discovered subdomains
   - Explain what an attacker could learn from this information

4. **Port Scan Analysis:**
   - Scan your own VM (127.0.0.1 or localhost)
   - List all open ports
   - For each open port, identify the service and explain its purpose
   - Determine if any services should be disabled

---

## Stage 03 Completion Checklist

### Network Models
- [ ] Can explain all 7 OSI layers
- [ ] Understand the 4 TCP/IP layers
- [ ] Know protocol placement at each layer
- [ ] Understand encapsulation

### IP Addressing
- [ ] Understand IPv4 address structure
- [ ] Can perform subnet calculations
- [ ] Know private vs. public address ranges
- [ ] Can use ipcalc or calculate manually

### Protocols
- [ ] Understand TCP vs. UDP differences
- [ ] Know the TCP three-way handshake
- [ ] Know common protocols and their ports
- [ ] Understand protocol security implications

### Network Commands
- [ ] Proficient with ip, ping, traceroute, ss
- [ ] Can use dig/nslookup for DNS
- [ ] Can use curl/wget for HTTP
- [ ] Understand netcat capabilities

### Packet Capture
- [ ] Can capture with tcpdump
- [ ] Can apply capture filters
- [ ] Can save and read PCAP files
- [ ] Created packet_capture.sh

### Traffic Analysis
- [ ] Can use tshark/Wireshark
- [ ] Can apply display filters
- [ ] Can follow TCP streams
- [ ] Can identify handshakes
- [ ] Created pcap_analyzer.sh

### Reconnaissance
- [ ] Understand passive vs. active recon
- [ ] Can perform WHOIS lookups
- [ ] Can perform DNS enumeration
- [ ] Understand port scanning concepts
- [ ] Can use nmap for basic scanning
- [ ] Created passive_recon.sh
- [ ] Created active_recon.sh

### Scripts Created
- [ ] network_doc.sh
- [ ] service_detector.sh
- [ ] network_toolkit.sh
- [ ] packet_capture.sh
- [ ] pcap_analyzer.sh
- [ ] passive_recon.sh
- [ ] active_recon.sh
- [ ] network_discovery.sh

### Assessment
- [ ] Written assessment completed
- [ ] Practical assessment completed

### Git Workflow
- [ ] Stage 03 committed
- [ ] Stage 03 pushed

---

## Definition of Done

Stage 03 is complete when:

1. All checklist items are checked
2. All scripts are created and functional
3. You can explain network concepts clearly
4. Assessment is complete
5. Work is committed and pushed

---

## What's Next: Stage 04 Preview

In Stage 04 — Kali Linux Setup and Security Methodology, you will:

- Install and configure Kali Linux
- Understand the penetration testing methodology
- Learn about the legal and ethical framework
- Set up your security testing lab
- Get familiar with Kali's tool categories

You've built the foundation—now you're ready for specialized security tools!

---

## Supplementary Resources

### Practice
- **TryHackMe:** "Network Fundamentals" pathway (free)
- **HackTheBox Academy:** "Introduction to Networking" module

### Reading
- CompTIA Network+ Study Guide
- "TCP/IP Illustrated" by W. Richard Stevens (classic reference)

### Tools to Explore Further
- Wireshark documentation: https://www.wireshark.org/docs/
- nmap documentation: https://nmap.org/book/

---

**Commit your work and proceed to Stage 04 when ready:**

```bash
cd ~/path-to-repo
git add .
git commit -m "Complete Stage 03 - Networking Fundamentals for Security"
git push
```
