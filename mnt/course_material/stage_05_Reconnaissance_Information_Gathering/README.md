# Stage 05 — Reconnaissance and Information Gathering
## The Foundation of Every Successful Security Assessment

**Kali Linux for Cybersecurity Learning Path**  
**Audience:** Learners who have completed Stages 01-04 (ready for active tool usage)

Welcome to Stage 05. You've set up your Kali environment and understand the methodology. Now it's time to put it into practice. Reconnaissance is the **most critical phase** of any security assessment—the better your recon, the more successful your testing will be.

---

## Prerequisites

Before starting Stage 05, you must have completed Stages 01-04:

- [ ] Kali Linux VM configured and working
- [ ] Metasploitable 2 or other vulnerable targets available
- [ ] Lab network connectivity verified
- [ ] Understanding of penetration testing methodology
- [ ] Familiarity with network protocols and services

If any of these are not checked, return to the previous stages first.

---

## Why Reconnaissance Matters

**"Give me six hours to chop down a tree and I will spend the first four sharpening the axe."** — Abraham Lincoln

The same principle applies to security testing:

| Time Spent on Recon | Result |
|---------------------|--------|
| Minimal recon | Miss vulnerabilities, waste time on dead ends |
| Thorough recon | Find attack surface, prioritize efforts, discover unexpected entry points |

### Real-World Impact

| Recon Discovery | What It Enables |
|-----------------|-----------------|
| Forgotten subdomain | Unpatched server to exploit |
| Employee email format | Targeted phishing, credential stuffing |
| Technology stack | Known vulnerability research |
| Open S3 bucket | Sensitive data exposure |
| Development server | Weaker security, test credentials |

**Professional pentesters spend 40-60% of engagement time on reconnaissance.**

---

## What You Will Learn

By the end of this stage, you will be able to:

- Conduct passive reconnaissance without alerting targets
- Perform active reconnaissance systematically
- Use professional OSINT tools effectively
- Enumerate DNS thoroughly
- Discover subdomains and hidden assets
- Harvest emails and identify employees
- Map network infrastructure
- Build comprehensive target profiles
- Automate reconnaissance workflows

---

## What You Will Build

1. **Passive recon report** — OSINT findings on practice target
2. **DNS enumeration script** — Automated DNS discovery
3. **Subdomain discovery toolkit** — Multiple method approach
4. **Target profile template** — Comprehensive documentation
5. **Automated recon framework** — Scripted reconnaissance workflow
6. **Practice engagement** — Full recon on Metasploitable

---

## Certification Alignment

This stage maps to objectives from:

| Certification | Relevant Domains |
|--------------|------------------|
| **CompTIA PenTest+** | 2.0 Information Gathering and Vulnerability Scanning |
| **CompTIA CySA+** | 1.0 Security Operations (threat intelligence) |
| **CEH** | Module 2: Footprinting and Reconnaissance |
| **eJPT** | Information Gathering |

> **Certification Exam Currency Notice:** Verify current exam objectives at the vendor's official website. See `docs/CERTIFICATION_MAPPING.md` for detailed alignment.

---

## Time Estimate

**Total: 35-40 hours**

| Section | Hours |
|---------|-------|
| Passive Reconnaissance Concepts | 4-5 |
| OSINT Tools and Techniques | 5-6 |
| DNS Enumeration | 5-6 |
| Subdomain Discovery | 4-5 |
| Email and Employee Harvesting | 3-4 |
| Active Reconnaissance | 5-6 |
| Network Mapping | 4-5 |
| Automation and Scripting | 3-4 |
| Stage Assessment | 2-3 |

---

## The Milestones Approach

### Stage 05 Milestones

1. **Master passive reconnaissance concepts**
2. **Use OSINT tools effectively**
3. **Perform comprehensive DNS enumeration**
4. **Discover subdomains using multiple methods**
5. **Harvest emails and identify targets**
6. **Conduct active reconnaissance**
7. **Map network infrastructure**
8. **Automate reconnaissance workflows**
9. **Complete the stage assessment**

---

## Part 1 — Passive Reconnaissance Concepts (Milestone 1)

### What is Passive Reconnaissance?

**Passive reconnaissance** (also called passive footprinting or OSINT) is gathering information about a target **without directly interacting with their systems**.

```
┌─────────────────────────────────────────────────────────────────┐
│                 Passive vs Active Reconnaissance                 │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  PASSIVE RECONNAISSANCE                                         │
│  ├── No direct contact with target systems                     │
│  ├── Uses publicly available information                        │
│  ├── Cannot be detected by target                               │
│  ├── Legal in most cases (public info)                          │
│  └── Examples:                                                   │
│      • Search engine queries                                    │
│      • WHOIS lookups                                            │
│      • Social media research                                    │
│      • Job posting analysis                                     │
│      • DNS records (from public DNS)                            │
│                                                                  │
│  ACTIVE RECONNAISSANCE                                          │
│  ├── Direct interaction with target systems                    │
│  ├── Can be logged and detected                                 │
│  ├── Requires authorization                                     │
│  ├── More detailed information                                  │
│  └── Examples:                                                   │
│      • Port scanning                                            │
│      • Banner grabbing                                          │
│      • Vulnerability scanning                                   │
│      • Web spidering                                            │
│      • Zone transfer attempts                                   │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

### Why Start Passive?

1. **No detection** — Target doesn't know you're looking
2. **Legal safety** — Public information is generally fair game
3. **Broad scope** — Find assets you didn't know existed
4. **Attack surface** — Discover forgotten/shadow IT
5. **Social engineering prep** — Employee names, roles, technologies

### Categories of Passive Information

#### Organizational Information
- Company structure
- Key personnel and roles
- Physical locations
- Business relationships
- Recent news and events

#### Technical Information
- Domain names and IP ranges
- Email formats and addresses
- Technology stack
- Public-facing infrastructure
- Historical data (old versions)

#### Human Information
- Employee names and roles
- Email addresses
- Social media profiles
- Published documents
- Conference presentations

### Information Sources

```
┌─────────────────────────────────────────────────────────────────┐
│                    Passive Information Sources                   │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  SEARCH ENGINES                                                 │
│  ├── Google (with operators)                                    │
│  ├── Bing                                                       │
│  ├── DuckDuckGo                                                 │
│  └── Yandex (different results)                                 │
│                                                                  │
│  DOMAIN/IP REGISTRIES                                           │
│  ├── WHOIS databases                                            │
│  ├── Regional Internet Registries (RIRs)                        │
│  └── DNS records                                                │
│                                                                  │
│  CERTIFICATE TRANSPARENCY                                       │
│  ├── crt.sh                                                     │
│  ├── Censys                                                     │
│  └── Certificate logs                                           │
│                                                                  │
│  SOCIAL MEDIA                                                   │
│  ├── LinkedIn                                                   │
│  ├── Twitter/X                                                  │
│  ├── Facebook                                                   │
│  └── GitHub (code, commits)                                     │
│                                                                  │
│  SPECIALIZED DATABASES                                          │
│  ├── Shodan (internet-connected devices)                        │
│  ├── Censys (internet scanning)                                 │
│  ├── SecurityTrails (DNS history)                               │
│  └── BuiltWith (technology profiling)                           │
│                                                                  │
│  ARCHIVED DATA                                                  │
│  ├── Wayback Machine (web archive)                              │
│  ├── Google Cache                                               │
│  └── CachedView                                                 │
│                                                                  │
│  DOCUMENTS AND FILES                                            │
│  ├── PDF metadata                                               │
│  ├── Office document properties                                 │
│  ├── Public code repositories                                   │
│  └── Pastebin/paste sites                                       │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

### Google Dorking (Advanced Search)

Google operators help find specific information:

| Operator | Purpose | Example |
|----------|---------|---------|
| `site:` | Limit to domain | `site:example.com` |
| `filetype:` | Find file types | `filetype:pdf` |
| `inurl:` | Search in URL | `inurl:admin` |
| `intitle:` | Search in title | `intitle:"index of"` |
| `intext:` | Search in body | `intext:password` |
| `cache:` | Cached version | `cache:example.com` |
| `-` | Exclude term | `site:example.com -www` |
| `""` | Exact phrase | `"internal use only"` |
| `OR` | Either term | `admin OR administrator` |
| `*` | Wildcard | `admin*.example.com` |

#### Useful Google Dorks

```bash
# Find subdomains
site:example.com -www

# Find login pages
site:example.com inurl:login OR inurl:admin

# Find exposed documents
site:example.com filetype:pdf OR filetype:doc OR filetype:xlsx

# Find configuration files
site:example.com filetype:conf OR filetype:cfg OR filetype:env

# Find email addresses
site:example.com "@example.com"

# Find directory listings
site:example.com intitle:"index of"

# Find exposed databases
site:example.com filetype:sql

# Find WordPress sites
site:example.com inurl:wp-content

# Find error messages
site:example.com "error" OR "warning" OR "mysql"

# Find credentials (be ethical!)
site:example.com intext:password filetype:txt
```

**Create a Google Dorks Reference:**

```bash
cat << 'EOF' > ~/notes/google_dorks_reference.md
# Google Dorks Reference for Reconnaissance

## Subdomain Discovery
site:example.com -www -www2
site:*.example.com

## Login and Admin Pages
site:example.com inurl:login
site:example.com inurl:admin
site:example.com intitle:login
site:example.com inurl:signin OR inurl:signup

## Sensitive Files
site:example.com filetype:pdf
site:example.com filetype:doc OR filetype:docx
site:example.com filetype:xls OR filetype:xlsx
site:example.com filetype:ppt OR filetype:pptx
site:example.com filetype:txt
site:example.com filetype:log
site:example.com filetype:bak
site:example.com filetype:sql
site:example.com filetype:xml
site:example.com filetype:conf OR filetype:cfg

## Configuration and Credentials
site:example.com filetype:env
site:example.com filetype:ini
site:example.com "password" filetype:txt
site:example.com "api_key" OR "apikey"
site:example.com "secret" filetype:json

## Directory Listings
site:example.com intitle:"index of"
site:example.com intitle:"parent directory"

## Error Messages
site:example.com "error" OR "exception"
site:example.com "mysql error"
site:example.com "warning" "on line"
site:example.com "stack trace"

## Technology Identification
site:example.com "powered by"
site:example.com "built with"
site:example.com inurl:wp-content (WordPress)
site:example.com inurl:joomla (Joomla)

## Email Harvesting
site:example.com "@example.com"
site:example.com "email" OR "contact"

## Cloud Exposure
site:s3.amazonaws.com "example"
site:blob.core.windows.net "example"
site:storage.googleapis.com "example"

## GitHub Leaks
site:github.com "example.com"
site:github.com "example.com" password
site:github.com "example.com" api_key

## Pastebin Leaks
site:pastebin.com "example.com"
site:pastebin.com "@example.com"

## IMPORTANT NOTES
# - Always have authorization before deep investigation
# - Document everything you find
# - Be aware of legal boundaries
# - Some findings may be coincidental
EOF

echo "Created: ~/notes/google_dorks_reference.md"
```

### OSINT Workflow

```
┌─────────────────────────────────────────────────────────────────┐
│                    OSINT Workflow Process                        │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  1. DEFINE SCOPE                                                │
│     └── What organization/domain/person are we researching?    │
│                                                                  │
│  2. DOMAIN INTELLIGENCE                                         │
│     ├── WHOIS lookup                                            │
│     ├── DNS records                                             │
│     ├── Subdomain enumeration                                   │
│     └── Historical DNS data                                     │
│                                                                  │
│  3. INFRASTRUCTURE MAPPING                                      │
│     ├── IP ranges and ASN                                       │
│     ├── Hosting providers                                       │
│     ├── CDN identification                                      │
│     └── Technology stack                                        │
│                                                                  │
│  4. ORGANIZATIONAL INTELLIGENCE                                 │
│     ├── Company structure                                       │
│     ├── Key personnel                                           │
│     ├── Business relationships                                  │
│     └── News and press releases                                 │
│                                                                  │
│  5. HUMAN INTELLIGENCE                                          │
│     ├── Employee discovery                                      │
│     ├── Email format identification                             │
│     ├── Social media profiles                                   │
│     └── Published documents                                     │
│                                                                  │
│  6. TECHNICAL INTELLIGENCE                                      │
│     ├── Technology identification                               │
│     ├── Exposed services (Shodan)                               │
│     ├── Code repositories                                       │
│     └── Leaked credentials                                      │
│                                                                  │
│  7. DOCUMENT AND ANALYZE                                        │
│     ├── Compile findings                                        │
│     ├── Identify patterns                                       │
│     ├── Note attack vectors                                     │
│     └── Prioritize targets                                      │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

---

### Milestone 1 Checkpoint

Before proceeding, verify:

- [ ] You understand passive vs. active reconnaissance
- [ ] You know the main categories of passive information
- [ ] You can use Google operators effectively
- [ ] You understand the OSINT workflow
- [ ] You have created the google_dorks_reference.md

**[CERT CHECKPOINT - PenTest+ 2.1 / CEH]**: OSINT and passive recon are heavily tested.

---

## Part 2 — OSINT Tools and Techniques (Milestone 2)

### WHOIS Lookups

WHOIS provides domain registration information.

```bash
# Basic WHOIS lookup
whois example.com

# Key information to extract:
# - Registrar
# - Registration date
# - Expiration date
# - Name servers
# - Registrant information (often redacted)
# - Admin/tech contacts
```

**Create WHOIS parsing script:**

```bash
#!/bin/bash
# whois_parser.sh - Extract key WHOIS information

DOMAIN="${1:-}"

if [ -z "$DOMAIN" ]; then
    echo "Usage: $0 <domain>"
    exit 1
fi

echo "=== WHOIS Analysis: $DOMAIN ==="
echo ""

WHOIS_DATA=$(whois "$DOMAIN" 2>/dev/null)

echo "=== Registration Info ==="
echo "$WHOIS_DATA" | grep -i "registrar:" | head -1
echo "$WHOIS_DATA" | grep -i "creation date:" | head -1
echo "$WHOIS_DATA" | grep -i "expir" | head -1
echo "$WHOIS_DATA" | grep -i "updated date:" | head -1

echo ""
echo "=== Name Servers ==="
echo "$WHOIS_DATA" | grep -i "name server:" | sort -u

echo ""
echo "=== Registrant Info ==="
echo "$WHOIS_DATA" | grep -i "registrant" | head -5

echo ""
echo "=== Contact Emails ==="
echo "$WHOIS_DATA" | grep -iE "email|e-mail" | sort -u

echo ""
echo "=== Full output saved to: whois_${DOMAIN}.txt ==="
echo "$WHOIS_DATA" > "whois_${DOMAIN}.txt"
```

Save to `~/scripts/whois_parser.sh`.

### theHarvester

theHarvester is a powerful OSINT tool for gathering emails, subdomains, IPs, and URLs.

```bash
# Basic usage
theHarvester -d example.com -b google

# Multiple sources
theHarvester -d example.com -b google,bing,linkedin,twitter

# All sources
theHarvester -d example.com -b all

# Save output
theHarvester -d example.com -b all -f output_file

# Limit results
theHarvester -d example.com -b google -l 500
```

**Data sources available:**

| Source | Type | Notes |
|--------|------|-------|
| `google` | Search engine | Emails, subdomains |
| `bing` | Search engine | Emails, subdomains |
| `linkedin` | Social media | Employee names |
| `twitter` | Social media | Tweets, users |
| `dnsdumpster` | DNS | Subdomains |
| `crtsh` | Certificates | Subdomains |
| `virustotal` | Threat intel | Subdomains |
| `shodan` | Device search | IPs, services (API key needed) |

**theHarvester script:**

```bash
#!/bin/bash
# run_harvester.sh - Run theHarvester with multiple sources

DOMAIN="${1:-}"
OUTPUT_DIR="${2:-$HOME/engagements/recon}"

if [ -z "$DOMAIN" ]; then
    echo "Usage: $0 <domain> [output_directory]"
    exit 1
fi

TIMESTAMP=$(date +%Y%m%d_%H%M%S)
OUTPUT_FILE="$OUTPUT_DIR/harvester_${DOMAIN}_${TIMESTAMP}"

mkdir -p "$OUTPUT_DIR"

echo "=== Running theHarvester on $DOMAIN ==="
echo "Output: $OUTPUT_FILE"
echo ""

# Run with common free sources
theHarvester -d "$DOMAIN" \
    -b google,bing,dnsdumpster,crtsh,urlscan \
    -l 500 \
    -f "$OUTPUT_FILE"

echo ""
echo "=== Results Summary ==="
if [ -f "${OUTPUT_FILE}.json" ]; then
    echo "Emails found: $(grep -c '"@"' ${OUTPUT_FILE}.json 2>/dev/null || echo 0)"
    echo "Hosts found: $(grep -c '"host"' ${OUTPUT_FILE}.json 2>/dev/null || echo 0)"
fi

echo ""
echo "Results saved to: $OUTPUT_FILE.*"
```

Save to `~/scripts/run_harvester.sh`.

### Recon-ng

Recon-ng is a full-featured reconnaissance framework (like Metasploit for OSINT).

```bash
# Start recon-ng
recon-ng

# Inside recon-ng:
# Create a workspace
workspaces create example_target
workspaces select example_target

# Add a domain
db insert domains
# Enter: example.com

# List available modules
modules search

# Load a module
modules load recon/domains-hosts/hackertarget

# Show module info
info

# Set options
options set SOURCE example.com

# Run the module
run

# View results
show hosts
show contacts

# Export data
modules load reporting/html
run
```

**Key recon-ng modules:**

| Module | Purpose |
|--------|---------|
| `recon/domains-hosts/hackertarget` | Find hosts |
| `recon/domains-hosts/bing_domain_web` | Bing subdomain search |
| `recon/domains-hosts/google_site_web` | Google subdomain search |
| `recon/domains-hosts/certificate_transparency` | Cert transparency |
| `recon/domains-contacts/whois_pocs` | WHOIS contacts |
| `recon/hosts-ports/shodan_ip` | Shodan port lookup |
| `recon/contacts-credentials/hibp_breach` | Check breaches |
| `reporting/html` | Generate HTML report |
| `reporting/csv` | Generate CSV export |

**Recon-ng automation script:**

```bash
#!/bin/bash
# recon_ng_auto.sh - Automated recon-ng workflow

DOMAIN="${1:-}"
WORKSPACE="${2:-autorecon}"

if [ -z "$DOMAIN" ]; then
    echo "Usage: $0 <domain> [workspace_name]"
    exit 1
fi

# Create recon-ng resource file
cat << EOF > /tmp/recon_commands.rc
workspaces create $WORKSPACE
workspaces select $WORKSPACE
db insert domains
$DOMAIN
modules load recon/domains-hosts/hackertarget
run
modules load recon/domains-hosts/certificate_transparency
options set SOURCE $DOMAIN
run
modules load recon/domains-contacts/whois_pocs
options set SOURCE $DOMAIN
run
show hosts
show contacts
exit
EOF

echo "=== Running Recon-ng Automation ==="
recon-ng -r /tmp/recon_commands.rc

rm /tmp/recon_commands.rc
```

Save to `~/scripts/recon_ng_auto.sh`.

### Shodan (Concepts)

Shodan is a search engine for internet-connected devices. It scans the internet and indexes:
- Open ports
- Running services
- Banners
- SSL certificates
- Device types

**Note:** Shodan requires an account for full access. Free accounts have limited queries.

**Shodan CLI (if you have an API key):**

```bash
# Install Shodan CLI
pip install shodan

# Initialize with API key
shodan init YOUR_API_KEY

# Search
shodan search "example.com"

# Host information
shodan host 1.2.3.4

# Search by organization
shodan search "org:Example Company"

# Search by technology
shodan search "apache" "example.com"
```

**Useful Shodan queries:**

```
# Find hosts for a domain
hostname:example.com

# Find hosts in an organization
org:"Example Company"

# Find specific ports
port:22 hostname:example.com

# Find specific services
product:Apache hostname:example.com

# Find vulnerable services
vuln:CVE-2021-44228

# Find webcams (example)
has_screenshot:true port:554

# Find default credentials
"default password"
```

### Certificate Transparency

SSL certificates are logged publicly. This reveals:
- Subdomains
- Internal hostnames
- Wildcard patterns

**Using crt.sh:**

```bash
# Query crt.sh API
curl -s "https://crt.sh/?q=example.com&output=json" | jq -r '.[].name_value' | sort -u

# Find subdomains
curl -s "https://crt.sh/?q=%.example.com&output=json" | jq -r '.[].name_value' | sort -u | grep -v '*'
```

**Certificate transparency script:**

```bash
#!/bin/bash
# cert_transparency.sh - Query certificate transparency logs

DOMAIN="${1:-}"

if [ -z "$DOMAIN" ]; then
    echo "Usage: $0 <domain>"
    exit 1
fi

echo "=== Certificate Transparency Search: $DOMAIN ==="
echo ""

# Query crt.sh
echo "Querying crt.sh..."
RESULTS=$(curl -s "https://crt.sh/?q=%25.$DOMAIN&output=json" 2>/dev/null)

if [ -z "$RESULTS" ] || [ "$RESULTS" == "[]" ]; then
    echo "No results found or error querying crt.sh"
    exit 1
fi

# Parse unique domains
echo "$RESULTS" | jq -r '.[].name_value' 2>/dev/null | \
    sed 's/\*\.//g' | \
    sort -u | \
    grep -v '^$'

echo ""
TOTAL=$(echo "$RESULTS" | jq -r '.[].name_value' 2>/dev/null | sed 's/\*\.//g' | sort -u | grep -v '^$' | wc -l)
echo "Total unique domains/subdomains found: $TOTAL"
```

Save to `~/scripts/cert_transparency.sh`.

### Wayback Machine

The Internet Archive's Wayback Machine stores historical website snapshots.

**Use cases:**
- Find old pages/functionality
- Discover removed content
- Find old endpoints
- Identify technology changes

```bash
# Using waybackurls tool
go install github.com/tomnomnom/waybackurls@latest

# Get all URLs from Wayback Machine
echo "example.com" | waybackurls

# Filter for specific files
echo "example.com" | waybackurls | grep -E '\.(js|json|xml|config|bak|sql)$'

# Using curl
curl -s "http://web.archive.org/cdx/search/cdx?url=example.com/*&output=text&fl=original&collapse=urlkey"
```

---

### Milestone 2 Checkpoint

Before proceeding, verify:

- [ ] You can perform WHOIS lookups and extract key information
- [ ] You can use theHarvester effectively
- [ ] You understand recon-ng basics
- [ ] You understand Shodan's capabilities
- [ ] You can query certificate transparency logs
- [ ] You have created the OSINT scripts

**[CERT CHECKPOINT - PenTest+ 2.1 / CEH]**: Know these tools and what information they provide.

---

## Part 3 — DNS Enumeration (Milestone 3)

### Why DNS Enumeration Matters

DNS is the backbone of the internet. Thorough DNS enumeration reveals:

| Discovery | Value |
|-----------|-------|
| Subdomains | Additional attack surface |
| Mail servers | Phishing targets, email security |
| Name servers | DNS infrastructure, potential vulnerabilities |
| IP addresses | Direct targets, network ranges |
| TXT records | SPF, DKIM, verification tokens, hidden info |
| Internal hostnames | Internal naming conventions |

### DNS Record Types

| Type | Purpose | Security Relevance |
|------|---------|-------------------|
| A | IPv4 address | Primary targets |
| AAAA | IPv6 address | Often overlooked targets |
| MX | Mail servers | Email attack vectors |
| NS | Name servers | DNS infrastructure |
| TXT | Text data | SPF, DKIM, secrets |
| CNAME | Alias | Subdomain takeover |
| SOA | Authority | Zone info, admin email |
| PTR | Reverse lookup | Discover hostnames from IPs |
| SRV | Service location | Internal services |

### Basic DNS Queries

```bash
# Using dig (preferred)
dig example.com               # Default (A record)
dig example.com A             # IPv4 address
dig example.com AAAA          # IPv6 address
dig example.com MX            # Mail servers
dig example.com NS            # Name servers
dig example.com TXT           # Text records
dig example.com ANY           # All records (may be blocked)
dig example.com SOA           # Zone authority

# Short output
dig +short example.com

# Detailed output
dig +noall +answer example.com

# Query specific DNS server
dig @8.8.8.8 example.com

# Trace DNS resolution
dig +trace example.com

# Reverse lookup
dig -x 1.2.3.4
```

```bash
# Using host (simpler)
host example.com
host -t MX example.com
host -t NS example.com
host -t TXT example.com

# Using nslookup (legacy)
nslookup example.com
nslookup -type=MX example.com
```

### Zone Transfers

A DNS zone transfer copies all DNS records from a name server. This is usually blocked, but always try.

```bash
# Attempt zone transfer
dig axfr @ns1.example.com example.com

# Using host
host -t axfr example.com ns1.example.com

# Try all name servers
for ns in $(dig +short NS example.com); do
    echo "Trying $ns..."
    dig axfr @$ns example.com
done
```

**If successful, you get the entire DNS zone—a goldmine!**

### Comprehensive DNS Enumeration Script

```bash
#!/bin/bash
# dns_enum.sh - Comprehensive DNS enumeration

DOMAIN="${1:-}"
OUTPUT_DIR="${2:-.}"

if [ -z "$DOMAIN" ]; then
    echo "Usage: $0 <domain> [output_directory]"
    exit 1
fi

OUTPUT="$OUTPUT_DIR/dns_enum_${DOMAIN}_$(date +%Y%m%d_%H%M%S).txt"

echo "=== DNS Enumeration: $DOMAIN ===" | tee "$OUTPUT"
echo "Date: $(date)" | tee -a "$OUTPUT"
echo "" | tee -a "$OUTPUT"

# A Records
echo "=== A Records (IPv4) ===" | tee -a "$OUTPUT"
dig +short "$DOMAIN" A | tee -a "$OUTPUT"
echo "" | tee -a "$OUTPUT"

# AAAA Records
echo "=== AAAA Records (IPv6) ===" | tee -a "$OUTPUT"
dig +short "$DOMAIN" AAAA | tee -a "$OUTPUT"
echo "" | tee -a "$OUTPUT"

# Name Servers
echo "=== Name Servers ===" | tee -a "$OUTPUT"
NS_SERVERS=$(dig +short "$DOMAIN" NS)
echo "$NS_SERVERS" | tee -a "$OUTPUT"
echo "" | tee -a "$OUTPUT"

# Mail Servers
echo "=== Mail Servers ===" | tee -a "$OUTPUT"
dig +short "$DOMAIN" MX | tee -a "$OUTPUT"
echo "" | tee -a "$OUTPUT"

# TXT Records
echo "=== TXT Records ===" | tee -a "$OUTPUT"
dig +short "$DOMAIN" TXT | tee -a "$OUTPUT"
echo "" | tee -a "$OUTPUT"

# SOA Record
echo "=== SOA Record ===" | tee -a "$OUTPUT"
dig +short "$DOMAIN" SOA | tee -a "$OUTPUT"
echo "" | tee -a "$OUTPUT"

# Zone Transfer Attempts
echo "=== Zone Transfer Attempts ===" | tee -a "$OUTPUT"
for ns in $NS_SERVERS; do
    echo "Trying zone transfer from: $ns" | tee -a "$OUTPUT"
    AXFR_RESULT=$(dig axfr @"$ns" "$DOMAIN" 2>&1)
    if echo "$AXFR_RESULT" | grep -q "Transfer failed"; then
        echo "  Transfer denied (expected)" | tee -a "$OUTPUT"
    elif echo "$AXFR_RESULT" | grep -q "ANSWER SECTION"; then
        echo "  ZONE TRANSFER SUCCESSFUL!" | tee -a "$OUTPUT"
        echo "$AXFR_RESULT" | tee -a "$OUTPUT"
    else
        echo "  No response or error" | tee -a "$OUTPUT"
    fi
done
echo "" | tee -a "$OUTPUT"

# Common Subdomain Checks
echo "=== Common Subdomain Check ===" | tee -a "$OUTPUT"
SUBDOMAINS="www mail ftp vpn remote admin portal api dev staging test uat beta prod internal intranet extranet webmail cloud ns1 ns2 mx smtp pop imap"

for sub in $SUBDOMAINS; do
    RESULT=$(dig +short "$sub.$DOMAIN" A 2>/dev/null)
    if [ -n "$RESULT" ]; then
        echo "$sub.$DOMAIN: $RESULT" | tee -a "$OUTPUT"
    fi
done
echo "" | tee -a "$OUTPUT"

# Reverse DNS for found IPs
echo "=== Reverse DNS Lookups ===" | tee -a "$OUTPUT"
FOUND_IPS=$(grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' "$OUTPUT" | sort -u)
for ip in $FOUND_IPS; do
    PTR=$(dig +short -x "$ip" 2>/dev/null)
    if [ -n "$PTR" ]; then
        echo "$ip -> $PTR" | tee -a "$OUTPUT"
    fi
done

echo "" | tee -a "$OUTPUT"
echo "=== Enumeration Complete ===" | tee -a "$OUTPUT"
echo "Results saved to: $OUTPUT"
```

Save to `~/scripts/dns_enum.sh`.

### DNSRecon

DNSRecon is a comprehensive DNS enumeration tool.

```bash
# Standard enumeration
dnsrecon -d example.com

# Zone transfer attempt
dnsrecon -d example.com -t axfr

# Brute force subdomains
dnsrecon -d example.com -t brt -D /usr/share/wordlists/dnsmap.txt

# Reverse lookup on range
dnsrecon -r 192.168.1.0/24

# Cache snooping
dnsrecon -d example.com -t snoop -D subdomains.txt -n ns1.example.com

# Output formats
dnsrecon -d example.com -x output.xml
dnsrecon -d example.com --csv output.csv
```

### DNSEnum

Another DNS enumeration tool with built-in features.

```bash
# Basic enumeration
dnsenum example.com

# With subdomain brute force
dnsenum --enum example.com

# Custom wordlist
dnsenum -f /path/to/wordlist.txt example.com

# Save output
dnsenum -o output.xml example.com
```

### Fierce

Fierce is designed for DNS reconnaissance.

```bash
# Basic scan
fierce --domain example.com

# With DNS server
fierce --domain example.com --dns-servers 8.8.8.8

# Custom wordlist
fierce --domain example.com --subdomain-file wordlist.txt
```

---

### Milestone 3 Checkpoint

Before proceeding, verify:

- [ ] You understand all DNS record types
- [ ] You can use dig effectively for DNS queries
- [ ] You can attempt zone transfers
- [ ] You can use DNSRecon and DNSEnum
- [ ] You have created the dns_enum.sh script
- [ ] You understand what information DNS reveals

**[CERT CHECKPOINT - PenTest+ 2.2 / CEH]**: DNS enumeration is a core skill.

---

## Part 4 — Subdomain Discovery (Milestone 4)

### Why Subdomains Matter

Subdomains often have:
- Weaker security than main domain
- Development/test environments
- Internal tools exposed
- Forgotten/unmaintained services
- Different technology stacks

### Subdomain Discovery Methods

```
┌─────────────────────────────────────────────────────────────────┐
│                  Subdomain Discovery Methods                     │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  PASSIVE METHODS                                                │
│  ├── Certificate Transparency logs                             │
│  ├── Search engine scraping                                     │
│  ├── VirusTotal                                                 │
│  ├── DNS aggregator databases                                   │
│  ├── GitHub/code repository search                              │
│  └── Wayback Machine                                            │
│                                                                  │
│  ACTIVE METHODS                                                 │
│  ├── DNS brute forcing                                          │
│  ├── Zone transfers                                             │
│  ├── Virtual host enumeration                                   │
│  └── DNS recursion/amplification                                │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

### Subdomain Brute Forcing

#### Gobuster

```bash
# DNS mode subdomain brute force
gobuster dns -d example.com -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt

# With custom resolver
gobuster dns -d example.com -w wordlist.txt -r 8.8.8.8

# Show IP addresses
gobuster dns -d example.com -w wordlist.txt -i

# Output to file
gobuster dns -d example.com -w wordlist.txt -o results.txt

# More threads (faster but noisier)
gobuster dns -d example.com -w wordlist.txt -t 50
```

#### Sublist3r

```bash
# Install if not present
sudo apt install sublist3r

# Basic usage
sublist3r -d example.com

# With brute force
sublist3r -d example.com -b

# Specific ports check
sublist3r -d example.com -p 80,443

# Output to file
sublist3r -d example.com -o subdomains.txt

# Verbose
sublist3r -d example.com -v
```

#### Amass

Amass is the most comprehensive subdomain tool (may need installation).

```bash
# Install amass
sudo apt install amass

# Passive enumeration (no direct contact)
amass enum -passive -d example.com

# Active enumeration
amass enum -d example.com

# With brute forcing
amass enum -brute -d example.com

# Output formats
amass enum -d example.com -o results.txt
amass enum -d example.com -json results.json

# Specify resolvers
amass enum -d example.com -rf resolvers.txt

# Use specific data sources
amass enum -d example.com -src

# Visualize
amass viz -d example.com -o graph.html
```

#### Subfinder

```bash
# Install subfinder
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest

# Basic usage
subfinder -d example.com

# All sources
subfinder -d example.com -all

# Output to file
subfinder -d example.com -o results.txt

# Silent mode (just results)
subfinder -d example.com -silent
```

### Combined Subdomain Discovery Script

```bash
#!/bin/bash
# subdomain_discovery.sh - Multi-method subdomain discovery

DOMAIN="${1:-}"
OUTPUT_DIR="${2:-$HOME/engagements/recon}"

if [ -z "$DOMAIN" ]; then
    echo "Usage: $0 <domain> [output_directory]"
    exit 1
fi

TIMESTAMP=$(date +%Y%m%d_%H%M%S)
OUTPUT_BASE="$OUTPUT_DIR/subdomains_${DOMAIN}_${TIMESTAMP}"
COMBINED="$OUTPUT_BASE/all_subdomains.txt"

mkdir -p "$OUTPUT_BASE"

echo "=== Subdomain Discovery: $DOMAIN ==="
echo "Output: $OUTPUT_BASE"
echo ""

# Method 1: Certificate Transparency
echo "[*] Method 1: Certificate Transparency (crt.sh)"
curl -s "https://crt.sh/?q=%25.$DOMAIN&output=json" 2>/dev/null | \
    jq -r '.[].name_value' 2>/dev/null | \
    sed 's/\*\.//g' | \
    sort -u > "$OUTPUT_BASE/crtsh.txt"
echo "    Found: $(wc -l < "$OUTPUT_BASE/crtsh.txt") subdomains"

# Method 2: DNS Brute Force (using common list)
echo "[*] Method 2: DNS Brute Force"
WORDLIST="/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt"
if [ -f "$WORDLIST" ]; then
    gobuster dns -d "$DOMAIN" -w "$WORDLIST" -q -o "$OUTPUT_BASE/gobuster.txt" 2>/dev/null
    echo "    Found: $(wc -l < "$OUTPUT_BASE/gobuster.txt" 2>/dev/null || echo 0) subdomains"
else
    echo "    Wordlist not found, skipping..."
fi

# Method 3: Sublist3r (if available)
echo "[*] Method 3: Sublist3r"
if command -v sublist3r &>/dev/null; then
    sublist3r -d "$DOMAIN" -o "$OUTPUT_BASE/sublist3r.txt" 2>/dev/null
    echo "    Found: $(wc -l < "$OUTPUT_BASE/sublist3r.txt" 2>/dev/null || echo 0) subdomains"
else
    echo "    Sublist3r not installed, skipping..."
fi

# Method 4: Amass passive (if available)
echo "[*] Method 4: Amass (passive)"
if command -v amass &>/dev/null; then
    timeout 300 amass enum -passive -d "$DOMAIN" -o "$OUTPUT_BASE/amass.txt" 2>/dev/null
    echo "    Found: $(wc -l < "$OUTPUT_BASE/amass.txt" 2>/dev/null || echo 0) subdomains"
else
    echo "    Amass not installed, skipping..."
fi

# Combine and deduplicate results
echo ""
echo "[*] Combining and deduplicating results..."
cat "$OUTPUT_BASE"/*.txt 2>/dev/null | \
    tr '[:upper:]' '[:lower:]' | \
    grep -E "^[a-z0-9]" | \
    grep "$DOMAIN" | \
    sort -u > "$COMBINED"

TOTAL=$(wc -l < "$COMBINED")
echo ""
echo "=== Results ==="
echo "Total unique subdomains: $TOTAL"
echo "Results saved to: $COMBINED"
echo ""
echo "=== Sample Results ==="
head -20 "$COMBINED"

# Resolve subdomains to IPs
echo ""
echo "[*] Resolving subdomains to IP addresses..."
while read -r subdomain; do
    IP=$(dig +short "$subdomain" A 2>/dev/null | head -1)
    if [ -n "$IP" ]; then
        echo "$subdomain,$IP"
    fi
done < "$COMBINED" > "$OUTPUT_BASE/resolved.csv"

echo "Resolved subdomains: $(wc -l < "$OUTPUT_BASE/resolved.csv")"
echo "Resolved results: $OUTPUT_BASE/resolved.csv"
```

Save to `~/scripts/subdomain_discovery.sh`.

### Wordlists for Subdomain Brute Forcing

**Key wordlists in Kali:**

```bash
# SecLists DNS wordlists
/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt
/usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt
/usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt
/usr/share/seclists/Discovery/DNS/bitquark-subdomains-top100000.txt

# DNSMap wordlist
/usr/share/dnsmap/wordlist_TLAs.txt

# Dirb wordlists (for web paths, but useful patterns)
/usr/share/wordlists/dirb/common.txt
```

**Install SecLists if not present:**

```bash
sudo apt install seclists
```

### Subdomain Takeover Vulnerability

When a subdomain points to an external service that's been decommissioned, attackers can claim it.

**Common vulnerable services:**
- GitHub Pages
- Heroku
- AWS S3
- Azure
- Shopify
- Fastly

**Signs of potential takeover:**
- CNAME to external service
- 404 or "not found" pages
- "There isn't a GitHub Pages site here"
- "NoSuchBucket" (AWS S3)

**Check script:**

```bash
#!/bin/bash
# subdomain_takeover_check.sh - Check for potential subdomain takeover

DOMAIN="${1:-}"

if [ -z "$DOMAIN" ]; then
    echo "Usage: $0 <domain_or_subdomain_file>"
    exit 1
fi

echo "=== Subdomain Takeover Check ==="

# Vulnerable fingerprints
declare -A FINGERPRINTS
FINGERPRINTS=(
    ["GitHub"]="There isn't a GitHub Pages site here"
    ["Heroku"]="No such app"
    ["AWS S3"]="NoSuchBucket"
    ["Shopify"]="Sorry, this shop is currently unavailable"
    ["Fastly"]="Fastly error: unknown domain"
    ["Pantheon"]="The gods are wise"
    ["Tumblr"]="There's nothing here"
    ["Ghost"]="The thing you were looking for is no longer here"
)

check_subdomain() {
    local sub="$1"
    
    # Get CNAME
    CNAME=$(dig +short CNAME "$sub" 2>/dev/null)
    
    if [ -n "$CNAME" ]; then
        # Check content
        CONTENT=$(curl -s -L -m 5 "http://$sub" 2>/dev/null)
        
        for service in "${!FINGERPRINTS[@]}"; do
            if echo "$CONTENT" | grep -qi "${FINGERPRINTS[$service]}"; then
                echo "[VULNERABLE] $sub -> $CNAME ($service)"
                return
            fi
        done
        
        echo "[CNAME] $sub -> $CNAME"
    fi
}

if [ -f "$DOMAIN" ]; then
    # File with list of subdomains
    while read -r sub; do
        check_subdomain "$sub"
    done < "$DOMAIN"
else
    # Single subdomain
    check_subdomain "$DOMAIN"
fi
```

Save to `~/scripts/subdomain_takeover_check.sh`.

---

### Milestone 4 Checkpoint

Before proceeding, verify:

- [ ] You understand why subdomains are valuable targets
- [ ] You can use multiple subdomain discovery tools
- [ ] You know where to find wordlists
- [ ] You understand subdomain takeover vulnerabilities
- [ ] You have created subdomain discovery scripts
- [ ] You can combine and deduplicate results

**[CERT CHECKPOINT - PenTest+ 2.2 / CEH]**: Subdomain enumeration is essential for thorough testing.

---

## Part 5 — Email and Employee Harvesting (Milestone 5)

### Why Harvest Emails and Employees?

| Use Case | Purpose |
|----------|---------|
| Phishing simulation | Identify targets |
| Password spraying | Guess usernames |
| Social engineering | Research individuals |
| Email format discovery | Generate valid addresses |
| OSINT profiling | Build target profiles |

### Email Format Discovery

Organizations use consistent email formats. Common patterns:

| Format | Example |
|--------|---------|
| first.last | john.doe@example.com |
| firstlast | johndoe@example.com |
| first_last | john_doe@example.com |
| flast | jdoe@example.com |
| firstl | johnd@example.com |
| first | john@example.com |
| last.first | doe.john@example.com |

**Once you know the format, you can generate emails for discovered employees.**

### Email Harvesting Tools

#### theHarvester (Emails Focus)

```bash
# Focus on email-rich sources
theHarvester -d example.com -b google,bing,linkedin

# Parse results for emails
theHarvester -d example.com -b all 2>/dev/null | grep "@"
```

#### Hunter.io (Web-based)

Hunter.io (https://hunter.io) provides:
- Email format detection
- Employee email discovery
- Email verification
- API access (limited free)

#### Phonebook.cz

Free email discovery service:

```bash
# Query phonebook.cz (web-based)
# Visit: https://phonebook.cz
# Search: @example.com
```

### LinkedIn Reconnaissance

LinkedIn is a goldmine for employee information:

**Manual approach:**
1. Search for company
2. View employees
3. Note names, roles, departments
4. Cross-reference with email format

**Tools:**

```bash
# theHarvester LinkedIn
theHarvester -d example.com -b linkedin

# CrossLinked (dedicated tool)
# https://github.com/m8sec/CrossLinked
```

### Email Harvesting Script

```bash
#!/bin/bash
# email_harvester.sh - Harvest emails from multiple sources

DOMAIN="${1:-}"
OUTPUT_DIR="${2:-$HOME/engagements/recon}"

if [ -z "$DOMAIN" ]; then
    echo "Usage: $0 <domain> [output_directory]"
    exit 1
fi

TIMESTAMP=$(date +%Y%m%d_%H%M%S)
OUTPUT="$OUTPUT_DIR/emails_${DOMAIN}_${TIMESTAMP}.txt"

mkdir -p "$OUTPUT_DIR"

echo "=== Email Harvesting: $DOMAIN ==="
echo ""

# Temporary file
TEMP_FILE=$(mktemp)

# Method 1: theHarvester
echo "[*] Running theHarvester..."
theHarvester -d "$DOMAIN" -b google,bing 2>/dev/null | \
    grep -oE '[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}' >> "$TEMP_FILE"

# Method 2: Search engine scraping
echo "[*] Searching Google..."
curl -s "https://www.google.com/search?q=%40$DOMAIN&num=100" 2>/dev/null | \
    grep -oE '[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}' >> "$TEMP_FILE"

# Method 3: Website scraping
echo "[*] Scraping main website..."
curl -s "https://$DOMAIN" 2>/dev/null | \
    grep -oE '[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}' >> "$TEMP_FILE"

curl -s "https://www.$DOMAIN/contact" 2>/dev/null | \
    grep -oE '[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}' >> "$TEMP_FILE"

curl -s "https://www.$DOMAIN/about" 2>/dev/null | \
    grep -oE '[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}' >> "$TEMP_FILE"

# Deduplicate and filter to target domain
cat "$TEMP_FILE" | \
    tr '[:upper:]' '[:lower:]' | \
    sort -u | \
    grep "@$DOMAIN" > "$OUTPUT"

rm "$TEMP_FILE"

echo ""
echo "=== Results ==="
echo "Emails found: $(wc -l < "$OUTPUT")"
echo ""

if [ -s "$OUTPUT" ]; then
    echo "=== Email Addresses ==="
    cat "$OUTPUT"
    
    echo ""
    echo "=== Email Format Analysis ==="
    # Try to detect format
    if head -1 "$OUTPUT" | grep -qE '^[a-z]+\.[a-z]+@'; then
        echo "Likely format: first.last@$DOMAIN"
    elif head -1 "$OUTPUT" | grep -qE '^[a-z][a-z]+@'; then
        echo "Likely format: flast@$DOMAIN or first@$DOMAIN"
    else
        echo "Format unclear - manual analysis needed"
    fi
fi

echo ""
echo "Results saved to: $OUTPUT"
```

Save to `~/scripts/email_harvester.sh`.

### Generate Email List from Names

Once you have employee names and the email format:

```bash
#!/bin/bash
# generate_emails.sh - Generate email addresses from names

NAMES_FILE="${1:-}"
DOMAIN="${2:-}"
FORMAT="${3:-first.last}"

if [ -z "$NAMES_FILE" ] || [ -z "$DOMAIN" ]; then
    echo "Usage: $0 <names_file> <domain> [format]"
    echo ""
    echo "Formats:"
    echo "  first.last    -> john.doe@domain.com"
    echo "  firstlast     -> johndoe@domain.com"
    echo "  flast         -> jdoe@domain.com"
    echo "  first         -> john@domain.com"
    echo "  lastfirst     -> doejohn@domain.com"
    echo "  last.first    -> doe.john@domain.com"
    exit 1
fi

while read -r line; do
    # Skip empty lines
    [ -z "$line" ] && continue
    
    # Parse first and last name
    FIRST=$(echo "$line" | awk '{print tolower($1)}')
    LAST=$(echo "$line" | awk '{print tolower($NF)}')
    
    [ -z "$FIRST" ] || [ -z "$LAST" ] && continue
    
    case "$FORMAT" in
        first.last)
            echo "${FIRST}.${LAST}@${DOMAIN}"
            ;;
        firstlast)
            echo "${FIRST}${LAST}@${DOMAIN}"
            ;;
        flast)
            echo "${FIRST:0:1}${LAST}@${DOMAIN}"
            ;;
        first)
            echo "${FIRST}@${DOMAIN}"
            ;;
        lastfirst)
            echo "${LAST}${FIRST}@${DOMAIN}"
            ;;
        last.first)
            echo "${LAST}.${FIRST}@${DOMAIN}"
            ;;
        *)
            echo "Unknown format: $FORMAT"
            exit 1
            ;;
    esac
done < "$NAMES_FILE"
```

Save to `~/scripts/generate_emails.sh`.

### Document Metadata Harvesting

Documents often contain metadata revealing:
- Author names
- Software versions
- Internal paths
- Usernames

```bash
# Using exiftool
exiftool document.pdf

# Batch process
exiftool *.pdf *.doc *.docx

# Extract specific fields
exiftool -Author -Creator -Producer -ModifyDate file.pdf

# Download and analyze PDFs from a site
wget -r -l 1 -A pdf https://example.com/
exiftool *.pdf | grep -i "author\|creator\|producer"
```

**Metadata harvesting script:**

```bash
#!/bin/bash
# metadata_harvest.sh - Download and extract document metadata

DOMAIN="${1:-}"
OUTPUT_DIR="${2:-$HOME/engagements/recon/metadata}"

if [ -z "$DOMAIN" ]; then
    echo "Usage: $0 <domain> [output_directory]"
    exit 1
fi

mkdir -p "$OUTPUT_DIR"

echo "=== Document Metadata Harvesting: $DOMAIN ==="
echo ""

# Download documents
echo "[*] Downloading documents..."
cd "$OUTPUT_DIR"

# Download PDFs
wget -q -r -l 1 -A pdf "https://$DOMAIN/" 2>/dev/null || true
wget -q -r -l 1 -A pdf "https://www.$DOMAIN/" 2>/dev/null || true

# Download Office docs
wget -q -r -l 1 -A doc,docx,xls,xlsx,ppt,pptx "https://$DOMAIN/" 2>/dev/null || true

# Find downloaded files
DOCS=$(find . -type f \( -name "*.pdf" -o -name "*.doc*" -o -name "*.xls*" -o -name "*.ppt*" \) 2>/dev/null)

if [ -z "$DOCS" ]; then
    echo "No documents found to analyze"
    exit 0
fi

echo ""
echo "[*] Analyzing metadata..."
echo ""

# Extract metadata
for doc in $DOCS; do
    echo "=== $doc ===" >> metadata_report.txt
    exiftool "$doc" >> metadata_report.txt 2>/dev/null
    echo "" >> metadata_report.txt
done

# Extract usernames/authors
echo "=== Discovered Authors/Creators ===" 
grep -hiE "^(Author|Creator|Last Modified By)" metadata_report.txt | \
    sort -u | \
    tee authors.txt

echo ""
echo "Results saved to: $OUTPUT_DIR/metadata_report.txt"
echo "Authors list: $OUTPUT_DIR/authors.txt"
```

Save to `~/scripts/metadata_harvest.sh`.

---

### Milestone 5 Checkpoint

Before proceeding, verify:

- [ ] You understand email format discovery
- [ ] You can use theHarvester for emails
- [ ] You understand LinkedIn reconnaissance
- [ ] You can extract document metadata
- [ ] You have created email harvesting scripts
- [ ] You can generate email lists from names

**[CERT CHECKPOINT - PenTest+ 2.1 / CEH]**: Email/employee harvesting supports social engineering and password attacks.

---

## Part 6 — Active Reconnaissance (Milestone 6)

### Transitioning to Active Recon

Now we directly interact with target systems. **This requires authorization!**

### Host Discovery

#### Ping Sweep

```bash
# Using nmap
nmap -sn 192.168.56.0/24

# Using fping
fping -a -g 192.168.56.0/24 2>/dev/null

# Bash script
for ip in $(seq 1 254); do
    ping -c 1 -W 1 192.168.56.$ip &>/dev/null && echo "192.168.56.$ip is up"
done
```

#### ARP Scan (Local Network)

```bash
# Most reliable for local networks
sudo arp-scan -l

# Specific interface
sudo arp-scan -I eth1 192.168.56.0/24
```

### Port Scanning with Nmap

Nmap is the essential port scanning tool.

#### Basic Scans

```bash
# Default scan (top 1000 ports)
nmap 192.168.56.101

# All ports
nmap -p- 192.168.56.101

# Specific ports
nmap -p 22,80,443 192.168.56.101

# Port range
nmap -p 1-1000 192.168.56.101

# Fast scan (top 100)
nmap -F 192.168.56.101

# UDP scan (slow but important)
sudo nmap -sU 192.168.56.101

# Combined TCP and UDP
sudo nmap -sS -sU 192.168.56.101
```

#### Scan Types

```bash
# TCP SYN scan (default, stealthy)
sudo nmap -sS 192.168.56.101

# TCP Connect scan (no root needed)
nmap -sT 192.168.56.101

# UDP scan
sudo nmap -sU 192.168.56.101

# FIN scan (stealthy)
sudo nmap -sF 192.168.56.101

# NULL scan
sudo nmap -sN 192.168.56.101

# XMAS scan
sudo nmap -sX 192.168.56.101

# ACK scan (firewall detection)
sudo nmap -sA 192.168.56.101

# Window scan
sudo nmap -sW 192.168.56.101
```

#### Version and OS Detection

```bash
# Service version detection
nmap -sV 192.168.56.101

# Operating system detection
sudo nmap -O 192.168.56.101

# Aggressive scan (OS, version, scripts, traceroute)
nmap -A 192.168.56.101

# Version intensity (0-9, higher = more probes)
nmap -sV --version-intensity 5 192.168.56.101
```

#### Nmap Scripting Engine (NSE)

```bash
# Default scripts
nmap -sC 192.168.56.101

# Specific script
nmap --script=http-title 192.168.56.101

# Script category
nmap --script=vuln 192.168.56.101
nmap --script=safe 192.168.56.101

# Multiple scripts
nmap --script=http-title,http-headers 192.168.56.101

# Wildcard matching
nmap --script="http-*" 192.168.56.101

# List available scripts
ls /usr/share/nmap/scripts/
nmap --script-help=http-title
```

**Important NSE Categories:**

| Category | Purpose |
|----------|---------|
| `auth` | Authentication bypass/testing |
| `broadcast` | Discover hosts via broadcast |
| `brute` | Brute force attacks |
| `default` | Default scripts (`-sC`) |
| `discovery` | Information gathering |
| `dos` | Denial of service (use carefully!) |
| `exploit` | Active exploitation |
| `external` | Use external resources |
| `fuzzer` | Fuzzing |
| `intrusive` | May crash services |
| `malware` | Malware detection |
| `safe` | Won't crash services |
| `version` | Version detection |
| `vuln` | Vulnerability detection |

#### Output Formats

```bash
# Normal output
nmap 192.168.56.101 -oN scan.txt

# Grepable output
nmap 192.168.56.101 -oG scan.gnmap

# XML output
nmap 192.168.56.101 -oX scan.xml

# All formats
nmap 192.168.56.101 -oA scan_results

# Verbose/Debug
nmap -v 192.168.56.101
nmap -vv 192.168.56.101
nmap -d 192.168.56.101
```

#### Timing Templates

```bash
# T0 - Paranoid (IDS evasion)
nmap -T0 192.168.56.101

# T1 - Sneaky
nmap -T1 192.168.56.101

# T2 - Polite
nmap -T2 192.168.56.101

# T3 - Normal (default)
nmap -T3 192.168.56.101

# T4 - Aggressive
nmap -T4 192.168.56.101

# T5 - Insane (fast but may miss)
nmap -T5 192.168.56.101
```

### Comprehensive Nmap Scan Script

```bash
#!/bin/bash
# full_nmap_scan.sh - Comprehensive nmap scanning workflow

TARGET="${1:-}"
OUTPUT_DIR="${2:-$HOME/engagements/scanning}"

if [ -z "$TARGET" ]; then
    echo "Usage: $0 <target_ip_or_range> [output_directory]"
    echo ""
    echo "Examples:"
    echo "  $0 192.168.56.101"
    echo "  $0 192.168.56.0/24"
    exit 1
fi

TIMESTAMP=$(date +%Y%m%d_%H%M%S)
SCAN_DIR="$OUTPUT_DIR/nmap_${TARGET/\//_}_${TIMESTAMP}"

mkdir -p "$SCAN_DIR"

echo "=== Comprehensive Nmap Scan ==="
echo "Target: $TARGET"
echo "Output: $SCAN_DIR"
echo ""

# Phase 1: Host Discovery
echo "[Phase 1] Host Discovery..."
sudo nmap -sn "$TARGET" -oA "$SCAN_DIR/01_host_discovery"
LIVE_HOSTS=$(grep "Up" "$SCAN_DIR/01_host_discovery.gnmap" | awk '{print $2}')
echo "Live hosts: $(echo "$LIVE_HOSTS" | wc -w)"
echo ""

# Phase 2: Quick Port Scan
echo "[Phase 2] Quick Port Scan (top 1000)..."
sudo nmap -sS -T4 "$TARGET" -oA "$SCAN_DIR/02_quick_scan"
echo ""

# Phase 3: Full Port Scan (may take a while)
echo "[Phase 3] Full Port Scan (all 65535 ports)..."
echo "This may take several minutes..."
sudo nmap -sS -p- -T4 "$TARGET" -oA "$SCAN_DIR/03_full_port_scan"

# Extract open ports
OPEN_PORTS=$(grep "open" "$SCAN_DIR/03_full_port_scan.gnmap" | \
    grep -oE '[0-9]+/open' | \
    cut -d'/' -f1 | \
    sort -un | \
    tr '\n' ',' | \
    sed 's/,$//')
echo "Open ports: $OPEN_PORTS"
echo ""

# Phase 4: Service Version Detection
echo "[Phase 4] Service Version Detection..."
if [ -n "$OPEN_PORTS" ]; then
    sudo nmap -sV -sC -p "$OPEN_PORTS" "$TARGET" -oA "$SCAN_DIR/04_service_versions"
else
    echo "No open ports found, skipping..."
fi
echo ""

# Phase 5: UDP Scan (top 20 ports)
echo "[Phase 5] UDP Scan (top 20)..."
sudo nmap -sU --top-ports 20 -T4 "$TARGET" -oA "$SCAN_DIR/05_udp_scan"
echo ""

# Phase 6: Vulnerability Scan
echo "[Phase 6] Vulnerability Scan..."
if [ -n "$OPEN_PORTS" ]; then
    sudo nmap --script=vuln -p "$OPEN_PORTS" "$TARGET" -oA "$SCAN_DIR/06_vuln_scan"
else
    echo "No open ports, skipping vuln scan..."
fi
echo ""

# Generate Summary
echo "[*] Generating summary..."
cat << EOF > "$SCAN_DIR/SUMMARY.txt"
=== Nmap Scan Summary ===
Target: $TARGET
Date: $(date)

=== Live Hosts ===
$LIVE_HOSTS

=== Open Ports ===
$OPEN_PORTS

=== Scan Files ===
$(ls -la "$SCAN_DIR")
EOF

echo ""
echo "=== Scan Complete ==="
echo "Results saved to: $SCAN_DIR"
echo ""
echo "Quick view of open ports:"
grep "open" "$SCAN_DIR/03_full_port_scan.nmap" | head -20
```

Save to `~/scripts/full_nmap_scan.sh`.

### Banner Grabbing

Get detailed information from services.

```bash
# Using netcat
nc -v 192.168.56.101 22
nc -v 192.168.56.101 80

# HTTP banner
echo -e "HEAD / HTTP/1.0\r\n\r\n" | nc 192.168.56.101 80

# Using nmap
nmap -sV --script=banner 192.168.56.101

# Using telnet
telnet 192.168.56.101 25
```

### Web Server Reconnaissance

```bash
# HTTP headers
curl -I http://192.168.56.101

# Follow redirects
curl -I -L http://192.168.56.101

# Verbose connection info
curl -v http://192.168.56.101 2>&1 | head -30

# Identify technologies
whatweb http://192.168.56.101

# Nikto scan
nikto -h http://192.168.56.101
```

---

### Milestone 6 Checkpoint

Before proceeding, verify:

- [ ] You can perform host discovery
- [ ] You understand different nmap scan types
- [ ] You can use NSE scripts effectively
- [ ] You can interpret nmap output
- [ ] You can perform banner grabbing
- [ ] You have created the full_nmap_scan.sh script

**[CERT CHECKPOINT - PenTest+ 2.2-2.3 / CEH]**: Nmap mastery is essential.

---

## Part 7 — Network Mapping (Milestone 7)

### Building the Network Picture

Network mapping creates a complete view of the target infrastructure.

### Identifying Network Ranges

```bash
# WHOIS for IP ranges
whois 1.2.3.4

# ASN lookup
whois -h whois.radb.net -- '-i origin AS12345'

# Using nmap
nmap --script=asn-query 1.2.3.4

# BGP info
curl -s "https://api.bgpview.io/ip/1.2.3.4" | jq
```

### Traceroute Analysis

```bash
# Standard traceroute
traceroute target.com

# TCP traceroute (bypass ICMP blocking)
sudo traceroute -T target.com

# UDP traceroute
traceroute -U target.com

# Increase max hops
traceroute -m 30 target.com

# Don't resolve hostnames (faster)
traceroute -n target.com
```

### Network Topology Discovery

```bash
# Discover network boundaries
# Look for IP address patterns, consistent naming, etc.

# Example: Scan a /24 and identify active hosts
nmap -sn 192.168.56.0/24 -oG - | grep "Up" | awk '{print $2}'

# Identify common infrastructure
nmap -sV -p 53,67,68,80,443 192.168.56.0/24
```

### Create Network Map Script

```bash
#!/bin/bash
# network_map.sh - Map network infrastructure

NETWORK="${1:-}"
OUTPUT_DIR="${2:-$HOME/engagements/recon}"

if [ -z "$NETWORK" ]; then
    echo "Usage: $0 <network_cidr> [output_directory]"
    echo "Example: $0 192.168.56.0/24"
    exit 1
fi

TIMESTAMP=$(date +%Y%m%d_%H%M%S)
MAP_DIR="$OUTPUT_DIR/network_map_${NETWORK/\//_}_${TIMESTAMP}"

mkdir -p "$MAP_DIR"

echo "=== Network Mapping: $NETWORK ==="
echo ""

# Host Discovery
echo "[*] Discovering live hosts..."
sudo nmap -sn "$NETWORK" -oG "$MAP_DIR/hosts.gnmap"
HOSTS=$(grep "Up" "$MAP_DIR/hosts.gnmap" | awk '{print $2}')
echo "$HOSTS" > "$MAP_DIR/live_hosts.txt"
echo "Found $(wc -l < "$MAP_DIR/live_hosts.txt") live hosts"
echo ""

# Service Detection on Live Hosts
echo "[*] Identifying services..."
for host in $HOSTS; do
    echo "  Scanning $host..."
    nmap -sV -F "$host" -oN "$MAP_DIR/services_${host}.txt" 2>/dev/null
done
echo ""

# Identify Infrastructure Roles
echo "[*] Identifying infrastructure roles..."
{
    echo "=== Infrastructure Analysis ==="
    echo ""
    
    echo "=== Potential Routers/Gateways (port 22, 23, 80, 443) ==="
    grep -l "22/open\|23/open" "$MAP_DIR"/services_*.txt 2>/dev/null | \
        sed 's/.*services_//;s/.txt//'
    
    echo ""
    echo "=== Web Servers (port 80, 443) ==="
    grep -l "80/open\|443/open" "$MAP_DIR"/services_*.txt 2>/dev/null | \
        sed 's/.*services_//;s/.txt//'
    
    echo ""
    echo "=== Database Servers (port 3306, 5432, 1433) ==="
    grep -l "3306/open\|5432/open\|1433/open" "$MAP_DIR"/services_*.txt 2>/dev/null | \
        sed 's/.*services_//;s/.txt//'
    
    echo ""
    echo "=== Mail Servers (port 25, 110, 143) ==="
    grep -l "25/open\|110/open\|143/open" "$MAP_DIR"/services_*.txt 2>/dev/null | \
        sed 's/.*services_//;s/.txt//'
    
    echo ""
    echo "=== DNS Servers (port 53) ==="
    grep -l "53/open" "$MAP_DIR"/services_*.txt 2>/dev/null | \
        sed 's/.*services_//;s/.txt//'
        
} > "$MAP_DIR/infrastructure_analysis.txt"

cat "$MAP_DIR/infrastructure_analysis.txt"

# Generate simple text diagram
echo "" 
echo "[*] Generating network diagram..."
{
    echo "Network: $NETWORK"
    echo "Scan Date: $(date)"
    echo ""
    echo "Live Hosts:"
    echo "-----------"
    for host in $HOSTS; do
        SERVICES=$(grep "open" "$MAP_DIR/services_${host}.txt" 2>/dev/null | \
            awk '{print $1}' | \
            cut -d'/' -f1 | \
            tr '\n' ',' | \
            sed 's/,$//')
        echo "  $host [$SERVICES]"
    done
} > "$MAP_DIR/network_diagram.txt"

echo ""
echo "=== Mapping Complete ==="
echo "Results: $MAP_DIR"
```

Save to `~/scripts/network_map.sh`.

### Target Profile Template

```bash
cat << 'EOF' > ~/templates/target_profile.md
# Target Profile

## Organization Information
- **Name:** 
- **Industry:** 
- **Website:** 
- **Locations:** 

## Network Information
- **Primary Domain:** 
- **IP Ranges:** 
- **ASN:** 
- **Hosting Provider:** 
- **CDN:** 

## DNS Information
- **Name Servers:** 
- **Mail Servers:** 
- **Notable Records:** 

## Subdomains Discovered
| Subdomain | IP Address | Technology | Notes |
|-----------|------------|------------|-------|
| | | | |

## Web Technologies
| URL | Server | Framework | CMS | Notes |
|-----|--------|-----------|-----|-------|
| | | | | |

## Email Information
- **Email Format:** 
- **Discovered Emails:** 

## Key Personnel
| Name | Role | Email | Social Media |
|------|------|-------|--------------|
| | | | |

## Open Ports/Services
| IP | Port | Service | Version | Notes |
|----|------|---------|---------|-------|
| | | | | |

## Potential Attack Vectors
1. 
2. 
3. 

## Notes
- 
- 
- 

EOF

echo "Created: ~/templates/target_profile.md"
```

---

### Milestone 7 Checkpoint

Before proceeding, verify:

- [ ] You can identify network ranges
- [ ] You can use traceroute effectively
- [ ] You can map network topology
- [ ] You can identify infrastructure roles
- [ ] You have created the network_map.sh script
- [ ] You have created the target_profile template

**[CERT CHECKPOINT - PenTest+ 2.2 / CEH]**: Network mapping provides the complete attack surface.

---

## Part 8 — Automation and Scripting (Milestone 8)

### Why Automate Reconnaissance?

| Benefit | Description |
|---------|-------------|
| Consistency | Same process every time |
| Speed | Multiple tools in parallel |
| Coverage | Nothing missed |
| Documentation | Automatic logging |
| Repeatability | Easy to re-run |

### Master Reconnaissance Script

This script combines all techniques into one workflow:

```bash
#!/bin/bash
# master_recon.sh - Comprehensive automated reconnaissance

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
TARGET="${1:-}"
OUTPUT_DIR="${2:-$HOME/engagements}"

if [ -z "$TARGET" ]; then
    echo -e "${RED}Usage: $0 <target_domain> [output_directory]${NC}"
    echo ""
    echo "This script performs comprehensive reconnaissance including:"
    echo "  - WHOIS lookup"
    echo "  - DNS enumeration"
    echo "  - Subdomain discovery"
    echo "  - Email harvesting"
    echo "  - Web technology identification"
    echo "  - Certificate transparency"
    echo ""
    echo "Example: $0 example.com ~/engagements"
    exit 1
fi

# Setup
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
ENGAGEMENT_DIR="$OUTPUT_DIR/recon_${TARGET}_${TIMESTAMP}"
LOG_FILE="$ENGAGEMENT_DIR/recon.log"

mkdir -p "$ENGAGEMENT_DIR"/{passive,active,subdomains,emails,web,reports}

# Logging function
log() {
    echo -e "$1" | tee -a "$LOG_FILE"
}

# Banner
echo ""
log "${BLUE}╔══════════════════════════════════════════════════════════════╗${NC}"
log "${BLUE}║           MASTER RECONNAISSANCE FRAMEWORK                    ║${NC}"
log "${BLUE}╚══════════════════════════════════════════════════════════════╝${NC}"
log ""
log "${GREEN}Target: $TARGET${NC}"
log "${GREEN}Output: $ENGAGEMENT_DIR${NC}"
log "${GREEN}Started: $(date)${NC}"
log ""

# ============================================================
# PHASE 1: PASSIVE RECONNAISSANCE
# ============================================================
log "${YELLOW}[PHASE 1] PASSIVE RECONNAISSANCE${NC}"
log "================================================"

# WHOIS
log "${BLUE}[1.1] WHOIS Lookup...${NC}"
whois "$TARGET" > "$ENGAGEMENT_DIR/passive/whois.txt" 2>&1
log "  Saved: passive/whois.txt"

# DNS Records
log "${BLUE}[1.2] DNS Enumeration...${NC}"
{
    echo "=== A Records ==="
    dig +short "$TARGET" A
    echo ""
    echo "=== AAAA Records ==="
    dig +short "$TARGET" AAAA
    echo ""
    echo "=== MX Records ==="
    dig +short "$TARGET" MX
    echo ""
    echo "=== NS Records ==="
    dig +short "$TARGET" NS
    echo ""
    echo "=== TXT Records ==="
    dig +short "$TARGET" TXT
    echo ""
    echo "=== SOA Record ==="
    dig +short "$TARGET" SOA
} > "$ENGAGEMENT_DIR/passive/dns_records.txt"
log "  Saved: passive/dns_records.txt"

# Certificate Transparency
log "${BLUE}[1.3] Certificate Transparency...${NC}"
curl -s "https://crt.sh/?q=%25.$TARGET&output=json" 2>/dev/null | \
    jq -r '.[].name_value' 2>/dev/null | \
    sed 's/\*\.//g' | \
    sort -u > "$ENGAGEMENT_DIR/subdomains/crtsh.txt"
CT_COUNT=$(wc -l < "$ENGAGEMENT_DIR/subdomains/crtsh.txt")
log "  Found: $CT_COUNT entries from crt.sh"

# ============================================================
# PHASE 2: SUBDOMAIN DISCOVERY
# ============================================================
log ""
log "${YELLOW}[PHASE 2] SUBDOMAIN DISCOVERY${NC}"
log "================================================"

# Sublist3r (if available)
log "${BLUE}[2.1] Sublist3r...${NC}"
if command -v sublist3r &>/dev/null; then
    sublist3r -d "$TARGET" -o "$ENGAGEMENT_DIR/subdomains/sublist3r.txt" 2>/dev/null
    log "  Saved: subdomains/sublist3r.txt"
else
    log "  ${RED}Sublist3r not installed, skipping...${NC}"
fi

# DNS Brute Force (small wordlist for speed)
log "${BLUE}[2.2] DNS Brute Force...${NC}"
WORDLIST="/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt"
if [ -f "$WORDLIST" ]; then
    gobuster dns -d "$TARGET" -w "$WORDLIST" -q -o "$ENGAGEMENT_DIR/subdomains/gobuster.txt" 2>/dev/null
    log "  Saved: subdomains/gobuster.txt"
else
    log "  ${RED}Wordlist not found, skipping...${NC}"
fi

# Combine subdomains
log "${BLUE}[2.3] Combining subdomain results...${NC}"
cat "$ENGAGEMENT_DIR"/subdomains/*.txt 2>/dev/null | \
    tr '[:upper:]' '[:lower:]' | \
    grep -E "^[a-z0-9]" | \
    grep "$TARGET" | \
    sort -u > "$ENGAGEMENT_DIR/subdomains/all_subdomains.txt"
TOTAL_SUBS=$(wc -l < "$ENGAGEMENT_DIR/subdomains/all_subdomains.txt")
log "  Total unique subdomains: $TOTAL_SUBS"

# Resolve subdomains
log "${BLUE}[2.4] Resolving subdomains...${NC}"
while read -r sub; do
    IP=$(dig +short "$sub" A 2>/dev/null | head -1)
    if [ -n "$IP" ]; then
        echo "$sub,$IP"
    fi
done < "$ENGAGEMENT_DIR/subdomains/all_subdomains.txt" > "$ENGAGEMENT_DIR/subdomains/resolved.csv"
RESOLVED=$(wc -l < "$ENGAGEMENT_DIR/subdomains/resolved.csv")
log "  Resolved: $RESOLVED subdomains"

# ============================================================
# PHASE 3: EMAIL HARVESTING
# ============================================================
log ""
log "${YELLOW}[PHASE 3] EMAIL HARVESTING${NC}"
log "================================================"

log "${BLUE}[3.1] theHarvester...${NC}"
theHarvester -d "$TARGET" -b google,bing 2>/dev/null | \
    grep -oE '[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}' | \
    sort -u > "$ENGAGEMENT_DIR/emails/harvested.txt"
EMAIL_COUNT=$(wc -l < "$ENGAGEMENT_DIR/emails/harvested.txt")
log "  Found: $EMAIL_COUNT emails"

# ============================================================
# PHASE 4: WEB RECONNAISSANCE
# ============================================================
log ""
log "${YELLOW}[PHASE 4] WEB RECONNAISSANCE${NC}"
log "================================================"

log "${BLUE}[4.1] Technology Identification...${NC}"
# Check main domain and www
for url in "https://$TARGET" "https://www.$TARGET" "http://$TARGET"; do
    log "  Checking: $url"
    {
        echo "=== $url ==="
        whatweb "$url" 2>/dev/null
        echo ""
    } >> "$ENGAGEMENT_DIR/web/technologies.txt"
done

log "${BLUE}[4.2] HTTP Headers...${NC}"
curl -sI "https://$TARGET" > "$ENGAGEMENT_DIR/web/headers.txt" 2>&1
curl -sI "https://www.$TARGET" >> "$ENGAGEMENT_DIR/web/headers.txt" 2>&1
log "  Saved: web/headers.txt"

# ============================================================
# PHASE 5: GENERATE REPORT
# ============================================================
log ""
log "${YELLOW}[PHASE 5] GENERATING REPORT${NC}"
log "================================================"

{
    echo "# Reconnaissance Report: $TARGET"
    echo "Generated: $(date)"
    echo ""
    echo "## Summary"
    echo "- Subdomains discovered: $TOTAL_SUBS"
    echo "- Subdomains resolved: $RESOLVED"
    echo "- Emails found: $EMAIL_COUNT"
    echo ""
    echo "## DNS Records"
    cat "$ENGAGEMENT_DIR/passive/dns_records.txt"
    echo ""
    echo "## Subdomains (Top 20)"
    head -20 "$ENGAGEMENT_DIR/subdomains/all_subdomains.txt"
    echo ""
    echo "## Emails Found"
    cat "$ENGAGEMENT_DIR/emails/harvested.txt"
    echo ""
    echo "## Web Technologies"
    cat "$ENGAGEMENT_DIR/web/technologies.txt"
    echo ""
} > "$ENGAGEMENT_DIR/reports/summary.md"

log "  Report saved: reports/summary.md"

# ============================================================
# COMPLETION
# ============================================================
log ""
log "${GREEN}╔══════════════════════════════════════════════════════════════╗${NC}"
log "${GREEN}║                    RECONNAISSANCE COMPLETE                    ║${NC}"
log "${GREEN}╚══════════════════════════════════════════════════════════════╝${NC}"
log ""
log "Results saved to: $ENGAGEMENT_DIR"
log "Log file: $LOG_FILE"
log "Completed: $(date)"
log ""

# Display quick summary
echo ""
echo "=== Quick Summary ==="
echo "Subdomains: $TOTAL_SUBS"
echo "Resolved: $RESOLVED"
echo "Emails: $EMAIL_COUNT"
echo ""
echo "Key files:"
echo "  - subdomains/all_subdomains.txt"
echo "  - subdomains/resolved.csv"
echo "  - emails/harvested.txt"
echo "  - reports/summary.md"
```

Save to `~/scripts/master_recon.sh`.

### Quick Recon One-Liner Collection

```bash
cat << 'EOF' > ~/notes/recon_oneliners.md
# Reconnaissance One-Liners

## Subdomain Discovery
```bash
# Certificate transparency
curl -s "https://crt.sh/?q=%25.DOMAIN&output=json" | jq -r '.[].name_value' | sort -u

# Quick subdomain brute
gobuster dns -d DOMAIN -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -q
```

## DNS
```bash
# All records
dig DOMAIN ANY +noall +answer

# Zone transfer attempt
dig axfr @$(dig +short NS DOMAIN | head -1) DOMAIN
```

## Email Discovery
```bash
# theHarvester quick
theHarvester -d DOMAIN -b google -l 100 2>/dev/null | grep @
```

## Web Recon
```bash
# Headers
curl -sI https://DOMAIN | grep -iE "server|x-powered|x-aspnet"

# Technology stack
whatweb -q https://DOMAIN
```

## IP/ASN
```bash
# IP to ASN
whois -h whois.cymru.com " -v $(dig +short DOMAIN)"

# Organization IP ranges
whois -h whois.radb.net -- '-i origin ASXXXX'
```
EOF

echo "Created: ~/notes/recon_oneliners.md"
```

---

### Milestone 8 Checkpoint

Before proceeding, verify:

- [ ] You understand the value of automation
- [ ] You have created the master_recon.sh script
- [ ] You can customize scripts for specific needs
- [ ] You have created the one-liner reference
- [ ] You can run comprehensive automated recon

**[CERT CHECKPOINT - PenTest+ 2.0]**: Automation skills make you more efficient and thorough.

---

## Stage 05 Assessment

### Written Assessment

Answer these questions in `~/notes/stage05_assessment.txt`:

1. Explain the difference between passive and active reconnaissance with two examples of each.

2. What information can you obtain from a WHOIS lookup?

3. Name five Google dork operators and explain what each does.

4. What is certificate transparency and how is it useful for reconnaissance?

5. List four methods for discovering subdomains and explain when you would use each.

6. What nmap scan type would you use to be stealthy? What about when you need to scan quickly?

7. Explain what a DNS zone transfer is and why it's valuable.

8. What is the purpose of the NSE (Nmap Scripting Engine)?

9. How would you identify the email format used by an organization?

10. Why is it important to document all reconnaissance findings?

### Practical Assessment

Complete these tasks on your **Metasploitable** target:

1. **Passive Recon Simulation:**
   - Since Metasploitable is local, simulate passive recon by running:
   - DNS enumeration
   - Document what you would look for in a real engagement

2. **Active Reconnaissance:**
   - Perform a complete nmap scan
   - Identify all open ports and services
   - Document version information for each service

3. **Network Mapping:**
   - Map your lab network
   - Identify all hosts
   - Document infrastructure roles

4. **Documentation:**
   - Create a target profile for Metasploitable
   - Use the template and fill in all available information
   - Generate a summary report

---

## Stage 05 Completion Checklist

### Passive Reconnaissance
- [ ] Understand passive vs. active recon
- [ ] Can use Google dorks effectively
- [ ] Created google_dorks_reference.md
- [ ] Understand OSINT workflow

### OSINT Tools
- [ ] Can perform WHOIS lookups
- [ ] Can use theHarvester
- [ ] Understand recon-ng basics
- [ ] Can query certificate transparency
- [ ] Created OSINT scripts

### DNS Enumeration
- [ ] Know all DNS record types
- [ ] Can use dig effectively
- [ ] Can attempt zone transfers
- [ ] Can use DNSRecon/DNSEnum
- [ ] Created dns_enum.sh

### Subdomain Discovery
- [ ] Can use multiple discovery methods
- [ ] Know subdomain wordlists
- [ ] Understand subdomain takeover
- [ ] Created subdomain_discovery.sh

### Email/Employee Harvesting
- [ ] Can discover email formats
- [ ] Can use email harvesting tools
- [ ] Can extract document metadata
- [ ] Created email_harvester.sh
- [ ] Created generate_emails.sh

### Active Reconnaissance
- [ ] Can perform host discovery
- [ ] Master nmap scan types
- [ ] Can use NSE scripts
- [ ] Can perform banner grabbing
- [ ] Created full_nmap_scan.sh

### Network Mapping
- [ ] Can identify network ranges
- [ ] Can map network topology
- [ ] Can identify infrastructure roles
- [ ] Created network_map.sh
- [ ] Created target_profile.md template

### Automation
- [ ] Created master_recon.sh
- [ ] Created recon_oneliners.md
- [ ] Can customize scripts

### Assessment
- [ ] Written assessment completed
- [ ] Practical assessment completed

### Git Workflow
- [ ] Stage 05 committed
- [ ] Stage 05 pushed

---

## Definition of Done

Stage 05 is complete when:

1. All checklist items are checked
2. All scripts are created and functional
3. Assessment is complete
4. You can perform thorough reconnaissance
5. Work is committed and pushed

---

## What's Next: Stage 06 Preview

In Stage 06 — Vulnerability Scanning and Analysis, you will:

- Understand vulnerability types and classifications
- Use Nessus, OpenVAS, and other scanners
- Analyze vulnerability scan results
- Research and validate vulnerabilities
- Prioritize findings by risk
- Prepare for exploitation phase

You've discovered the attack surface—now it's time to find the weaknesses!

---

## Supplementary Resources

### Practice
- **TryHackMe:** "OSINT" room
- **TryHackMe:** "Passive Reconnaissance" room  
- **TryHackMe:** "Active Reconnaissance" room
- **HackTheBox:** Any machine's reconnaissance phase

### Tools to Explore
- Maltego (GUI OSINT visualization)
- SpiderFoot (automated OSINT)
- FOCA (document metadata)
- Aquatone (subdomain screenshots)

### Reading
- "Open Source Intelligence Techniques" by Michael Bazzell
- "The Hacker Playbook 3" - Reconnaissance chapter

---

**Commit your work and proceed to Stage 06 when ready:**

```bash
cd ~/path-to-repo
git add .
git commit -m "Complete Stage 05 - Reconnaissance and Information Gathering"
git push
```
