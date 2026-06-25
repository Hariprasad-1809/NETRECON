# NetRecon Pro 🛡️

> **A real-time Network Reconnaissance Dashboard built on Kali Linux.**
> Runs actual Nmap scans and Wireshark packet captures — streams live output to your browser via Firefox.

---

## What Is This?

NetRecon Pro is a web-based security dashboard that wraps **Nmap** and **Wireshark (tshark)** inside a clean browser interface running on Kali Linux.

Instead of reading hundreds of lines of terminal text, you get:

- 🔍 **Live Nmap scanning** — output streams line by line to your browser as it happens
- 🖥️ **Host discovery** — shows all live devices on the network with IP, MAC, vendor, OS
- 🔌 **Port & service map** — every open port with version and colour-coded risk level
- 📡 **Packet capture** — tshark records packets to a `.pcap` file (same file Wireshark GUI reads)
- 🔬 **Traffic analysis** — extracts HTTP requests, FTP credentials, Telnet keystrokes, DNS queries
- ⚠️ **Auto findings** — maps detected service versions to real CVEs automatically
- 📄 **Report tab** — structured security findings with CVSS scores and fix steps

**This is a Week 1 & 2 Capstone Project** from the 2-Month Ethical Hacking Roadmap.
All tools used — Kali Linux, Nmap, Wireshark — are from the first two weeks.
Python Flask is a bonus layer that makes everything visual.

---

## How It Works (Simple Version)

```
You (Firefox) → Flask (Python) → Nmap / tshark (Kali Linux) → Target Network
                    ↑
            Streams output back
            live via SSE
```

1. You open Firefox on Kali → go to `http://localhost:5000`
2. Enter a target IP and click **Run Scan**
3. Flask runs the real `nmap` command on Kali
4. Every line of nmap output streams live to your browser
5. Results are parsed from XML and shown as visual cards
6. You can also capture packets with tshark and analyze them

---

## Lab Setup (Required Before Running)

This tool scans a **local network**. It does NOT work on the internet.
You need a home lab with two virtual machines.

```
VirtualBox NAT Network: 192.168.1.0/24
├── Kali Linux VM      → 192.168.1.100  (your attacker machine — runs this app)
└── Metasploitable2    → 192.168.1.105  (intentionally vulnerable target VM)
```

### Step 1 — Download VirtualBox
- Download: https://www.virtualbox.org/wiki/Downloads
- Install on your host machine (Windows/Mac/Linux)

### Step 2 — Download Kali Linux VM
- Download OVA: https://www.kali.org/get-kali/#kali-virtual-machines
- Import into VirtualBox: File → Import Appliance

### Step 3 — Download Metasploitable2 (Target VM)
- Download: https://sourceforge.net/projects/metasploitable/
- Extract the `.vmdk` file
- Create a new VM in VirtualBox → use existing virtual disk → select the `.vmdk`

### Step 4 — Set Up Isolated Network
Both VMs must be on the same isolated network so they can talk to each other.

In VirtualBox:
1. Go to **File → Preferences → Network → NAT Networks → Add**
2. Name it: `PentestLab`
3. CIDR: `192.168.1.0/24`
4. Tick "Enable DHCP"

For **each VM** (Kali and Metasploitable2):
1. VM → Settings → Network → Adapter 1
2. Attached to: **NAT Network**
3. Name: **PentestLab**

### Step 5 — Find Your IPs
After both VMs boot, in **Kali terminal**:
```bash
ip a                        # find your Kali IP
ping 192.168.1.105          # check if Metasploitable2 is reachable
```

---

## Prerequisites

### On Your Kali Linux Machine

| Requirement | How to Check | How to Install |
|---|---|---|
| Kali Linux | `uname -a` | Download from kali.org |
| Python 3 | `python3 --version` | Pre-installed on Kali |
| pip3 | `pip3 --version` | `sudo apt install python3-pip` |
| Flask | `python3 -c "import flask"` | `pip3 install flask --break-system-packages` |
| Nmap | `nmap --version` | Pre-installed on Kali |
| tshark | `tshark --version` | `sudo apt install tshark` |
| Firefox | Opens from app menu | Pre-installed on Kali |

> ⚠️ **Must run as root** — SYN scan, OS detection, and tshark capture need root privileges.
> Always start the app with `sudo python3 app.py`

---

## Installation

### 1. Copy the Project to Kali

Download the zip and extract it, or copy the folder to your Kali Desktop:

```bash
cd ~/Desktop
# copy NetRecon_Pro_Kali.zip here, then:
unzip NetRecon_Pro_Kali.zip
cd netrecon
```

### 2. Run the Setup Script (One Time Only)

```bash
sudo bash setup.sh
```

This installs Flask and tshark automatically.

### 3. Start the App

```bash
sudo python3 app.py
```

You should see:
```
====================================================
  NetRecon Pro — Nmap + Wireshark Dashboard
  Root: YES ✓
  XML output:  /root/nmap_out.xml
  PCAP output: /root/netrecon_capture.pcap
  Open Firefox: http://localhost:5000
====================================================
```

### 4. Open Firefox

Open Firefox on Kali and go to:
```
http://localhost:5000
```

The dashboard loads immediately. No internet required.

---

## How to Use — Step by Step

### Running a Scan

1. Click **"Run Scan"** in the left sidebar
2. Fill in the form:
   - **Target IP / Range**: enter your target (e.g. `192.168.1.105` or `192.168.1.0/24`)
   - **Scan Type**: choose from the 5 options (see below)
   - **Port Range**: e.g. `1-1000` or `1-65535`
3. Click **▶ RUN SCAN**
4. Watch the live terminal — real nmap output streams here
5. When scan finishes, check **Live Hosts** and **Open Ports** tabs

### Scan Types Explained

| Scan Type | Command Run | What It Does | Needs Root |
|---|---|---|---|
| **Ping Sweep** | `nmap -sn [target]` | Find all live devices on network | No |
| **SYN Stealth** | `nmap -sS -p [ports] [target]` | Fast quiet port scan | Yes |
| **Version Detection** | `nmap -sV -p [ports] [target]` | Find software versions on open ports | No |
| **OS + Version** | `nmap -sV -O -p [ports] [target]` | Versions + operating system guess | Yes |
| **Full Aggressive** | `nmap -sV -O -A -p [ports] [target]` | Everything + vulnerability scripts | Yes |

> 💡 **Start with Ping Sweep** → then Version Detection → then Full Aggressive for complete recon.

### Capturing Traffic

1. Click **"Capture Traffic"** in sidebar
2. Select your **network interface** (usually `eth0`)
3. Set **duration** (30 seconds is a good start)
4. Click **⏺ START CAPTURE**
5. While capturing, do something on the network (ping target, run a scan, attempt FTP login)
6. After capture ends, click the button to **open in Wireshark GUI**

```bash
# Or open manually in terminal:
wireshark ~/netrecon_capture.pcap &
```

### Analyzing Packets

1. Run a capture first (see above)
2. Click **"Analyze Packets"** in sidebar
3. Click **🔬 ANALYZE PCAP**
4. You will see:
   - Protocol breakdown (what % is TCP, ARP, DNS, HTTP...)
   - HTTP requests (pages visited)
   - FTP commands (usernames and passwords in plain text)
   - Telnet data (keystrokes — passwords visible)
   - DNS queries (what domain names were looked up)

---

## Project File Structure

```
netrecon/
│
├── app.py                  ← Main Flask backend (the brain)
│   │                         Runs nmap and tshark as real subprocesses
│   │                         Exposes REST API + SSE streaming endpoints
│   │                         Parses nmap XML output automatically
│   │                         Classifies port risk levels
│
├── setup.sh                ← One-time installer script
│   │                         Installs Flask, tshark
│
├── README.md               ← This file
│
└── templates/
    └── index.html          ← Complete dashboard UI
                              7 tabs: Overview, Scan, Hosts, Ports,
                              Capture, Analyze, Findings
                              Connects to Flask API via JavaScript
                              SSE stream updates terminal in real time
```

**Output files created when you run the tool:**

| File | Location | What It Contains |
|---|---|---|
| `nmap_out.xml` | `~/nmap_out.xml` | Nmap scan results in XML format |
| `netrecon_capture.pcap` | `~/netrecon_capture.pcap` | Wireshark packet capture file |

---

## API Endpoints (For Reference)

Flask exposes these routes — the browser calls them automatically:

| Method | Endpoint | What It Does |
|---|---|---|
| `POST` | `/api/scan/start` | Starts a new nmap scan |
| `GET` | `/api/scan/log` | SSE stream — live nmap output line by line |
| `GET` | `/api/scan/results` | Returns parsed scan results as JSON |
| `GET` | `/api/scan/status` | Returns whether a scan is running |
| `POST` | `/api/capture/start` | Starts tshark packet capture |
| `GET` | `/api/capture/analyze` | Runs tshark analysis on saved pcap file |
| `GET` | `/api/capture/status` | Returns capture status and file size |
| `GET` | `/api/interfaces` | Lists available network interfaces |

---

## Common Errors and Fixes

### Error: Permission denied writing XML file
```
Failed to open XML output file for writing: Permission denied
```
**Fix:** Run Flask as root:
```bash
sudo python3 app.py
```

### Error: nmap not found
```
[-] ERROR: nmap not found
```
**Fix:**
```bash
sudo apt install nmap
```

### Error: tshark not found
```
[-] tshark not found
```
**Fix:**
```bash
sudo apt install tshark
# When asked "Should non-superusers be able to capture packets?" → select YES
```

### Error: Flask not found
```
ModuleNotFoundError: No module named 'flask'
```
**Fix:**
```bash
pip3 install flask --break-system-packages
```

### Error: No hosts found after scan
- Check that both VMs are on the same VirtualBox NAT Network
- Check the target IP is correct: `ping 192.168.1.105`
- Try Ping Sweep first to confirm devices are reachable

### Dashboard shows but scan does nothing
- Make sure you clicked RUN SCAN and not just pressing Enter
- Check the Flask terminal for error messages
- Try a simpler scan type first (Ping Sweep)

---

## Security Warning

```
⚠️  LEGAL NOTICE

This tool is built for educational use in an isolated home lab only.

Never scan networks you do not own or have written permission to scan.
Scanning someone else's network without permission is illegal in most countries.

Metasploitable2 is a deliberately vulnerable VM designed for practice.
It should NEVER be exposed to the internet or a real network.

Always run your lab in an isolated VirtualBox NAT Network.
```

---

## Roadmap — Future Upgrades

This project is designed to grow with the 8-week Ethical Hacking Roadmap:

| Week | Planned Upgrade |
|---|---|
| Week 3–4 | Web vulnerability scanner (SQLi, XSS detection via requests) |
| Week 5–6 | Live packet streaming to browser via WebSocket |
| Week 5–6 | SQLite database — save all scan history across sessions |
| Week 7–8 | User login system + HTTPS |
| Week 7–8 | Agent + central server architecture (like Nessus) |
| Post-course | GitHub open source release + portfolio presentation |

---

## Tech Stack Summary

| Layer | Technology | Purpose |
|---|---|---|
| OS | Kali Linux 2024.1 | Attacker machine — all tools pre-installed |
| Lab | VirtualBox 7.x | Isolated home lab environment |
| Scanner | Nmap 7.94 | Host discovery, port scanning, version detection |
| Traffic | tshark / Wireshark 4.2 | Packet capture and analysis |
| Backend | Python 3 + Flask | Web server — runs tools, streams results |
| Frontend | HTML5 / CSS3 / JS | Dashboard UI in Firefox — no framework |
| Target | Metasploitable2 | Intentionally vulnerable practice target |

---

## Author

**[Your Name]**
Ethical Hacking Roadmap — Week 1 & 2 Capstone Project
June 2025

*Built using only tools from Weeks 1 and 2: Kali Linux, Nmap, Wireshark.*
*Flask and HTML are a bonus layer to make results visual and presentable.*
