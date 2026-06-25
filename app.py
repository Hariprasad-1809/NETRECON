#!/usr/bin/env python3
"""
NetRecon Pro — Real Nmap + Wireshark Web Dashboard
Run on Kali Linux as root:  sudo python3 app.py
Then open Firefox:          http://localhost:5000
"""

import subprocess, json, os, re, threading, time, xml.etree.ElementTree as ET
from flask import Flask, render_template, request, jsonify, Response, stream_with_context
from datetime import datetime

app = Flask(__name__)

# ── Store scan results in memory ──
scan_results   = {}   # nmap parsed results
scan_log       = []   # live log lines
scan_running   = False
pcap_file      = "/tmp/netrecon_capture.pcap"
tshark_running = False

# ─────────────────────────────────────────────
# NMAP HELPERS
# ─────────────────────────────────────────────

def run_nmap(target, scan_type, ports):
    global scan_running, scan_log, scan_results
    scan_running = True
    scan_log = []
    scan_results = {}

    # Build nmap command based on scan type
    cmds = {
        "ping":    ["nmap", "-sn", target],
        "syn":     ["nmap", "-sS", "-p", ports, target, "-oX", "/tmp/nmap_out.xml"],
        "version": ["nmap", "-sV", "-p", ports, target, "-oX", "/tmp/nmap_out.xml"],
        "os":      ["nmap", "-sV", "-O", "-p", ports, target, "-oX", "/tmp/nmap_out.xml"],
        "full":    ["nmap", "-sV", "-O", "-A", "-p", ports, target, "-oX", "/tmp/nmap_out.xml"],
    }
    cmd = cmds.get(scan_type, cmds["version"])
    scan_log.append(f"[*] Running: {' '.join(cmd)}")
    scan_log.append(f"[*] Started at: {datetime.now().strftime('%H:%M:%S')}")

    try:
        proc = subprocess.Popen(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True, bufsize=1
        )
        for line in proc.stdout:
            line = line.rstrip()
            if line:
                scan_log.append(line)
        proc.wait()
        scan_log.append(f"[*] Nmap exit code: {proc.returncode}")

        # Parse XML output
        if scan_type != "ping" and os.path.exists("/tmp/nmap_out.xml"):
            scan_results = parse_nmap_xml("/tmp/nmap_out.xml")
            scan_log.append(f"[+] Parsed {len(scan_results.get('hosts', []))} host(s)")
        elif scan_type == "ping":
            scan_results = parse_ping_output('\n'.join(scan_log))

    except FileNotFoundError:
        scan_log.append("[-] ERROR: nmap not found. Install with: sudo apt install nmap")
    except Exception as e:
        scan_log.append(f"[-] ERROR: {e}")

    scan_log.append(f"[*] Finished at: {datetime.now().strftime('%H:%M:%S')}")
    scan_running = False


def parse_nmap_xml(xml_file):
    """Parse nmap -oX XML output into a clean dict."""
    try:
        tree = ET.parse(xml_file)
        root = tree.getroot()
    except Exception as e:
        return {"error": str(e), "hosts": []}

    hosts = []
    for host in root.findall("host"):
        # Status
        status = host.find("status")
        if status is None or status.get("state") != "up":
            continue

        # IP
        addr = host.find("address[@addrtype='ipv4']")
        ip = addr.get("addr") if addr is not None else "unknown"

        # MAC
        mac_el = host.find("address[@addrtype='mac']")
        mac = mac_el.get("addr","—") if mac_el is not None else "—"
        vendor = mac_el.get("vendor","—") if mac_el is not None else "—"

        # Hostname
        hn = host.find(".//hostname")
        hostname = hn.get("name","—") if hn is not None else "—"

        # OS
        os_el = host.find(".//osmatch")
        os_name = os_el.get("name","Unknown") if os_el is not None else "Unknown"
        os_acc  = os_el.get("accuracy","") if os_el is not None else ""

        # Ports
        ports = []
        for port in host.findall(".//port"):
            state_el = port.find("state")
            if state_el is None or state_el.get("state") != "open":
                continue
            svc = port.find("service")
            svc_name    = svc.get("name","unknown") if svc is not None else "unknown"
            svc_product = svc.get("product","") if svc is not None else ""
            svc_version = svc.get("version","") if svc is not None else ""
            svc_extra   = svc.get("extrainfo","") if svc is not None else ""
            full_ver    = " ".join(filter(None,[svc_product, svc_version, svc_extra])).strip()
            ports.append({
                "port":     port.get("portid"),
                "protocol": port.get("protocol"),
                "service":  svc_name,
                "version":  full_ver or "—",
                "risk":     classify_risk(svc_name, full_ver, port.get("portid"))
            })

        hosts.append({
            "ip": ip, "mac": mac, "vendor": vendor,
            "hostname": hostname, "os": os_name,
            "os_accuracy": os_acc, "ports": ports
        })

    return {
        "hosts": hosts,
        "total_hosts": len(hosts),
        "total_ports": sum(len(h["ports"]) for h in hosts),
        "scan_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    }


def parse_ping_output(text):
    """Parse ping sweep output (no XML for -sn)."""
    hosts = []
    for line in text.split('\n'):
        m = re.search(r'Nmap scan report for (.+)', line)
        if m:
            raw = m.group(1)
            ip_m = re.search(r'\(?([\d.]+)\)?', raw)
            ip = ip_m.group(1) if ip_m else raw
            hn = re.search(r'^(\S+)\s+\(', raw)
            hostname = hn.group(1) if hn else "—"
            hosts.append({"ip": ip, "hostname": hostname, "mac":"—",
                          "vendor":"—","os":"Unknown","os_accuracy":"","ports":[]})
    return {"hosts": hosts, "total_hosts": len(hosts),
            "total_ports": 0, "scan_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S")}


def classify_risk(service, version, port):
    """Assign risk level based on service + known CVEs."""
    high_risk_services = ["telnet","ftp","rsh","rlogin","rexec","tftp",
                          "finger","netbios","msrpc","vnc"]
    medium_risk = ["http","smtp","mysql","postgresql","mssql",
                   "oracle","rdp","snmp","irc"]
    known_critical = {
        "21": "vsftpd 2.3.4",   # backdoor
        "445": "Samba 3.0.20",  # CVE-2007-2447
        "1524": "ingreslock",   # metasploitable backdoor
        "512": "rexec",
        "513": "rlogin",
        "514": "shell",
    }
    if port in known_critical:
        if any(v.lower() in version.lower() for v in ["2.3.4","3.0.20","3.0.2"]):
            return "critical"
        return "high"
    if service.lower() in high_risk_services:
        return "high"
    if service.lower() in medium_risk:
        return "medium"
    return "low"


# ─────────────────────────────────────────────
# WIRESHARK / TSHARK HELPERS
# ─────────────────────────────────────────────

def start_capture(interface, duration):
    global tshark_running, scan_log
    tshark_running = True
    scan_log.append(f"[*] Starting tshark capture on {interface} for {duration}s...")
    try:
        cmd = ["tshark", "-i", interface, "-a", f"duration:{duration}",
               "-w", pcap_file, "-q"]
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=int(duration)+5)
        scan_log.append(f"[+] Capture saved to {pcap_file}")
        scan_log.append(f"[*] tshark stderr: {proc.stderr[:200]}" if proc.stderr else "[+] Capture complete")
    except FileNotFoundError:
        scan_log.append("[-] tshark not found. Install: sudo apt install tshark")
    except subprocess.TimeoutExpired:
        scan_log.append("[+] Capture duration reached")
    except Exception as e:
        scan_log.append(f"[-] Capture error: {e}")
    tshark_running = False


def analyze_pcap():
    """Run tshark analysis on saved pcap — protocol stats + interesting frames."""
    if not os.path.exists(pcap_file):
        return {"error": "No capture file found. Run a capture first."}

    results = {}

    # Protocol hierarchy
    try:
        out = subprocess.check_output(
            ["tshark", "-r", pcap_file, "-q", "-z", "io,phs"],
            text=True, stderr=subprocess.DEVNULL, timeout=15)
        results["protocol_hierarchy"] = out
    except Exception as e:
        results["protocol_hierarchy"] = f"Error: {e}"

    # Total packet count
    try:
        out = subprocess.check_output(
            ["tshark", "-r", pcap_file, "-q", "-z", "conv,ip"],
            text=True, stderr=subprocess.DEVNULL, timeout=15)
        results["conversations"] = out[:3000]
    except Exception as e:
        results["conversations"] = f"Error: {e}"

    # Extract HTTP requests
    try:
        out = subprocess.check_output(
            ["tshark", "-r", pcap_file, "-Y", "http.request",
             "-T", "fields", "-e", "ip.src", "-e", "http.request.method",
             "-e", "http.request.uri", "-e", "http.host"],
            text=True, stderr=subprocess.DEVNULL, timeout=15)
        results["http_requests"] = out[:2000] if out.strip() else "No HTTP requests found"
    except Exception as e:
        results["http_requests"] = f"Error: {e}"

    # Extract FTP commands (plaintext creds)
    try:
        out = subprocess.check_output(
            ["tshark", "-r", pcap_file, "-Y", "ftp",
             "-T", "fields", "-e", "ip.src", "-e", "ftp.request.command",
             "-e", "ftp.request.arg"],
            text=True, stderr=subprocess.DEVNULL, timeout=15)
        results["ftp_commands"] = out[:2000] if out.strip() else "No FTP traffic found"
    except Exception as e:
        results["ftp_commands"] = f"Error: {e}"

    # Extract Telnet data (plaintext)
    try:
        out = subprocess.check_output(
            ["tshark", "-r", pcap_file, "-Y", "telnet",
             "-T", "fields", "-e", "ip.src", "-e", "telnet.data"],
            text=True, stderr=subprocess.DEVNULL, timeout=15)
        results["telnet_data"] = out[:2000] if out.strip() else "No Telnet traffic found"
    except Exception as e:
        results["telnet_data"] = f"Error: {e}"

    # DNS queries
    try:
        out = subprocess.check_output(
            ["tshark", "-r", pcap_file, "-Y", "dns.flags.response == 0",
             "-T", "fields", "-e", "ip.src", "-e", "dns.qry.name"],
            text=True, stderr=subprocess.DEVNULL, timeout=15)
        results["dns_queries"] = out[:2000] if out.strip() else "No DNS queries found"
    except Exception as e:
        results["dns_queries"] = f"Error: {e}"

    # Packet count
    try:
        out = subprocess.check_output(
            ["tshark", "-r", pcap_file, "-q", "-z", "frame,bytes"],
            text=True, stderr=subprocess.DEVNULL, timeout=15)
        # Count lines as packets
        pkt_count = subprocess.check_output(
            ["tshark", "-r", pcap_file, "-T", "fields", "-e", "frame.number"],
            text=True, stderr=subprocess.DEVNULL, timeout=15)
        results["packet_count"] = len(pkt_count.strip().split('\n')) if pkt_count.strip() else 0
    except:
        results["packet_count"] = "unknown"

    return results


def get_interfaces():
    """List available network interfaces."""
    try:
        out = subprocess.check_output(["ip", "-o", "link", "show"],
                                       text=True, stderr=subprocess.DEVNULL)
        ifaces = re.findall(r'\d+: (\S+):', out)
        return [i for i in ifaces if i != "lo"]
    except:
        return ["eth0", "wlan0"]


# ─────────────────────────────────────────────
# ROUTES
# ─────────────────────────────────────────────

@app.route("/")
def index():
    interfaces = get_interfaces()
    return render_template("index.html", interfaces=interfaces)


@app.route("/api/scan/start", methods=["POST"])
def api_scan_start():
    global scan_running
    if scan_running:
        return jsonify({"error": "Scan already running"}), 400
    data = request.json
    target    = data.get("target", "192.168.1.0/24")
    scan_type = data.get("scan_type", "version")
    ports     = data.get("ports", "1-1024")
    thread = threading.Thread(target=run_nmap, args=(target, scan_type, ports), daemon=True)
    thread.start()
    return jsonify({"status": "started"})


@app.route("/api/scan/log")
def api_scan_log():
    """SSE stream — pushes log lines to browser in real time."""
    def generate():
        sent = 0
        while True:
            if len(scan_log) > sent:
                for line in scan_log[sent:]:
                    yield f"data: {json.dumps(line)}\n\n"
                sent = len(scan_log)
            if not scan_running and sent >= len(scan_log):
                yield "data: __DONE__\n\n"
                break
            time.sleep(0.3)
    return Response(stream_with_context(generate()), mimetype="text/event-stream")


@app.route("/api/scan/results")
def api_scan_results():
    return jsonify(scan_results)


@app.route("/api/scan/status")
def api_scan_status():
    return jsonify({"running": scan_running, "log_lines": len(scan_log)})


@app.route("/api/capture/start", methods=["POST"])
def api_capture_start():
    global tshark_running
    if tshark_running:
        return jsonify({"error": "Capture already running"}), 400
    data      = request.json
    iface     = data.get("interface", "eth0")
    duration  = data.get("duration", "30")
    thread = threading.Thread(target=start_capture, args=(iface, duration), daemon=True)
    thread.start()
    return jsonify({"status": "capturing", "file": pcap_file})


@app.route("/api/capture/analyze")
def api_capture_analyze():
    results = analyze_pcap()
    return jsonify(results)


@app.route("/api/capture/status")
def api_capture_status():
    return jsonify({
        "running": tshark_running,
        "file_exists": os.path.exists(pcap_file),
        "file_size": os.path.getsize(pcap_file) if os.path.exists(pcap_file) else 0
    })


@app.route("/api/interfaces")
def api_interfaces():
    return jsonify({"interfaces": get_interfaces()})


if __name__ == "__main__":
    print("\n" + "="*50)
    print("  NetRecon Pro — Real Nmap + Wireshark Dashboard")
    print("  Run as ROOT for full scan capabilities")
    print("  Open Firefox: http://localhost:5000")
    print("="*50 + "\n")
    app.run(host="0.0.0.0", port=5000, debug=False, threaded=True)
