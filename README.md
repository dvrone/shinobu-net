# ❖ Shinobu-Net

A network anomaly analyzer built with Python/Flask. Upload `.pcap` or `.pcapng` capture files and get instant detection of DDoS, DoS, brute-force, and network scan attacks.

## Features

- Upload and analyze `.pcap` / `.pcapng` files
- Detects: DDoS, DoS, SYN Flood, Net Scan, Host Sweep, Brute Force (SSH/FTP/RDP)
- Shannon entropy analysis per traffic dimension
- SQLite scan history with full report per scan
- Dark terminal UI

## Stack

- Python 3 / Flask
- SQLAlchemy + SQLite
- Scapy
- Jinja2 templates

---

## Setup

```bash
git clone git@github.com:dvrone/shinobu-net.git
cd shinobu-net

python -m venv venv
source venv/bin/activate

pip install -r requirements.txt
python run.py
```

Open `http://127.0.0.1:5000`

---

## Testing

### Capture live traffic

```bash
# Find your interface
ip a

# Capture on WiFi
sudo tcpdump -i wlo1 -w test/capture.pcapng

# Capture on loopback
sudo tcpdump -i lo -w test/capture.pcapng
```

### Simulate DDoS (loopback)

```bash
# Terminal 1 — start capture
sudo tcpdump -i lo -w test/capture_ddos.pcapng

# Terminal 2 — flood with random spoofed sources
sudo hping3 --flood --rand-source -p 80 127.0.0.1

# Ctrl+C both after 10–15 seconds
```

### Trim large captures

```bash
# Keep first 500k packets
sudo tcpdump -r test/capture_ddos.pcapng -w test/capture_small.pcapng -c 500000
```

### Simulate all attack types (no root needed)

```bash
python test/gen_attack.py
# outputs test/attack_sim.pcapng
```

`gen_attack.py`:

```python
from scapy.all import *

pkts = []

# DoS
for i in range(6000):
    pkts.append(IP(src="10.0.0.1", dst="192.168.1.100") /
                TCP(dport=80, flags="S"))

# DDoS
for i in range(30):
    for j in range(300):
        pkts.append(IP(src=f"10.{i}.0.{j}", dst="192.168.1.200") /
                    UDP(dport=53) / Raw(b"X" * 64))

# Net scan
for port in range(1, 1024):
    pkts.append(IP(src="10.99.0.1", dst="192.168.1.50") /
                TCP(dport=port, flags="S"))

# Brute force SSH
for i in range(100):
    pkts.append(IP(src="10.88.0.1", dst="192.168.1.10") /
                TCP(dport=22, flags="S"))

wrpcap("test/attack_sim.pcapng", pkts)
print(f"[+] Written {len(pkts)} packets to test/attack_sim.pcapng")
```

---

## Detection Thresholds

| Detection | Threshold |
| --- | --- |
| DoS PPS | > 1000 pps per conversation |
| DoS packets | > 5000 packets (no timing) |
| DDoS total | > 15000 packets + 25 sources |
| DDoS distributed | > 25 sources each sending >= 200 pkts |
| Port scan | > 20 unique destination ports |
| Host sweep | > 15 unique hosts |
| Brute force | > 25 SYN attempts to port 21/22/3389 |

---

## Project Structure

```shinobu-net/
├── app/
│   ├── __init__.py
│   ├── models/
│   │   └── scan.py
│   ├── routes/
│   │   └── main.py
│   ├── services/
│   │   └── analyzer.py
│   └── templates/
│       ├── base.html
│       ├── index.html
│       └── report.html
├── config.py
├── run.py
└── requirements.txt
```
