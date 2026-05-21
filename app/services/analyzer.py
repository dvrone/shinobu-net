from collections import Counter, defaultdict
from math import log2

from scapy.all import IP, TCP, UDP, PcapReader

# =========================
# Threshold Config
# =========================
DOS_PPS_THRESHOLD = 1000
DOS_PACKET_THRESHOLD = 5000
DDOS_PACKET_THRESHOLD = 15000
DDOS_SOURCE_THRESHOLD = 25
DDOS_PER_SRC_THRESHOLD = 200
SCAN_PORT_THRESHOLD = 20
SCAN_HOST_THRESHOLD = 15
BRUTE_FORCE_THRESHOLD = 25


def entropy_from_counts(counts_dict, total):
    if total == 0:
        return 0.0
    ent = 0.0
    for count in counts_dict.values():
        p = count / total
        if p > 0:
            ent -= p * log2(p)
    return ent


def analyze_pcap(filepath):
    """
    Analyze a PCAP file and return a result dictionary.
    Raises ValueError on empty or unreadable files.
    """

    # -- Counters --
    total_packets = 0
    src_counter = Counter()
    dst_counter = Counter()
    port_counter = Counter()

    ports_by_src = defaultdict(set)
    hosts_by_src = defaultdict(set)
    sources_per_target = defaultdict(set)
    conversations = defaultdict(lambda: defaultdict(int))
    syn_per_conversation = defaultdict(lambda: defaultdict(int))

    ssh_attempts = Counter()
    ftp_attempts = Counter()
    rdp_attempts = Counter()

    min_time = float("inf")
    max_time = float("-inf")

    # -- Parse --
    with PcapReader(filepath) as reader:
        for pkt in reader:
            if IP not in pkt:
                continue

            total_packets += 1
            src = pkt[IP].src
            dst = pkt[IP].dst

            src_counter[src] += 1
            dst_counter[dst] += 1
            conversations[src][dst] += 1
            sources_per_target[dst].add(src)
            hosts_by_src[src].add(dst)

            if hasattr(pkt, "time"):
                t = float(pkt.time)
                min_time = min(min_time, t)
                max_time = max(max_time, t)

            if TCP in pkt:
                tcp = pkt[TCP]
                dport = tcp.dport
                port_counter[dport] += 1
                ports_by_src[src].add(dport)

                if bool(tcp.flags & 0x02):
                    syn_per_conversation[src][dst] += 1
                    if dport == 22:
                        ssh_attempts[src] += 1
                    elif dport == 21:
                        ftp_attempts[src] += 1
                    elif dport == 3389:
                        rdp_attempts[src] += 1

            elif UDP in pkt:
                dport = pkt[UDP].dport
                port_counter[dport] += 1
                ports_by_src[src].add(dport)

    if total_packets == 0:
        raise ValueError("No valid IP traffic found in file.")

    # -- Timing --
    if (
        min_time == float("inf")
        or max_time == float("-inf")
        or (max_time - min_time) <= 0
    ):
        capture_duration = None
        pps = None
    else:
        capture_duration = max_time - min_time
        pps = total_packets / capture_duration

    # -- Entropy --
    src_entropy = entropy_from_counts(src_counter, total_packets)
    dst_entropy = entropy_from_counts(dst_counter, total_packets)
    port_entropy = entropy_from_counts(port_counter, sum(port_counter.values()))

    # -- Detection --
    findings = []
    attack_types = set()

    for src, unique_ports in ports_by_src.items():
        if len(unique_ports) > SCAN_PORT_THRESHOLD:
            attack_types.add("Net Scan")
            findings.append(
                f"Port scan from {src} — {len(unique_ports)} unique destination ports targeted"
            )

    for src, unique_hosts in hosts_by_src.items():
        if len(unique_hosts) > SCAN_HOST_THRESHOLD:
            attack_types.add("Net Scan")
            findings.append(
                f"Host sweep from {src} — {len(unique_hosts)} unique hosts targeted"
            )

    for src, count in ssh_attempts.items():
        if count > BRUTE_FORCE_THRESHOLD:
            attack_types.add("Brute Force")
            findings.append(
                f"SSH brute-force suspected from {src} ({count} SYN attempts)"
            )

    for src, count in ftp_attempts.items():
        if count > BRUTE_FORCE_THRESHOLD:
            attack_types.add("Brute Force")
            findings.append(
                f"FTP brute-force suspected from {src} ({count} SYN attempts)"
            )

    for src, count in rdp_attempts.items():
        if count > BRUTE_FORCE_THRESHOLD:
            attack_types.add("Brute Force")
            findings.append(
                f"RDP brute-force suspected from {src} ({count} SYN attempts)"
            )

    for src, targets in conversations.items():
        for dst, pkt_count in targets.items():
            if capture_duration:
                conv_pps = pkt_count / capture_duration
                if conv_pps > DOS_PPS_THRESHOLD:
                    attack_types.add("DoS")
                    findings.append(
                        f"DoS suspected: {src} -> {dst} ({pkt_count} pkts, {conv_pps:.1f} pps)"
                    )
            elif pkt_count > DOS_PACKET_THRESHOLD:
                attack_types.add("DoS")
                findings.append(
                    f"DoS suspected: {src} -> {dst} ({pkt_count} packets, no timing data)"
                )

            syn_count = syn_per_conversation[src][dst]
            if capture_duration:
                syn_pps = syn_count / capture_duration
                if syn_pps > DOS_PPS_THRESHOLD:
                    attack_types.add("DoS")
                    findings.append(
                        f"SYN flood suspected: {src} -> {dst} ({syn_count} SYN pkts, {syn_pps:.1f} pps)"
                    )
            elif syn_count > DOS_PACKET_THRESHOLD:
                attack_types.add("DoS")
                findings.append(
                    f"SYN flood suspected: {src} -> {dst} ({syn_count} SYN packets)"
                )

    for dst, pkt_count in dst_counter.items():
        unique_sources = len(sources_per_target[dst])
        if pkt_count > DDOS_PACKET_THRESHOLD and unique_sources > DDOS_SOURCE_THRESHOLD:
            attack_types.add("DDoS")
            findings.append(
                f"DDoS on {dst} — {pkt_count} total packets from {unique_sources} distinct sources"
            )
        elif unique_sources > DDOS_SOURCE_THRESHOLD:
            qualifying = sum(
                1
                for src in sources_per_target[dst]
                if conversations[src][dst] >= DDOS_PER_SRC_THRESHOLD
            )
            if qualifying > DDOS_SOURCE_THRESHOLD:
                attack_types.add("DDoS")
                findings.append(
                    f"Distributed low-volume DDoS on {dst} — {qualifying} sources each sent >= {DDOS_PER_SRC_THRESHOLD} packets"
                )

    # -- Classification --
    PRIORITY = ["DDoS", "DoS", "Brute Force", "Net Scan"]
    if attack_types:
        classification = next((t for t in PRIORITY if t in attack_types), "Unknown")
        if len(attack_types) > 1:
            classification += f" (also detected: {', '.join(sorted(attack_types))})"
    else:
        classification = "Normal"

    return {
        "total_packets": total_packets,
        "capture_duration": capture_duration,
        "pps": pps,
        "unique_src_ips": len(src_counter),
        "unique_dst_ips": len(dst_counter),
        "unique_ports": len(port_counter),
        "src_entropy": round(src_entropy, 4),
        "dst_entropy": round(dst_entropy, 4),
        "port_entropy": round(port_entropy, 4),
        "classification": classification,
        "findings": findings,
        "top_src_ips": src_counter.most_common(10),
        "top_dst_ips": dst_counter.most_common(10),
    }
