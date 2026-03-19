from scapy.all import sniff, IP, TCP, ICMP, ARP

from port_scan_detector import detect_port_scan
from syn_flood_detector import detect_syn_flood
from icmp_flood_detector import detect_icmp_flood
from arp_spoof_detector import detect_arp_spoof


def packet_handler(packet):

    # ---------------- TCP ATTACKS ----------------
    if packet.haslayer(IP) and packet.haslayer(TCP):

        src_ip = packet[IP].src
        dst_port = packet[TCP].dport
        flags = packet[TCP].flags

        # SYN packets
        if flags == "S":
            detect_port_scan(src_ip, dst_port)
            detect_syn_flood(src_ip)

    # ---------------- ICMP ATTACK ----------------
    if packet.haslayer(ICMP):
        detect_icmp_flood(packet)

    # ---------------- ARP ATTACK ----------------
    if packet.haslayer(ARP):
        detect_arp_spoof(packet)


def start_ids():
    print("Hybrid Network IDS Started...")

    sniff(
        prn=packet_handler,
        store=0,
        iface=None   # Auto-detect interface (FIXED)
    )


if __name__ == "__main__":
    start_ids()