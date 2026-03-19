import time
from scapy.all import IP, ICMP
from logger import log_alert

icmp_tracker = {}

ICMP_THRESHOLD = 50
ICMP_TIME_WINDOW = 1


def detect_icmp_flood(packet):
    if packet.haslayer(IP) and packet.haslayer(ICMP):

        src_ip = packet[IP].src
        current_time = time.time()

        if src_ip not in icmp_tracker:
            icmp_tracker[src_ip] = {
                "count": 1,
                "start_time": current_time
            }
        else:
            icmp_tracker[src_ip]["count"] += 1

        elapsed_time = current_time - icmp_tracker[src_ip]["start_time"]

        if elapsed_time <= ICMP_TIME_WINDOW:
            if icmp_tracker[src_ip]["count"] > ICMP_THRESHOLD:
                log_alert(f"⚠ ICMP FLOOD detected from {src_ip}")
                icmp_tracker.pop(src_ip)
        else:
            icmp_tracker[src_ip] = {
                "count": 1,
                "start_time": current_time
            }