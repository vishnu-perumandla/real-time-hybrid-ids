import time
from config import SYN_FLOOD_THRESHOLD, SYN_FLOOD_TIME_WINDOW
from logger import log_alert

syn_tracker = {}


def detect_syn_flood(src_ip):
    current_time = time.time()

    if src_ip not in syn_tracker:
        syn_tracker[src_ip] = {
            "count": 1,
            "start_time": current_time
        }
    else:
        syn_tracker[src_ip]["count"] += 1

    elapsed_time = current_time - syn_tracker[src_ip]["start_time"]

    if elapsed_time <= SYN_FLOOD_TIME_WINDOW:
        if syn_tracker[src_ip]["count"] > SYN_FLOOD_THRESHOLD:
            log_alert(f"⚠ SYN FLOOD detected from {src_ip}")
            syn_tracker.pop(src_ip)
    else:
        syn_tracker[src_ip] = {
            "count": 1,
            "start_time": current_time
        }