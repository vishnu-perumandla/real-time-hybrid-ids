import time
from config import PORT_SCAN_THRESHOLD, PORT_SCAN_TIME_WINDOW
from logger import log_alert

scan_tracker = {}


def detect_port_scan(src_ip, dst_port):
    current_time = time.time()

    if src_ip not in scan_tracker:
        scan_tracker[src_ip] = {
            "ports": set(),
            "start_time": current_time
        }

    scan_tracker[src_ip]["ports"].add(dst_port)

    elapsed_time = current_time - scan_tracker[src_ip]["start_time"]

    if elapsed_time <= PORT_SCAN_TIME_WINDOW:
        if len(scan_tracker[src_ip]["ports"]) > PORT_SCAN_THRESHOLD:
            log_alert(f"⚠ PORT SCAN detected from {src_ip}")
            scan_tracker.pop(src_ip)
    else:
        scan_tracker[src_ip] = {
            "ports": set(),
            "start_time": current_time
        }