import streamlit as st
import time
import matplotlib.pyplot as plt
import re

LOG_FILE = "ids_log.txt"

st.set_page_config(page_title="Network Defense Dashboard", layout="wide")
st.title("🛡 Proactive Network Defense Dashboard")


def read_logs():
    try:
        with open(LOG_FILE, "r") as f:
            return f.readlines()
    except:
        return []


logs = read_logs()

port_scans = 0
syn_floods = 0
icmp_floods = 0
arp_spoofs = 0
suspicious_ips = []

for log in logs:

    # Extract IP safely (FIXED)
    ip_match = re.search(r'\d+\.\d+\.\d+\.\d+', log)
    if ip_match:
        suspicious_ips.append(ip_match.group())

    if "PORT SCAN" in log:
        port_scans += 1

    elif "SYN FLOOD" in log:
        syn_floods += 1

    elif "ICMP FLOOD" in log:
        icmp_floods += 1

    elif "ARP SPOOF" in log:
        arp_spoofs += 1


# ---------------- METRICS ----------------
col1, col2, col3, col4 = st.columns(4)

col1.metric("Port Scans", port_scans)
col2.metric("SYN Floods", syn_floods)
col3.metric("ICMP Floods", icmp_floods)
col4.metric("ARP Spoofs", arp_spoofs)

st.divider()

# ---------------- GRAPH ----------------
st.subheader("Attack Distribution")

labels = ["Port Scan", "SYN Flood", "ICMP Flood", "ARP Spoof"]
values = [port_scans, syn_floods, icmp_floods, arp_spoofs]

fig, ax = plt.subplots()
ax.bar(labels, values)

st.pyplot(fig)

st.divider()

# ---------------- SUSPICIOUS IPS ----------------
st.subheader("Suspicious IP Addresses")

for ip in set(suspicious_ips):
    st.write(ip)

st.divider()

# ---------------- LOGS ----------------
st.subheader("IDS Logs")
st.text("".join(logs))

# Auto refresh every 2 sec (FIXED)
time.sleep(2)
st.rerun()