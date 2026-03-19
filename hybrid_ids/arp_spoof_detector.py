from scapy.all import ARP
from logger import log_alert

arp_table = {}


def detect_arp_spoof(packet):
    if packet.haslayer(ARP):

        ip = packet[ARP].psrc
        mac = packet[ARP].hwsrc

        if ip in arp_table:

            if arp_table[ip] != mac:
                log_alert(f"⚠ ARP SPOOF detected: {ip} is claiming new MAC {mac}")

        else:
            arp_table[ip] = mac