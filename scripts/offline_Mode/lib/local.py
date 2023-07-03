from netaddr import *
from scapy.all import *

def is_pkt_of_interest(packet):
    global hwv4_broadcast  ## MAC address for broadcasts
    global ipv4_broadcast  ## IP address for broadcasts
    global hwv6_broadcast  ## MAC address for broadcasts
    global ipv6_broadcast  ## IP address for broadcasts

    try:
        if IPv6 in packet:
            if str(packet[Ether].dst).startswith(hwv6_broadcast):
                return True
            elif str(packet[IPv6].dst).startswith(ipv6_broadcast):
                return True
            else:
                return False
        if IP in packet:
            if str(packet[Ether].dst) == hwv4_broadcast:
                return True
            elif str(packet[IP].dst) == "255.255.255.255":
                return True
            elif str(packet[IP].dst) == ipv4_broadcast:
                return True
        if ARP in packet:
            if str(packet[Ether].dst) == hwv4_broadcast:
                return True
        else:
            return False
    except:
        return False