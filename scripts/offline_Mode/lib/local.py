from netaddr import *
from scapy.all import *

import lib.constants as consts


def is_pkt_of_interest(packet, ipv4_broadcast):

    try:
        if IPv6 in packet:
            if str(packet[Ether].dst).startswith(consts.hwv6_broadcast):
                return True
            elif str(packet[IPv6].dst).startswith(consts.ipv6_broadcast):
                return True
            else:
                return False
        if IP in packet:
            if str(packet[Ether].dst) == consts.hwv4_broadcast:
                return True
            elif str(packet[IP].dst) == "255.255.255.255":
                return True
            elif str(packet[IP].dst) == ipv4_broadcast:
                return True
        if ARP in packet:
            if str(packet[Ether].dst) == consts.hwv4_broadcast:
                return True
        else:
            return False
    except:
        return False