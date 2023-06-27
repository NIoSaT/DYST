from netaddr import *
from scapy.layers.inet import IP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import Ether

import lib.constants as consts


# ToDo: Auch Multicast raus werfen
def is_pkt_of_interest(packet):
    if IPv6 in packet:
        if IPAddress(packet[IPv6].dst).is_private():
            return False
        elif IPAddress(packet[IPv6].dst).is_multicast():
            return False
        elif str(packet[Ether].dst) == consts.hwv6_broadcast:
            return False
        elif str(packet[IPv6].dst).startswith(consts.ipv6_broadcast):
            return False
        return True
    elif IP in packet:
        if IPAddress(packet[IP].dst).is_private():
            return False
        elif IPAddress(packet[IP].dst).is_multicast():
            return False
        elif str(packet[Ether].dst) == consts.hwv4_broadcast:
            return False
        elif str(packet[IP].dst) == "255.255.255.255":
            return False
        return True
    else:
        return False
