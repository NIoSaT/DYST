from bitstring import BitArray
import numpy as np
import hashlib
import itertools

from netaddr import IPAddress
from scapy.layers.inet import IP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import ARP, Ether

import lib.constants as consts


def remote_is_pkt_of_interest(packet, *args, **kwargs):

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


def local_is_pkt_of_interest(packet, ipv4_broadcast):

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

def get_string_to_binary(input_string):
    bin_value = BitArray(input_string.encode('utf-8')).bin
    return bin_value


def get_bit_string_to_string(bits):
    return ''.join(chr(int(bits[i*8:i*8+8], 2)) for i in range(len(bits)//8))


def get_string_to_binary_bch(input_string, bch):
    bin_value = BitArray(input_string.encode('utf-8'))
    ecc = bch.encode(bin_value.bytes)
    return bin_value.bin + BitArray(ecc).bin


def get_match_percent(a, b):
    if len(a) != len(b):
        raise ValueError("Length of arrays does not match!")
    return np.count_nonzero(np.array(a) == np.array(b)) / len(a)


def get_match_count(a, b):
    if len(a) != len(b):
        raise ValueError("Length of arrays does not match!")
    return np.count_nonzero(np.array(a) == np.array(b))


def get_hash_value(input_string):
    try:
        temp_hash = hashlib.sha512(input_string)
    except TypeError:
        temp_hash = hashlib.sha512(input_string.encode('utf-8'))
    return temp_hash


def kbits(n, k):
    result = []
    for bits in itertools.combinations(range(n), k):
        s = ['0'] * n
        for bit in bits:
            s[bit] = '1'
        result.append(''.join(s))
    return result


def get_mask(n, k):
    result = []
    for i in range(k + 1):
        res = kbits(n, i)
        res.reverse()
        result.append(res)
    ret = [item for sublist in result for item in sublist]
    ret = list(map(list, ret))
    ret = list(map(lambda x: [int(y) for y in x], ret))
    return ret


def get_check_sum(input_hash, number_of_chars):
    if number_of_chars == 1:
        return '{0:04b}'.format(np.count_nonzero(np.array(input_hash).astype(int)))
    elif number_of_chars == 2:
        return '{0:05b}'.format(np.count_nonzero(np.array(input_hash).astype(int)))
    else:
        print("Checksum not Calculated")
        exit(100)


def test_check_sum(input_hash, number_of_chars):
    if number_of_chars == 1:
        non_zero_count = np.count_nonzero(np.array(input_hash[:-4]).astype(int))
        format_list = list('{0:04b}'.format(non_zero_count))
        int_list = list(map(int, format_list))
        return int_list == input_hash[-4:]
    elif number_of_chars == 2:
        non_zero_count = np.count_nonzero(np.array(input_hash[:-5]).astype(int))
        format_list = list('{0:05b}'.format(non_zero_count))
        int_list = list(map(int, format_list))
        return int_list == input_hash[-5:]
    else:
        print("Checksum not Calculated")
        exit(100)


def do_bit_flips(input_hash, number_of_chars, masks):
    if number_of_chars == 1:
        cflen = -4
    elif number_of_chars == 2:
        cflen = -5
    else:
        print("Checksum Length to long")
        exit(100)

    for i in masks:
        cur_flipped = list(map(lambda x, y: x ^ int(y), input_hash, list(i)))
        if test_check_sum(cur_flipped, number_of_chars):
            return cur_flipped
    return "_"


def check_bit_flips(input_hash, orig, number_of_chars, masks):
    if number_of_chars == 1:
        cflen = -4
    elif number_of_chars == 2:
        cflen = -5
    else:
        print("Checksum Length to long")
        exit(100)

    for i in masks:
        cur_flipped = list(map(lambda x, y: x ^ int(y), input_hash, list(i)))
        if test_check_sum(cur_flipped, number_of_chars):
            if cur_flipped[:cflen] == orig[:cflen]:
                return True
            else:
                return False
        else:
            pass
    return False


def get_input_values(input_packet: Ether):
    temp_string = ""
    timestamp = str(input_packet.time)
    if IPv6 in input_packet:
        temp_string = str(input_packet[IPv6].src) + timestamp
    elif IP in input_packet:
        temp_string = str(input_packet[IP].chksum) + timestamp
    elif ARP in input_packet:
        temp_string = str(input_packet[ARP].pdst) + str(input_packet[ARP].psrc) + timestamp

    return temp_string
