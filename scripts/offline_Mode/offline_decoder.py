import argparse
import pandas as pd
from bitstring import BitArray
from scapy.layers.l2 import Ether
from scapy.utils import rdpcap
from lib.offline_lib import get_input_values, get_hash_value, do_bit_flips, get_mask, get_check_sum, get_bit_string_to_string


def decode_basic(pkt: Ether, number_of_chars: int) -> str:
    pkt_hash = get_hash_value(get_input_values(pkt))
    return pkt_hash.digest()[:number_of_chars].decode("utf-8")


def decode_ext(pkt: Ether, number_of_chars: int, masks) -> str:
    pkt_hash = get_hash_value(get_input_values(pkt))
    pkt_hash = list(map(int, list(BitArray(bytes=pkt_hash.digest()).bin[:8*number_of_chars])))
    input_hash = [int(x) for x in pkt_hash + list(get_check_sum(pkt_hash, number_of_chars))]
    unflipped_hash = do_bit_flips(input_hash, number_of_chars, masks)
    return get_bit_string_to_string("".join(str(x) for x in unflipped_hash))


parser = argparse.ArgumentParser(prog="OfflineDecoder", description="Decode DYST offline outpput")

parser.add_argument("-p", "--pcap", required=True)
parser.add_argument("-l", "--logfile", required=True)
parser.add_argument("-e", "--ext", action="store_true")
parser.add_argument('-nc', '--number-of-chars', dest="noc", type=int, required=True)
parser.add_argument('-tc', '--target-count', dest="tc", type=int, required=True)

args = parser.parse_args()

input_pcap = rdpcap(args.pcap)
input_log = pd.read_csv(args.logfile)

if args.ext:
    computed_masks = get_mask(8*args.noc + 3+args.noc, 8*args.noc + 3+args.noc - args.tc)
matches = input_log[input_log["match"]]

decoded_msg = ""
for match_counter in matches["counter_total"]:
    if args.ext:
        decoded_msg += (decode_ext(input_pcap[match_counter-1], args.noc, computed_masks))
    else:
        decoded_msg += (decode_basic(input_pcap[match_counter-1], args.noc))

print('Decoded Message: ')
print(decoded_msg)
