import sys
import argparse

from scapy.sendrecv import sniff

from lib.offline_lib import get_mask, get_string_to_binary, get_check_sum
from lib.offline_mode import OfflineMode

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description='DYST Offline Mode')
    parser.add_argument('-cf', '--covert-message-file', dest="cmf")
    parser.add_argument('-nc', '--number-of-chars', dest="noc", type=int)
    parser.add_argument('-i', '--input')
    parser.add_argument('-o', '--output')
    parser.add_argument('-tc', '--target-count', default=0, dest="tc", type=int)
    parser.add_argument('-r', '--robust', action='store_true')
    parser.add_argument('-m', '--mode')
    parser.add_argument('-bc', '--broad-cast', dest="bc", default="255.255.255.255")
    parser.add_argument('-s', '--scenario', choices=["local", "remote"])

    args = parser.parse_args()

    print("========Loading configuration=========")
    covert_message_file = args.cmf
    arg_number_of_chars = args.noc
    inputFile = args.input
    arg_mode = args.mode
    output = args.output
    arg_target_count = args.tc
    robust = args.robust
    ipv4_broadcast = args.bc
    scenario = args.scenario

    print("========Reading Covert Message=========")
    covert_message = open(covert_message_file, 'r').read()

    arg_cm_array = [covert_message[i:i + arg_number_of_chars] for i in range(0, len(covert_message), arg_number_of_chars)]
    arg_ba_curr = get_string_to_binary(arg_cm_array[0])

    #arg_masks = get_mask(len(list(arg_ba_curr + get_check_sum(list(arg_ba_curr), arg_number_of_chars))),
    #                 len(list(arg_ba_curr + get_check_sum(list(arg_ba_curr), arg_number_of_chars))) - arg_target_count)

    arg_masks = [[int(x) for x in list(format(i, f"0{8*args.noc + 3+args.noc}b"))] for i in range(0, 2 ** (8*args.noc + 3+args.noc))]

    offline_mode_worker = OfflineMode(arg_mode, arg_ba_curr, arg_cm_array, arg_masks, arg_target_count,
                                      arg_number_of_chars, robust, ipv4_broadcast, scenario)

    print("========Starting Offline Mode=========")
    sniff(offline=inputFile, prn=offline_mode_worker, store=False)

    print("Opening Output File ", output)
    with open(output, 'w') as f:
        f.write("match,counter_interest,counter_total,matchPerc,matchTime,timeSincelast_hit,signal_number\n")
        for i in offline_mode_worker.res:
            f.write(i)
        f.close()

    print("-------- PoI ---------")
    print(offline_mode_worker.counter_interest)
