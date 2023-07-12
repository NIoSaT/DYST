import math

from bitstring import BitArray

import lib.constants as consts
from lib.offline_lib import get_hash_value, get_input_values, get_match_percent, \
    get_string_to_binary, get_match_count, check_bit_flips, get_check_sum
from lib.local import is_pkt_of_interest


class OfflineMode:
    def __init__(self, mode, ba_curr, cm_array, masks, target_count, number_of_chars, robust, ipv4_broadcast):

        self.robust = robust

        self.counter_interest = 0
        self.counter_total = 0

        self.ipv4_broadcast = ipv4_broadcast

        self.old_pkt = None
        self.bad_pkt = None
        self.sent_pkt = None

        self.last_hit = 0

        self.res = []

        self.target_count = target_count
        self.number_of_chars = number_of_chars

        self.ba_curr = ba_curr
        self.cm_array_current = 0
        self.cm_array = cm_array

        self.masks = masks

        self.mode = mode

        self.done = False

    def check_and_update_pkt_delays(self, packet):
        if self.old_pkt is None and self.bad_pkt is None:
            self.old_pkt = packet
            return False
        elif self.old_pkt is not None and float(packet.time - self.old_pkt.time) < consts.delay:
            self.old_pkt = None
            self.bad_pkt = packet
            return False
        elif self.bad_pkt is not None and float(packet.time - self.bad_pkt.time) < consts.delay:
            self.bad_pkt = packet
            return False
        elif self.bad_pkt is not None and float(packet.time - self.bad_pkt.time) >= consts.delay:
            self.old_pkt = packet
            self.bad_pkt = None
            return False
        else:
            return True

    def __call__(self, packet):
        self.counter_total += 1

        if self.done:
            return

        if not is_pkt_of_interest(packet, self.ipv4_broadcast):
            return
        if not self.robust or self.check_and_update_pkt_delays(packet):
            if not self.robust:
                self.old_pkt = packet

            if self.mode == "basic":
                curr_target = list(map(int, self.ba_curr))
            elif self.mode == "ext":
                curr_target = list(map(int, self.ba_curr+get_check_sum(list(self.ba_curr),self.number_of_chars)))

            self.counter_interest += 1
            critical_fraction, seconds = math.modf(self.old_pkt.time)
            if critical_fraction > consts.crit_fraction_high or critical_fraction < consts.crit_fraction_low:
                self.res.append("{},{},{},{},{},{}\n".format(False, self.counter_interest, self.counter_total, -1, self.old_pkt.time, -1))
                self.old_pkt = packet
                return

            pkt_hash = get_hash_value(get_input_values(self.old_pkt))
            pkt_hash = list(map(int, list(BitArray(bytes=pkt_hash.digest()).bin[:len(curr_target)])))

            if self.mode == "basic":
                match_percentage = get_match_percent(pkt_hash, list(curr_target))

                if match_percentage == 1.0:
                    if self.last_hit != 0:
                        self.res.append(
                            "{},{},{},{},{},{}\n".format(True, self.counter_interest, self.counter_total, match_percentage,
                                                         self.old_pkt.time,
                                                         (self.old_pkt.time - self.last_hit)))
                    else:
                        self.res.append(
                            "{},{},{},{},{},{}\n".format(True, self.counter_interest, self.counter_total, match_percentage,
                                                         self.old_pkt.time,
                                                         -1))
                    self.cm_array_current += 1
                    if self.cm_array_current >= len(self.cm_array)-1:
                        self.done = True
                    self.ba_curr = get_string_to_binary(self.cm_array[self.cm_array_current])
                    self.last_hit = self.old_pkt.time
                    self.sent_pkt = self.old_pkt
                else:
                    self.res.append(
                        "{},{},{},{},{},{}\n".format(False, self.counter_interest, self.counter_total, match_percentage,
                                                     self.old_pkt.time, -1))
            elif self.mode == "ext":
                match_count = get_match_count(pkt_hash, list(curr_target))

                if match_count >= self.target_count:
                    if check_bit_flips(pkt_hash, curr_target, self.number_of_chars, self.masks):
                        if self.last_hit != 0:
                            self.res.append(
                                "{},{},{},{},{},{}\n".format(True, self.counter_interest, self.counter_total, match_count,
                                                             self.old_pkt.time,
                                                             (self.old_pkt.time - self.last_hit)))
                        else:
                            self.res.append(
                                "{},{},{},{},{},{}\n".format(True, self.counter_interest, self.counter_total, match_count,
                                                             self.old_pkt.time,
                                                             -1))
                        self.cm_array_current += 1
                        if self.cm_array_current >= len(self.cm_array) - 1:
                            self.done = True
                        self.ba_curr = get_string_to_binary(self.cm_array[self.cm_array_current])
                        self.last_hit = self.old_pkt.time
                        self.sent_pkt = self.old_pkt
                    else:
                        self.res.append(
                            "{},{},{},{},{},{}\n".format(False, self.counter_interest, self.counter_total, match_count,
                                                         self.old_pkt.time, -1))
                else:
                    self.res.append(
                        "{},{},{},{},{},{}\n".format(False, self.counter_interest, self.counter_total, match_count,
                                                     self.old_pkt.time, -1))

            self.old_pkt = packet
