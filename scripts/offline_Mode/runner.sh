#! /usr/bin/env bash

#Local
tsp python offlineModeV2.py -s remote -cf short.msg -nc 1 -i idlerun_4_complete.pcap -m basic -r -o remote_short1_robust_1byte.out
tsp python offlineModeV2.py -s remote -cf short.msg -nc 1 -i idlerun_4_complete.pcap -m basic -o remote_short1_non_robust_1byte.out
tsp python offlineModeV2.py -s remote -cf short2.msg -nc 1 -i idlerun_4_complete.pcap -m basic -r -o remote_short2_robust_1byte.out
tsp python offlineModeV2.py -s remote -cf short2.msg -nc 1 -i idlerun_4_complete.pcap -m basic -o remote_short2_non_robust_1byte.out
tsp python offlineModeV2.py -s remote -cf short3.msg -nc 1 -i idlerun_4_complete.pcap -m basic -r -o remote_short3_robust_1byte.out
tsp python offlineModeV2.py -s remote -cf short3.msg -nc 1 -i idlerun_4_complete.pcap -m basic -o remote_short3_non_robust_1byte.out
tsp python offlineModeV2.py -s remote -cf fox.msg -nc 1 -i idlerun_4_complete.pcap -m basic -o remote_fox_non_robust_1byte.out
tsp python offlineModeV2.py -s remote -cf fox.msg -nc 1 -i idlerun_4_complete.pcap -m basic -r -o remote_fox_robust_1byte.out
tsp python offlineModeV2.py -s remote -cf long.msg -nc 1 -i idlerun_4_complete.pcap -m basic -r -o remote_long_robust_1byte.out
tsp python offlineModeV2.py -s remote -cf long.msg -nc 1 -i idlerun_4_complete.pcap -m basic -o remote_long_non_robust_1byte.out

tsp python offlineModeV2.py -s remote -cf short.msg -nc 2 -i idlerun_4_complete.pcap -m basic -r -o remote_short1_robust_2byte.out
tsp python offlineModeV2.py -s remote -cf short.msg -nc 2 -i idlerun_4_complete.pcap -m basic -o remote_short1_non_robust_2byte.out
tsp python offlineModeV2.py -s remote -cf short2.msg -nc 2 -i idlerun_4_complete.pcap -m basic -r -o remote_short2_robust_2byte.out
tsp python offlineModeV2.py -s remote -cf short2.msg -nc 2 -i idlerun_4_complete.pcap -m basic -o remote_short2_non_robust_2byte.out
tsp python offlineModeV2.py -s remote -cf short3.msg -nc 2 -i idlerun_4_complete.pcap -m basic -r -o remote_short3_robust_2byte.out
tsp python offlineModeV2.py -s remote -cf short3.msg -nc 2 -i idlerun_4_complete.pcap -m basic -o remote_short3_non_robust_2byte.out
tsp python offlineModeV2.py -s remote -cf fox.msg -nc 2 -i idlerun_4_complete.pcap -m basic -o remote_fox_non_robust_2byte.out
tsp python offlineModeV2.py -s remote -cf fox.msg -nc 2 -i idlerun_4_complete.pcap -m basic -r -o remote_fox_robust_2byte.out
tsp python offlineModeV2.py -s remote -cf long.msg -nc 2 -i idlerun_4_complete.pcap -m basic -r -o remote_long_robust_2byte.out
tsp python offlineModeV2.py -s remote -cf long.msg -nc 2 -i idlerun_4_complete.pcap -m basic -o remote_long_non_robust_2byte.out


#Office
tsp python offlineModeV2.py -s local -cf short.msg -nc 1 -i office_legit_merged.pcap -bc 143.93.247.127 -m basic -r -o office_short1_robust_basic_1byte.out
tsp python offlineModeV2.py -s local -cf short.msg -nc 1 -i office_legit_merged.pcap -bc 143.93.247.127 -m basic -o office_short1_non_robust_basic_1byte.out
#tsp python offlineModeV2.py -cf short.msg -nc 1 -i office_legit_merged.pcap -bc 143.93.247.127 -m ext -r -o office_short1_robust_ext_1byte.out
#tsp python offlineModeV2.py -cf short.msg -nc 1 -i office_legit_merged.pcap -bc 143.93.247.127 -m ext -o office_short1_non_robust_ext_1byte.out
tsp python offlineModeV2.py -s local -cf short2.msg -nc 1 -i office_legit_merged.pcap -bc 143.93.247.127 -m basic -r -o office_short2_robust_basic_1byte.out
tsp python offlineModeV2.py -s local -cf short2.msg -nc 1 -i office_legit_merged.pcap -bc 143.93.247.127 -m basic -o office_short2_non_robust_basic_1byte.out
#tsp python offlineModeV2.py -cf short2.msg -nc 1 -i office_legit_merged.pcap -bc 143.93.247.127 -m ext -r -o office_short2_robust_ext_1byte.out
#tsp python offlineModeV2.py -cf short2.msg -nc 1 -i office_legit_merged.pcap -bc 143.93.247.127 -m ext -o office_short2_non_robust_ext_1byte.out
tsp python offlineModeV2.py -s local -cf short3.msg -nc 1 -i office_legit_merged.pcap -bc 143.93.247.127 -m basic -r -o office_short3_robust_basic_1byte.out
tsp python offlineModeV2.py -s local -cf short3.msg -nc 1 -i office_legit_merged.pcap -bc 143.93.247.127 -m basic -o office_short3_non_robust_basic_1byte.out
#tsp python offlineModeV2.py -cf short3.msg -nc 1 -i office_legit_merged.pcap -bc 143.93.247.127 -m ext -r -o office_short3_robust_ext_1byte.out
#tsp python offlineModeV2.py -cf short3.msg -nc 1 -i office_legit_merged.pcap -bc 143.93.247.127 -m ext -o office_short3_non_robust_ext_1byte.out

tsp python offlineModeV2.py -s local -cf short.msg -nc 2 -i office_legit_merged.pcap -bc 143.93.247.127 -m basic -r -o office_short1_robust_basic_2byte.out
tsp python offlineModeV2.py -s local -cf short.msg -nc 2 -i office_legit_merged.pcap -bc 143.93.247.127 -m basic -o office_short1_non_robust_basic_2byte.out
#tsp python offlineModeV2.py -cf short.msg -nc 2 -i office_legit_merged.pcap -bc 143.93.247.127 -m ext -r -o office_short1_robust_ext_2byte.out
#tsp python offlineModeV2.py -cf short.msg -nc 2 -i office_legit_merged.pcap -bc 143.93.247.127 -m ext -o office_short1_non_robust_ext_2byte.out
tsp python offlineModeV2.py -s local -cf short2.msg -nc 2 -i office_legit_merged.pcap -bc 143.93.247.127 -m basic -r -o office_short2_robust_basic_2byte.out
tsp python offlineModeV2.py -s local -cf short2.msg -nc 2 -i office_legit_merged.pcap -bc 143.93.247.127 -m basic -o office_short2_non_robust_basic_2byte.out
#tsp python offlineModeV2.py -cf short2.msg -nc 2 -i office_legit_merged.pcap -bc 143.93.247.127 -m ext -r -o office_short2_robust_ext_2byte.out
#tsp python offlineModeV2.py -cf short2.msg -nc 2 -i office_legit_merged.pcap -bc 143.93.247.127 -m ext -o office_short2_non_robust_ext_2byte.out
tsp python offlineModeV2.py -s local -cf short3.msg -nc 2 -i office_legit_merged.pcap -bc 143.93.247.127 -m basic -r -o office_short3_robust_basic_2byte.out
tsp python offlineModeV2.py -s local -cf short3.msg -nc 2 -i office_legit_merged.pcap -bc 143.93.247.127 -m basic -o office_short3_non_robust_basic_2byte.out
#tsp python offlineModeV2.py -cf short3.msg -nc 2 -i office_legit_merged.pcap -bc 143.93.247.127 -m ext -r -o office_short3_robust_ext_2byte.out
#tsp python offlineModeV2.py -cf short3.msg -nc 2 -i office_legit_merged.pcap -bc 143.93.247.127 -m ext -o office_short3_non_robust_ext_2byte.out


# Home
tsp python offlineModeV2.py -s local -cf short.msg -nc 1 -i home_legit.pcap -bc 192.168.2.255 -m basic -r -o home_short1_robust_basic_1byte.out
tsp python offlineModeV2.py -s local -cf short.msg -nc 1 -i home_legit.pcap -bc 192.168.2.255 -m basic -o home_short1_non_robust_basic_1byte.out
#tsp python offlineModeV2.py -cf short.msg -nc 1 -i home_legit.pcap -bc 192.168.2.255 -m ext -r -o home_short1_robust_ext_1byte.out
#tsp python offlineModeV2.py -cf short.msg -nc 1 -i home_legit.pcap -bc 192.168.2.255 -m ext -o home_short1_non_robust_ext_1byte.out
tsp python offlineModeV2.py -s local -cf short2.msg -nc 1 -i home_legit.pcap -bc 192.168.2.255 -m basic -r -o home_short2_robust_basic_1byte.out
tsp python offlineModeV2.py -s local -cf short2.msg -nc 1 -i home_legit.pcap -bc 192.168.2.255 -m basic -o home_short2_non_robust_basic_1byte.out
#tsp python offlineModeV2.py -cf short2.msg -nc 1 -i home_legit.pcap -bc 192.168.2.255 -m ext -r -o home_short2_robust_ext_1byte.out
#tsp python offlineModeV2.py -cf short2.msg -nc 1 -i home_legit.pcap -bc 192.168.2.255 -m ext -o home_short2_non_robust_ext_1byte.out
tsp python offlineModeV2.py -s local -cf short3.msg -nc 1 -i home_legit.pcap -bc 192.168.2.255 -m basic -r -o home_short3_robust_basic_1byte.out
tsp python offlineModeV2.py -s local -cf short3.msg -nc 1 -i home_legit.pcap -bc 192.168.2.255 -m basic -o home_short3_non_robust_basic_1byte.out
#tsp python offlineModeV2.py -cf short3.msg -nc 1 -i home_legit.pcap -bc 192.168.2.255 -m ext -r -o home_short3_robust_ext_1byte.out
#tsp python offlineModeV2.py -cf short3.msg -nc 1 -i home_legit.pcap -bc 192.168.2.255 -m ext -o home_short3_non_robust_ext_1byte.out

tsp python offlineModeV2.py -s local -cf short.msg -nc 2 -i home_legit.pcap -bc 192.168.2.255 -m basic -r -o home_short1_robust_basic_2byte.out
tsp python offlineModeV2.py -s local -cf short.msg -nc 2 -i home_legit.pcap -bc 192.168.2.255 -m basic -o home_short1_non_robust_basic_2byte.out
#tsp python offlineModeV2.py -cf short.msg -nc 2 -i home_legit.pcap -bc 192.168.2.255 -m ext -r -o home_short1_robust_ext_2byte.out
#tsp python offlineModeV2.py -cf short.msg -nc 2 -i home_legit.pcap -bc 192.168.2.255 -m ext -o home_short1_non_robust_ext_2byte.out
tsp python offlineModeV2.py -s local -cf short2.msg -nc 2 -i home_legit.pcap -bc 192.168.2.255 -m basic -r -o home_short2_robust_basic_2byte.out
tsp python offlineModeV2.py -s local -cf short2.msg -nc 2 -i home_legit.pcap -bc 192.168.2.255 -m basic -o home_short2_non_robust_basic_2byte.out
#tsp python offlineModeV2.py -cf short2.msg -nc 2 -i home_legit.pcap -bc 192.168.2.255 -m ext -r -o home_short2_robust_ext_2byte.out
#tsp python offlineModeV2.py -cf short2.msg -nc 2 -i home_legit.pcap -bc 192.168.2.255 -m ext -o home_short2_non_robust_ext_2byte.out
tsp python offlineModeV2.py -s local -cf short3.msg -nc 2 -i home_legit.pcap -bc 192.168.2.255 -m basic -r -o home_short3_robust_basic_2byte.out
tsp python offlineModeV2.py -s local -cf short3.msg -nc 2 -i home_legit.pcap -bc 192.168.2.255 -m basic -o home_short3_non_robust_basic_2byte.out
#tsp python offlineModeV2.py -cf short3.msg -nc 2 -i home_legit.pcap -bc 192.168.2.255 -m ext -r -o home_short3_robust_ext_2byte.out
#tsp python offlineModeV2.py -cf short3.msg -nc 2 -i home_legit.pcap -bc 192.168.2.255 -m ext -o home_short3_non_robust_ext_2byte.out