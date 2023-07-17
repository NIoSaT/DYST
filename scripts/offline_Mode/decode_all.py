import glob
import re
import subprocess

for file_path in glob.glob("*.out"):
    re_matches = re.search("(office|remote|home)_([^_]+)_(non_robust|robust)_(ext|basic)?_?(1|2)byte\.out", file_path)
    print(file_path)

    if re_matches.groups()[0] == "remote":
        recording_path = "idlerun_4_complete.pcap"
    elif re_matches.groups()[0] == "office":
        recording_path = "office_legit_merged.pcap"
    elif re_matches.groups()[0] == "home":
        recording_path = "home_legit.pcap"

    if re_matches.groups()[3] == "ext":
        arguments = ["tsp", "python", "offline_decoder_v2.py",
                     "-l", file_path,
                     "-p", recording_path,
                     "-nc", re_matches.groups()[4],
                     "-tc", "0",
                     "-e"]
    else:
        arguments = ["tsp", "python", "offline_decoder_v2.py",
                     "-l", file_path,
                     "-p", recording_path,
                     "-nc", re_matches.groups()[4],
                     "-tc", "0"]

    if re_matches.groups()[2] == "robust":
        arguments.append("-r")

    subprocess.run(arguments)