import glob
import re
import subprocess

short_1 = open("short.msg", "r").read()
short_2 = open("short2.msg", "r").read()
short_3 = open("short3.msg", "r").read()
fox = open("fox.msg", "r").read()
long = open("long.msg", "r").read()

for file_path in glob.glob("*.out"):
    re_matches = re.search("(office|remote|home)_([^_]+)_.*robust_(ext|basic)?_?(1|2)byte\.out", file_path)
    print(file_path)

    if re_matches.groups()[0] == "remote":
        recording_path = "idlerun_4_complete.pcap"
    elif re_matches.groups()[0] == "office":
        recording_path = "office_legit_merged.pcap"
    elif re_matches.groups()[0] == "home":
        recording_path = "home_legit.pcap"

    if re_matches.groups()[2] == "ext":
        arguments = ["python", "offline_decoder.py",
                     "-l", file_path,
                     "-p", recording_path,
                     "-nc", re_matches.groups()[3],
                     "-tc", "0",
                     "-e"]
    else:
        arguments = ["python", "offline_decoder.py",
                     "-l", file_path,
                     "-p", recording_path,
                     "-nc", re_matches.groups()[3],
                     "-tc", "0"]

    subprocess.run(arguments)

    #decoded_file_content = open(file_path+".decoded", "r").read()
    #if "short1" in file_path:
    #print(decoded_file_content)
