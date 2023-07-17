import glob
import re
import subprocess

for file_path in glob.glob("*.out"):
    re_matches = re.search("(local|remote)_([^_]+)_(non_robust|robust)_(ext|basic)?_?(1|2)byte\.out", file_path)
    print(file_path)

    recording_path = "small.pcapng"

    if re_matches.groups()[3] == "ext":
        arguments = ["python", "offline_decoder_v2.py",
                     "-l", file_path,
                     "-p", recording_path,
                     "-nc", re_matches.groups()[4],
                     "-tc", "0",
                     "-e"]
    else:
        arguments = ["python", "offline_decoder_v2.py",
                     "-l", file_path,
                     "-p", recording_path,
                     "-nc", re_matches.groups()[4],
                     "-tc", "0"]

    if re_matches.groups()[2] == "robust":
        arguments.append("-r")

    subprocess.run(arguments)