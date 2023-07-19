import glob
import re



short_1 = open("short.msg", "r").read()
short_2 = open("short2.msg", "r").read()
short_3 = open("short3.msg", "r").read()
long = open("long.msg", "r").read()
fox = open("fox.msg", "r").read()

test_msg = {"short1": short_1, "short2": short_2, "short3": short_3, "long": long, "fox": fox}

for file_path in glob.glob("*.out.decoded"):
    print(file_path)

    re_matches = re.search("(office|remote|home)_([^_]+)_(non_robust|robust)_(ext|basic)?_?(1|2)byte\.out.decoded", file_path)
    re_groups = re_matches.groups()
    orig_msg = test_msg[re_groups[1]]
    
    decoded_msg = open(file_path, "r").read()
    if orig_msg.startswith(decoded_msg):
        print(f"Orig. Len:\t{len(orig_msg)}\nDecoded Len:\t{len(decoded_msg)}")
        print("---Passed---\n")
    else:
        print("---Failed---\n")