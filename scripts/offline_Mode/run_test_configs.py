import subprocess

pcap_path = "small.pcapng"
msg_path = "small.msg"

for num_bytes in ["1", "2"]:
    for mode in ["ext", "basic"]:
        for scenario in ["local", "remote"]:
            for robust in [True, False]:
                arguments = ["python", "offlineModeV2.py",
                             "-cf", "test.msg",
                             "-nc", num_bytes,
                             "-i", "small.pcapng",
                             "-m", mode,
                             "-o", f"{scenario}_small_{'non_' if not robust else ''}robust_{mode}_{num_bytes}byte.out",
                             "-bc", "192.168.1.255",
                             "-s", scenario]
                if robust:
                    arguments.append("-r")
                subprocess.run(arguments)
