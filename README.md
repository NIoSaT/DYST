# DYST (*Did You See That?*) – A Covert Channel Exploiting Recent Legitimate Traffic

This repository contains the proof-of-concept implementation of the **DYST** covert channel, accompanying the paper

Steffen Wendzel, Tobias Schmidbauer, Sebastian Zillien, Jörg Keller: *[Did You See That? A Covert Channel Exploiting Recent Legitimate Traffic](http://www.wendzel.de/dr.org/files/Papers/DYSTv1_History_CCs.pdf)*, pre-print, December 2022.

## Live Mode

Live mode of DYST. This mode will send a covert message via the DYST covert channel.

### Usage
```
sudo python3 DYST.py <Covert Message File> <# of Chars>   <interface> <logfile binaries> <[cr|cs]> <[trivial_single|trivial_multiple|ECC]> <CS and CR! :Broadcast Target IP> <Signal Source IP (=CS IP)> <CR:Message Log>
```

- `Covert Message File`
  - Path to a text file containing the covert message to be sent
- `# of Chars`
  - How many characters to sent at once
- `interface`
  - What netwotk interface to use for the covert channel
- `logfile binaries`
  - Path to the logfile for statistics (seen hashes, match percentages, timestamps, etc.)
- `cr|cs`
  - What mode to use? Covert Sender or Covert Receiver
- `trivial|trivial_robust|ext|ext_robust|ECC`
  - What encoding mode to use?
    - trivial: DYST-Basic, waits for 100% matches for each signal, no robustness measures
    - trivial_robust: Same as trivial, added robustness measures
    - ext: DYST-Ext, uses checksums for faster trnsmission, no robustness measures
    - ext_robust: Same as ext, added robustness measures
    - ECC: Experimental DYST-ECC mode.
- `Broadcast Target IP` (CR and CS)
  - Target IP that the CS will use in its signal-ARP-requests.
  - CR will watch for this IP to filter signals
- `Signal Source IP` (CR only)
  - The IP of the covert sender, is used to filter signals
- `Message Log` (CR only)
  - Path to logfile which will contain teh recieved message

### CS Example
`sudo python3 scripts/DYST.py config/The_Shadow_Out_of_Time.txt 2 wlan0 log/CS/HomeLANcs trivial_single 192.168.2.254 2>/dev/null`

### CR Example
`sudo python3 scripts/DYST.py config/The_Shadow_Out_of_Time.txt 2 wlan0 log/CR/HomeLan cr trivial_single 192.168.2.254 192.168.2.146 log/CR/HomeLan_msg 2>/dev/null`

## Offline Mode

Offline Mode to analyse pcap files for matches. Reads pcap files packet by packet and looks for matches.

For each `PacketOfInterest`, the match (true/false), number of `PacketOfInterest`, total number of packets, match percentage/count and match time is recorded.

With this we can do statistics on how often we would send out an ARP packet, either based on time or on packet count.

The tool needs the broadcast IP of the subnet from the recording to know wich packets can be seen by CS and CR.

`offlineMode.py` contains robustness measures while `offlineMode_nonrobust.py` does not.

### Example call - Basic
```
python scripts/offlineMode.py /config/The_Shadow_Out_of_Time.txt 3 test.pcapng basic 192.168.200.255 test.out
```
The basic mode uses no checksums and waitss for a 100% match between hash and message

### Example call - Extended
```
python scripts/offlineMode.py /config/The_Shadow_Out_of_Time.txt 2 test.pcapng ext 192.168.200.255 test.out 21
```
The extended mode uses a basic 8 bit checksum (byte alignment). The checksum contains the number of 1s in the original message, binary encoded.

### Usage
```
python offlineMode.py <Message Input File> <Bytes per Pkt> <Pcap Input> <Mode> <Broadcast IP of Recording> <Output File> [<Match Target>]
```

- `Message Input File`
  - Path to a text file containing the covert message to be sent
- `Bytes per Pkt`
  - How many bytes/characters to be sent at once
- `Pcap Input`
  - Path to a pcap file, which will be used as a base for the simulation
- `Mode`
  - `basic`: DYST-Basic mode
  - `ext`: DYST-Ext mode
- `Broadcast IP of Recording`
  - What is the broadcast IP of the network present in the input pcap (is used to filter packets of interest)
- `Output File`
  - Path to the logfile for statistics (seen hashes, match percentages, timestamps, etc.)
- `Match Target`(ext Mode only)
  - How many bits to match in DYST-Ext mode before sendign a signal


## Log Folder
The log folder contains some extracted example IPDs in the CSV format.
