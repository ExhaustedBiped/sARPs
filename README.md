# sARPs

sARPs is a python ARP spoofer that uses scapy to spoof the gateway mac address of a network and allows you to execute a man-in-the-middle attack in a simple manner.

  - Enables IP Routing on any capable os completely automatically
  - Finds MAC address of the selected device on the network
  - Creates the spoofed ARP reply packet and sends it across the network

# Requirements

  - scapy `pip install scapy`
  - On Linux: tcpdump (apt or yum)
  - On MacOS: libpcap (brew)
  - On Windows: npcap (https://nmap.org/npcap/#download)

# Usage

```
usage: sarps.py [-h] [-v] target host
```

- `-h` = help
- `-v` = verbose
- `target` = target ip
- `host` = host ip

For example:
```
python3 sarps.py 192.168.1.24 192.168.1.17 --verbose
```
