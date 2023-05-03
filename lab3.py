import scapy.all as scapy
import sys
sys.path.append('/home/kali/.local/lib/python3.10/site-packages')
import pyshark
import os
import argparse
import time

def parser():
    p = argparse.ArgumentParser(description="Spoof ARP table")
    p.add_argument("-s", "--src", dest = "src", help="The address of the gateway")
    options= p.parse_args()
    return options

def flag1(gip):
    #get the mac address of the gateway using gateway ip
    gmac = get_mac(gip)
    #get mac address of the source machine of packet
    capture = pyshark.LiveCapture(interface='eth0', display_filter='arp.opcode == 2')
    for packet in capture.sniff_continuously():
        sip = packet.arp.src_proto_ipv4
        #compare the addresses. raise flag if not equal
        if(sip== gip and gmac != packet.arp.dst_hw_mac):
             return True
    return False

def flag2():
    wordlist1 = makeArpTable()
    dict = {}
    for i in range(1,len(wordlist1)+1,2):
        if wordlist1[i] in dict:
            if(dict[wordlist1[i]] != wordlist1[i-1]):
                return True
        else:
            dict[wordlist1[i]]= wordlist1[i-1]
    return False

def flag3(gip):
    #find gateway mac address
    gmac = get_mac(gip)
    arpTable = makeArpTable()
    #check if arp table contains mac address of gateways. if not raise flag
    if(gmac not in arpTable):
        return True
    return False

#----------DIDN'T END UP IMPLEMENTING. FINISH LATER-------------
# def flag4():
#     dict = {}
#     #using wireshark, moniter for a machine sending arp replies without requests
#     capture = pyshark.LiveCapture(interface='eth0', display_filter='arp')
#     for packet in capture.sniff_continuously():
#         if packet.arp.opCode == '1':
#             if packet.arp.src_proto_ipv4 in dict:  
#                 dict[packet.arp.src_proto_ipv4] += 1
#             else:
#                 dict[packet.arp.src_proto_ipv4] = 1

    #make a dictionary for each arp with op code == 1, store add to its dest ip add key in dict a tally
    #for every arp op code == 2 and sender ip add matches in dict, subtract tally
    #if there is an op code 2 ip with a tally of more than 4 then risk of spoofing
    
    return

def makeArpTable():
    #print("start time stamp" ,time.time())
    filterlist = ['?', 'eth0', '[ether]', 'on', 'at', 'home.home']
    #go through arp table, check if the same mac address is associated with diff ip's
    with os.popen('arp -a') as f:
        data = f.read()
        dataN = data.split()
        wordlist1 = [word for word in dataN if word not in filterlist]
    #print("end time stamp ", time.time())
    return wordlist1

def get_mac(ip):
    ans = scapy.srp(scapy.Ether(dst = "ff:ff:ff:ff:ff:ff")/scapy.ARP(pdst = ip), verbose = False)[0]
    return ans[0][1].hwsrc

while True:
    options = parser()
    flag=0

    if(flag1(options.src)):
        flag+=1
    if(flag2()):
        flag+=1
    if(flag3(options.src)):
        flag+=1
    if(flag>=2):
        print("Warning! You may be a victim of arp spoofing!")
    
