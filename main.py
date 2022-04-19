#! /usr/bin/env python

import scapy.all as scapy
import argparse


def get_argms():
    argms = argparse.ArgumentParser()
    argms.add_argument("-r", "--range", dest="ip", help="target ip/ range")
    options = argms.parse_args()
    return options


def scan(ip):
    req_arp = scapy.ARP(pdst=ip)
    req_bdst = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    req_pck = req_bdst / req_arp
    result = scapy.srp(req_pck, timeout=100, verbose=False)[0]
    answer = []
    for element in result:
        answer.append({"ip": element[1].psrc, "mac": element[1].hwsrc})
    return answer


def rst_print(list):
    print("IP \t\t\t MAC \n-------------------------")
    for elem in list:
        print(elem["ip"] + "\t\t" + elem["mac"])


IP = get_argms()
result = scan(IP)
rst_print(result)
