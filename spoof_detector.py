import subprocess
import scapy.all as scapy

def scan(ip):
    print(ip)
    req_arp = scapy.ARP(pdst=ip)
    req_bdst = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    req_pck = req_bdst / req_arp
    result = scapy.srp(req_pck, timeout=1, verbose=False)[0]
    try:
        return result[1][0].hwsrc
    except IndexError:
        pass

def sniff(interface):
    scapy.sniff(iface=interface, store=False, prn=cap)


def cap(packet):
    if packet.haslayer(scapy.ARP):
        print(packet[scapy.ARP].psrc)
        rl_mac = scan(1)
        rp_mac = packet[scapy.ARP].hwsrc
        print(rl_mac)
        print(rp_mac)
        if rl_mac != rp_mac:
            print("ARP SPOOFING")



sniff("eth0")
