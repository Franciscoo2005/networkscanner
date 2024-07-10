import scapy.all as scapy
import argparse


def get_cmd_arg():
    parser = argparse.ArgumentParser()
    parser.add_argument("-t", "--target", dest="target_ip", help="specify the target ip")
    parser.add_argument("-s", "--spoofed", dest="spoofed_ip", help="specify the spoofed ip")
    options = parser.parse_args()
    return options


def packet(ip_range):
    ARP_REQUEST = scapy.ARP(pdst=ip_range)
    BROADCAST = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    ARP_REQUEST_BROADCAST = BROADCAST/ARP_REQUEST
    return ARP_REQUEST_BROADCAST


def send_n_response(arp_packet):
    item = []
    answered_request =scapy.srp(arp_packet,timeout=2, verbose=False)[0]
    for elements in answered_request:
        dict_values={"ip":elements[1].psrc, "mac":elements[1].hwsrc}
        item.append(dict_values)
    return item


def print_values():
    values = send_n_response(arp_packet)
    print("IP ADDRESS\t\tMAC ADDRESS\n...........................................")
    for element in values:
        print(element["ip"] + "\t\t" + element["mac"])


arp_packet = packet("192.168.125.0/24")
send_n_response(arp_packet)
print_values()
