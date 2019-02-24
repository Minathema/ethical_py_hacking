#!/usr/bin/env python

'''This programm can also be ran using the optparse library which needs an
argument "target" from the user as the IP range which the network
scanner will scan. In the current state, the needed argument is already given
in line 40. If one wants to run it using the optparse library, they need
to un-comment all the lines and comment line 40.'''

import scapy.all as scapy
#import optparse

#def get_argument():
    #parser = optparse.OptionParser()
    #parser.add_option("-t", "--target", dest = "target", help = "Target IP/IP range")
    #(options, argument) = parser.parse_args()
    #if not options.target:
        #parser.error("Please specify an IP range using -t or --target followed by the target IP/IP range, use --help for more info.")
    #return options

def scan(ip):
    arp_request = scapy.ARP(pdst = ip)
    broadcast = scapy.Ether(dst = "ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout = 1, verbose = False)[0]

    clients_list = []
    for element in answered_list:
        clients_dict = {"ip":element[1].psrc, "mac": element[1].hwsrc}
        clients_list.append(clients_dict)
    return clients_list

def print_result(results_list):
    print("IP\t\t\tMAC Address\n-------------------------------------------")
    for client in results_list:
        print(client["ip"] + "\t\t" + client["mac"])


#options = get_argument()
#scan_result = scan(options.target)
scan_result = scan("10.0.2.1/24")
print_result(scan_result)
