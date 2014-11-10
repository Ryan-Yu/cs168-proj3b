#!/usr/bin/env python

from main import PKT_DIR_INCOMING, PKT_DIR_OUTGOING

import socket
import struct
import time

# TODO: Feel free to import any Python standard moduless as necessary.
# (http://docs.python.org/2/library/)
# You must not use any 3rd-party libraries, though.

class Firewall:
    def __init__(self, config, iface_int, iface_ext):
        self.iface_int = iface_int
        self.iface_ext = iface_ext

        # TODO: Load the firewall rules (from rule_filename) here.
        print 'I am supposed to load rules from %s, but I am feeling lazy.' % \
                config['rule']

        self.rules_file = config['rule']
        # Initialize geo_id map, given the geo_id text file
        self.geo_id_map = self.initialize_geo_id_file("geoipdb.txt")

        # Initialize DNS maps, given the rules file
        self.exact_dns_map = {}
        self.wild_card_dns_map = {}

        

        self.initialize_all_maps(self.rules_file)

        print(self.exact_dns_map)
        print(self.wild_card_dns_map)

        # TODO: Initialize TCP, UDP, ICMP data structures  


    def initialize_all_maps(self, rules_file):
        
        rules = open(rules_file)
        
        # Iterate through each rule in rules file, handling different types of rules separately
        for line in rules:
            stripped_line = line.strip()
            split_line = stripped_line.split(" ")
            
            current_verdict = split_line[0].upper()
            current_protocol = split_line[1].upper()
           
            # Handle DNS rule
            if (current_protocol == "DNS"):

               current_domain = split_line[2] 

               # Wild card
               # Entries look like: <current_domain, T/F>
               if (split_line[2].startswith("*")):
                   if (current_verdict == "PASS"):
                       self.wild_card_dns_map[current_domain[1:]] = True
                   # current verdict is DROP, so we set value to False
                   else:
                       self.wild_card_dns_map[current_domain[1:]] = False
               # Exact match
               else:
                   if (current_verdict == "PASS"):
                       self.exact_dns_map[current_domain] = True
                   # Current verdict is DROP, so we set value to False
                   else:
                       self.exact_dns_map[current_domain] = False

            elif (current_protocol == "TCP"):
                continue
            elif (current_protocol == "UDP"):
                continue
            elif (current_protocol == "ICMP"):
                continue


    '''
    Returns a map of <country_code -> list of IP ranges corresponding to the country_code>
    given a geo_id file ('filename' parameter)
    '''
    def initialize_geo_id_file(self, filename):
        resultant_map = {}
        read_in = open(filename)
        for line in read_in:
            stripped_line = line.strip()
            current_line_split = stripped_line.split(" ")
            current_country = current_line_split[2]
            
            if current_country not in resultant_map:
                # Current country does not exist
                resultant_map[current_country] = []

            resultant_map[current_country].append((current_line_split[0], current_line_split[1]))
        return resultant_map



    # @pkt_dir: either PKT_DIR_INCOMING or PKT_DIR_OUTGOING
    # @pkt: Python string that contains the actual data of the IPv4 packet (including IP header)
    def handle_packet(self, pkt_dir, pkt):
        # TODO: Your main firewall code will be here.
        # Whenever a packet is captured, this handler will be invoked. 
        
        src_ip = socket.inet_ntoa(pkt[12:16])
        dst_ip = socket.inet_ntoa(pkt[16:20])

        src_ip_array = src_ip.split(".")
        dst_ip_array = dst_ip.split(".")

        ip_header_length = ord(pkt[0:1]) & 0x0f
        # i.e. number of bytes before UDP/TCP header begins
        byte_offset = ip_header_length * 4

        packet_protocol_number = ord(pkt[9:10])
        
        # UDP case
        if (packet_protocol_number == 17):
            # If UDP, then source port is given by [20:22] and dst port given by [22:24]
            
            # pkt[byte_offset:(byte_offset + 2)] returns String representing source port
            # struct.unpack then unpacks this String as a short, and returns it as a tuple with a blank second item
            source_port = struct.unpack('!H', pkt[byte_offset:(byte_offset + 2)])[0]
            destination_port = struct.unpack('!H', pkt[(byte_offset + 2):(byte_offset + 4)])[0]
            
            # If the following conditions are met, then we know current packet is a DNS query packet:
            # (1) 

        elif (packet_protocol_number == 6):
            # TCP
            pass

        elif (packet_protocol_number == 1):
            # ICMP
            pass

        # We encounter a DNS query packet
        if (1 == 1):
            pass
        # IP packet
        else:
            pass
        


        print("src_ip: " + src_ip + "; dst_ip: " + dst_ip)

        # PKT_DIR_INCOMING: The packet has been received from the ext interface. You
        # need to call self.iface_int.send_ip_packet() to pass this packet.
        # PKT_DIR_OUTGOING: The packet has been received from the int interface. You
        # need to call self.iface_ext.send_ip_packet() to pass this packet.
        
        # To drop the packet, simply omit the call to .send_ip_packet()


    # TODO: You can add more methods as you want.

# TODO: You may want to add more classes/functions as well.
