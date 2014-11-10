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

        # Initialize DNS data structure, given the rules file
        # Entries are nested tuples in a list (we need to maintain ordering) that look like:
        # (current_domain , ("WILDCARD"/"EXACT", "PASS"/"DROP"))
        self.dns_rules_list = []

        self.initialize_all_maps(self.rules_file)

        print(self.dns_rules_list)

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
                       self.dns_rules_list.append((current_domain[1:], ("WILDCARD", "PASS")))
                   # current verdict is DROP, so we set value to False
                   else:
                       self.dns_rules_list.append((current_domain[1:], ("WILDCARD", "DROP")))
               # Exact match
               else:
                   if (current_verdict == "PASS"):
                       self.dns_rules_list.append((current_domain, ("EXACT", "PASS")))
                   # Current verdict is DROP, so we set value to False
                   else:
                       self.dns_rules_list.append((current_domain, ("EXACT", "DROP")))

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
            # (1) UDP packet with destination port 53
            # (2) has exactly one DNS question entry
            # The query type of the entry is either A or AAAA (QTYPE == 1 or QTYPE == 28)
            # QCLASS == 1
            
            # Grab question count in DNS header
            question_count_offset = byte_offset + 12
            question_count = struct.unpack('!H', pkt[question_count_offset:(question_count_offset + 2)])[0]
            # Now we find the beginning of the QNAME field
            q_name_offset = question_count_offset + 8

            # Use q_name_offset to find the beginning of the q_type field
            q_type_offset = q_name_offset
            
            # Build the name of the requested URL
            q_name = ""

            while ord(pkt[q_type_offset:(q_type_offset + 1)]) is not 0:
                index = 0
                current_length = ord(pkt[q_type_offset:(q_type_offset + 1)])
                q_type_offset += 1
                while (index < current_length):
                    current_character = pkt[q_type_offset:(q_type_offset + 1)]
                    q_name += current_character
                    q_type_offset += 1
                    index += 1
                q_name += "."

            # Move away from the 0 byte
            q_type_offset += 1
            q_name = q_name[:(len(q_name) - 1)]

            print("our domain name is: " + q_name)

            # At this point, q_name represents the URL that was requested, as a String
            
            # At this point, q_type_offset is set correctly
            # Unpack q_type_offset
            q_type = struct.unpack('!H', pkt[q_type_offset:(q_type_offset + 2)])[0]
           
            print("q_type: " + str(q_type))

            # Grab q_class and unpack it
            q_class = struct.unpack('!H', pkt[(q_type_offset + 2):(q_type_offset + 4)])[0]
        
            

            # If we have satisfied all of our DNS conditions, then we have verified this packet is a DNS query packet
            if ((destination_port == 53) and (question_count == 1) and ((q_type == 1) or (q_type == 28)) and (q_class == 1)):
                print("About to make decision on packet with name: " + q_name)
                send_packet = self.make_decision_on_dns_packet(pkt, q_name)
                if send_packet:
                    if pkt_dir == PKT_DIR_INCOMING:
                        self.iface_int.send_ip_packet(pkt)
                    elif pkt_dir == PKT_DIR_OUTGOING:
                        self.iface_ext.send_ip_packet(pkt)
                else:
                    print("We've dropped a packet.")
                    return

            # Current packet is a REGULAR UDP packet
            else:
                pass


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

        if pkt_dir == PKT_DIR_INCOMING:
            self.iface_int.send_ip_packet(pkt)
        elif pkt_dir == PKT_DIR_OUTGOING:
            self.iface_ext.send_ip_packet(pkt)
        


        print("src_ip: " + src_ip + "; dst_ip: " + dst_ip)

        # PKT_DIR_INCOMING: The packet has been received from the ext interface. You
        # need to call self.iface_int.send_ip_packet() to pass this packet.
        # PKT_DIR_OUTGOING: The packet has been received from the int interface. You
        # need to call self.iface_ext.send_ip_packet() to pass this packet.
        
        # To drop the packet, simply omit the call to .send_ip_packet()

    '''
    Returns true if the DNS packet that is requesting the domain 'domain_name'
    should be passed, and returns false if the packet should be dropped
    '''
    def make_decision_on_dns_packet(self, packet, domain_name):
        pass_packet_through = True
        for (matched_domain_name, (type_of_match, verdict)) in self.dns_rules_list:
            
            # Exact matches
            if (type_of_match == "EXACT"):
                # If we've matched exactly...
                if (matched_domain_name == domain_name):
                    if (verdict == "DROP"):
                        pass_packet_through = False
                    elif (verdict == "PASS"):
                        pass_packet_through = True
            
            # Wild card matches
            else:  
                # If we've matched our wild card
                if (domain_name.endswith(matched_domain_name)):
                    if (verdict == "DROP"):
                        pass_packet_through = False
                    elif (verdict == "PASS"):
                        pass_packet_through = True

                
        return pass_packet_through


    # TODO: You can add more methods as you want.

# TODO: You may want to add more classes/functions as well.
