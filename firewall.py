#!/usr/bin/env python

from main import PKT_DIR_INCOMING, PKT_DIR_OUTGOING

import socket
import struct
import time

# TODO: Feel free to import any Python standard moduless as necessary.
# (http://docs.python.org/2/library/)
# You must not use any 3rd-party libraries, though.

class TCPRule:
    def __init__(self, ip_lower_bound, ip_upper_bound, port_lower_bound, port_upper_bound, verdict, country_code=None):
        self.ip_range = (ip_lower_bound, ip_upper_bound)
        self.verdict = verdict
        self.port_range = (port_lower_bound, port_upper_bound)
        self.country_code = country_code

class UDPRule:
    def __init__(self, ip_lower_bound, ip_upper_bound, port_lower_bound, port_upper_bound, verdict, country_code=None):
        self.ip_range = (ip_lower_bound, ip_upper_bound)
        self.verdict = verdict
        self.port_range = (port_lower_bound, port_upper_bound)
        self.country_code = country_code

class ICMPRule:
    def __init__(self, ip_lower_bound, ip_upper_bound, icmp_type, verdict, country_code=None):
        self.ip_range = (ip_lower_bound, ip_upper_bound)
        self.verdict = verdict
        self.icmp_type = icmp_type
        self.country_code = country_code

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


        ########## Initialization of rules lists ##########

        # Initialize DNS rules list
        # Entries are nested tuples in a list (we need to maintain ordering) that look like:
        # (current_domain , ("WILDCARD"/"EXACT", "PASS"/"DROP"))
        self.dns_rules_list = []

        # Initialize regular UDP rules list
        self.udp_rules_list = []

        self.initialize_all_maps(self.rules_file)

        ########## End of initialization of rules lists ##########

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
            # Example: pass dns google.com
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
            # Handle UDP rule
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

        ######################################### 
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

        #######################################

        elif (packet_protocol_number == 6):
            # TCP
            pass

        #######################################

        elif (packet_protocol_number == 1):
            # ICMP
            pass

        # Send all packets that aren't marked for drop
        if pkt_dir == PKT_DIR_INCOMING:
            self.iface_int.send_ip_packet(pkt)
        elif pkt_dir == PKT_DIR_OUTGOING:
            self.iface_ext.send_ip_packet(pkt)
        
        print("src_ip: " + src_ip + "; dst_ip: " + dst_ip)


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


    '''
    Converts a CIDR IP address (i.e. 1.1.1.1/24) to an IP range.

    i.e. (1.1.1.1/24) -> (1.1.1.0, 1.1.1.255)
    '''
    def convert_slash_notation_to_ip_range(self, ip_slash_notation):
        lower_bound_to_return = ""
        upper_bound_to_return = ""
        
        ip_split = ip_slash_notation.split('/')
        ip_address = ip_split[0]
        subnet_mask = int(ip_split[1])

        # Split ip_address (1.1.1.1) into its four components
        split_ip_address = ip_address.split('.')

        # Will be a length 32 bit array that represents the IP address (unmodified)
        resultant_bit_array = []

        for component in split_ip_address:
            parsed_component = int(component)
            # Convert each component into array of 1's and 0's
            # For example, '1' gets translated to [0, b, 1], where all elements are strings.
            # We cut off indexes 0 and 1 to get rid of the '0' and 'b'
            component_bit_array = bin(parsed_component)[2:]

            # Since each component is represented by 8 bits, we must pad our resultant_bit_array with 0s
            # if our component value doesn't fill all 8 bits
            number_of_zeros_to_pad = 8 - len(component_bit_array)
            while (number_of_zeros_to_pad > 0):
                resultant_bit_array.append(0)
                number_of_zeros_to_pad -= 1
    
            for string_bit in component_bit_array:
                resultant_bit_array.append(int(string_bit))
       
        # At this point, resultant_bit_array is a length 32 array with all 0's and 1's (integers)
        # It represents the binary representation of our ip address
       
        # Create two length 32 arrays that represent the lower and upper bounds of our range, given the subnet mask
        lower_bound_bit_array = []
        upper_bound_bit_array = []
        for i in range(32):
            # If we're past the subnet mask boundary, fill the lower bound with 0 and the upper bound with 1
            if (i >= subnet_mask):
                lower_bound_bit_array.append(0)
                upper_bound_bit_array.append(1)
            # If we're still to the left of the boundary, just copy the same value over
            else:
                lower_bound_bit_array.append(resultant_bit_array[i])
                upper_bound_bit_array.append(resultant_bit_array[i])

        # Generate two length 4 arrays that represent the (decimal) components of our lower and upper IP bounds
        lower_bound_decimal_components = []
        upper_bound_decimal_components = []
        
        lower_bound_decimal_components.append(self.translate_binary_array_into_decimal(lower_bound_bit_array[:8]))
        upper_bound_decimal_components.append(self.translate_binary_array_into_decimal(upper_bound_bit_array[:8]))
        lower_bound_decimal_components.append(self.translate_binary_array_into_decimal(lower_bound_bit_array[8:16]))
        upper_bound_decimal_components.append(self.translate_binary_array_into_decimal(upper_bound_bit_array[8:16]))
        lower_bound_decimal_components.append(self.translate_binary_array_into_decimal(lower_bound_bit_array[16:24]))
        upper_bound_decimal_components.append(self.translate_binary_array_into_decimal(upper_bound_bit_array[16:24]))
        lower_bound_decimal_components.append(self.translate_binary_array_into_decimal(lower_bound_bit_array[24:32]))
        upper_bound_decimal_components.append(self.translate_binary_array_into_decimal(upper_bound_bit_array[24:32]))

        # Generate a lower_bound string and an upper_bound string from our integer components above, and return!
        for i in range(4):
            lower_bound_to_return += str(lower_bound_decimal_components[i])
            upper_bound_to_return += str(upper_bound_decimal_components[i])
            if (i != 3):
                lower_bound_to_return += "."
                upper_bound_to_return += "."
            
        return (lower_bound_to_return, upper_bound_to_return)


    '''
    Translates a binary array of integers (i.e. [1, 1, 1, 1, 1, 1, 1, 1])
    into its decimal equivalent (i.e. 255)
    '''
    def translate_binary_array_into_decimal(self, binary_array):
        output = 0
        for bit in binary_array:
            output = (output << 1) | bit
        return output

