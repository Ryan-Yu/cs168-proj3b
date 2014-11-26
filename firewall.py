#!/usr/bin/env python

from main import PKT_DIR_INCOMING, PKT_DIR_OUTGOING

import socket
import struct
import time

# Feel free to import any Python standard modules as necessary.
# (http://docs.python.org/2/library/)
# You must not use any 3rd-party libraries, though.

class TCPRule:
    def __init__(self, ip_lower_bound, ip_upper_bound, port_lower_bound, port_upper_bound, verdict, country_code=None):
        self.ip_range = (ip_lower_bound, ip_upper_bound)
        self.verdict = verdict
        self.port_range = (port_lower_bound, port_upper_bound)
        self.country_code = country_code

    def __str__(self):
        string_representation = "\nTCP RULE --\n"
        string_representation += "Verdict: %s\n" % self.verdict
        string_representation += "IP Range: %s\n" % (self.ip_range,)
        string_representation += "Port Range: %s\n" % (self.port_range,)
        string_representation += "Country Code: %s\n" % self.country_code
        return string_representation


class UDPRule:
    def __init__(self, ip_lower_bound, ip_upper_bound, port_lower_bound, port_upper_bound, verdict, country_code=None):
        self.ip_range = (ip_lower_bound, ip_upper_bound)
        self.verdict = verdict
        self.port_range = (port_lower_bound, port_upper_bound)
        self.country_code = country_code

    def __str__(self):
        string_representation = "\nUDP RULE --\n"
        string_representation += "Verdict: %s\n" % self.verdict
        string_representation += "IP Range: %s\n" % (self.ip_range,)
        string_representation += "Port Range: %s\n" % (self.port_range,)
        string_representation += "Country Code: %s\n" % self.country_code
        return string_representation


class ICMPRule:
    def __init__(self, ip_lower_bound, ip_upper_bound, icmp_type, verdict, country_code=None):
        self.ip_range = (ip_lower_bound, ip_upper_bound)
        self.verdict = verdict
        self.icmp_type = icmp_type
        self.country_code = country_code

    def __str__(self):
        string_representation = "\nICMP RULE --\n"
        string_representation += "Verdict: %s\n" % self.verdict
        string_representation += "IP Range: %s\n" % (self.ip_range,)
        string_representation += "ICMP Type: %s\n" % self.icmp_type
        string_representation += "Country Code: %s\n" % self.country_code
        return string_representation


class DNSRule:
    def __init__(self, domain, type_of_match, verdict):
        self.domain = domain
        self.type_of_match = type_of_match
        self.verdict = verdict

    def __str__(self):
        string_repres = "\nDNS RULE --\n"
        string_repres += "Domain: %s\n" % self.domain
        string_repres += "Type of match: %s\n" % self.type_of_match
        string_repres += "Verdict: %s\n" % self.verdict
        return string_repres

class Firewall:
    def __init__(self, config, iface_int, iface_ext):
        self.iface_int = iface_int
        self.iface_ext = iface_ext

        self.rules_file = config['rule']
        # Initialize geo_id map, given the geo_id text file
        self.geo_id_map = self.initialize_geo_id_file("geoipdb.txt")
        ########## Initialization of rules lists ##########

        # Initialize DNS rules list
        # Entries are nested tuples in a list (we need to maintain ordering) that look like:
        # (current_domain , ("WILDCARD"/"EXACT", "PASS"/"DROP"))
        self.dns_rules_list = []

        # Initialize regular UDP rules list, TCP rules list, and ICMP rules list
        self.udp_rules_list = []
        self.tcp_rules_list = []
        self.icmp_rules_list = []

        self.initialize_all_maps(self.rules_file)

        ########## End of initialization of rules lists ##########
        
        
        for udp_rule in self.udp_rules_list:
            print(udp_rule)

        for tcp_rule in self.tcp_rules_list:
            print(tcp_rule)

        for icmp_rule in self.icmp_rules_list:
            print(icmp_rule)
        

    def initialize_all_maps(self, rules_file):
       
        rules = open(rules_file)
        
        # Iterate through each rule in rules file, handling different types of rules separately
        for line in rules:
            stripped_line = line.strip()
            
            # Ignore empty lines
            if (len(stripped_line) == 0):
                continue

            # Ignore comments (lines starting with %)
            if (stripped_line[0] == '%'):
                continue

            split_line = stripped_line.split(" ")
            
            current_verdict = split_line[0].upper()
            current_protocol = split_line[1].upper()
           
            ########## Handle DNS rule ##########
            if (current_protocol == "DNS"):

               current_domain = split_line[2] 

               # Wild card
               # Entries look like: <current_domain, T/F>
               if (split_line[2].startswith("*")):
                   if (current_verdict == "PASS"):
                       new_dns_rule = DNSRule(current_domain[1:], "WILDCARD", "PASS")
                       self.udp_rules_list.append(new_dns_rule)
                       
                   # current verdict is DROP, so we set value to False
                   else:
                       new_dns_rule = DNSRule(current_domain[1:], "WILDCARD", "DROP")
                       self.udp_rules_list.append(new_dns_rule)
                       
               # Exact match
               else:
                   if (current_verdict == "PASS"):
                       new_dns_rule = DNSRule(current_domain, "EXACT", "PASS")
                       self.udp_rules_list.append(new_dns_rule)
                       
                   # Current verdict is DROP, so we set value to False
                   else:
                       new_dns_rule = DNSRule(current_domain, "EXACT", "DROP")
                       self.udp_rules_list.append(new_dns_rule)
                       

            ########## Handle TCP rule ##########
            elif (current_protocol == "TCP"):
                ip = split_line[2]
                port = split_line[3]
                
                # The arguments that will be used in the constructor
                declared_country_code = None
                declared_ip_lower_bound = ""
                declared_ip_upper_bound = ""
                declared_port_lower_bound = float("-inf")
                declared_port_upper_bound = float("inf")

                # Initialize IP range
                
                if (ip == "any"):
                    declared_ip_lower_bound = "0.0.0.0"
                    declared_ip_upper_bound = "255.255.255.255"
                # IP is country code
                elif (ip.upper() in self.geo_id_map):
                    declared_country_code = ip.upper()
                    declared_ip_lower_bound = "country"
                    declared_ip_upper_bound = "country"
                # IP is in CIDR notation
                elif ("/" in ip):
                    ip_range = self.convert_slash_notation_to_ip_range(ip)
                    declared_ip_lower_bound = ip_range[0]
                    declared_ip_upper_bound = ip_range[1]

                # IP is a singular IP address
                else:
                    declared_ip_lower_bound = ip
                    declared_ip_upper_bound = ip

                # Initialize port range
                
                if (port == "any"):
                    pass
                elif ("-" in port):
                    split_port_range = port.split('-')
                    declared_port_lower_bound = split_port_range[0]
                    declared_port_upper_bound = split_port_range[1]
                else:
                    declared_port_lower_bound = port
                    declared_port_upper_bound = port
                
                # Initialize new TCP rule and append it to our TCP rules list
                new_tcp_rule = TCPRule(declared_ip_lower_bound, declared_ip_upper_bound, declared_port_lower_bound, declared_port_upper_bound, current_verdict, declared_country_code)
                self.tcp_rules_list.append(new_tcp_rule)

            ########## Handle UDP rule ##########
            elif (current_protocol == "UDP"):
                ip = split_line[2]
                port = split_line[3]
                
                # The arguments that will be used in the constructor
                declared_country_code = None
                declared_ip_lower_bound = ""
                declared_ip_upper_bound = ""
                declared_port_lower_bound = float("-inf")
                declared_port_upper_bound = float("inf")

                # Initialize IP range
                
                if (ip == "any"):
                    declared_ip_lower_bound = "0.0.0.0"
                    declared_ip_upper_bound = "255.255.255.255"
                # IP is country code
                elif (ip.upper() in self.geo_id_map):
                    declared_country_code = ip.upper()
                    declared_ip_lower_bound = "country"
                    declared_ip_upper_bound = "country"
                # IP is in CIDR notation
                elif ("/" in ip):
                    ip_range = self.convert_slash_notation_to_ip_range(ip)
                    declared_ip_lower_bound = ip_range[0]
                    declared_ip_upper_bound = ip_range[1]

                # IP is a singular IP address
                else:
                    declared_ip_lower_bound = ip
                    declared_ip_upper_bound = ip

                # Initialize port range
                
                if (port == "any"):
                    pass
                elif ("-" in port):
                    split_port_range = port.split('-')
                    declared_port_lower_bound = split_port_range[0]
                    declared_port_upper_bound = split_port_range[1]
                else:
                    declared_port_lower_bound = port
                    declared_port_upper_bound = port
                
                # Initialize new UDP rule and append it to our UDP rules list
                new_udp_rule = UDPRule(declared_ip_lower_bound, declared_ip_upper_bound, declared_port_lower_bound, declared_port_upper_bound, current_verdict, declared_country_code)
                self.udp_rules_list.append(new_udp_rule)

            ########## Handle ICMP rule ##########
            elif (current_protocol == "ICMP"):
                ip = split_line[2]
                icmp_type = split_line[3]
                
                # The arguments that will be used in the constructor
                declared_country_code = None
                declared_ip_lower_bound = ""
                declared_ip_upper_bound = ""

                # Initialize IP range
                
                if (ip == "any"):
                    declared_ip_lower_bound = "0.0.0.0"
                    declared_ip_upper_bound = "255.255.255.255"
                # IP is country code
                elif (ip.upper() in self.geo_id_map):
                    declared_country_code = ip.upper()
                    declared_ip_lower_bound = "country"
                    declared_ip_upper_bound = "country"
                # IP is in CIDR notation
                elif ("/" in ip):
                    ip_range = self.convert_slash_notation_to_ip_range(ip)
                    declared_ip_lower_bound = ip_range[0]
                    declared_ip_upper_bound = ip_range[1]

                # IP is a singular IP address
                else:
                    declared_ip_lower_bound = ip
                    declared_ip_upper_bound = ip

                # Initialize new ICMP rule and append it to our ICMP rules list
                new_icmp_rule = ICMPRule(declared_ip_lower_bound, declared_ip_upper_bound, icmp_type, current_verdict, declared_country_code)
                self.icmp_rules_list.append(new_icmp_rule)



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
        # Whenever a packet is captured, this handler will be invoked. 
        
        try: 
            src_ip = socket.inet_ntoa(pkt[12:16])
            dst_ip = socket.inet_ntoa(pkt[16:20])

            src_ip_array = src_ip.split(".")
            dst_ip_array = dst_ip.split(".")

            ip_header_length = ord(pkt[0:1]) & 0x0f
            # i.e. number of bytes before UDP/TCP header begins
            byte_offset = ip_header_length * 4

            packet_protocol_number = ord(pkt[9:10])

        except:
            return

        ######################################### 
        # UDP case
        if (packet_protocol_number == 17):
            # If UDP, then source port is given by [20:22] and dst port given by [22:24]
            
            # pkt[byte_offset:(byte_offset + 2)] returns String representing source port
            # struct.unpack then unpacks this String as a short, and returns it as a tuple with a blank second item
            source_port = struct.unpack('!H', pkt[byte_offset:(byte_offset + 2)])[0]
            destination_port = struct.unpack('!H', pkt[(byte_offset + 2):(byte_offset + 4)])[0]
         
            # Set external IP and external port based on direction of packet
            external_ip = dst_ip
            external_port = destination_port
            if (pkt_dir == PKT_DIR_INCOMING):
                external_ip = src_ip
                external_port = source_port

            try:

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

                # At this point, q_name represents the URL that was requested, as a String
                
                # At this point, q_type_offset is set correctly
                # Unpack q_type_offset
                q_type = struct.unpack('!H', pkt[q_type_offset:(q_type_offset + 2)])[0]
               
                # Grab q_class and unpack it
                q_class = struct.unpack('!H', pkt[(q_type_offset + 2):(q_type_offset + 4)])[0]
        
                # If we have satisfied all of our DNS conditions, then we have verified this packet is a DNS query packet
                if ((external_port == 53) and (question_count == 1) and ((q_type == 1) or (q_type == 28)) and (q_class == 1)):
                    send_packet = self.make_decision_on_udp_packet(external_ip, external_port, True, q_name)
                    if send_packet:
                        if pkt_dir == PKT_DIR_INCOMING:
                            self.iface_int.send_ip_packet(pkt)
                        elif pkt_dir == PKT_DIR_OUTGOING:
                            self.iface_ext.send_ip_packet(pkt)

                        # print("SENT DNS PACKET")
                    else:
                        # We've dropped our packet, so just return
                        # print("DROPPED DNS PACKET")
                        return
                
                # Not a DNS query packet (it is a regular UDP packet)
                else:
                    # Destination ip address given by 'dst_ip'; destination port given by 'destination_port'
                    send_packet = self.make_decision_on_udp_packet(external_ip, external_port, False)                
                    if send_packet:
                        if pkt_dir == PKT_DIR_INCOMING:
                            self.iface_int.send_ip_packet(pkt)
                        elif pkt_dir == PKT_DIR_OUTGOING:
                            self.iface_ext.send_ip_packet(pkt)
                        # print("SENT UDP PACKET")
                    else:
                        # We've dropped our packet, so just return
                        # print("DROPPED UDP PACKET")
                        return

            # Current packet is a regular UDP packet, because we encountered an error trying to parse DNS-specific stuff
            except:
                # Look at UDP rules list and determine whether UDP packet should be dropped
                 
                # Destination ip address given by 'dst_ip'; destination port given by 'destination_port'
                send_packet = self.make_decision_on_udp_packet(external_ip, external_port, False)                
                if send_packet:
                    if pkt_dir == PKT_DIR_INCOMING:
                        self.iface_int.send_ip_packet(pkt)
                    elif pkt_dir == PKT_DIR_OUTGOING:
                        self.iface_ext.send_ip_packet(pkt)
                    # print("SENT UDP PACKET")
                else:
                    # We've dropped our packet, so just return
                    # print("DROPPED UDP PACKET")
                    return



        #######################################

        elif (packet_protocol_number == 6):
            # Look at TCP rules list and determine whether TCP packet should be dropped
            
            # pkt[byte_offset:(byte_offset + 2)] returns String representing source port
            # struct.unpack then unpacks this String as a short, and returns it as a tuple with a blank second item
            source_port = struct.unpack('!H', pkt[byte_offset:(byte_offset + 2)])[0]
            destination_port = struct.unpack('!H', pkt[(byte_offset + 2):(byte_offset + 4)])[0]
            
            # Set external IP and external port based on direction of packet
            external_ip = dst_ip
            external_port = destination_port

            internal_ip = src_ip
            internal_port = source_port

            if (pkt_dir == PKT_DIR_INCOMING):
                external_ip = src_ip
                external_port = source_port
                internal_ip = dst_ip
                internal_port = destination_port

            send_packet = self.make_decision_on_tcp_packet(external_ip, external_port, internal_ip, internal_port, pkt)                
            if send_packet:
                if pkt_dir == PKT_DIR_INCOMING:
                    self.iface_int.send_ip_packet(pkt)
                elif pkt_dir == PKT_DIR_OUTGOING:
                    self.iface_ext.send_ip_packet(pkt)
                # print("SENT TCP PACKET")
            else:
                # We've dropped our packet, so just return
                # print("DROPPED TCP PACKET")
                return


        #######################################

        elif (packet_protocol_number == 1):
            # Look at ICMP rules list and determine whether ICMP packet should be dropped
            
            # Set external IP based on direction of packet
            external_ip = dst_ip
            if (pkt_dir == PKT_DIR_INCOMING):
                external_ip = src_ip

            # Parse ICMP type from the packet
            icmp_type = ord(pkt[byte_offset:(byte_offset + 1)])
            send_packet = self.make_decision_on_icmp_packet(external_ip, icmp_type)                
            if send_packet:
                if pkt_dir == PKT_DIR_INCOMING:
                    self.iface_int.send_ip_packet(pkt)
                elif pkt_dir == PKT_DIR_OUTGOING:
                    self.iface_ext.send_ip_packet(pkt)
                # print("SENT ICMP PACKET")
            else:
                # We've dropped our packet, so just return
                # print("DROPPED ICMP PACKET")
                return


        else:
            # Send all packets that aren't marked for drop
            if pkt_dir == PKT_DIR_INCOMING:
                self.iface_int.send_ip_packet(pkt)
            elif pkt_dir == PKT_DIR_OUTGOING:
                self.iface_ext.send_ip_packet(pkt)
        

    '''
    Returns true if the ICMP packet with destination_ip and icmp_type should be passed, and false if it should be dropped
    '''
    def make_decision_on_icmp_packet(self, destination_ip, icmp_type):
        
        pass_packet_through = True
        for icmp_rule in self.icmp_rules_list:
            icmp_rule_satisfied = False
            ip_rule_satisfied = False

            icmp_type_rule = int(icmp_rule.icmp_type)

            # if our packet's destination port lies within the rule's port range
            if (icmp_type_rule == icmp_type): 
                icmp_rule_satisfied = True

            # Our IP rule is a country code
            if icmp_rule.country_code is not None:
                list_of_ip_ranges_for_country = self.geo_id_map[icmp_rule.country_code]

                if self.binary_search_list_of_ip_ranges(list_of_ip_ranges_for_country, destination_ip):
                    ip_rule_satisfied = True

            # Our IP rule is an IP range
            else:
                ip_range = icmp_rule.ip_range
                if self.is_ip_contained_within_range(ip_range[0], ip_range[1], destination_ip):
                    ip_rule_satisfied = True

            # Depending on the verdict and whether our port/ip rules are satisfied, we decide whether to pass/drop the packet
            if (icmp_rule_satisfied and ip_rule_satisfied):
                if (icmp_rule.verdict == "PASS"):
                    pass_packet_through = True
                elif (icmp_rule.verdict == "DROP"):
                    pass_packet_through = False

        return pass_packet_through 



    '''
    Returns true if the UDP packet with destination_ip and destination_port should be passed, and false if it should be dropped
    '''
    def make_decision_on_tcp_packet(self, destination_ip, destination_port, source_ip, source_port, packet):
        
        pass_packet_through = True
        for tcp_rule in self.tcp_rules_list:
            port_rule_satisfied = False
            ip_rule_satisfied = False

            port_range = tcp_rule.port_range

            # if our packet's destination port lies within the rule's port range
            if (port_range[1] == float("inf") and port_range[0] == float("-inf")):
                port_rule_satisfied = True
            elif ((destination_port <= int(port_range[1])) and (destination_port >= int(port_range[0]))):
                port_rule_satisfied = True

            # Our IP rule is a country code
            if tcp_rule.country_code is not None:
                list_of_ip_ranges_for_country = self.geo_id_map[tcp_rule.country_code]

                if self.binary_search_list_of_ip_ranges(list_of_ip_ranges_for_country, destination_ip):
                    ip_rule_satisfied = True

            # Our IP rule is an IP range
            else:
                ip_range = tcp_rule.ip_range
                if self.is_ip_contained_within_range(ip_range[0], ip_range[1], destination_ip):
                    ip_rule_satisfied = True

            # Depending on the verdict and whether our port/ip rules are satisfied, we decide whether to pass/drop the packet
            if (port_rule_satisfied and ip_rule_satisfied):
                if (tcp_rule.verdict == "PASS"):
                    pass_packet_through = True
                elif (tcp_rule.verdict == "DROP"):
                    pass_packet_through = False
                # New rule for project 3b
                elif (tcp_rule.verdict == "DENY"):
                    pass_packet_through = False

                    self.send_reset_packet(packet, destination_ip, destination_port, source_ip, source_port)
    
        
        return pass_packet_through 
    
    
    '''
    Returns true if the UDP packet with destination_ip and destination_port should be passed, and false if it should be dropped
    '''
    def make_decision_on_udp_packet(self, destination_ip, destination_port, is_dns_packet, domain_name=None):
        pass_packet_through = True
        
        # We're not making a decision on a DNS Query packet, so we iterate through ONLY the UDP rules (and not the DNS rules)
        if not is_dns_packet:
            for udp_rule in self.udp_rules_list:
                
                if isinstance(udp_rule, DNSRule):
                    continue

                port_rule_satisfied = False
                ip_rule_satisfied = False

                port_range = udp_rule.port_range

                # if our packet's destination port lies within the rule's port range
                if (port_range[1] == float("inf") and port_range[0] == float("-inf")):
                    port_rule_satisfied = True
                elif ((destination_port <= int(port_range[1])) and (destination_port >= int(port_range[0]))):
                    port_rule_satisfied = True

                # Our IP rule is a country code
                if udp_rule.country_code is not None:
                    list_of_ip_ranges_for_country = self.geo_id_map[udp_rule.country_code]

                    if self.binary_search_list_of_ip_ranges(list_of_ip_ranges_for_country, destination_ip):
                        ip_rule_satisfied = True

                # Our IP rule is an IP range
                else:
                    ip_range = udp_rule.ip_range
                    if self.is_ip_contained_within_range(ip_range[0], ip_range[1], destination_ip):
                        ip_rule_satisfied = True

                # Depending on the verdict and whether our port/ip rules are satisfied, we decide whether to pass/drop the packet
                if (port_rule_satisfied and ip_rule_satisfied):
                    if (udp_rule.verdict == "PASS"):
                        pass_packet_through = True
                    elif (udp_rule.verdict == "DROP"):
                        pass_packet_through = False
        
        # We are making a decision on a DNS Query packet, so iterate through ALL rules, including DNS rules
        else:
            for udp_rule in self.udp_rules_list:
                
                # Consider DNS rule
                if isinstance(udp_rule, DNSRule):
                    
                    if (udp_rule.type_of_match == "EXACT"):
                        # If we've matched exactly...
                        if (domain_name == udp_rule.domain):
                            if (udp_rule.verdict == "DROP"):
                                pass_packet_through = False
                            elif (udp_rule.verdict == "PASS"):
                                pass_packet_through = True

                    
                    # Wild card matches
                    else:  
                        # If we've matched our wild card
                        if (domain_name.endswith(udp_rule.domain)):
                            if (udp_rule.verdict == "DROP"):
                                pass_packet_through = False
                            elif (udp_rule.verdict == "PASS"):
                                pass_packet_through = True
                
                # Consider regular UDP rule
                elif isinstance(udp_rule, UDPRule):
                    port_rule_satisfied = False
                    ip_rule_satisfied = False

                    port_range = udp_rule.port_range

                    # if our packet's destination port lies within the rule's port range
                    if (port_range[1] == float("inf") and port_range[0] == float("-inf")):
                        port_rule_satisfied = True
                    elif ((destination_port <= int(port_range[1])) and (destination_port >= int(port_range[0]))):
                        port_rule_satisfied = True

                    # Our IP rule is a country code
                    if udp_rule.country_code is not None:
                        list_of_ip_ranges_for_country = self.geo_id_map[udp_rule.country_code]

                        if self.binary_search_list_of_ip_ranges(list_of_ip_ranges_for_country, destination_ip):
                            ip_rule_satisfied = True

                    # Our IP rule is an IP range
                    else:
                        ip_range = udp_rule.ip_range
                        if self.is_ip_contained_within_range(ip_range[0], ip_range[1], destination_ip):
                            ip_rule_satisfied = True

                    # Depending on the verdict and whether our port/ip rules are satisfied, we decide whether to pass/drop the packet
                    if (port_rule_satisfied and ip_rule_satisfied):
                        if (udp_rule.verdict == "PASS"):
                            pass_packet_through = True
                        elif (udp_rule.verdict == "DROP"):
                            pass_packet_through = False
        
        return pass_packet_through    




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


    def send_reset_packet(self, packet, destination_ip, destination_port, source_ip, source_port):
        # Need destination_ip, destination_port, ipv4 header length 
        # Need to set RST flag to 1

        reset_packet_to_send = ""
        ip_header_length = ord(packet[0:1]) & 0x0f
        reset_packet_checksum = self.calculate_checksum(ip_header_length * 4, packet)
       
        packet_total_length = struct.unpack('!H', packet[2:4])[0]

        reset_packet_tcp_checksum = self.calculate_tcp_checksum(packet_total_length, ip_header_length * 4, packet)

        

        reset_packet_destination_ip = source_ip
        reset_packet_destination_port = source_port



    def calculate_tcp_checksum(self, total_length, ip_header_length, packet):
        print("Total length: %s; ip header length: %s" % (total_length, ip_header_length))
      
        source_ip = struct.unpack('!L', packet[12:16])[0]
        destination_ip = struct.unpack('!L', packet[16:20])[0]

        byte_counter = ip_header_length
        total_sum = 0

        # Parse up to the tcp checksum, which starts at byte 16
        while (byte_counter < total_length):
            # Skip 2 bytes of tcp checksum
            if (byte_counter == (16 + ip_header_length)):
                byte_counter += 2
                continue
            total_sum += struct.unpack('!H', packet[byte_counter:(byte_counter + 2)])[0]    
            byte_counter += 2
       
        # Add on the source IP, destination IP, protocol (always 6), total 16-bit TCP length
        total_sum += source_ip
        total_sum += destination_ip
        total_sum += 6
        total_sum += (total_length - ip_header_length)

        # Extract first four bits of our sum as a binary string
        first_four_bits = bin(total_sum)[:6]

        # Isolate the remainder of our sum as a binary string
        final_segment = bin(total_sum)[6:]
        final_segment = '0b%s' % final_segment

        # Add the carry and the remainder
        summed_segment = bin(int(first_four_bits, 2) + int(final_segment, 2))
       
        # Flip all bits in summed_segment
        final_checksum = '0b'
        index = 2
        while (index < len(summed_segment)):
            if (summed_segment[index] == '0'):
                final_checksum += '1'
            else:
                final_checksum += '0'
            index += 1
  
        decimal_final_checksum = int(final_checksum, 2)
        return decimal_final_checksum



    '''
    Calculates a new checksum (in decimal) based off of an IPv4 header, and a header_length (given in bytes)
    '''
    def calculate_checksum(self, ipv4_header_length, packet):
        
        byte_counter = 0
        total_sum = 0

        # Parse up to the header checksum, which starts at byte 10
        while (byte_counter < ipv4_header_length):
            # Skip 2 bytes of ipv4 checksum
            if (byte_counter == 10):
                byte_counter += 2
                continue
            total_sum += struct.unpack('!H', packet[byte_counter:(byte_counter + 2)])[0]    
            byte_counter += 2
        
        # Extract first four bits of our sum as a binary string
        first_four_bits = bin(total_sum)[:6]

        # Isolate the remainder of our sum as a binary string
        final_segment = bin(total_sum)[6:]
        final_segment = '0b%s' % final_segment

        # Add the carry and the remainder
        summed_segment = bin(int(first_four_bits, 2) + int(final_segment, 2))
       
        # Flip all bits in summed_segment
        final_checksum = '0b'
        index = 2
        while (index < len(summed_segment)):
            if (summed_segment[index] == '0'):
                final_checksum += '1'
            else:
                final_checksum += '0'
            index += 1
  
        decimal_final_checksum = int(final_checksum, 2)
        return decimal_final_checksum


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

        # Generate a length 32 integer array that represents the binary representation of the ip address
        resultant_bit_array = self.break_ip_address_into_binary_array(ip_address)

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
    Given two IP addresses that represent the lower bound and upper bound of an IP range,
    returns (T/F) whether a third IP address (i.e. 'ip_address') is contained within the range of the lower and upper bound addresses.

    Containment is inclusive; i.e. 2.2.2.2 is indeed contained within the range (2.2.2.2, 2.2.2.3)
    '''
    def is_ip_contained_within_range(self, range_lower_bound, range_upper_bound, ip_address):
        lower_bound_bit_array = self.break_ip_address_into_binary_array(range_lower_bound)
        upper_bound_bit_array = self.break_ip_address_into_binary_array(range_upper_bound)
        ip_address_bit_array = self.break_ip_address_into_binary_array(ip_address)

        lower_bound_in_decimal = self.translate_binary_array_into_decimal(lower_bound_bit_array)
        upper_bound_in_decimal = self.translate_binary_array_into_decimal(upper_bound_bit_array)
        ip_address_in_decimal = self.translate_binary_array_into_decimal(ip_address_bit_array)

        return (ip_address_in_decimal <= upper_bound_in_decimal) and (ip_address_in_decimal >= lower_bound_in_decimal)


    '''
    Given a ip_address represented as a String in dotted quad notation (i.e. 1.1.1.1),
    returns a length 32 integer array that represents the binary representation of the ip address)

    i.e. 1.1.1.1 returns
    [0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1]
    '''
    def break_ip_address_into_binary_array(self, ip_address):
        # Split ip_address (1.1.1.1) into its four components
        split_ip_address = ip_address.split('.')

        # Will be a length 32 bit array that represents the IP address
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
        
        return resultant_bit_array


    '''
    Translates a binary array of integers (i.e. [1, 1, 1, 1, 1, 1, 1, 1])
    into its decimal equivalent (i.e. 255)
    '''
    def translate_binary_array_into_decimal(self, binary_array):
        output = 0
        for bit in binary_array:
            output = (output << 1) | bit
        return output


    '''
    Given an ip address, converts the IP address into the integer representation of the 32 bits in the IP address.
    This is used for comparing whether one IP address is "larger" or "smaller" than another IP address
    '''
    def translate_ip_address_into_integer(self, ip_address):
        ip_address_as_binary_array = self.break_ip_address_into_binary_array(ip_address)
        return self.translate_binary_array_into_decimal(ip_address_as_binary_array)


    '''
    Given a list of IP range tuples in ascending sorted order, binary searches the list to see of any of the ranges contain the 'ip_address'
    
    Returns true if the 'ip_address' is contained within ANY of the ranges in the list_of_ip_ranges
    '''
    def binary_search_list_of_ip_ranges(self, list_of_ip_ranges, ip_address):
        low = 0
        high = len(list_of_ip_ranges) - 1
        while (low <= high):
            middle = (low + high) / 2
            middle_ip_range = list_of_ip_ranges[middle]
            # ip_address is contained within the current ip range, so return True
            if self.is_ip_contained_within_range(middle_ip_range[0], middle_ip_range[1], ip_address):
                return True
            # Look on left side of middle index
            if self.translate_ip_address_into_integer(ip_address) < self.translate_ip_address_into_integer(middle_ip_range[0]):
                high = middle - 1
            # Look on right side of middle index
            if self.translate_ip_address_into_integer(ip_address) > self.translate_ip_address_into_integer(middle_ip_range[1]):
                low = middle + 1
        return False
            


