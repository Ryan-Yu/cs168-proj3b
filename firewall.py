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


class HTTPRule:
    def __init__(self, hostname, hostname_type):
        # Hostname can be an IP address, wildcard domain name, or exact match domain name, (or alternatively, just a *)
        self.hostname = hostname
        # IP, WILDCARD, EXACT, ANY
        self.hostname_type = hostname_type

    def __str__(self):
        string_repres = "\nHTTPRule --\n"
        string_repres += "Hostname: %s\n" % self.hostname
        string_repres += "Hostname type: %s\n" % self.hostname_type
        return string_repres


class HTTPConnection:
    def __init__(self, unparsed_request="", unparsed_response="", is_request_complete=False, is_response_complete=False, host_name="", method="", path="", version="", status_code="", object_size="", expected_request_seq_no=None, expected_response_seq_no=None):
        self.unparsed_request = unparsed_request
        self.unparsed_response = unparsed_response
        self.is_request_complete = is_request_complete
        self.is_response_complete = is_response_complete
        self.host_name = host_name
        self.method = method
        self.path = path
        self.version = version
        self.status_code = status_code
        self.object_size = object_size
        self.expected_request_seq_no = expected_request_seq_no
        self.expected_response_seq_no = expected_response_seq_no

    def append_to_unparsed_request(self, string_to_append):
        self.unparsed_request += string_to_append

    def append_to_unparsed_response(self, string_to_append):
        self.unparsed_response += string_to_append

    def __str__(self):
        string_repres = "\nHTTPConnection --\n"
        string_repres += "Unparsed request: %s\n" % self.unparsed_request
        string_repres += "Unparsed response: %s\n" % self.unparsed_response
        string_repres += "Is message complete? %s\n" % (self.is_request_complete and self.is_response_complete)
        string_repres += "LOG message: (%s, %s, %s, %s, %s, %s)" % (self.host_name, self.method, self.path, self.version, self.status_code, self.object_size)
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
        self.http_rules_list = []

        self.initialize_all_maps(self.rules_file)

        ########## End of initialization of rules lists ##########
        
        ########## Initialize HTTP connections map ##########

        self.http_connections_map = {}

        for udp_rule in self.udp_rules_list:
            print(udp_rule)

        for tcp_rule in self.tcp_rules_list:
            print(tcp_rule)

        for icmp_rule in self.icmp_rules_list:
            print(icmp_rule)
        
        for http_rule in self.http_rules_list:
            print(http_rule)


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
                    
                   elif (current_verdict == "DENY"):
                       new_dns_rule = DNSRule(current_domain[1:], "WILDCARD", "DENY")
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
                       
                   elif (current_verdict == "DENY"):
                       new_dns_rule = DNSRule(current_domain, "EXACT", "DENY")
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
            
            ########## Handle HTTP LOG rule ##########
            elif (current_protocol == "HTTP"):
                hostname = split_line[2]

                # hostname is *
                if (hostname == '*'):
                    new_http_rule = HTTPRule(hostname, "ANY")

                # hostname is IP address
                elif (hostname.translate(None, '.').isdigit()):
                    new_http_rule = HTTPRule(hostname, "IP")

                # hostname is wild card domain
                elif (hostname.startswith('*')):
                    new_http_rule = HTTPRule(hostname, "WILDCARD")

                # hostname is exact domain
                else:
                    new_http_rule = HTTPRule(hostname, "EXACT")
                
                self.http_rules_list.append(new_http_rule)


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
                    send_packet = self.make_decision_on_udp_packet(pkt, external_ip, external_port, True, q_name, q_type, q_type_offset)
                    if send_packet:
                        if pkt_dir == PKT_DIR_INCOMING:
                            self.iface_int.send_ip_packet(pkt)
                        elif pkt_dir == PKT_DIR_OUTGOING:
                            self.iface_ext.send_ip_packet(pkt)

                        print("SENT DNS PACKET")
                    else:
                        # We've dropped our packet, so just return
                        print("DROPPED DNS PACKET")
                        return
                
                # Not a DNS query packet (it is a regular UDP packet)
                else:
                    # Destination ip address given by 'dst_ip'; destination port given by 'destination_port'
                    send_packet = self.make_decision_on_udp_packet(pkt, external_ip, external_port, False)                
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
                send_packet = self.make_decision_on_udp_packet(pkt, external_ip, external_port, False)                
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

            send_packet = self.make_decision_on_tcp_packet(pkt_dir, external_ip, external_port, internal_ip, internal_port, pkt)                
            if send_packet:
                
                if pkt_dir == PKT_DIR_INCOMING:
                    
                    if (external_port == 80):
                        # Since direction is incoming, we know that the TCP options in this packet correspond to a HTTP RESPONSE

                        # If external port is 80, then we parse bytestream and then use fields in parsed bytestream to check HTTP rules list,
                        # and then decide whether we need to log the HTTP request/response
                        
                        # Check <5-tuple -> HTTPObject> map, if 5-tuple is not in the map, then message = new HTTPObject.
                        # If 5-tuple IS in the map, then message = map.get(5-tuple)
                        # Pass message into update_http_message function call
                        # In the update_http_message function call, we will determine whether we need to append to this message,
                        # based on the packet's sequence number, and the sequence number that we next expect
      
                        # Form 5-tuple
                        five_tuple = (src_ip, dst_ip, source_port, destination_port, "TCP")
                        http_connection = None
                        for map_five_tuple in self.http_connections_map:
                            if self.is_same_http_connection(five_tuple, map_five_tuple): 
                                http_connection = self.http_connections_map[map_five_tuple]
                                five_tuple = map_five_tuple
                        if http_connection is None:
                            http_connection = HTTPConnection()
                            self.http_connections_map[five_tuple] = http_connection
                        send_packet_or_not = self.update_http_message(pkt, "RESPONSE", http_connection, five_tuple)
                        
                        if (send_packet_or_not):
                            self.iface_int.send_ip_packet(pkt)

                        self.write_to_log_file(http_connection)

                    # External port is not 80, so just send the packet through
                    else:
                        self.iface_int.send_ip_packet(pkt)
                         

                elif pkt_dir == PKT_DIR_OUTGOING:
                 
                    if (external_port == 80):
                        # since direction is incoming, we know that the TCP optinos in this packet correspond to a HTTP REQUEST

                        # If external port is 80, then we parse bytestream and then use fields in parsed bytestream to check HTTP rules list,
                        # and then decide whether we need to log the HTTP request/response

                        # Form 5-tuple
                        five_tuple = (src_ip, dst_ip, source_port, destination_port, "TCP")
                        http_connection = None
                        for map_five_tuple in self.http_connections_map:
                            if self.is_same_http_connection(five_tuple, map_five_tuple): 
                                http_connection = self.http_connections_map[map_five_tuple]
                                five_tuple = map_five_tuple
                        if http_connection is None:
                            http_connection = HTTPConnection()
                            self.http_connections_map[five_tuple] = http_connection
                        send_packet_or_not = self.update_http_message(pkt, "REQUEST", http_connection, five_tuple)
                        
                        if (send_packet_or_not):
                            self.iface_ext.send_ip_packet(pkt)

                        self.write_to_log_file(http_connection)

                #print("SENT TCP PACKET")
            else:
                # We've dropped our packet, so just return
                print("DROPPED TCP PACKET")
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
        


    def write_to_log_file(self, http_connection):
        pass



    '''
    Given a http_connection and a packet whose HTTP payload MAY need to be appended to this http_connection
    update the http_connection object accordingly
    
    Returns True if this packet should be passed by handle_packet
    Returns False if this packet should be dropped by handle_packet
    '''
    def update_http_message(self, packet, message_type, http_connection, tuple_id):

        ip_header_length = ord(packet[0:1]) & 0x0f
        ip_header_length = ip_header_length * 4
        
        # 5-Tuple: (source IP, destination IP, source port, destination port, protocol)
        source_ip = socket.inet_ntoa(packet[12:16])
        destination_ip = socket.inet_ntoa(packet[16:20])
        source_port = struct.unpack('!H', packet[ip_header_length:(ip_header_length + 2)])[0]
        destination_port = struct.unpack('!H', packet[(ip_header_length + 2):(ip_header_length + 4)])[0]
        protocol = struct.unpack('!B', packet[9:10])[0]

        # Sequence number of packet
        sequence_number = struct.unpack('!L', packet[(ip_header_length + 4):(ip_header_length + 8)])[0]
        
        # message_type is either 'RESPONSE' or 'REQUEST'
        print("\n----- New packet has arrived with sequence number %s and message type %s! ------" % (sequence_number, message_type))
        print("----- This packet has the 5-tuple (%s, %s, %s, %s, %s)" % (source_ip, destination_ip, source_port, destination_port, protocol))

        tcp_header_length = ord(packet[(ip_header_length + 12):(ip_header_length + 13)]) >> 4
        tcp_header_length = tcp_header_length * 4

        length_of_packet = struct.unpack('!H', packet[2:4])[0]
        payload_length = length_of_packet - ip_header_length - tcp_header_length
        
        print("Length of packet: %s; IP header length: %s; TCP header length: %s; Length of payload: %s" % (length_of_packet, ip_header_length, tcp_header_length, payload_length))

        options_offset = ip_header_length + tcp_header_length
        print("----- HTTP Payload: \n")
        print(packet[options_offset:])

        

        if (message_type == "REQUEST"):
            # If payload is nonempty...
            if payload_length > 0 and not http_connection.is_request_complete:
                # If this packet is the first packet in the HTTP request...
                if http_connection.expected_request_seq_no is None:
                    # ...then set our next expected sequence number to this packet's sequence number + 1
                    http_connection.expected_request_seq_no = sequence_number + 1
                    # Append payload byte by byte. After every append, check the last 2? bytes to see if we've reached the end of our HTTP request
                    # Begin appending starting at the beginning of the HTTP payload
                    counter = options_offset
                    while (counter < length_of_packet):
                        byte_to_append = packet[counter:(counter + 1)]
                        http_connection.append_to_unparsed_request(byte_to_append)
                        # Check the last four bytes of unparsed request to see if we're finished... if it has four or more bytes to begin with
                        if (len(http_connection.unparsed_request) >= 4):
                            # Check whether last four characters of unparsed request are \r\n\r\n; if so, we break because we're done appending
                            if (http_connection.unparsed_request[-4:] == '\r\n\r\n'):
                                http_connection.is_request_complete = True
                                break
                        counter += 1
                
                # Current packet's HTTP payload is NOT the first packet in the HTTP request
                else:
                    # Check sequence number of this packet to find out what to do with its payload...
                    
                    if (sequence_number > http_connection.expected_request_seq_no):
                        print("Out of order packet! Drop it!")
                        return False
                    elif (sequence_number < http_connection.expected_request_seq_no):
                        # Simply return the packet, because its sequence number is smaller than the sequence number that we expect
                        return True
                    elif (sequence_number == http_connection.expected_request_seq_no):
                        
                        http_connection.expected_request_seq_no += 1
                        
                        # Append payload byte by byte. After every append, check the last 2? bytes to see if we've reached the end of our HTTP request
                        # Begin appending starting at the beginning of the HTTP payload
                        counter = options_offset
                        while (counter < length_of_packet):
                            byte_to_append = packet[counter:(counter + 1)]
                            http_connection.append_to_unparsed_request(byte_to_append)
                            # Check the last four bytes of unparsed request to see if we're finished... if it has four or more bytes to begin with
                            if (len(http_connection.unparsed_request) >= 4):
                                # Check whether last four characters of unparsed request are \r\n\r\n; if so, we break because we're done appending
                                if (http_connection.unparsed_request[-4:] == '\r\n\r\n'):
                                    # If request is done being appended, change the boolean variable in our http connection object
                                    http_connection.is_request_complete = True
                                    break
                            counter += 1
       
        elif (message_type == "RESPONSE"):
            if payload_length > 0 and not http_connection.is_response_complete:
                if http_connection.expected_response_seq_no is None:
                    http_connection.expected_response_seq_no = sequence_number + 1
                    counter = options_offset
                    while (counter < length_of_packet):
                        byte_to_append = packet[counter:(counter + 1)]
                        http_connection.append_to_unparsed_response(byte_to_append)
                        if (len(http_connection.unparsed_response) >= 4):
                            if (http_connection.unparsed_response[-4:] == '\r\n\r\n'):
                                http_connection.is_response_complete = True
                                print("response has been marked as complete")
                                break
                        counter += 1
                else:
                    if (sequence_number > http_connection.expected_response_seq_no):
                        print("Out of order packet! Drop it!")
                        return False
                    elif (sequence_number < http_connection.expected_response_seq_no):
                        return True
                    elif (sequence_number == http_connection.expected_response_seq_no):
                        http_connection.expected_response_seq_no += 1
                        counter = options_offset
                        while (counter < length_of_packet):
                            byte_to_append = packet[counter:(counter + 1)]
                            http_connection.append_to_unparsed_response(byte_to_append)
                            if (len(http_connection.unparsed_response) >= 4):
                                if (http_connection.unparsed_response[-4:] == '\r\n\r\n'):
                                    http_connection.is_response_complete = True
                                    print("response has been marked as complete")
                                    break
                            counter += 1

        print("is request complete: %s; is response complete: %s" % (http_connection.is_request_complete, http_connection.is_response_complete))

        # At this point, our http_connection's unparsed request/response are both complete
        if (http_connection.is_request_complete and http_connection.is_response_complete):
           print("##### HTTP CONNECTION: #####\n: %s" % http_connection)


        return True
        

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
    def make_decision_on_tcp_packet(self, pkt_dir, destination_ip, destination_port, source_ip, source_port, packet):
        
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

                    # Generate the RST packet, and send it, given direction
                    reset_packet_to_send = self.generate_reset_packet(packet)
                    
                    if pkt_dir == PKT_DIR_INCOMING:
                        self.iface_ext.send_ip_packet(reset_packet_to_send)
                    elif pkt_dir == PKT_DIR_OUTGOING:
                        self.iface_int.send_ip_packet(reset_packet_to_send)
                    
        return pass_packet_through 
    
    
    '''
    Returns true if the UDP packet with destination_ip and destination_port should be passed, and false if it should be dropped
    '''
    def make_decision_on_udp_packet(self, packet, destination_ip, destination_port, is_dns_packet, domain_name=None, q_type=None, q_type_offset=None):
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
                            elif (udp_rule.verdict == "DENY"):
                                pass_packet_through = False
                                # Only generate DNS deny packet if q_type == 1 (we ignore when q_type is 28)
                                if (q_type == 1):
                                    dns_deny_packet = self.generate_a_dns_deny_packet(packet, q_type_offset)
                                    self.iface_int.send_ip_packet(dns_deny_packet)
                    # Wild card matches
                    else:  
                        # If we've matched our wild card
                        if (domain_name.endswith(udp_rule.domain)):
                            if (udp_rule.verdict == "DROP"):
                                pass_packet_through = False
                            elif (udp_rule.verdict == "PASS"):
                                pass_packet_through = True
                            elif (udp_rule.verdict == "DENY"):
                                pass_packet_through = False
                                # Only generate DNS deny packet if q_type == 1 (we ignore when q_type is 28)
                                if (q_type == 1):
                                    dns_deny_packet = self.generate_a_dns_deny_packet(packet, q_type_offset)
                                    self.iface_int.send_ip_packet(dns_deny_packet)

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


    def generate_a_dns_deny_packet(self, packet, q_type_offset):
        dns_deny_packet_to_send = ""
        ip_header_length = ord(packet[0:1]) & 0x0f
        ip_header_length = ip_header_length * 4

        packet_total_length = struct.unpack('!H', packet[2:4])[0]

        # Pack first 2 bytes of IP header
        dns_deny_packet_to_send += packet[0:2]
        
        # Pack total length into IP header
        dns_deny_packet_to_send += packet[2:4]
        
        dns_deny_packet_to_send += packet[4:6]
        dns_deny_packet_to_send += packet[6:8]
        # Pack TTL of 64
        dns_deny_packet_to_send += struct.pack('!B', 64)
        dns_deny_packet_to_send += packet[9:10]

        # Pad bytes 10-12 with zeros (the bytes reserved for IP checksum)
        dns_deny_packet_to_send += (struct.pack('!H', 0))

        dns_deny_packet_destination_ip = packet[12:16]
        dns_deny_packet_source_ip = packet[16:20]

        # Pack bytes 12-20 (source and destination IP)
        dns_deny_packet_to_send += dns_deny_packet_source_ip
        dns_deny_packet_to_send += dns_deny_packet_destination_ip

        ##### UDP HEADER
        # Copy bytes 20-28 (source/destination port, length, checksum)
        reset_packet_source_port = packet[(ip_header_length + 2):(ip_header_length + 4)]
        reset_packet_destination_port = packet[(ip_header_length):(ip_header_length + 2)]

        # Pack packet source and destination ports
        # Bytes 20-22
        dns_deny_packet_to_send += reset_packet_source_port
        # Bytes 22-24
        dns_deny_packet_to_send += reset_packet_destination_port


        # Bytes 24-28 
        dns_deny_packet_to_send += packet[24:28] 
 
        ##### DNS HEADER (starting at byte 28)
        # Copy bytes 28-30 (ID field)
        dns_deny_packet_to_send += packet[28:30]

        # For bytes 30-32, leave everything the same, except change first bit (QR bit) to 1
        option_bits = struct.unpack('!H', packet[30:32])[0]
        option_bits = 0x8000 | option_bits
        dns_deny_packet_to_send += struct.pack('!H', option_bits)

        # Copy bytes 32-34 (QDCOUNT)
        dns_deny_packet_to_send += packet[32:34]

        # Pack the value 1 for bytes 34-36 (ANCOUNT)
        dns_deny_packet_to_send += struct.pack('!H', 1)

        # Copy bytes 36-40 (NSCOUNT and ARCOUNT)
        dns_deny_packet_to_send += packet[36:40]
        # Copy QNAME
        dns_deny_packet_to_send += packet[40:q_type_offset]
        
        length_of_q_name = q_type_offset - 40

        # Pack the value 1 (QTYPE) for bytes (q_type_offset -> q_type_offset+2)
        dns_deny_packet_to_send += struct.pack('!H', 1)
        # Pack the value 1 (QCLASS) for bytes (q_type_offset+2 -> q_type_offset+4)
        dns_deny_packet_to_send += struct.pack('!H', 1)

        # Copy fields QNAME, QTYPE, QCLASS into answer section
        dns_deny_packet_to_send += dns_deny_packet_to_send[40:(40 + length_of_q_name)] 
        dns_deny_packet_to_send += struct.pack('!H', 1)
        dns_deny_packet_to_send += struct.pack('!H', 1)

        # Pack TTL of 1 (four bytes)
        dns_deny_packet_to_send += struct.pack('!L', 1)
        # Pack RDLENGTH (two bytes)
        dns_deny_packet_to_send += struct.pack('!H', 4)
        # Pack IP address into RDATA field (4 bytes)
        dns_deny_packet_to_send += socket.inet_aton('54.173.224.150')
        
        udp_length = len(dns_deny_packet_to_send) - 20
        dns_deny_packet_to_send = dns_deny_packet_to_send[0:24] + struct.pack('!H', udp_length) + dns_deny_packet_to_send[26:]
       
        length_of_packet = len(dns_deny_packet_to_send)
        dns_deny_packet_to_send = dns_deny_packet_to_send[0:2] + struct.pack('!H', length_of_packet) + dns_deny_packet_to_send[4:]
       
        ip_checksum = struct.pack('!H', self.calculate_checksum(20, dns_deny_packet_to_send))
        dns_deny_packet_to_send = dns_deny_packet_to_send[0:10] + ip_checksum + dns_deny_packet_to_send[12:]

        udp_checksum = struct.pack('!H', self.calculate_tcp_checksum(0, 20, dns_deny_packet_to_send))
        dns_deny_packet_to_send = dns_deny_packet_to_send[0:26] + udp_checksum + dns_deny_packet_to_send[28:]
        return dns_deny_packet_to_send

    def generate_reset_packet(self, packet):
        reset_packet_to_send = ""
        ip_header_length = ord(packet[0:1]) & 0x0f
        ip_header_length = ip_header_length * 4

        packet_total_length = struct.unpack('!H', packet[2:4])[0]

        # Pack first 2 bytes of IP header
        reset_packet_to_send += packet[0:2]
        
        # Pack total length into IP header
        reset_packet_to_send += (struct.pack('!H', 40))
        
        reset_packet_to_send += packet[4:6]
        reset_packet_to_send += packet[6:8]
        # Pack TTL of 64
        reset_packet_to_send += struct.pack('!B', 64)
        reset_packet_to_send += packet[9:10]

        # Pad bytes 10-12 with zeros (the bytes reserved for IP checksum)
        reset_packet_to_send += (struct.pack('!H', 0))

        reset_packet_destination_ip = packet[12:16]
        reset_packet_source_ip = packet[16:20]

        reset_packet_to_send += reset_packet_source_ip
        reset_packet_to_send += reset_packet_destination_ip

        ########## TCP header ##########
        reset_packet_source_port = packet[(ip_header_length + 2):(ip_header_length + 4)]
        reset_packet_destination_port = packet[(ip_header_length):(ip_header_length + 2)]

        # Pack packet source and destination ports
        # Bytes 20-22
        reset_packet_to_send += reset_packet_source_port
        # Bytes 22-24
        reset_packet_to_send += reset_packet_destination_port

        previous_sequence_number = struct.unpack('!L', packet[24:28])[0]
       
        new_sequence_number = 0

        # Increase sequence number by 1 and pack it
        # Bytes 24-28
        reset_packet_to_send += struct.pack('!L', new_sequence_number)

        # Pack ACK number
        # Bytes 28-32
        reset_packet_to_send += struct.pack('!L', previous_sequence_number + 1)

        # Bytes 32-33
        reset_packet_to_send += struct.pack('!B', 0x50)

        # Pack flags into 1 byte, with ACK and RST flags turned on
        # Bytes 33-34
        reset_packet_to_send += struct.pack('!B', 0x14)

        # Bytes 34-36
        reset_packet_to_send += struct.pack('!H', 0)

        # Pad bytes 36-38 with zeros
        reset_packet_to_send += (struct.pack('!H', 0))
        reset_packet_to_send += packet[38:40]
        # At this point, bytes 10-12 and 36-38 have been packed with zeros

        # Calculate IP checksum and pack
       
        reset_packet_checksum = struct.pack('!H', self.calculate_checksum(ip_header_length, reset_packet_to_send))
        reset_packet_to_send = reset_packet_to_send[0:10] + reset_packet_checksum + reset_packet_to_send[12:]

        # Calculate TCP checksum and pack
        reset_packet_tcp_checksum = struct.pack('!H', self.calculate_tcp_checksum(packet_total_length, ip_header_length * 4, reset_packet_to_send))
        reset_packet_to_send = reset_packet_to_send[0:36] + reset_packet_tcp_checksum + reset_packet_to_send[38:]

        return reset_packet_to_send

    
    def calculate_tcp_checksum(self, total_length, ip_header_length, packet):
        total_len = struct.unpack('!H', packet[2:4])[0]
        header_len = (struct.unpack('!B', packet[0:1])[0] & 0x0F) * 4
        protocol = struct.unpack('!B', packet[9:10])[0]

        if total_len % 2 != 0:
            new_len = total_len + 1
            packet += struct.pack('!B', 0)
        else:
            new_len = total_len

        checksum = 0
        if (protocol == 6): #TCP
            prot = "tcp"
            orig_chksum = struct.unpack('!H', packet[header_len + 16:header_len + 18])[0] #TCP
            for i in range(header_len, new_len, 2):
                if i != (header_len + 16):
                    checksum += struct.unpack("!H", packet[i: i+ 2])[0]
        elif (protocol == 17): #UDP
            prot = "udp"
            orig_chksum = struct.unpack('!H', packet[header_len + 6:header_len + 8])[0] #UDP
            for i in range(header_len, new_len, 2):
                if i != (header_len + 6):
                    checksum += struct.unpack("!H", packet[i: i+ 2])[0]

        checksum += struct.unpack("!H", packet[12:14])[0] #src address
        checksum += struct.unpack("!H", packet[14:16])[0] #src address
        checksum += struct.unpack("!H", packet[16:18])[0] #dst address
        checksum += struct.unpack("!H", packet[18:20])[0] #dst address

        checksum += protocol #protocol number
        checksum += total_len - header_len #length

        checksum = (checksum >> 16) + (checksum & 0xFFFF)
        checksum += (checksum >> 16)
        checksum = ~checksum & 0xFFFF

        return checksum       

    def calculate_tcp_checksum2(self, total_length, ip_header_length, packet):
      
        source_ip = struct.unpack('!H', packet[12:14])[0]
        source_ip_segment_2 = struct.unpack('!H', packet[14:16])[0]
        destination_ip = struct.unpack('!H', packet[16:18])[0]
        destination_ip_segment_2 = struct.unpack('!H', packet[18:20])[0]

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
        total_sum += source_ip + source_ip_segment_2
        total_sum += destination_ip + destination_ip_segment_2
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
        
        leftmost_four_bits = total_sum >> 16
        final_segment = total_sum & 0xFFFF
        
        total_sum = leftmost_four_bits + final_segment

        total_sum += (total_sum >> 16)

        # Flip bits
        total_sum = (~total_sum)
        total_sum = total_sum & 0xFFFF

        return total_sum 


    '''
    Given two 5-tuples for connection identification, checks to see whether the two 5-tuples are equivalent (i.e. correspond to the same connection)
    (connection_one and connection_two are both 5-tuples)
    '''
    def is_same_http_connection(self, connection_one, connection_two):
        connection_one_set = set(connection_one) 
        connection_two_set = set(connection_two)
        return (connection_one_set.issubset(connection_two_set) and connection_one_set.issuperset(connection_two_set))
    
    
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
            


