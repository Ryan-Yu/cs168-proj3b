#!/usr/bin/env python

from main import PKT_DIR_INCOMING, PKT_DIR_OUTGOING

# TODO: Feel free to import any Python standard moduless as necessary.
# (http://docs.python.org/2/library/)
# You must NOT use any 3rd-party libraries, though.

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

        # TODO: Initialize TCP, UDP, ICMP data structures  


    def initialize_all_maps(self, rules_file):
        for line in rules_file:
            stripped_line = line.strip()
            split_line = stripped_line.split(" ")
            current_verdict = split_line[0].upper()
            current_protocol = split_line[1].upper()
           
            # Handle DNS rule
            if (current_protocol == "DNS"):

               current_domain = split_line[2] 

                # Wild card
                if (split_line[2].startswith("*"):
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
        
        


        print("src_ip: " + src_ip + "; dst_ip: " + dst_ip)

        # PKT_DIR_INCOMING: The packet has been received from the ext interface. You
        # need to call self.iface_int.send_ip_packet() to pass this packet.
        # PKT_DIR_OUTGOING: The packet has been received from the int interface. You
        # need to call self.iface_ext.send_ip_packet() to pass this packet.
        
        # To drop the packet, simply omit the call to .send_ip_packet()


    # TODO: You can add more methods as you want.

# TODO: You may want to add more classes/functions as well.
