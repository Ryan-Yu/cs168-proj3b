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

        # TODO: Load the GeoIP DB ('geoipdb.txt') as well.
        # TODO: Also do some initialization if needed.

    # @pkt_dir: either PKT_DIR_INCOMING or PKT_DIR_OUTGOING
    # @pkt: Python string that contains the actual data of the IPv4 packet (including IP header)
    def handle_packet(self, pkt_dir, pkt):
        # TODO: Your main firewall code will be here.
        # Whenever a packet is captured, this handler will be invoked. 
        
        # PKT_DIR_INCOMING: The packet has been received from the ext interface. You
        # need to call self.iface_int.send_ip_packet() to pass this packet.
        # PKT_DIR_OUTGOING: The packet has been received from the int interface. You
        # need to call self.iface_ext.send_ip_packet() to pass this packet.
        
        # To drop the packet, simply omit the call to .send_ip_packet()

        pass

    # TODO: You can add more methods as you want.

# TODO: You may want to add more classes/functions as well.
