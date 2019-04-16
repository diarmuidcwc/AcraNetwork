#!/usr/bin/python
# -*- coding: utf-8 -*-
"""
===== 
Proxy iNetx or IENA packets to UDP 
===== 


"""
__author__ = "Diarmuid Collins"
__copyright__ = "Copyright 2018"
__version__ = "0.1.0"
__maintainer__ = "Diarmuid Collins"
__email__ = "dcollins@curtisswright.com"
__status__ = "Production"


import sys
sys.path.append("..")
import socket
import argparse
import AcraNetwork.iNetX as inetx
import AcraNetwork.IENA as iena
import AcraNetwork.McastSocket as McastSocket

VERSION = __version__

parser = argparse.ArgumentParser(description='Proxy iNetX or IENA packets to UDP')
parser.add_argument('--ipaddress', type=str, default="235.0.0.1", required=True, help='The multicast IP address on which the iNetX or IENA packets are being transmitted')
parser.add_argument('--inetx', type=int, default=None, required=False, help='Receiving iNetX packets on this UDP port. Either this argument of --iena should be supplpied')
parser.add_argument('--iena', type=int, default=None, required=False, help='Receiving IENA packets on this UDP port')
parser.add_argument('--udp', type=int, default=None, required=True, help='Transmit UDP packets on this UDP port')
parser.add_argument('--version', action='version', version='%(prog)s {}'.format(VERSION))

args = parser.parse_args()

if not (args.inetx or args.iena):
    print(parser.print_help())
    sys.exit(1)

# The incoming iNetx port
if args.inetx:
    incoming_udp_port = args.inetx
else:
    incoming_udp_port = args.iena

# Outgoing UDP port
outgoing_udp_port = args.udp

#------------------------------------------------------------
# Setup a socket to recieve all traffic
#------------------------------------------------------------
try:
    recv_socket = McastSocket.McastSocket(local_port=incoming_udp_port, reuse=1)
    recv_socket.mcast_add(args.ipaddress, '0.0.0.0')
    recv_socket.settimeout(10)
except:
    print("Can't bind to socket {} on multicast {}".format(incoming_udp_port, args.ipaddress))
    exit()

tx_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

packet_count = 1


while True:
    # Capture some data
    try:
        data, addr = recv_socket.recvfrom(2048) # buffer size is 1500 bytes
    except socket.timeout:
        print("ERROR: No incoming packets received on UDP port {} on multicast {}. Timeout on socket".format(
            incoming_udp_port, args.ipaddress))
        exit()

    (udpsrcport,srcipaddr) = addr
    # Decode it as iNetx
    if args.inetx:
        avionics_packet = inetx.iNetX()
    else:
        avionics_packet = iena.IENA()

    try:
        avionics_packet.unpack(data)
    except ValueError:
        # This isn't an inetx packet
        continue
    else:
        packet_count += 1
        # Transmit the _payload back out
        tx_socket.sendto(avionics_packet.payload, (args.ipaddress, outgoing_udp_port))
        # Print some info for the user
        if packet_count % 50 == 0:
            print(".")
        else:
            print(".",)