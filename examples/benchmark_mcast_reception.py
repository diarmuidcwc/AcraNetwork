#!/usr/bin/python
# -*- coding: utf-8 -*-
"""
===== 
Benchmark Multicast UDP Reception
===== 

Benchmark the reception of multicast packets
"""
__author__ = "Diarmuid Collins"
__copyright__ = "Copyright 2018"
__version__ = "0.0.1"
__maintainer__ = "Diarmuid Collins"
__email__ = "dcollins@curtisswright.com"
__status__ = "Production"



import sys
sys.path.append("..")


import time
import struct
import AcraNetwork.IENA as iena
import AcraNetwork.iNetX as inetx
import AcraNetwork.McastSocket as mcast
import AcraNetwork.SimpleEthernet as SimpleEthernet
import argparse
from collections import deque


def main():

    # Setup some constants
    PACKETS_TO_RECEIVE = 1000

    #----------------------------------
    # Setup the command line parser
    #----------------------------------
    parser = argparse.ArgumentParser(description='Live Analysis of BCU transmitted packets.')
    parser.add_argument('--inetx', type=int,  default=None, required=False,  help='Receiving iNetX packets on this UDP port')
    parser.add_argument('--iena', type=int,  default=None, required=False,  help='Receiving IENA packets on this UDP port')
    parser.add_argument('--address', type=str,  default="235.0.0.1", required=False,  help='Destination multicast address')
    args = parser.parse_args()

    if args.inetx != None:
        udp_port = args.inetx
        is_inetx = True
    elif args.iena != None:
        udp_port = args.iena
        is_inetx = False
    else:
        parser.print_help()
        exit()

    #------------------------------------------------------------
    # Setup a socket to receive all traffic
    #------------------------------------------------------------
    try:
        recv_socket = mcast.McastSocket(local_port=udp_port, reuse=1)
        recv_socket.mcast_add(args.address, '0.0.0.0')
        recv_socket.settimeout(3)
    except:
        print("Can't bind to socket {}".format(udp_port))
        exit()

    start_time = time.time()
    packet_count = 1
    drop_count = 0
    streams = dict()
    data_len = deque()


    while packet_count < PACKETS_TO_RECEIVE:

        # Capture some data from the socket
        try:
            data, addr = recv_socket.recvfrom(2048) # buffer size is 1500 bytes
        except:
            print("timeout on socket")
            exit()

        (udpsrcport,srcipaddr) = addr

        # keep a track of the sizes of the last 20 packets received so that we
        # can calculate the bandwitdh
        # The data returned in the UDP _payload only so add 42 bytes for the rest of the
        # ethernet header just so the calculated number agress with Wireshark
        data_len.append(len(data)+42)
        if len(data_len) > 20:
            data_len.popleft()

        # Create a new packet depending on the command line arguments
        # and unpack the received data into these objects
        if is_inetx:
            avionics_packet = inetx.iNetX()
            avionics_packet.unpack(data)
            try:
                avionics_packet.unpack(data)
            except ValueError:
                # This isn't an inetx packet
                packet_count += 1
                continue
        else:
            avionics_packet = iena.IENA()
            try:
                avionics_packet.unpack(data)
            except ValueError:
                # Not a valid IENA packet
                packet_count += 1
                continue

        if is_inetx:
            if avionics_packet.streamid in streams:
                if avionics_packet.sequence != ((streams[avionics_packet.streamid] +1) % 0x100000000):
                    drop_count += 1
            streams[avionics_packet.streamid] = avionics_packet.sequence

        else:
            if avionics_packet.key in streams:
                if avionics_packet.sequence != ((streams[avionics_packet.key] +1) % 65536):
                    drop_count += 1
            streams[avionics_packet.key] = avionics_packet.sequence



        packet_count += 1

    end_time = time.time()
    average_len = sum(data_len)/len(data_len)
    print("INFO: Recevied {} packets in {} seconds with {} dropped packets".format(packet_count,end_time-start_time,drop_count))
    print("INFO: Recevied {:.3f} Mbps".format((average_len*packet_count*8)/((end_time-start_time)*1024*1024)))

if __name__ == '__main__':
    main()