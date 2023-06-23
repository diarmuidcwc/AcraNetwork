#!/usr/bin/env python3

# -*- coding: utf-8 -*-
"""
=====
 Sending IENA packets
=====

Simplified IENA packet generator. Sends one fixed size packet at the specified rate
Can be used as a base for generating more complex configurations

"""
__author__ = "Diarmuid Collins"
__copyright__ = "Copyright 2023"
__version__ = "0.1.0"
__maintainer__ = "Diarmuid Collins"
__email__ = "dcollins@curtisswright.com"
__status__ = "Production"


import sys
sys.path.append("..")
import time
import struct
import AcraNetwork.SimpleEthernet as eth
import AcraNetwork.IENA as iena
import argparse
import socket
import signal
import datetime


def create_parser():
    # Argument parser
    parser = argparse.ArgumentParser(description='Send IENA packets at a specified rate')
    parser.add_argument('--rate', required=False, type=float, default=1.0, help="Packet rate in Mbps")
    parser.add_argument('--ipaddress', required=False, type=str, default="192.168.0.26", help="Destination IP")

    return parser


def accurate_sleep(duration, get_now=time.perf_counter):
    now = get_now()
    end = now + duration
    while now < end:
        now = get_now()


def main(args):
    dst_udp_port = 4444

    # open a UDP socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)

    # Get the accurate size of the packet
    FCS_LEN = 4
    PREAMBLE = 8
    hdr_lens = eth.UDP.UDP_HEADER_SIZE + eth.IP.IP_HEADER_SIZE + eth.Ethernet.HEADERLEN + FCS_LEN + PREAMBLE

    # Work out the usecond timestamp
    now = datetime.datetime.now()
    seconds_since_jan1st = (now - now.replace(day=1, month=1, hour=0, minute=0, second=0, microsecond=0)).total_seconds()
    useconds_since_jan1st = int(seconds_since_jan1st * 1e6)

    # Create an inetx packet
    myiena = iena.IENA()
    myiena.key = 0xDC
    myiena.keystatus = 0x0
    myiena.status = 0x0
    myiena.timeusec = useconds_since_jan1st
    myiena.payload = struct.pack(">700H", *(range(700)))
    myiena.sequence = 0

    # Figure how much of a gap between packets
    _payload_len = len(myiena.pack())
    total_vol_data = 0
    chunk_count_ps = args.rate * 1e6/(_payload_len * 8)
    tx_time_vol = total_vol_data * 8 * 1e-9
    gap_per_pkt = (1 - tx_time_vol) / (chunk_count_ps)
    if gap_per_pkt <= 0:
        gap_per_pkt = 0

    print("UDP target IP:", args.ipaddress)
    print("UDP target port:", dst_udp_port)
    print("Rate = {} Mbps".format(args.rate))
    print("DLY = {:.6f} s".format(gap_per_pkt))

    # keep a track of the packets sent
    sequence_roll_over = pow(2, 16)
    packet_count = 1
    vol_data_sent = 0

    # Handle the user interruption gracefully
    def signal_handler(*args):
        print(f"Exiting. Sent {packet_count:>12,} packets and {vol_data_sent:>15,} bytes")
        sys.exit()
    signal.signal(signal.SIGINT, signal_handler)

    # loop forever
    while True:
        mypayload  = myiena.pack()
        sock.sendto(mypayload, (args.ipaddress, dst_udp_port))
        vol_data_sent += (len(mypayload) + hdr_lens)
        # Increment the sequence number
        myiena.sequence = (myiena.sequence + 1) % sequence_roll_over
        # Add to the timeuseconds
        myiena.timeusec += int(gap_per_pkt * 1e6)
        # Sleep
        accurate_sleep(gap_per_pkt)
        # Information
        packet_count += 1
        if packet_count % 100 == 0:
            print(f"{packet_count:>12,} packets sent. {vol_data_sent:>18,} bytes send.")


if __name__ == '__main__':
    parser = create_parser()
    pargs = parser.parse_args()
    main(pargs)
    sys.exit(0)

