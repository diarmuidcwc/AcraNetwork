#!/usr/bin/python
# -*- coding: utf-8 -*-
"""
===== 
 Sending UDP packets
===== 

Send UDP packets at a specific rate
"""
__author__ = "Diarmuid Collins"
__copyright__ = "Copyright 2018"
__version__ = "0.0.3"
__maintainer__ = "Diarmuid Collins"
__email__ = "dcollins@curtisswright.com"
__status__ = "Production"


import sys
sys.path.append("..")
import time
import struct
import AcraNetwork.iNetX as inetx
import argparse
import socket

parser = argparse.ArgumentParser(description='Send iNetX packets at a specified rate')
parser.add_argument('--rate',required=False, type=int, default=1, help="Packet rate in Mbps")
parser.add_argument('--ipaddress',required=False, type=str, default="192.168.0.26", help="Destination IP")
args = parser.parse_args()

# simple application that tests building and sending of iena and inetx packets

UDP_IP = args.ipaddress
UDP_PORT = 4444

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
#sock.mcast_add(UDP_IP)

# Create an inetx packet
myinetx = inetx.iNetX()

payload = struct.pack(">H",0xa5)

myinetx.inetxcontrol = inetx.iNetX.DEF_CONTROL_WORD
myinetx.pif = 0
myinetx.streamid = 0xdc
myinetx.sequence = 0
myinetx.payload = payload * 700
myinetx.setPacketTime(int(time.time()))
packet_payload = myinetx.pack()
pkt_size = len(packet_payload) + 8 + 20 + 14

granularity = 100
pps_rate = int(((args.rate * 1024 * 1024) / (pkt_size * 8)) / 100) * 100

packet_count = 1
dly = granularity / 2 / pps_rate
delta_change = 1 / pps_rate

st = time.time()

print("UDP target IP:", UDP_IP)
print("UDP target port:", UDP_PORT)
print("Rate = {} Hz".format(pps_rate))
print("Rate = {} Mbps".format(args.rate))

while True:
    myinetx.sequence += 1

    sock.sendto(myinetx.pack(), (UDP_IP, UDP_PORT))
    if packet_count % granularity == 0:
        # Report some information
        data_vol = packet_count * pkt_size * 8
        rate = data_vol / (time.time() - st) / 1000 / 1000
        pps = packet_count / (time.time() - st)
        if packet_count % pps_rate == 0:
            print("Rate = {:.0f} Mbps {:.0f} pps".format(rate, pps))
        # Tweak the delay so we converge to the required pps
        if rate > args.rate:
            dly += delta_change
        elif rate < args.rate:
            dly -= delta_change
        if dly >= 0:
            time.sleep(dly)
    packet_count += 1


