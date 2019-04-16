#!/usr/bin/python
# -*- coding: utf-8 -*-
"""
===== 
Benchmark PCAP Creaion
===== 

Benchmark the transmission of multicast packets
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
import AcraNetwork.Pcap as pcap
import AcraNetwork.SimpleEthernet as SimpleEthernet
import argparse

parser = argparse.ArgumentParser(description='Benchmark the transmission of multicast packets')
parser.add_argument('--type',  required=True, type=str,choices=["udp","iena","inetx"],  help='The type of _payload, udp iena or inetx')
parser.add_argument('--ignoretime',required=False, action='store_true', default=False)
args = parser.parse_args()

# constants
PACKETS_TO_SEND = 50000
PAYLOAD_SIZE = 1300 # size of the _payload in bytes
HEADER_SIZE = {'udp' : 58 , 'inetx' :86 ,'iena':74}
UDP_IP = "235.0.0.1"
UDP_PORT = 8888

# Fixed _payload for both
payload = (struct.pack(">B",5) * PAYLOAD_SIZE)

if args.type == "inetx":
    # Create an inetx packet
    avionics_packet = inetx.iNetX()
    avionics_packet.inetxcontrol = inetx.iNetX.DEF_CONTROL_WORD
    avionics_packet.pif = 0
    avionics_packet.streamid = 0xdc
    avionics_packet.sequence = 0
    avionics_packet.payload = payload
elif args.type == "iena":
    # Create an iena packet
    avionics_packet = iena.IENA()
    avionics_packet.key = 0xdc
    avionics_packet.keystatus = 0
    avionics_packet.endfield = 0xbeef
    avionics_packet.sequence = 0
    avionics_packet.payload = payload
    avionics_packet.status = 0

mcastsocket = mcast.McastSocket(2048)
mcastsocket.mcast_add(UDP_IP)

packets_sent = 0

start_time = time.time()
while packets_sent < PACKETS_TO_SEND:
    if args.type == "udp":
        packet_payload = payload
    else:
        if args.ignoretime:
            currenttime = 0
        else:
            currenttime = int(time.time())
        if args.type == "iena":
            avionics_packet.sequence = (avionics_packet.sequence +1) % 65536
        else:
            avionics_packet.sequence = (avionics_packet.sequence +1) % 0x100000000

        avionics_packet.setPacketTime(currenttime)
        packet_payload = avionics_packet.pack()

    mcastsocket.sendto(packet_payload, (UDP_IP, UDP_PORT))
    packets_sent += 1

end_time = time.time()
print("INFO: Sent {} packets of type {} with _payload of {} bytes in {} seconds".format(PACKETS_TO_SEND,args.type,PAYLOAD_SIZE,end_time-start_time))
print("INFO: Sent {} bytes in {}".format((HEADER_SIZE[args.type]+PAYLOAD_SIZE)*PACKETS_TO_SEND,end_time-start_time))
print("INFO: Sent {} packets per second".format(PACKETS_TO_SEND/(end_time-start_time)))
print("INFO: Sent {:.2f} Mbps".format((HEADER_SIZE[args.type]+PAYLOAD_SIZE)*PACKETS_TO_SEND*8/((end_time-start_time)*1024*1024)))