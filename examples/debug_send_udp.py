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
import argparse
import socket

parser = argparse.ArgumentParser(description='Send iNetX packets at a specified rate')
#parser.add_argument('--type',  required=True, type=str,choices=["udp","iena","inetx"],  help='The type of _payload, udp iena or inetx')
parser.add_argument('--rate',required=False, type=int, default=1, help="Packet rate in Hz")
args = parser.parse_args()

# simple application that tests building and sending of iena and inetx packets

UDP_IP = "192.168.28.100"
UDP_PORT = 4444

print("UDP target IP:", UDP_IP)
print("UDP target port:", UDP_PORT)
print("Rate = {} Hz".format(args.rate))

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
#sock.mcast_add(UDP_IP)

# Fixed _payload for both


# Create an inetx packet
myinetx = inetx.iNetX()

payload = struct.pack(">I",0xa5)

myinetx.inetxcontrol = inetx.iNetX.DEF_CONTROL_WORD
myinetx.pif = 0
myinetx.streamid = 0xdc
myinetx.sequence = 0
myinetx.payload = payload * 512

# Create an iena packet
myiena = iena.IENA()
myiena.key = 0xdc
myiena.keystatus = 0
myiena.endfield = 0xbeef
myiena.sequence = 0
myiena.payload = payload
myiena.status = 0


packet_count = 1
while True:

    currenttime = int(time.time())

    #myiena.sequence += 1
    #myiena.setPacketTime(currenttime)
    #sock.sendto(myiena.pack(), (UDP_IP, UDP_PORT))
    #print "iena sent"

    myinetx.payload = payload * (packet_count % 600)
    myinetx.sequence += 1
    myinetx.setPacketTime(currenttime)

    tftp_req = struct.pack(">H4s6s", 1, bytes("/0/c", 'utf8'), bytes("octet.", 'utf8'))
    sock.sendto(tftp_req, (UDP_IP, UDP_PORT))
    if packet_count % 100 == 0:
        print("100 packets sent")
        packet_count = 1
    else:
        packet_count += 1

    time.sleep(1.0/args.rate)
