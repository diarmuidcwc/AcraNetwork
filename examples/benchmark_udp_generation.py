# -------------------------------------------------------------------------------
# Name:        
# Purpose:     
#
# Author:      
#
# Created:     
#
# Copyright 2014 Diarmuid Collins
#
#    This program is free software; you can redistribute it and/or
#    modify it under the terms of the GNU General Public License
#    as published by the Free Software Foundation; either version 2
#    of the License, or (at your option) any later version.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with this program; if not, write to the Free Software
#    Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.



__author__ = 'diarmuid'
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
parser.add_argument('--type',  required=True, type=str,choices=["udp","iena","inetx"],  help='The type of payload, udp iena or inetx')
parser.add_argument('--ignoretime',required=False, action='store_true', default=False)
args = parser.parse_args()

# constants
PACKETS_TO_SEND = 50000
PAYLOAD_SIZE = 1300 # size of the payload in bytes
HEADER_SIZE = {'udp' : 58 , 'inetx' :86 ,'iena':74}
UDP_IP = "235.0.0.1"
UDP_PORT = 8888

# Fixed payload for both
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
print "INFO: Sent {} packets of type {} with payload of {} bytes in {} seconds".format(PACKETS_TO_SEND,args.type,PAYLOAD_SIZE,end_time-start_time)
print "INFO: Sent {} bytes in {}".format((HEADER_SIZE[args.type]+PAYLOAD_SIZE)*PACKETS_TO_SEND,end_time-start_time)
print "INFO: Sent {} packets per second".format(PACKETS_TO_SEND/(end_time-start_time))
print "INFO: Sent {:.2f} Mbps".format((HEADER_SIZE[args.type]+PAYLOAD_SIZE)*PACKETS_TO_SEND*8/((end_time-start_time)*1024*1024))