# -------------------------------------------------------------------------------
# Name:        benchmark_pcap
# Purpose:     Benchmark the creation and parsing of a biug pcap file
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


import sys
sys.path.append("..")


import time
import struct
import AcraNetwork.IENA as iena
import AcraNetwork.iNetX as inetx
import AcraNetwork.Pcap as pcap
import AcraNetwork.SimpleEthernet as SimpleEthernet
import argparse

parser = argparse.ArgumentParser(description='Benchmark the creation of pcap files containing packets')
parser.add_argument('--type',  required=True, type=str,choices=["udp","iena","inetx"],  help='The type of payload, udp iena or inetx')
parser.add_argument('--ignoretime',required=False, action='store_true', default=False)
args = parser.parse_args()

# constants
PCAP_FNAME = "output_test.pcap"
PACKETS_TO_WRITE = 50000
PAYLOAD_SIZE = 1300 # size of the payload in bytes
HEADER_SIZE = {'udp' : 58 , 'inetx' :86 ,'iena':74}

# Write out a pcapfile with each inetx and iena packet generated
mypcap = pcap.Pcap(PCAP_FNAME,forreading=False)
mypcap.writeGlobalHeader()
ethernet_packet = SimpleEthernet.Ethernet()
ethernet_packet.srcmac = 0x001122334455
ethernet_packet.dstmac = 0x554433221100
ethernet_packet.type = SimpleEthernet.Ethernet.TYPE_IP
ip_packet = SimpleEthernet.IP()
ip_packet.dstip = "235.0.0.2"
ip_packet.srcip = "127.0.0.1"
udp_packet = SimpleEthernet.UDP()
udp_packet.dstport = 4422


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



packets_written = 0

start_time = time.time()
while packets_written < PACKETS_TO_WRITE:

    if args.type == "udp":
        udp_packet.srcport = 4999
        udp_packet.payload = payload
    else:
        if args.ignoretime:
            currenttime = 0
        else:
            currenttime = int(time.time())
        if args.type == "iena":
            avionics_packet.sequence = (avionics_packet.sequence +1) % 65536
            udp_packet.srcport = 5000
        else:
            avionics_packet.sequence = (avionics_packet.sequence +1) % 0x100000000
            udp_packet.srcport = 5001

        avionics_packet.setPacketTime(currenttime)
        udp_packet.payload = avionics_packet.pack()

    ip_packet.payload = udp_packet.pack()
    ethernet_packet.payload = ip_packet.pack()
    record = pcap.PcapRecord()
    if args.ignoretime:
        record.usec = 0
        record.sec = 0
    else:
        record.setCurrentTime()
    record.packet = ethernet_packet.pack()
    mypcap.writeARecord(record)

    packets_written += 1

mypcap.close()
end_time = time.time()
print "INFO: Wrote {} packets of type {} with payload of {} bytes in {} seconds".format(PACKETS_TO_WRITE,args.type,PAYLOAD_SIZE,end_time-start_time)
print "INFO: Wrote {} bytes in {}".format((HEADER_SIZE[args.type]+PAYLOAD_SIZE)*PACKETS_TO_WRITE,end_time-start_time)
print "INFO: Wrote {} packets per second".format(PACKETS_TO_WRITE/(end_time-start_time))
print "INFO: Wrote {:.2f} Mbps".format((HEADER_SIZE[args.type]+PAYLOAD_SIZE)*PACKETS_TO_WRITE*8/((end_time-start_time)*1024*1024))