__author__ = 'diarmuid'


import sys
sys.path.append("../")
# Simulate an ADC placed packet.

import AcraNetwork.iNetX as inetx
import socket
import struct
import math
import time


#  configuration

SAMPLE_RATE = 512
PARAMETERS_PER_PACKET = 64
DELAY_BETWEEN_PACKETS = float(PARAMETERS_PER_PACKET)/SAMPLE_RATE # milliseconds
FREQ = 10
MULTICAST_IP = "235.0.0.1"
MULTICAST_PORT = 8010
AMPLITUDE = 30000
# end configuration


# open a socket
udp_socket = socket.socket(socket.AF_INET,socket.SOCK_DGRAM,socket.IPPROTO_UDP)
udp_socket.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)

# Setup an inetx packet
adcpacket = inetx.iNetX()
adcpacket.streamid = 0xdc
adcpacket.sequence = 1
adcpacket.inetxcontrol = 0x11000000
adcpacket.pif = 0
adcpacket.ptptimeseconds = 0
adcpacket.ptptimenanoseconds = 0

sampletime = 0.0

# loop forever
while True:
    signalValues = []
    # calculate the sample values for all the parameters in the current packet
    for sample in range(PARAMETERS_PER_PACKET):
        sampletime = (sampletime + float(1.0/SAMPLE_RATE)) % 1.0
        signalValues.append(int(AMPLITUDE * (math.sin(FREQ*sampletime)+1)))
    # pack the payload with the parameters
    adcpacket.payload = struct.pack("{}H".format(PARAMETERS_PER_PACKET),*signalValues)
    # work out the timestamos
    adcpacket.ptptimenanoseconds = int(((DELAY_BETWEEN_PACKETS * 1e9)+adcpacket.ptptimenanoseconds) % 1e9)
    adcpacket.ptptimeseconds += int(((DELAY_BETWEEN_PACKETS * 1e9)+adcpacket.ptptimenanoseconds) / 1e9)
    # send the packet
    udp_socket.sendto(adcpacket.pack(),(MULTICAST_IP,MULTICAST_PORT))
    # wait
    time.sleep(DELAY_BETWEEN_PACKETS)
