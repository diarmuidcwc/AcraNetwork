#-------------------------------------------------------------------------------
# Name:        module1
# Purpose:
#
# Author:      Diarmuid
#
# Created:     16/12/2013
# Copyright:   (c) SPACE 2013
# Licence:     <your licence>
#-------------------------------------------------------------------------------
import sys
sys.path.append("..")

import socket

import AcraNetwork.iNetX as inetx
import AcraNetwork.McastSocket as McastSocket
udp_port = 5555

#------------------------------------------------------------
# Setup a socket to recieve all traffic
#------------------------------------------------------------
try:
    recv_socket = McastSocket.McastSocket(local_port=udp_port, reuse=1)
    recv_socket.mcast_add('235.0.0.2', '0.0.0.0')
    recv_socket.settimeout(10)
except:
    print "Can't bind to socket {}".format(udp_port)
    exit()

packet_count = 1
while True:
    try:
        data, addr = recv_socket.recvfrom(2048) # buffer size is 1500 bytes
    except socket.timeout:
        print "timeout on socket"
        exit()

    (udpsrcport,srcipaddr) = addr
    avionics_packet = inetx.iNetX()
    data_len = len(data)
    try:
        avionics_packet.unpack(data)
    except ValueError:
        # This isn't an inetx packet
        packet_count += 1
        continue
    else:
        print "Packet withStread ID = {:0X}".format(avionics_packet.streamid)