#!/usr/bin/python
# -*- coding: utf-8 -*-
"""
===== 
MPEG OVER INETX 
===== 

This script listens to a udp port for inetx packets containing MPEG TS packets on reception it prints out the PIDs found
"""
__author__ = "Diarmuid Collins"
__copyright__ = "Copyright 2018"
__version__ = "0.0.1"
__maintainer__ = "Diarmuid Collins"
__email__ = "dcollins@curtisswright.com"
__status__ = "Production"


import socket,os,sys
sys.path.append("..")
import argparse
import AcraNetwork.iNetX as inetx
import AcraNetwork.MPEGTS as mpegts
import AcraNetwork.McastSocket as McastSocket
import struct

def align_payload(buf):
    byteindex = 0
    while len(buf) > byteindex:
            #print "idx={} len={}".format(byteindex,len(self._payload))
            (thisByte,) = struct.unpack_from('B',buf[byteindex])
            #logging.error("Byte = {:0X}".format(thisByte))
            if thisByte == 0x47:
                return buf[byteindex:]
            else:
                byteindex += 1
    return 0


def main():

    #----------------------------------
    # Setup the command line parser
    #----------------------------------
    parser = argparse.ArgumentParser(description='Analyse MPEG TS over inetx.')
    parser.add_argument('--inetx', type=int,  default=None, required=True,  help='Capture iNetX packets on this port')
    parser.add_argument('--multicast', type=str,  default="235.0.0.1", required=False,  help='The transmited multicast address')
    parser.add_argument('--localhost', type=str,  default='192.168.28.110', required=False,  help='The IP address of the local ethernet card')
    args = parser.parse_args()

    if args.inetx == None :
        parser.print_help()
        exit()


    PID_TEXT = {0x1fff : "Null", 0x0 : "Program Association Table", 0x100 : "VID106_Video" , 0x101 : "VID106_Audio", 0x1000 : "Program Map Table", 0x3E8 : "VID103_Video", 0x20 : "Unkn"}

    #------------------------------------------------------------
    # Setup a socket to recieve all traffic
    #------------------------------------------------------------
    #try:
    recv_socket = McastSocket.McastSocket(local_port=args.inetx, reuse=1)
    recv_socket.mcast_add(args.multicast, args.localhost)
    recv_socket.settimeout(10)
    #except:
    #    print "Can't bind to socket {}".format(args.inetx)
    #    print sys.exc_info()[0]
    #    exit()


    aligned_payload = ""

    while True:

        # Capture some data from the socket
        try:
            data, addr = recv_socket.recvfrom(2048) # buffer size is 1500 bytes
        except socket.timeout:
            print("timeout on socket")
            exit()

        # we are expecting a iNetX packets
        inetxpacket = inetx.iNetX()
        try:
            inetxpacket.unpack(data)
        except:
            pass

        # if we are in snarfer mode then align the _payload
        aligned_payload = align_payload(aligned_payload+inetxpacket.payload)
        if len(aligned_payload) >= 1316:

            # take the aligned _payload and convert it into MPEG TS blocks
            # Then print out the blocks
            mpegtspackets = mpegts.MPEGTS()
            mpegtspackets.unpack(aligned_payload[:1316])
            for mpegblock in mpegtspackets.blocks:
                print("PID = {}".format(PID_TEXT[mpegblock.pid]))

            aligned_payload = aligned_payload[1316:]


if __name__ == '__main__':
    main()
