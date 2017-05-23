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

import socket,os,sys
import argparse
import datetime, time

import AcraNetwork.iNetX as inetx
import AcraNetwork.IENA as iena
import AcraNetwork.ColouredOutput as ColouredOutput
import AcraNetwork.McastSocket as McastSocket

if os.name == "nt":
    import msvcrt



def main():

    #----------------------------------
    # Setup the command line parser
    #----------------------------------
    parser = argparse.ArgumentParser(description='Live Analysis of BCU transmitted packets.')
    parser.add_argument('--inetx', type=int,  default=None, required=False,  help='Receiving iNetX packets on this UDP port')
    parser.add_argument('--iena', type=int,  default=None, required=False,  help='Receiving IENA packets on this UDP port')
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
    # Setup the coloured output
    #------------------------------------------------------------
    colouredop = ColouredOutput.ColouredOutput()
    colouredop.PrintHeader()
    colouredop.PrintFileName("UDP Port={}".format(udp_port))
    colouredop.PrintExitInfo("Hit ESC to exit...")
    #------------------------------------------------------------
    # Setup a socket to recieve all traffic
    #------------------------------------------------------------
    try:
        recv_socket = McastSocket.McastSocket(local_port=udp_port, reuse=1)
        recv_socket.mcast_add('235.0.0.1', '0.0.0.0')
        recv_socket.settimeout(10)
    except:
        print("Can't bind to socket {}".format(udp_port))
        exit()

    packet_count = 1
    while True:
        # Exit if the esc or q key is hit
        if os.name == "nt":
            # Exit if the esc or q key is hit
            if msvcrt.kbhit():
                if ( ord(msvcrt.getch()) == 27 or ord(msvcrt.getch()) == 113):
                    exit()

        # Capture some data from the socket
        try:
            data, addr = recv_socket.recvfrom(2048) # buffer size is 1500 bytes
        except socket.timeout:
            print("timeout on socket")
            exit()

        (udpsrcport,srcipaddr) = addr

        # Create a new packet depending on the command line arguments
        # and unpack the received data into these objects
        if is_inetx:
            avionics_packet = inetx.iNetX()
            data_len = len(data)
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
                # We got a length error. Should really handle this better. We could bail on this?
                packet_count += 1
                exit()

        if is_inetx:

            # What string do we want outputted to the screen. The output format is defined in the coloredop class
            outstring =colouredop.output_format.format(avionics_packet.streamid,udpsrcport,avionics_packet.sequence,datetime.datetime.fromtimestamp(avionics_packet.ptptimeseconds).strftime('%H:%M:%S'))
            # Print out one line and the dropped packet info
            colouredop.PrintALine(outstring,avionics_packet.sequence,avionics_packet.streamid)
            colouredop.PrintDroppedPacket(avionics_packet.sequence,avionics_packet.streamid,packet_count,udp_port)
        else:
            outstring =colouredop.output_format.format(avionics_packet.key,udpsrcport,avionics_packet.sequence,datetime.datetime.fromtimestamp(avionics_packet._getPacketTime()).strftime('%H:%M:%S'))
            colouredop.PrintALine(outstring,avionics_packet.sequence,avionics_packet.key)

        packet_count += 1

if __name__ == '__main__':
    main()
