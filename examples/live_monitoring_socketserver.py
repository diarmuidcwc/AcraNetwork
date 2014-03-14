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

import socket,os,sys
import argparse
import datetime, time
import SocketServer

# Add the directory above to the search path
sys.path.append("../..")


import AcraNetwork.iNetX as inetx
import AcraNetwork.IENA as iena
import AcraNetwork.ColouredOutput as ColouredOutput
import AcraNetwork.McastSocket as McastSocket

if os.name == "nt":
    import msvcrt


class MyMulticastHandler(SocketServer.BaseRequestHandler):


    def handle(self):
        packet_count = 0
        data = self.request[0].strip()
        # Create a new packet depending on the command line arguments
        # and unpack the received data into these objects
        if is_inetx:
            avionics_packet = inetx.iNetX()
            try:
                avionics_packet.unpack(data,True)
            except ValueError:
                # This isn't an inetx packet
                packet_count += 1

        else:
            avionics_packet = iena.IENA()
            try:
                avionics_packet.unpack(data,True)
                avionics_packet.CalcTimeStamp()
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
            outstring =colouredop.output_format.format(avionics_packet.key,udpsrcport,avionics_packet.sequence,datetime.datetime.fromtimestamp(avionics_packet.timestamp).strftime('%H:%M:%S'))
            colouredop.PrintALine(outstring,avionics_packet.sequence,avionics_packet.key)

        packet_count += 1

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
    #try:
    HOST, PORT = "235.0.0.1", udp_port
    server = MulticastServer((HOST,PORT),MyMulticastHandler)
    server.serve_forever()



if __name__ == '__main__':
    main()
