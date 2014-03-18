#-------------------------------------------------------------------------------
# Name:        pcap_monitor.py
# Purpose:
#
# Author:      Diarmuid
#
# Created:     16/12/2013
# Copyright:   (c) ACRA 2013
# Licence:     <your licence>
# About:       This script will read in some pcap files containing pcap packets
#              It will parse through all the packets in the file, pull out the inetx
#              packets and then print the individual streams to the screen
#              The sequence numbers are printed and highlighted in red if they reset
#              Any dropped packets are reported
#              Visually it will be easy to see if any streamid stops or resets
#              I have also added a feature to watch the BCU temperature which is
#              contained in one particular packet
#-------------------------------------------------------------------------------

import socket,os,sys
import argparse
import datetime, time

import AcraNetwork.iNetX as inetx
import AcraNetwork.Pcap as pcap
import AcraNetwork.ColouredOutput as ColouredOutput

if os.name == "nt":
    import msvcrt

def main():

    #----------------------------------
    # Setup the command line parser
    #----------------------------------
    parser = argparse.ArgumentParser(description='Analyse a pcap file looking for resets in particlar or missing packets')
    parser.add_argument('--pcap', required=True,  action='append',  help='The dump pcap packet')
    args = parser.parse_args()

    #------------------------------------------------------------
    # Setup the coloured output
    #------------------------------------------------------------
    colouredop = ColouredOutput.ColouredOutput()
    colouredop.PrintHeader()
    colouredop.PrintExitInfo("Hit ESC to exit...")
    #------------------------------------------------------------
    # Now read the input.
    #------------------------------------------------------------

    # The input will take multiple pcap files and loop through each

    for pcapfilename in args.pcap:
        try:
            pcapfile = pcap.Pcap(pcapfilename)
        except IOError:
            print "ERROR: File {} not found".format(pcapfilename)
            exit()

        packet_count = 1

        # Print out a line with the filename we are analysisng
        colouredop.PrintFileName(pcapfilename)
        start_of_run = time.time() # benchmarking


        while True:
            if os.name == "nt":
                # Exit if the esc or q key is hit
                if msvcrt.kbhit():
                    if ( ord(msvcrt.getch()) == 27 or ord(msvcrt.getch()) == 113):
                        exit()

            try:

                # So we loop through the file one packet at a time. This will eventually return an
                # exception at the end of file so handle that when it occurs
                (inetx_packet,ip_packet,udp_packet,packetseconds,bcutemp) = pcapfile.ReadNextPacket()

                # What string do we want outputted to the screen. The output format is defined in the coloredop class
                outstring =colouredop.output_format.format(inetx_packet.streamid,ip_packet.srcip,inetx_packet.sequence,datetime.datetime.fromtimestamp(packetseconds).strftime('%H:%M:%S'))
                # Print out one line and the dropped packet info
                colouredop.PrintALine(outstring,inetx_packet.sequence,inetx_packet.streamid)
                colouredop.PrintDroppedPacket(inetx_packet.sequence,inetx_packet.streamid,packet_count,pcapfilename)

                # If we have a temperature reading then display that as a column
                if bcutemp != None:
                    # The temperature returned is in degresss * 1000
                    actualbcutemp = (float(bcutemp)/1000.0)
                    # Normalise the temperature to 0. The lowest temperature I expect is -8
                    temp_offset_from_0 = int((actualbcutemp+20)/10)
                    colouredop.PrintTemperatureBar(actualbcutemp,temp_offset_from_0)


                packet_count += 1
            except NotImplementedError:
                # We received a packet that we don't care about. So skip silently
                packet_count += 1
                pass
            except IOError:
                # We are at the end of the file so lets jump to the next file
                #print ( pos(lastyposition+1, x_location) + "End of file reached. Packets Per Second ={:5.1f}".format(packet_count/(time.time()-start_of_run)))
                break


if __name__ == '__main__':
    main()
