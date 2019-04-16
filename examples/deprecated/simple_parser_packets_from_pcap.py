#-------------------------------------------------------------------------------
# Name:        pcap_monitor.py
# Purpose:
#
# Author:      Diarmuid
#
# Created:     16/12/2013
# Copyright:   (c) ACRA 2013
# Licence:     <your licence>
# About:       This is a simple test script that loops through a pcap file pulling out the
#               packets.
#-------------------------------------------------------------------------------

import socket,os,struct,sys
import argparse
import datetime, time


import AcraNetwork.iNetX as inetx
import AcraNetwork.Pcap as pcap
import AcraNetwork.SimpleEthernet as SimpleEthernet
import AcraNetwork.ParserAligned as ParserAligned




def main():

    try:
        pcapfile = pcap.Pcap("SSR_ABM_102_capture_example1.pcap")
    except IOError:
        print("ERROR: Could not find input file SSR_ABM_102_capture_example1.pcap")
        exit()

    # Keep a running count of the packets
    packet_count = 1
    # Keep a count of previous sequence number to detect a dropped packets
    PreviousSeqNum = dict()

    while True: # while we are not at the end of the file
        try:
            # So we loop through the file one packet at a time. This will eventually return an
            # exception at the end of file so handle that when it occurs
            pcaprecord = pcapfile.readAPacket()
            eth = SimpleEthernet.Ethernet()
            eth.unpack(pcaprecord.packet)
            ip = SimpleEthernet.IP()
            ip.unpack(eth.payload)
            udp_packet = SimpleEthernet.UDP()
            udp_packet.unpack(ip.payload)
            (ctrl_word,) = struct.unpack('>I',udp_packet.payload[:4])
            if ctrl_word == 0x11000000: # This is a rough guess assuming the control word is 0x11000000
                inetx_packet = inetx.iNetX()
                inetx_packet.unpack(udp_packet.payload)

                #----------------------------
                # Check for dropped packet
                #----------------------------
                if inetx_packet.streamid not in PreviousSeqNum:
                    PreviousSeqNum[inetx_packet.streamid] = inetx_packet.sequence
                else:
                    if PreviousSeqNum[inetx_packet.streamid]+1 != inetx_packet.sequence:
                        print("ERROR: Dropped {} packets on streamid={:#x} at packet count={}".format(inetx_packet.sequence - PreviousSeqNum[inetx_packet.streamid] + 1,inetx_packet.streamid,packet_count))
                    PreviousSeqNum[inetx_packet.streamid] = inetx_packet.sequence

                print("----- StreamID={:#10x} SourceIP= {:10s} -----".format(inetx_packet.streamid,ip_packet.srcip))
                #--------------------------------------------------------------------------------
                # Packets on stream id 0x11121314 is a parser aligned block so lets look at this
                #--------------------------------------------------------------------------------
                if inetx_packet.streamid == 0x11121314:
                    parser_aligned_packet = ParserAligned.ParserAlignedPacket()
                    # unpack the _payload as the parser data
                    parser_aligned_packet.unpack(inetx_packet.payload)

                    # Loop through all the blocks in the packet and spit them out
                    for pblock in parser_aligned_packet.parserblocks:
                        (payload_data,) =struct.unpack('>I',pblock.payload)
                        print("Sequence Number = {:8} Quadbyes={:5} Msgcnt={:5} BusId={:4} Elapsed={:20} ".format(inetx_packet.sequence, pblock.quadbytes,pblock.messagecount,pblock.busid,pblock.elapsedtime,payload_data))


            packet_count += 1

        except NotImplementedError:
            # We received a packet that we don't care about. So skip silently
            packet_count += 1
            pass

        except IOError:
            # We are at the end of the file so lets jump to the next file
            print ( "End of file reached")
            exit()


if __name__ == '__main__':
    main()
