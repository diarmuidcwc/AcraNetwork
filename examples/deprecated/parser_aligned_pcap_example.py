#-------------------------------------------------------------------------------
# Name:        parser_aligned_pcap_example.py
# Purpose:
#
# Author:      Diarmuid
#
# Created:     19/12/2013
#
# Copyright 2014 Diarmuid Collins
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#-------------------------------------------------------------------------------

import socket,os,struct,sys
import argparse
import datetime, time

import AcraNetwork.iNetX as inetx
import AcraNetwork.Pcap as pcap
from AcraNetwork.SimpleEthernet import mactoreadable
import AcraNetwork.ParserAligned as ParserAligned

def main():

    #----------------------------------
    # Setup the command line parser
    #----------------------------------
    parser = argparse.ArgumentParser(description='Analyse a pcap file looking for iNetX parser aligned packets')
    parser.add_argument('--pcap',  required=True, action='append',  help='The dump pcap packet')
    args = parser.parse_args()

    #------------------------------------------------------------
    # Now read the input.
    #------------------------------------------------------------

    # The input will take multiple pcap files and loop through each

    for pcapfilename in args.pcap:
        try:
            pcapfile = pcap.Pcap(pcapfilename)
        except IOError:
            print("ERROR: File {} not found".format(pcapfilename))
            exit()


        packet_count = 1


        start_of_run = time.time() # benchmarking


        while True:
            try:

                # So we loop through the file one packet at a time. This will eventually return an
                # exception at the end of file so handle that when it occurs
                (eth_packet,ip_packet,udp_packet) = pcapfile._readNextUDPPacket()
                if udp_packet.isinetx: # This is a rough guess assuming the control word is 0x11000000
                    inetx_packet = inetx.iNetX()
                    inetx_packet.unpack(udp_packet.payload)
                    readablemac = mactoreadable(eth_packet.srcmac) # handy function to return the mac address in a readable format
                    output_format = "SRCMAC={:>20s} SRCIP={:>15s} DSTPORT={:5d} StreamID={:#5x} Sequence={:10d}"

                    # What string do we want outputted to the screen. The output format is defined in the coloredop class
                    outstring =output_format.format(readablemac ,ip_packet.srcip, udp_packet.dstport,inetx_packet.streamid,inetx_packet.sequence)
                    # Print out one line and the dropped packet info
                    print(outstring)

                    # We have a parser aligned block
                    if inetx_packet.streamid == 0x11121314: # This specific streamid is a parser aligned block
                        parser_aligned_packet = ParserAligned.ParserAlignedPacket()
                        # unpack the _payload as the parser data
                        parser_aligned_packet.unpack(inetx_packet.payload)
                        # Loop through all the blocks in the packet and spit them out
                        for pblock in parser_aligned_packet.parserblocks:
                            (payload_data,) =struct.unpack('>I',pblock.payload)
                            print("Quadb={:5} Msgcnt={:5} BusId={:4} Elapsed={:20}".format(pblock.quadbytes,pblock.messagecount,pblock.busid,pblock.elapsedtime,payload_data))


                packet_count += 1
            except NotImplementedError:
                # We received a packet that we don't care about. So skip silently
                packet_count += 1
                pass
            except IOError:
                # We are at the end of the file so lets jump to the next file
                print(( "End of file reached. Packets Per Second ={:5.1f}".format(packet_count/(time.time()-start_of_run))))
                break


if __name__ == '__main__':
    main()
