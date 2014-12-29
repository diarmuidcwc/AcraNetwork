#-------------------------------------------------------------------------------
# Name:        pcap_to_ascii.py
# Purpose:
#
# Author:      Diarmuid
#
# Created:     18/03/2014
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
#
# About:       This is a simple test script that loops through a pcap file
#               Finds all iNetX packets and dumps the ASCII representation of the
#               data to the output
#-------------------------------------------------------------------------------
import sys
sys.path.append("..")

import socket,os,struct,sys
import argparse
import datetime, time


import AcraNetwork.iNetX as inetx
import AcraNetwork.Pcap as pcap
import AcraNetwork.SimpleEthernet as SimpleEthernet
import AcraNetwork.ParserAligned as ParserAligned

def main():

    #----------------------------------
    # Setup the command line parser
    #----------------------------------
    parser = argparse.ArgumentParser(description='Dump out the payload of iNetX packets as ASCII representations')
    parser.add_argument('--pcap',  required=True, action='append',  help='The input pcap file(s)')
    parser.add_argument('--hex',  required=False, action='store_true', default=False,  help='Print the hex representation not the ASCII coded version')
    parser.add_argument('--outdir',  required=False, default="out", help='Name of output directory. Default is out')
    args = parser.parse_args()

    #------------------------------------------------------------
    # Now read the input.
    #------------------------------------------------------------
    # The input will take multiple pcap files and loop through each

    # Keep a track of the position in the line for each streamID
    output_byte_count ={}

    for pcapfilename in args.pcap:
        try:
            pcapfile = pcap.Pcap(pcapfilename)
        except IOError:
            print "ERROR: File {} not found".format(pcapfilename)
            exit()


        if not os.path.exists(args.outdir):
            os.mkdir(args.outdir)

        pcapfile.readGlobalHeader()
        while True:
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
                if ctrl_word == 0x11000000:
                    inetx_packet = inetx.iNetX()
                    # Unpack the udp payload as an iNetx packet
                    inetx_packet.unpack(udp_packet.payload)
                    # Do we want to dump out an ascii or hex output
                    if args.hex == True:
                        prefix = "hex"
                    else:
                        prefix = "ascii"

                    # Create an output  file per streamID and open it
                    output_file_name = "{}/{}_{:08X}.txt".format(args.outdir,prefix,inetx_packet.streamid)
                    # NB: We are appending to the file here so if you have existing files in the directory then it will be appended
                    output_file = open(output_file_name,'a')

                    # Start the byte count per streamID
                    if  not output_byte_count.has_key(inetx_packet.streamid):
                        output_byte_count[inetx_packet.streamid] = 1

                    # Go thorough each byte in the payload. Not particularly efficient
                    for byte in inetx_packet.payload:
                        # Unpack the payload as an unsigned integer
                        (byte_in_ascii,) =struct.unpack('B',byte)

                        # Write the output depending on what you want
                        if args.hex == True:
                            output_file.write("{:02X} ".format(byte_in_ascii))
                        else:
                            # Only some ASCII codes are printable so don't print out
                            # the non printable ones. Emulate the wireshark method of printing a period
                            if byte_in_ascii < 31 or byte_in_ascii > 126:
                                printable_string = "."
                            else:
                                printable_string = chr(byte_in_ascii)

                            output_file.write("{}".format(printable_string))

                        # Create a new line after 16 bytes for readability
                        if (output_byte_count[inetx_packet.streamid] % 16 == 0):
                            output_file.write('\n')
                        output_byte_count[inetx_packet.streamid] += 1



            except NotImplementedError:
                # We received a packet that we don't care about. So skip silently
                pass

            except IOError:
                # We are at the end of the file so lets jump to the next file
                print ( "End of {} reached.".format(pcapfilename))
                break

        print "Output files created in {} directory".format(args.outdir)



if __name__ == '__main__':
    main()
