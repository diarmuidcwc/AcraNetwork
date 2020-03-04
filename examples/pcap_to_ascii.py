#!/usr/bin/python
# -*- coding: utf-8 -*-
"""
===== 
PCAP to ASCII
===== 


"""
__author__ = "Diarmuid Collins"
__copyright__ = "Copyright 2018"
__version__ = "0.0.1"
__maintainer__ = "Diarmuid Collins"
__email__ = "dcollins@curtisswright.com"
__status__ = "Production"


import sys
sys.path.append("..")

import os,struct
import argparse

import AcraNetwork.iNetX as inetx
import AcraNetwork.Pcap as pcap
import AcraNetwork.SimpleEthernet as SimpleEthernet


def main():

    #----------------------------------
    # Setup the command line parser
    #----------------------------------
    parser = argparse.ArgumentParser(description='Dump out the _payload of iNetX packets as ASCII representations')
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
            print("ERROR: File {} not found".format(pcapfilename))
            exit()

        if not os.path.exists(args.outdir):
            os.mkdir(args.outdir)

        for pcaprecord in pcapfile:
            eth = SimpleEthernet.Ethernet()
            eth.unpack(pcaprecord.packet)
            ip = SimpleEthernet.IP()
            ip.unpack(eth.payload)
            udp_packet = SimpleEthernet.UDP()
            udp_packet.unpack(ip.payload)
            (ctrl_word,) = struct.unpack('>I',udp_packet.payload[:4])

            if ctrl_word == 0x11000000:
                inetx_packet = inetx.iNetX()
                # Unpack the udp _payload as an iNetx packet
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
                if  inetx_packet.streamid not in output_byte_count:
                    output_byte_count[inetx_packet.streamid] = 1

                # Go thorough each byte in the _payload. Not particularly efficient
                for offset in range(len(inetx_packet.payload)):
                    # Unpack the _payload as an unsigned integer
                    (byte_in_ascii,) =struct.unpack_from('B', inetx_packet.payload, offset)

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

        print("Output files created in {} directory".format(args.outdir))



if __name__ == '__main__':
    main()
