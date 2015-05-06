__author__ = 'DCollins'

import sys
sys.path.append("..")
import os

import unittest
import AcraNetwork.Pcap as pcap
import AcraNetwork.SimpleEthernet as SimpleEthernet
import AcraNetwork.iNetX as inetx
import AcraNetwork.MPEGTS as MPEGTS

import struct


class MPEGTSBasicTest(unittest.TestCase):


    ######################
    # Read a complete pcap file
    ######################

    def test_readFirstMPEGTS(self):
        '''
        Very simple test that reads a pcap file with mpegts packets.
        Takes the first packet in there and decoms the mpegts blocks
        Verifies each block in that first packet
        '''
        p = pcap.Pcap("mpegts_input.pcap")
        p.readGlobalHeader()
        mypcaprecord = p.readAPacket()

        ethpacket = SimpleEthernet.Ethernet()   # Create an Ethernet object
        ethpacket.unpack(mypcaprecord.packet)   # Unpack the pcap record into the eth object
        ippacket =  SimpleEthernet.IP()         # Create an IP packet
        ippacket.unpack(ethpacket.payload)      # Unpack the ethernet payload into the IP packet
        udppacket = SimpleEthernet.UDP()        # Create a UDP packet
        udppacket.unpack(ippacket.payload)      # Unpack the IP payload into the UDP packet
        inetxpacket = inetx.iNetX()             # Create an iNetx object
        inetxpacket.unpack(udppacket.payload)   # Unpack the UDP payload into this iNetX object

        mpegts = MPEGTS.MPEGTS()
        mpegts.unpack(inetxpacket.payload)
        self.assertEqual(mpegts.NumberOfBlocks(),7)
        self.assertFalse(mpegts.contunityerror)
        for packet_index in (range(7)):
            if packet_index == 0:
                self.assertEqual(mpegts.blocks[packet_index].pid,0)
                self.assertEqual(mpegts.blocks[packet_index].syncbyte,0x47)
            elif packet_index == 1:
                self.assertEqual(mpegts.blocks[packet_index].pid,4096)
                self.assertEqual(mpegts.blocks[packet_index].syncbyte,0x47)
            else:
                self.assertEqual(mpegts.blocks[packet_index].pid,256)
                self.assertEqual(mpegts.blocks[packet_index].syncbyte,0x47)
        p.close()


    def test_readAllMPEGTS(self):
        '''
        Reads the same mpeg ts file as previously but reads all the data
        in the file and checks for any continuity errors
        :return:
        '''
        p = pcap.Pcap("mpegts_input.pcap")
        p.readGlobalHeader()
        while True:
            # Loop through the pcap file reading one packet at a time
            try:
                mypcaprecord = p.readAPacket()
            except IOError:
                # End of file reached
                break

            ethpacket = SimpleEthernet.Ethernet()   # Create an Ethernet object
            ethpacket.unpack(mypcaprecord.packet)   # Unpack the pcap record into the eth object
            ippacket =  SimpleEthernet.IP()         # Create an IP packet
            ippacket.unpack(ethpacket.payload)      # Unpack the ethernet payload into the IP packet
            udppacket = SimpleEthernet.UDP()        # Create a UDP packet
            udppacket.unpack(ippacket.payload)      # Unpack the IP payload into the UDP packet
            inetxpacket = inetx.iNetX()             # Create an iNetx object
            inetxpacket.unpack(udppacket.payload)   # Unpack the UDP payload into this iNetX object
            mpegts = MPEGTS.MPEGTS()
            mpegts.unpack(inetxpacket.payload)
            self.assertEqual(mpegts.NumberOfBlocks(),7)
            self.assertFalse(mpegts.contunityerror)

        p.close()

if __name__ == '__main__':
    unittest.main()
