__author__ = 'DCollins'

import sys
sys.path.append("..")
import os

import unittest
import AcraNetwork.Pcap as pcap
import AcraNetwork.SimpleEthernet as SimpleEthernet
import AcraNetwork.iNetX as inetx
import AcraNetwork.MPEGTS as MPEGTS

THIS_DIR = os.path.dirname(os.path.abspath(__file__))


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
        p = pcap.Pcap(os.path.join(THIS_DIR, "mpegts_input.pcap"))
        p._read_global_header()
        mypcaprecord = p[0]

        ethpacket = SimpleEthernet.Ethernet()   # Create an Ethernet object
        ethpacket.unpack(mypcaprecord.packet)   # Unpack the pcap record into the eth object
        ippacket =  SimpleEthernet.IP()         # Create an IP packet
        ippacket.unpack(ethpacket.payload)      # Unpack the ethernet _payload into the IP packet
        udppacket = SimpleEthernet.UDP()        # Create a UDP packet
        udppacket.unpack(ippacket.payload)      # Unpack the IP _payload into the UDP packet
        inetxpacket = inetx.iNetX()             # Create an iNetx object
        inetxpacket.unpack(udppacket.payload)   # Unpack the UDP _payload into this iNetX object

        mpegts = MPEGTS.MPEGTS()
        mpegts.unpack(inetxpacket.payload)
        self.assertEqual(mpegts.NumberOfBlocks(),7)
        self.assertFalse(mpegts.contunityerror)
        for packet_index in (list(range(7))):
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
        p = pcap.Pcap(os.path.join(THIS_DIR, "mpegts_input.pcap"))
        for mypcaprecord in p:

            ethpacket = SimpleEthernet.Ethernet()   # Create an Ethernet object
            ethpacket.unpack(mypcaprecord.packet)   # Unpack the pcap record into the eth object
            ippacket =  SimpleEthernet.IP()         # Create an IP packet
            ippacket.unpack(ethpacket.payload)      # Unpack the ethernet _payload into the IP packet
            udppacket = SimpleEthernet.UDP()        # Create a UDP packet
            udppacket.unpack(ippacket.payload)      # Unpack the IP _payload into the UDP packet
            inetxpacket = inetx.iNetX()             # Create an iNetx object
            inetxpacket.unpack(udppacket.payload)   # Unpack the UDP _payload into this iNetX object
            mpegts = MPEGTS.MPEGTS()
            mpegts.unpack(inetxpacket.payload)
            self.assertEqual(mpegts.NumberOfBlocks(),7)
            self.assertFalse(mpegts.contunityerror)

        p.close()

    def test_stanag(self):
        ts_file = open(os.path.join(THIS_DIR, "stanag_sample.ts"), mode='rb')
        h264_data = MPEGTS.H264()
        self.assertTrue(h264_data.unpack(ts_file.read()))
        ts_file.close()
        self.assertEqual(len(h264_data.nals),258)
        nal_counts ={}
        for nal in h264_data.nals:
            if not nal.type in nal_counts:
                nal_counts[nal.type] = 1
            else:
                nal_counts[nal.type] += 1
        self.assertEqual(nal_counts[0], 35)
        self.assertEqual(nal_counts[6], 70)

if __name__ == '__main__':
    unittest.main()
