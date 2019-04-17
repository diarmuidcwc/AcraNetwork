__author__ = 'diarmuid'
import sys
sys.path.append("..")

import unittest
import AcraNetwork.iNetX as inetx
import AcraNetwork.SimpleEthernet as SimpleEthernet
import AcraNetwork.Pcap as pcap
import struct
import os
import copy

THIS_DIR = os.path.dirname(os.path.abspath(__file__))

class iNetXTest(unittest.TestCase):

    def test_defaultiNet(self):
        i = inetx.iNetX()
        self.assertEqual(i.packetlen,None)
        self.assertEqual(i.inetxcontrol,inetx.iNetX.DEF_CONTROL_WORD)
        self.assertEqual(i.ptptimeseconds,None)
        self.assertEqual(i.ptptimenanoseconds,None)
        self.assertEqual(i.pif,None)
        self.assertEqual(i.payload,None)
        self.assertEqual(i.sequence,None)
        self.assertEqual(i.streamid,None)

    def test_basiciNet(self):
        i = inetx.iNetX()
        i.sequence = 1
        i.pif = 0
        i.streamid = 0xdc
        i.setPacketTime(1,1)
        i.payload = struct.pack('H',0x5)
        expected_payload = struct.pack(inetx.iNetX.INETX_HEADER_FORMAT,inetx.iNetX.DEF_CONTROL_WORD,0xdc,1,30,1,1,0) + struct.pack('H',0x5)
        self.assertEqual(i.pack(),expected_payload)

    def test_unpackiNet(self):
        expected_payload = struct.pack(inetx.iNetX.INETX_HEADER_FORMAT,inetx.iNetX.DEF_CONTROL_WORD, 0xdc, 2, 30, 1, 1, 0) + \
                           struct.pack('H',0x5)
        i = inetx.iNetX(expected_payload)
        self.assertEqual(i.sequence,2)
        self.assertEqual(i.streamid,0xdc)
        self.assertEqual(i.ptptimeseconds,1)
        self.assertEqual(i.ptptimenanoseconds,1)
        self.assertEqual(i.packetlen,30)
        self.assertEqual(i.pif,0)
        self.assertEqual(i.payload,struct.pack('H',0x5))
        self.assertEqual(repr(i), "STREAMID=0XDC SEQ=2 LEN=30 PTPS=1 PTPNS=1")
        i2 = copy.copy(i)
        self.assertEqual(i, i2)
        self.assertEqual(len(i), 28+2)

    def test_unpackiNetFromPcap(self):
        p = pcap.Pcap(os.path.join(THIS_DIR, "inetx_test.pcap"))
        mypcaprecord = p[0]
        p.close()
        e = SimpleEthernet.Ethernet()
        e.unpack(mypcaprecord.packet)
        ip =  SimpleEthernet.IP()
        ip.unpack(e.payload)
        u = SimpleEthernet.UDP()
        u.unpack(ip.payload)
        # Now I have a _payload that will be an inetx packet
        i = inetx.iNetX()
        i.unpack(u.payload)
        self.assertEqual(i.inetxcontrol,0x11000000)
        self.assertEqual(i.streamid,0xca)
        self.assertEqual(i.sequence,1011)
        self.assertEqual(i.packetlen,72)
        self.assertEqual(i.ptptimeseconds,0x2f3)
        self.assertEqual(i.ptptimenanoseconds,0x2cb4158c)
        self.assertEqual(i.pif,0)

    def test_unpackMultiplePackets(self):
        sequencenum = 1011
        mypcap = pcap.Pcap(os.path.join(THIS_DIR, "inetx_test.pcap"))       # Read the pcap file
        for mypcaprecord in mypcap:

            ethpacket = SimpleEthernet.Ethernet()   # Create an Ethernet object
            ethpacket.unpack(mypcaprecord.packet)   # Unpack the pcap record into the eth object
            ippacket =  SimpleEthernet.IP()         # Create an IP packet
            ippacket.unpack(ethpacket.payload)      # Unpack the ethernet _payload into the IP packet
            udppacket = SimpleEthernet.UDP()        # Create a UDP packet
            udppacket.unpack(ippacket.payload)      # Unpack the IP _payload into the UDP packet
            inetxpacket = inetx.iNetX()             # Create an iNetx object
            inetxpacket.unpack(udppacket.payload)   # Unpack the UDP _payload into this iNetX object
            #print "INETX: StreamID ={:08X} Sequence = {:8d} PTP Seconds = {}".format(inetxpacket.streamid,inetxpacket.sequence,inetxpacket.ptptimeseconds)
            self.assertEqual(inetxpacket.sequence,sequencenum)
            sequencenum += 1
        mypcap.close()




if __name__ == '__main__':
    unittest.main()
