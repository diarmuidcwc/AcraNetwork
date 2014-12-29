__author__ = 'diarmuid'
import sys
sys.path.append("..")

import unittest
import AcraNetwork.iNetX as inetx
import AcraNetwork.SimpleEthernet as SimpleEthernet
import AcraNetwork.Pcap as pcap

import struct

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
        expected_payload = struct.pack(inetx.iNetX.INETX_HEADER_FORMAT,inetx.iNetX.DEF_CONTROL_WORD,0xdc,2,30,1,1,0) + struct.pack('H',0x5)
        i = inetx.iNetX()
        i.unpack(expected_payload)
        self.assertEqual(i.sequence,2)
        self.assertEqual(i.streamid,0xdc)
        self.assertEqual(i.ptptimeseconds,1)
        self.assertEqual(i.ptptimenanoseconds,1)
        self.assertEqual(i.packetlen,30)
        self.assertEqual(i.pif,0)
        self.assertEqual(i.payload,struct.pack('H',0x5))

    def test_unpackiNetFromPcap(self):
        p = pcap.Pcap("inetx_test.pcap")
        p.readGlobalHeader()
        mypcaprecord = p.readAPacket()
        e = SimpleEthernet.Ethernet()
        e.unpack(mypcaprecord.packet)
        ip =  SimpleEthernet.IP()
        ip.unpack(e.payload)
        u = SimpleEthernet.UDP()
        u.unpack(ip.payload)
        # Now I have a payload that will be an inetx packet
        i = inetx.iNetX()
        i.unpack(u.payload)
        self.assertEquals(i.inetxcontrol,0x11000000)
        self.assertEquals(i.streamid,0xca)
        self.assertEquals(i.sequence,1011)
        self.assertEquals(i.packetlen,72)
        self.assertEquals(i.ptptimeseconds,0x2f3)
        self.assertEquals(i.ptptimenanoseconds,0x2cb4158c)
        self.assertEquals(i.pif,0)




if __name__ == '__main__':
    unittest.main()
