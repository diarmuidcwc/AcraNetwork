__author__ = 'diarmuid'
import sys
sys.path.append("..")
import os

import unittest
import struct

import AcraNetwork.Ethernet as Ethernet
import AcraNetwork.Pcap as pcap
from AcraNetwork.protocols.network.ip import IP
from AcraNetwork.protocols.network.udp import UDP
from AcraNetwork.protocols.network.udp import UDP
from AcraNetwork.protocols.network.MacAddress import MacAddress

class EthernetTest(unittest.TestCase):

    ######################
    # Ethernet
    ######################
    def test_DefaultEthernet(self):
        e = Ethernet.Ethernet()
        self.assertEqual(e.dstmac,None)
        self.assertEqual(e.srcmac,None)
        self.assertEqual(e.type,None)
        self.assertEqual(e.payload,None)

    def test_basicEthernet(self):
        '''Create an ethernet frame, then unpack it to a new object'''
        e = Ethernet.Ethernet()
        e.srcmac = 0x001122334455
        e.dstmac = 0x998877665544
        e.type = Ethernet.Ethernet().TYPE_IP
        e.payload = struct.pack("H",0xa)
        ethbuf = e.pack()

        e2  = Ethernet.Ethernet()
        e2.regress = False
        e2.unpack(ethbuf)

        self.assertEqual(e2.dstmac, 0x998877665544)
        self.assertEqual(e2.type, Ethernet.Ethernet().TYPE_IP)
        #self.assertEqual(e2.srcmac, 0x001122334455)

    def test_basicMacAddress(self):
        '''
        Test Basic MacAddress class
        '''
        e = Ethernet.Ethernet()
        e.srcmac = MacAddress(0x001122334455)
        e.dstmac = MacAddress(0x998877665544)
        e.type = Ethernet.Ethernet().TYPE_IP
        e.payload = struct.pack("H",0xa)
        ethbuf = e.pack()

        e2  = Ethernet.Ethernet()
        e2.regress = False
        e2.unpack(ethbuf)

        self.assertEqual(e2.dstmac, 0x998877665544)
        self.assertEqual(e2.dstmac, '99:88:77:66:55:44')
        self.assertEqual(e2.type, Ethernet.Ethernet().TYPE_IP)
        #self.assertEqual(e2.srcmac, 0x001122334455)
        
        e2.dstmac += 1
        self.assertEqual(e2.dstmac, 0x998877665545)
        self.assertEqual(e2.dstmac, '99:88:77:66:55:45')
        e2.dstmac -= 2
        self.assertEqual(e2.dstmac, 0x998877665543)
        self.assertEqual(e2.dstmac, '99:88:77:66:55:43')
        
        e2.dstmac.set(0x998812665544)
        self.assertEqual(e2.dstmac, 0x998812665544)
        self.assertEqual(e2.dstmac, '99:88:12:66:55:44')

        e3 = Ethernet.Ethernet()
        #print(e3.dstmac.str)
        self.assertEqual(e3.dstmac, None)
        #self.assertEqual(e3.dstmac.int, None)
    
    def test_buildEmptyEthernet(self):
        '''Try and create an empty ethernet frame'''
        e = Ethernet.Ethernet()
        self.assertRaises(ValueError,lambda: e.pack())


    ######################
    # IP
    ######################
    def test_defaultIP(self):
        i = IP()
        self.assertRaises(ValueError, lambda : i.pack())

    def test_basicIP(self):
        i = IP()
        i.dstip = "235.0.0.1"
        i.srcip = "192.168.1.1"
        i.payload = struct.pack(">H",0xa5)
        ippayload = i.pack()

        i2 = IP()
        i2.regress = False
        i2.unpack(ippayload)
        self.assertEqual(i2.srcip,"192.168.1.1")
        self.assertEqual(i2.dstip,"235.0.0.1")
        self.assertEqual(i2.payload,struct.pack(">H",0xa5))

    def test_unpackIPShort(self):
        i = IP()
        dummypayload = struct.pack('H',0xa5)
        self.assertRaises(ValueError, lambda : i.unpack(dummypayload))

    ######################
    # UDP
    ######################

    def test_defaultUDP(self):
        u = UDP()
        self.assertRaises(ValueError,lambda :u.pack())

    def test_basicUDP(self):
        u = UDP()
        u.dstport = 5500
        u.srcport = 4400
        u.payload = struct.pack('B',0x5)
        mypacket = u.pack()
        self.assertEqual(mypacket,struct.pack('>HHHHB',4400,5500,9,0,0x5))

    def test_unpackUDPShort(self):
        u = UDP()
        dymmypayload =  struct.pack('H',0xa5)
        self.assertRaises(ValueError,lambda : u.unpack(dymmypayload))

    ######################
    # Read a complete pcap file
    ######################
    def test_readUDP(self):
        TESTDATA_FILENAME = os.path.join(os.path.dirname(__file__), 'test_input.pcap')
        p = pcap.Pcap(TESTDATA_FILENAME)
        p.readGlobalHeader()
        mypcaprecord = p.readAPacket()
        e = Ethernet.Ethernet()
        e.regress = False
        e.unpack(mypcaprecord.packet)
        self.assertEqual(e.srcmac,0x0018f8b84454)
        self.assertEqual(e.dstmac,0xe0f847259336)
        self.assertEqual(e.type,0x0800)

        i = IP()
        i.regress = False
        i.unpack(e.payload)
        self.assertEqual(i.dstip,"192.168.1.110")
        self.assertEqual(i.srcip,"213.199.179.165")
        self.assertEqual(i.protocol,0x6)
        self.assertEqual(i.ttl,48)
        self.assertEqual(i.flags,0x2)
        self.assertEqual(i.id,0x4795)
        self.assertEqual(i.len,56)
        p.close()

if __name__ == '__main__':
    unittest.main()
