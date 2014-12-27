__author__ = 'diarmuid'
import sys
sys.path.append("..")
import os

import unittest
import AcraNetwork.SimpleEthernet as SimpleEthernet
import struct

class SimpleEthernetTest(unittest.TestCase):

    ######################
    # Ethernet
    ######################
    def test_DefaultEthernet(self):
        e = SimpleEthernet.Ethernet()
        self.assertEqual(e.dstmac,None)
        self.assertEqual(e.srcmac,None)
        self.assertEqual(e.type,None)
        self.assertEqual(e.payload,None)

    def test_basicEthernet(self):
        '''Create an ethernet frame, then unpack it to a new object'''
        e = SimpleEthernet.Ethernet()
        e.srcmac = 0x001122334455
        e.dstmac = 0x998877665544
        e.type = SimpleEthernet.Ethernet.TYPE_IP
        e.payload = struct.pack("H",0xa)
        ethbuf = e.pack()

        e2  = SimpleEthernet.Ethernet()
        e2.unpack(ethbuf)

        self.assertEqual(e2.dstmac,0x998877665544)
        self.assertEqual(e2.type,SimpleEthernet.Ethernet.TYPE_IP)
        self.assertEqual(e2.srcmac,0x001122334455)

    def test_buildEmptyEthernet(self):
        '''Try and create an empty ethernet frame'''
        e = SimpleEthernet.Ethernet()
        self.assertRaises(ValueError,lambda: e.pack())


    ######################
    # IP
    ######################
    def test_defaultIP(self):
        i = SimpleEthernet.IP()
        self.assertRaises(ValueError, lambda : i.pack())

    def test_basicIP(self):
        i = SimpleEthernet.IP()
        i.dstip = "235.0.0.1"
        i.srcip = "192.168.1.1"
        i.payload = struct.pack(">H",0xa5)
        ippayload = i.pack()

        i2 = SimpleEthernet.IP()
        i2.unpack(ippayload)
        self.assertEqual(i2.srcip,"192.168.1.1")
        self.assertEqual(i2.dstip,"235.0.0.1")
        self.assertEqual(i2.payload,struct.pack(">H",0xa5))

    def test_unpackIPShort(self):
        i = SimpleEthernet.IP()
        dummypayload = struct.pack('H',0xa5)
        self.assertRaises(ValueError, lambda : i.unpack(dummypayload))

    ######################
    # UDP
    ######################

    def test_defaultUDP(self):
        u = SimpleEthernet.UDP()
        self.assertRaises(ValueError,lambda :u.pack())

    def test_basicUDP(self):
        u = SimpleEthernet.UDP()
        u.dstport = 5500
        u.srcport = 4400
        u.payload = struct.pack('B',0x5)
        mypacket = u.pack()
        self.assertEqual(mypacket,struct.pack('>HHHHB',4400,5500,9,0,0x5))

    def test_unpackUDPShort(self):
        u = SimpleEthernet.UDP()
        dymmypayload =  struct.pack('H',0xa5)
        self.assertRaises(ValueError,lambda : u.unpack(dymmypayload))

if __name__ == '__main__':
    unittest.main()
