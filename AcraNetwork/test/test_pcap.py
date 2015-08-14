__author__ = 'diarmuid'
import sys
sys.path.append("..")
import os

import unittest
import struct
import AcraNetwork.Pcap as pcap

class PcapBasicTest(unittest.TestCase):

    def test_missingfilename(self):
        self.assertRaises(TypeError,lambda: pcap.Pcap())

    def test_missingreadfile(self):
        self.assertRaises(IOError,lambda: pcap.Pcap("nofile.pcap"))

    def test_defaultMagicNumber(self):
        p = pcap.Pcap("_tmp.pcap",forreading=False)
        self.assertEqual(p.magic,0xa1b2c3d4)
        p.close()

    def test_defaultVersionMaj(self):
        p = pcap.Pcap("_tmp.pcap",forreading=False)
        self.assertEqual(p.versionmaj,2)
        p.close()

    def test_defaultVersionMin(self):
        p = pcap.Pcap("_tmp.pcap",forreading=False)
        self.assertEqual(p.versionmin,4)
        p.close()

    def test_readTestFile(self):
        TESTDATA_FILENAME = os.path.join(os.path.dirname(__file__), 'test_input.pcap')
        p = pcap.Pcap(TESTDATA_FILENAME)
        p.readGlobalHeader()
        self.assertEqual(p.magic,0xa1b2c3d4)
        self.assertEqual(p.network,1)
        self.assertEqual(p.sigfigs,0)
        self.assertEqual(p.snaplen,262144)
        self.assertEqual(p.versionmaj,2)
        self.assertEqual(p.versionmin,4)
        self.assertEqual(p.zone,0)
        self.assertEqual(p.filesize,704)
        p.close()



    def test_readARecord(self):
        TESTDATA_FILENAME = os.path.join(os.path.dirname(__file__), 'test_input.pcap')
        p = pcap.Pcap(TESTDATA_FILENAME)
        p.readGlobalHeader()
        mypcaprecord = p.readAPacket()
        self.assertEqual(mypcaprecord.sec,1419678111)
        self.assertEqual(mypcaprecord.usec,811463)
        self.assertEqual(mypcaprecord.orig_len,70)
        self.assertEqual(mypcaprecord.incl_len,70)
        p.close()

    def test_writeARecord(self):
        p = pcap.Pcap("_tmp.pcap",forreading=False)
        p.writeGlobalHeader()
        r = pcap.PcapRecord()
        r.setCurrentTime()
        r.packet = struct.pack("H",0x5)
        p.writeARecord(r)
        p.close()
        p = pcap.Pcap("_tmp.pcap")
        p.readGlobalHeader()
        self.assertEqual(p.magic,0xa1b2c3d4)
        self.assertEqual(p.network,1)
        self.assertEqual(p.sigfigs,0)
        self.assertEqual(p.snaplen,65535)
        self.assertEqual(p.versionmaj,2)
        self.assertEqual(p.versionmin,4)
        self.assertEqual(p.zone,0)
        self.assertEqual(p.filesize,42)
        p.close()
        os.remove("_tmp.pcap")

    ######################
    # Read a complete pcap file and check two different mac addresses
    ######################
    def test_readMultiplePackets(self):
        TESTDATA_FILENAME = os.path.join(os.path.dirname(__file__), 'test_input.pcap')
        p = pcap.Pcap(TESTDATA_FILENAME)
        p.silent = True
        packets = p.parse()
        
        self.assertEqual(packets[0].eth.srcmac,0x0018f8b84454)
        self.assertEqual(packets[0].eth.dstmac,0xe0f847259336)
        self.assertEqual(packets[0].eth.type,0x0800)

        self.assertEqual(packets[1].eth.srcmac,0xe0f847259336)
        self.assertEqual(packets[1].eth.dstmac,0x0018f8b84454)
        self.assertEqual(packets[1].eth.type,0x0800)

        p.close()


if __name__ == '__main__':
    unittest.main()

