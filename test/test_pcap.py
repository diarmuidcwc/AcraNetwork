__author__ = 'diarmuid'
import sys
sys.path.append("..")
import os

import unittest
import AcraNetwork.Pcap as pcap
import struct

class PcapBasicTest(unittest.TestCase):

    def test_missingfilename(self):
        self.assertRaises(TypeError,lambda: pcap.Pcap())

    def test_missingreadfile(self):
        self.assertRaises(IOError,lambda: pcap.Pcap("nofile.pcap"))

    def test_defaultMagicNumber(self):
        p = pcap.Pcap("_tmp.pcap",forreading=False)
        self.assertEqual(p.magic,0xa1b2c3d4)

    def test_defaultVersionMaj(self):
        p = pcap.Pcap("_tmp.pcap",forreading=False)
        self.assertEqual(p.versionmaj,2)

    def test_defaultVersionMin(self):
        p = pcap.Pcap("_tmp.pcap",forreading=False)
        self.assertEqual(p.versionmin,4)

    def test_readTestFile(self):
        p = pcap.Pcap("test_input.pcap")
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
        p = pcap.Pcap("test_input.pcap")
        p.readGlobalHeader()
        mypcaprecord = p.readAPacket()
        self.assertEqual(mypcaprecord.sec,1419678111)
        self.assertEqual(mypcaprecord.usec,811463)
        self.assertEqual(mypcaprecord.orig_len,70)
        self.assertEqual(mypcaprecord.incl_len,70)

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
        os.remove("_tmp.pcap")



if __name__ == '__main__':
    unittest.main()

