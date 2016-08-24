__author__ = 'diarmuid'
import sys
sys.path.append("..")
import os

import unittest
import AcraNetwork.Pcap as pcap
import AcraNetwork.SimpleEthernet as SimpleEthernet
import struct

def getEthernetPacket(data=0xa):
    e = SimpleEthernet.Ethernet()
    e.srcmac = 0x001122334455
    e.dstmac = 0x998877665544
    e.type = SimpleEthernet.Ethernet.TYPE_IP
    e.payload = struct.pack("H",data)
    return e.pack()

class PcapBasicTest(unittest.TestCase):

    def test_missingfilename(self):
        self.assertRaises(TypeError,lambda: pcap.Pcap())

    def test_missingreadfile(self):
        self.assertRaises(IOError,lambda: pcap.Pcap("nofile.pcap"))

    def test_defaultMagicNumber(self):
        p = pcap.Pcap("_tmp.pcap",mode='w')
        self.assertEqual(p.magic,0xa1b2c3d4)

    def test_defaultVersionMaj(self):
        p = pcap.Pcap("_tmp.pcap",mode='w')
        self.assertEqual(p.versionmaj,2)

    def test_defaultVersionMin(self):
        p = pcap.Pcap("_tmp.pcap",mode='w')
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
        p = pcap.Pcap("_tmp.pcap",mode='w')
        p.writeGlobalHeader()
        r = pcap.PcapRecord()
        r.setCurrentTime()
        r.packet = getEthernetPacket(0xa)
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
        self.assertEqual(p.filesize,56)
        p.close()
        os.remove("_tmp.pcap")

    def test_appendARecord(self):
        p = pcap.Pcap("_tmp2.pcap",mode='w')
        p.writeGlobalHeader()
        r = pcap.PcapRecord()
        r.setCurrentTime()
        r.packet = getEthernetPacket(0xa)
        p.writeARecord(r)
        p.close()
        # Now try to append a record
        p = pcap.Pcap("_tmp2.pcap",mode='a')
        r.packet = getEthernetPacket(0xb)
        p.writeARecord(r)
        p.close()
        # Read back to verify
        p = pcap.Pcap("_tmp2.pcap")
        p.readGlobalHeader()
        self.assertEqual(p.filesize,88)
        rec1 = p.readAPacket()
        rec2 = p.readAPacket()
        e = SimpleEthernet.Ethernet()
        e.unpack(rec1.packet)
        self.assertEqual(e.payload,struct.pack("H",0xa))
        e.unpack(rec2.packet)
        self.assertEqual(e.payload,struct.pack("H",0xb))
        p.close()
        os.remove("_tmp2.pcap")



if __name__ == '__main__':
    unittest.main()

