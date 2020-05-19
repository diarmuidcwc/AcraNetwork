__author__ = 'diarmuid'
import sys
sys.path.append("..")
import os

import unittest
import AcraNetwork.Pcap as pcap
import AcraNetwork.SimpleEthernet as SimpleEthernet
import struct


THIS_DIR = os.path.dirname(os.path.abspath(__file__))


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
        self.assertRaises(IOError, lambda: pcap.Pcap(os.path.join(THIS_DIR, "nofile.pcap")))

    def test_defaultMagicNumber(self):
        p = pcap.Pcap("_tmp.pcap", mode='w')
        self.assertEqual(p.magic, 0xa1b2c3d4)
        p.close()

    def test_defaultVersionMaj(self):
        p = pcap.Pcap("_tmp.pcap", mode='w')
        self.assertEqual(p.versionmaj, 2)
        p.close()

    def test_defaultVersionMin(self):
        p = pcap.Pcap("_tmp.pcap", mode='w')
        self.assertEqual(p.versionmin, 4)
        p.close()

    def test_readTestFile(self):
        p = pcap.Pcap(os.path.join(THIS_DIR, "test_input.pcap"))
        self.assertEqual(p.magic,0xa1b2c3d4)
        self.assertEqual(p.network,1)
        self.assertEqual(p.sigfigs,0)
        self.assertEqual(p.snaplen,262144)
        self.assertEqual(p.versionmaj,2)
        self.assertEqual(p.versionmin,4)
        self.assertEqual(p.zone,0)
        self.assertEqual(p.filesize, 704)
        for idx, rec in enumerate(p):
            if id == 3:
                self.assertEqual(len(rec), 66)
        p.close()



    def test_readARecord(self):
        p = pcap.Pcap(os.path.join(THIS_DIR, "test_input.pcap"))
        mypcaprecord = p[0]
        p.close()
        self.assertEqual(mypcaprecord.sec,1419678111)
        self.assertEqual(mypcaprecord.usec,811463)
        self.assertEqual(mypcaprecord.orig_len,70)
        self.assertEqual(mypcaprecord.incl_len,70)
        self.assertEqual(repr(mypcaprecord), "LEN:70 SEC:1419678111 USEC:811463")
        p.close()

    def test_writeARecord(self):
        p = pcap.Pcap("_tmp.pcap",mode='w')
        p.write_global_header()
        r = pcap.PcapRecord()
        r.setCurrentTime()
        r.packet = getEthernetPacket(0xa)
        p.write(r)
        p.close()
        p = pcap.Pcap("_tmp.pcap")
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
        p.write_global_header()
        r = pcap.PcapRecord()
        r.setCurrentTime()
        r.packet = getEthernetPacket(0xa)
        p.write(r)
        p.close()
        # Now try to append a record
        p = pcap.Pcap("_tmp2.pcap",mode='a')
        r.packet = getEthernetPacket(0xb)
        p.write(r)
        p.close()
        # Read back to verify
        p = pcap.Pcap("_tmp2.pcap")
        self.assertEqual(p.filesize,88)
        for idx, rec in enumerate(p):
            e = SimpleEthernet.Ethernet()
            e.unpack(rec.packet)
            if idx == 0:
                self.assertEqual(e.payload,struct.pack("H",0xa))
            else:
                self.assertEqual(e.payload,struct.pack("H",0xb))
        p.close()
        os.remove("_tmp2.pcap")


if __name__ == '__main__':
    unittest.main()

