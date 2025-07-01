__author__ = "diarmuid"
import sys

sys.path.append("..")
import os

import unittest
import AcraNetwork.Pcap as pcap
import AcraNetwork.SimpleEthernet as SimpleEthernet
import struct


THIS_DIR = os.path.dirname(os.path.abspath(__file__))


def getEthernetPacket(data=0xA):
    e = SimpleEthernet.Ethernet()
    e.srcmac = 0x001122334455
    e.dstmac = 0x998877665544
    e.type = SimpleEthernet.Ethernet.TYPE_IP
    e.payload = struct.pack("H", data)
    return e.pack()


class PcapBasicTest(unittest.TestCase):
    def test_missingfilename(self):
        self.assertRaises(TypeError, lambda: pcap.Pcap())

    def test_missingreadfile(self):
        self.assertRaises(IOError, lambda: pcap.Pcap(os.path.join(THIS_DIR, "nofile.pcap")))

    def test_defaultMagicNumber(self):
        p = pcap.Pcap("_tmp.pcap", mode="w")
        self.assertEqual(p.magic, 0xA1B2C3D4)
        p.close()

    def test_defaultVersionMaj(self):
        p = pcap.Pcap("_tmp.pcap", mode="w")
        self.assertEqual(p.versionmaj, 2)
        p.close()

    def test_defaultVersionMin(self):
        p = pcap.Pcap("_tmp.pcap", mode="w")
        self.assertEqual(p.versionmin, 4)
        p.close()

    def test_readTestFile(self):
        p = pcap.Pcap(os.path.join(THIS_DIR, "test_input.pcap"))
        self.assertEqual(p.magic, 0xA1B2C3D4)
        self.assertEqual(p.network, 1)
        self.assertEqual(p.sigfigs, 0)
        self.assertEqual(p.snaplen, 262144)
        self.assertEqual(p.versionmaj, 2)
        self.assertEqual(p.versionmin, 4)
        self.assertEqual(p.zone, 0)
        self.assertEqual(p.filesize, 704)
        for idx, rec in enumerate(p):
            if id == 3:
                self.assertEqual(len(rec), 66)
        p.close()

    def test_readARecord(self):
        p = pcap.Pcap(os.path.join(THIS_DIR, "test_input.pcap"))
        mypcaprecord = p[0]
        p.close()
        self.assertEqual(mypcaprecord.sec, 1419678111)
        self.assertEqual(mypcaprecord.usec, 811463)
        self.assertEqual(mypcaprecord.orig_len, 70)
        self.assertEqual(mypcaprecord.incl_len, 70)
        self.assertEqual(repr(mypcaprecord), "LEN:70 SEC:1419678111 USEC:811463")
        p.close()

    def test_writeARecord(self):
        p = pcap.Pcap("_tmp.pcap", mode="w")
        r = pcap.PcapRecord()
        r.setCurrentTime()
        r.packet = getEthernetPacket(0xA)
        p.write(r)
        p.close()
        p = pcap.Pcap("_tmp.pcap")
        self.assertEqual(p.magic, 0xA1B2C3D4)
        self.assertEqual(p.network, 1)
        self.assertEqual(p.sigfigs, 0)
        self.assertEqual(p.snaplen, 65535)
        self.assertEqual(p.versionmaj, 2)
        self.assertEqual(p.versionmin, 4)
        self.assertEqual(p.zone, 0)
        self.assertEqual(p.filesize, 56)
        p.close()
        os.remove("_tmp.pcap")

    def test_appendARecord(self):
        p = pcap.Pcap("_tmp2.pcap", mode="w")
        r = pcap.PcapRecord()
        r.setCurrentTime()
        r.packet = getEthernetPacket(0xA)
        p.write(r)
        p.close()
        # Now try to append a record
        p = pcap.Pcap("_tmp2.pcap", mode="a")
        r.packet = getEthernetPacket(0xB)
        p.write(r)
        p.close()
        # Read back to verify
        p = pcap.Pcap("_tmp2.pcap")
        self.assertEqual(p.filesize, 88)
        for idx, rec in enumerate(p):
            e = SimpleEthernet.Ethernet()
            e.unpack(rec.packet)
            if idx == 0:
                self.assertEqual(e.payload, struct.pack("H", 0xA))
            else:
                self.assertEqual(e.payload, struct.pack("H", 0xB))
        p.close()
        os.remove("_tmp2.pcap")

    def test_context_manager(self):
        """
        tests the use of __enter__() and __exit() to allow "with" to ensure
        the file is closed. Also verifies the behaviour of the rec_no value.        
        """
        test_filename = "_tmp3.pcap"

        # define a payload for packet i
        def pkt_payload(i): return i+1234

        with pcap.Pcap(test_filename, mode="w") as p:
            for i in range(10):
                r = pcap.PcapRecord(now=True)
                r.packet = getEthernetPacket(pkt_payload(i))
                p.write(r)
                self.assertEqual(p.rec_no, i+1)
        self.assertTrue(p.fopen.closed)
        
        # Read the file back. This also shows how to handle an exception when 
        # opening the file... the first filename will be invalid, the second 
        # will work.
        for filename in ("this_file_does_not_exist", test_filename):
            exception_msg = None
            if filename == test_filename:
                exp_exception_msg = None
            else:
                exp_exception_msg = f"Failed to open {filename}. err=[Errno 2] No such file or directory: '{filename}'"
            try:
                p = pcap.Pcap(filename, mode="r")
            except IOError as e:
                exception_msg = str(e)
            else:
                with p:
                    for i, rec in enumerate(p):
                        e = SimpleEthernet.Ethernet()
                        e.unpack(rec.packet)

                        self.assertEqual(e.payload, 
                                         struct.pack("H", pkt_payload(i))
                                        )
            self.assertEqual(exception_msg, exp_exception_msg)
            if filename == test_filename:
                # file should have been closed properly by __exit__()
                self.assertTrue(p.fopen.closed)
            else:
                # exception should have happened so object has not even been
                # created
                self.assertIsNot(exception_msg, None)
        os.remove(test_filename)
        

if __name__ == "__main__":
    unittest.main()
