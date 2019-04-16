__author__ = 'diarmuid'
import sys
sys.path.append("..")

import unittest
import AcraNetwork.iNetX as inetx
import AcraNetwork.ParserAligned as paligned
import AcraNetwork.Pcap as pcap
import struct
import os

THIS_DIR = os.path.dirname(os.path.abspath(__file__))
class TestParserAligned(unittest.TestCase):
    def test_read_pcap(self):
        p = pcap.Pcap(os.path.join(THIS_DIR, "valid_paligned.pcap"))
        mypcaprecord = p[0]
        p.close()
        # Now I have a _payload that
        # will be an inetx packet
        i = inetx.iNetX()
        i.unpack(mypcaprecord.payload[0x2a:-4])
        self.assertEqual(i.streamid, 0xa00)

        p = paligned.ParserAlignedPacket()
        p.unpack(i.payload)
        self.assertEqual(len(p), 83)
        self.assertEqual(repr(p[3]), "Block: QuadBytes=3 Error=False ErrorCode=0 BusID=16 MessageCount=3 ElapsedTime=10000")


if __name__ == '__main__':
    unittest.main()
