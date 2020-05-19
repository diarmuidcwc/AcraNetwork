__author__ = 'diarmuid'
import sys
sys.path.append("..")

import unittest
import AcraNetwork.iNetX as inetx
import AcraNetwork.ParserAligned as paligned
import AcraNetwork.Pcap as pcap
import struct
import os
import copy

THIS_DIR = os.path.dirname(os.path.abspath(__file__))


expected_p = """Block 0: QuadBytes=3 Error=False ErrorCode=0 BusID=0 MessageCount=0 ElapsedTime=0
Block 1: QuadBytes=3 Error=False ErrorCode=0 BusID=2 MessageCount=1 ElapsedTime=0
Block 2: QuadBytes=3 Error=False ErrorCode=0 BusID=6 MessageCount=2 ElapsedTime=10000
Block 3: QuadBytes=3 Error=False ErrorCode=0 BusID=16 MessageCount=3 ElapsedTime=10000
Block 4: QuadBytes=3 Error=False ErrorCode=0 BusID=18 MessageCount=4 ElapsedTime=20000
Block 5: QuadBytes=3 Error=False ErrorCode=0 BusID=11 MessageCount=5 ElapsedTime=20000
Block 6: QuadBytes=3 Error=False ErrorCode=0 BusID=14 MessageCount=6 ElapsedTime=30000
Block 7: QuadBytes=3 Error=False ErrorCode=0 BusID=17 MessageCount=7 ElapsedTime=30000
Block 8: QuadBytes=3 Error=False ErrorCode=0 BusID=22 MessageCount=8 ElapsedTime=30000
Block 9: QuadBytes=3 Error=False ErrorCode=0 BusID=23 MessageCount=9 ElapsedTime=30000
Block 10: QuadBytes=3 Error=False ErrorCode=0 BusID=7 MessageCount=10 ElapsedTime=30000
Block 11: QuadBytes=3 Error=False ErrorCode=0 BusID=8 MessageCount=11 ElapsedTime=30000
Block 12: QuadBytes=3 Error=False ErrorCode=0 BusID=9 MessageCount=12 ElapsedTime=40000
Block 13: QuadBytes=3 Error=False ErrorCode=0 BusID=10 MessageCount=13 ElapsedTime=50000
Block 14: QuadBytes=3 Error=False ErrorCode=0 BusID=12 MessageCount=14 ElapsedTime=50000
Block 15: QuadBytes=3 Error=False ErrorCode=0 BusID=13 MessageCount=15 ElapsedTime=50000
Block 16: QuadBytes=3 Error=False ErrorCode=0 BusID=15 MessageCount=16 ElapsedTime=40000
Block 17: QuadBytes=3 Error=False ErrorCode=0 BusID=19 MessageCount=17 ElapsedTime=50000
Block 18: QuadBytes=3 Error=False ErrorCode=0 BusID=20 MessageCount=18 ElapsedTime=50000
Block 19: QuadBytes=3 Error=False ErrorCode=0 BusID=21 MessageCount=19 ElapsedTime=40000
Block 20: QuadBytes=3 Error=False ErrorCode=0 BusID=1 MessageCount=20 ElapsedTime=50000
Block 21: QuadBytes=3 Error=False ErrorCode=0 BusID=3 MessageCount=21 ElapsedTime=50000
Block 22: QuadBytes=3 Error=False ErrorCode=0 BusID=4 MessageCount=22 ElapsedTime=50000
Block 23: QuadBytes=3 Error=False ErrorCode=0 BusID=5 MessageCount=23 ElapsedTime=50000
Block 24: QuadBytes=3 Error=False ErrorCode=0 BusID=2 MessageCount=24 ElapsedTime=360000
Block 25: QuadBytes=3 Error=False ErrorCode=0 BusID=11 MessageCount=25 ElapsedTime=370000
Block 26: QuadBytes=3 Error=False ErrorCode=0 BusID=16 MessageCount=26 ElapsedTime=370000
Block 27: QuadBytes=3 Error=False ErrorCode=0 BusID=0 MessageCount=27 ElapsedTime=370000
Block 28: QuadBytes=3 Error=False ErrorCode=0 BusID=23 MessageCount=28 ElapsedTime=380000
Block 29: QuadBytes=3 Error=False ErrorCode=0 BusID=7 MessageCount=29 ElapsedTime=390000
Block 30: QuadBytes=3 Error=False ErrorCode=0 BusID=15 MessageCount=30 ElapsedTime=410000
Block 31: QuadBytes=3 Error=False ErrorCode=0 BusID=17 MessageCount=31 ElapsedTime=410000
Block 32: QuadBytes=3 Error=False ErrorCode=0 BusID=18 MessageCount=32 ElapsedTime=410000
Block 33: QuadBytes=3 Error=False ErrorCode=0 BusID=21 MessageCount=33 ElapsedTime=410000
Block 34: QuadBytes=3 Error=False ErrorCode=0 BusID=22 MessageCount=34 ElapsedTime=420000
Block 35: QuadBytes=3 Error=False ErrorCode=0 BusID=3 MessageCount=35 ElapsedTime=410000
Block 36: QuadBytes=3 Error=False ErrorCode=0 BusID=4 MessageCount=36 ElapsedTime=420000
Block 37: QuadBytes=3 Error=False ErrorCode=0 BusID=5 MessageCount=37 ElapsedTime=420000
Block 38: QuadBytes=3 Error=False ErrorCode=0 BusID=6 MessageCount=38 ElapsedTime=410000
Block 39: QuadBytes=3 Error=False ErrorCode=0 BusID=8 MessageCount=39 ElapsedTime=420000
Block 40: QuadBytes=3 Error=False ErrorCode=0 BusID=9 MessageCount=40 ElapsedTime=420000
Block 41: QuadBytes=3 Error=False ErrorCode=0 BusID=10 MessageCount=41 ElapsedTime=430000
Block 42: QuadBytes=3 Error=False ErrorCode=0 BusID=12 MessageCount=42 ElapsedTime=420000
Block 43: QuadBytes=3 Error=False ErrorCode=0 BusID=13 MessageCount=43 ElapsedTime=440000
Block 44: QuadBytes=3 Error=False ErrorCode=0 BusID=14 MessageCount=44 ElapsedTime=420000
Block 45: QuadBytes=3 Error=False ErrorCode=0 BusID=19 MessageCount=45 ElapsedTime=440000
Block 46: QuadBytes=3 Error=False ErrorCode=0 BusID=20 MessageCount=46 ElapsedTime=430000
Block 47: QuadBytes=3 Error=False ErrorCode=0 BusID=1 MessageCount=47 ElapsedTime=430000
Block 48: QuadBytes=3 Error=False ErrorCode=0 BusID=16 MessageCount=48 ElapsedTime=720000
Block 49: QuadBytes=3 Error=False ErrorCode=0 BusID=2 MessageCount=49 ElapsedTime=750000
Block 50: QuadBytes=3 Error=False ErrorCode=0 BusID=7 MessageCount=50 ElapsedTime=750000
Block 51: QuadBytes=3 Error=False ErrorCode=0 BusID=11 MessageCount=51 ElapsedTime=760000
Block 52: QuadBytes=3 Error=False ErrorCode=0 BusID=15 MessageCount=52 ElapsedTime=760000
Block 53: QuadBytes=3 Error=False ErrorCode=0 BusID=0 MessageCount=53 ElapsedTime=760000
Block 54: QuadBytes=3 Error=False ErrorCode=0 BusID=4 MessageCount=54 ElapsedTime=770000
Block 55: QuadBytes=3 Error=False ErrorCode=0 BusID=9 MessageCount=55 ElapsedTime=770000
Block 56: QuadBytes=3 Error=False ErrorCode=0 BusID=17 MessageCount=56 ElapsedTime=770000
Block 57: QuadBytes=3 Error=False ErrorCode=0 BusID=18 MessageCount=57 ElapsedTime=770000
Block 58: QuadBytes=3 Error=False ErrorCode=0 BusID=23 MessageCount=58 ElapsedTime=770000
Block 59: QuadBytes=3 Error=False ErrorCode=0 BusID=6 MessageCount=59 ElapsedTime=780000
Block 60: QuadBytes=3 Error=False ErrorCode=0 BusID=8 MessageCount=60 ElapsedTime=780000
Block 61: QuadBytes=3 Error=False ErrorCode=0 BusID=13 MessageCount=61 ElapsedTime=790000
Block 62: QuadBytes=3 Error=False ErrorCode=0 BusID=20 MessageCount=62 ElapsedTime=790000
Block 63: QuadBytes=3 Error=False ErrorCode=0 BusID=21 MessageCount=63 ElapsedTime=790000
Block 64: QuadBytes=3 Error=False ErrorCode=0 BusID=22 MessageCount=64 ElapsedTime=800000
Block 65: QuadBytes=3 Error=False ErrorCode=0 BusID=3 MessageCount=65 ElapsedTime=800000
Block 66: QuadBytes=3 Error=False ErrorCode=0 BusID=10 MessageCount=66 ElapsedTime=800000
Block 67: QuadBytes=3 Error=False ErrorCode=0 BusID=12 MessageCount=67 ElapsedTime=800000
Block 68: QuadBytes=3 Error=False ErrorCode=0 BusID=14 MessageCount=68 ElapsedTime=810000
Block 69: QuadBytes=3 Error=False ErrorCode=0 BusID=1 MessageCount=69 ElapsedTime=820000
Block 70: QuadBytes=3 Error=False ErrorCode=0 BusID=5 MessageCount=70 ElapsedTime=820000
Block 71: QuadBytes=3 Error=False ErrorCode=0 BusID=19 MessageCount=71 ElapsedTime=830000
Block 72: QuadBytes=3 Error=False ErrorCode=0 BusID=16 MessageCount=72 ElapsedTime=1080000
Block 73: QuadBytes=3 Error=False ErrorCode=0 BusID=2 MessageCount=73 ElapsedTime=1110000
Block 74: QuadBytes=3 Error=False ErrorCode=0 BusID=17 MessageCount=74 ElapsedTime=1120000
Block 75: QuadBytes=3 Error=False ErrorCode=0 BusID=18 MessageCount=75 ElapsedTime=1130000
Block 76: QuadBytes=3 Error=False ErrorCode=0 BusID=23 MessageCount=76 ElapsedTime=1130000
Block 77: QuadBytes=3 Error=False ErrorCode=0 BusID=4 MessageCount=77 ElapsedTime=1130000
Block 78: QuadBytes=3 Error=False ErrorCode=0 BusID=6 MessageCount=78 ElapsedTime=1130000
Block 79: QuadBytes=3 Error=False ErrorCode=0 BusID=7 MessageCount=79 ElapsedTime=1140000
Block 80: QuadBytes=3 Error=False ErrorCode=0 BusID=0 MessageCount=80 ElapsedTime=1140000
Block 81: QuadBytes=3 Error=False ErrorCode=0 BusID=9 MessageCount=81 ElapsedTime=1150000
Block 82: QuadBytes=3 Error=False ErrorCode=0 BusID=12 MessageCount=82 ElapsedTime=1150000
"""

class TestParserAligned(unittest.TestCase):
    def test_read_pcap(self):
        p = pcap.Pcap(os.path.join(THIS_DIR, "valid_paligned.pcap"))
        mypcaprecord = p[0]
        p.close()
        # Now I have a _payload that will be an inetx packet
        inetxp = inetx.iNetX()
        inetxp.unpack(mypcaprecord.payload[0x2a:-4])
        self.assertEqual(inetxp.streamid, 0xa00)
        p = paligned.ParserAlignedPacket()
        p.unpack(inetxp.payload)
        self.assertEqual(len(p), 83)
        self.assertEqual(repr(p), expected_p)
        for i, b in enumerate(p):
            if i == 3:
                self.assertEqual(len(b), 12)
                self.assertEqual(repr(b), "QuadBytes=3 Error=False ErrorCode=0 BusID=16 MessageCount=3 ElapsedTime=10000")

        p2 = paligned.ParserAlignedPacket()
        for b in p:
            blk = copy.copy(b)
            p2.parserblocks.append(blk)

        self.assertEqual(p2.pack(), inetxp.payload)
        self.assertTrue(p2==p)


if __name__ == '__main__':
    unittest.main()
