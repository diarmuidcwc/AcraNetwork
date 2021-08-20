__author__ = 'diarmuid'
import sys
sys.path.append("..")
import unittest
import AcraNetwork.Pcap as pcap
import AcraNetwork.SimpleEthernet as SimpleEthernet
import AcraNetwork.NPD as NPD
import struct
import os

THIS_DIR = os.path.dirname(os.path.abspath(__file__))


def getEthernetPacket(data=""):
    e = SimpleEthernet.Ethernet()
    e.srcmac = 0x001122334455
    e.dstmac = 0x998877665544
    e.type = SimpleEthernet.Ethernet.TYPE_IP
    i = SimpleEthernet.IP()
    i.dstip = "235.0.0.1"
    i.srcip = "192.168.1.1"
    i.protocol = SimpleEthernet.IP.PROTOCOLS["UDP"]
    u = SimpleEthernet.UDP()
    u.dstport = 6667
    u.srcport = 6667
    u.payload = data
    i.payload = u.pack()
    e.payload = i.pack()
    return e.pack()


test_npd_exp="""NPD: DataType=0X2 Seq=10 DataSrcID=0X1 MCastAddr=235.0.0.1
\tNPD Segment. TimeDelta=3 Segment Len=18 ErrorCode=0 Flags=0X1
\tNPD Segment. TimeDelta=3 Segment Len=22 ErrorCode=0 Flags=0X1
\tNPD Segment. TimeDelta=3 Segment Len=26 ErrorCode=0 Flags=0X1
\tNPD Segment. TimeDelta=3 Segment Len=30 ErrorCode=0 Flags=0X1"""


class testNPD(unittest.TestCase):

    def  setUp(self):
        self.n = NPD.NPD()
        self.n.datasrcid = 1
        self.n.datatype = 2
        self.n.cfgcnt = 3
        self.n.flags = 4
        self.n.timestamp = 5
        self.n.sequence = 10
        self.n.mcastaddr = "235.0.0.1"

        self.ns = NPD.NPDSegment()
        self.ns.timedelta = 3
        self.ns.errorcode = 0
        self.ns.flags = 1

        pcapr = pcap.Pcap(os.path.join(THIS_DIR, "npd_ref.pcap"), mode="r")
        rec = pcapr[0]
        pcapr.close()
        self.readnpd_payload = rec.payload[(14+20+8):]

    def test_npds_print(self):
        self.ns.payload = struct.pack(">II", 2, 3)
        self.assertEqual(repr(self.ns), "NPD Segment. TimeDelta=3 Segment Len=16 ErrorCode=0 Flags=0X1")

    def test_npds_eq(self):
        self.ns.payload = struct.pack(">II", 2, 3)
        n2 = NPD.NPDSegment()
        n2.timedelta = 3
        n2.errorcode = 0
        n2.flags = 1
        n2.payload = struct.pack(">II", 2, 3)
        self.assertTrue(n2 == self.ns)
        n2.flags = 3
        self.assertTrue(n2 != self.ns)

    def test_npd_basic(self):
        # No _payload
        buf=self.n.pack()
        self.assertEqual(len(buf), 20)

    def test_npd_sec(self):
        self.ns.payload =  struct.pack(">III",1,2,3)
        buf = self.ns.pack()
        self.assertEqual(len(buf), 20)

    def test_npd_in_npd(self):
        # Add a segment to the _payload
        self.ns.payload = struct.pack(">III", 1, 2, 3)
        self.n.segments.append(self.ns)
        buf = self.n.pack()
        self.assertEqual(len(buf), 40)

    def test_nd_to_pcap(self):
        for segment in range(3,7):
            ns = NPD.NPDSegment()
            ns.timedelta = 3
            ns.errorcode = 0
            ns.flags = 1
            ns.payload = struct.pack(">{}IH".format(segment-1), *list(range(segment)))
            self.n.segments.append(ns)
        rec = getEthernetPacket(self.n.pack())
        self.pcapw = pcap.Pcap("test_npd.pcap", mode="w")
        self.pcapw.write_global_header()
        self.rec = pcap.PcapRecord()
        self.rec.payload = rec
        self.pcapw.write(self.rec)
        self.pcapw.close()

    def test_odd_payload(self):
        # Add a segment to the _payload
        self.ns.payload = struct.pack(">IIH", 1, 2, 3)
        self.n.segments.append(self.ns)
        buf = self.n.pack()
        self.assertEqual(len(buf), 40)

    def test_unpack(self):
        n = NPD.NPD()
        n.unpack(self.readnpd_payload)
        self.assertEqual(len(n),4)
        self.assertEqual(n.segments[3].segmentlen, 30)
        #print repr(n)
        self.assertEqual(repr(n), test_npd_exp)
        for i,s in enumerate(n):
            if i == 1:
                self.assertEqual(s.timedelta, 3)

    @unittest.skip("no pcap")
    def test_unpackwrap(self):
        pcapr = pcap.Pcap(os.path.join(THIS_DIR, "npd_pcm.pcap"), mode="r")
        rec = pcapr[0]
        readnpd_payload = rec.payload[(14+20+8):]
        n = NPD.NPD()
        n.unpack(readnpd_payload)
        self.assertEqual(len(n.segments),2)
        self.assertEqual(n.segments[0].segmentlen, 34)
        #print(repr(n))
        self.assertEqual(n.segments[0].sfid, 0x0)
        pcapr.close()

    def test_rs232(self):
        self.n.datatype = 0x50
        for segment in range(3, 7):
            ns = NPD.RS232Segment()
            ns.timedelta = 3
            ns.errorcode = 0
            ns.flags = 1
            ns.block_status = NPD.RS232Segment.BSL_PARN_EN + NPD.RS232Segment.BSL_422
            ns.data = os.urandom(50+segment)
            self.n.segments.append(ns)
        for segment in range(1, 5):
            ns = NPD.RS232Segment()
            ns.timedelta = 3
            ns.errorcode = 0
            ns.flags = 1
            ns.block_status = NPD.RS232Segment.BSL_PARN_EN + NPD.RS232Segment.BSL_422
            ns.sync_bytes = [segment] * segment
            ns.data = os.urandom(50+segment)
            self.n.segments.append(ns)

        rec = getEthernetPacket(self.n.pack())
        self.pcapw = pcap.Pcap("test_npd_rs232.pcap", mode="w")
        self.pcapw.write_global_header()
        self.rec = pcap.PcapRecord()
        self.rec.payload = rec
        self.pcapw.write(self.rec)
        self.pcapw.close()

        n2= NPD.NPD()
        n2.unpack(self.n.pack())
        self.assertEqual(self.n, n2)
        self.assertEqual(repr(n2[0]), "RS232 NPD Segment. TimeDelta=3 Segment Len=63 ErrorCode=0X0 Flags=0X1 Block_Status=0X840 DataLen=53")


if __name__ == '__main__':
    unittest.main()
