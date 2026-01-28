import unittest
import AcraNetwork.Pcap as pcap
import AcraNetwork.SimpleEthernet as SimpleEthernet
import AcraNetwork.IRIG106.Chapter24 as ch24
import struct
import os
import os.path
import tempfile
import logging

THIS_DIR = os.path.dirname(os.path.abspath(__file__))
TMP_DIR = tempfile.gettempdir()


logging.basicConfig(level=logging.INFO)
# logging.info(f"Temp folder={TMP_DIR}")


def getEthernetPacket(data: bytes = b""):
    e = SimpleEthernet.Ethernet()
    e.srcmac = 0x001122334455
    e.dstmac = 0x998877665544
    e.type = SimpleEthernet.Ethernet.TYPE_IP
    i = SimpleEthernet.IP()
    i.dstip = "235.0.0.1"
    i.srcip = "192.168.1.1"
    i.protocol = SimpleEthernet.IP.PROTOCOLS["UDP"]
    u = SimpleEthernet.UDP()
    u.dstport = 9999
    u.srcport = 9999
    u.payload = data
    i.payload = u.pack()
    e.payload = i.pack()
    return e.pack()


class Ch24UDP(unittest.TestCase):
    def test_basic(self):
        p = ch24.TmNSMessage()
        b = p.pack()
        p2 = ch24.TmNSMessage()
        p2.unpack(b)
        self.assertEqual(p, p2)

    def test_modified(self):
        pkt = ch24.TmNSMessage()
        pkt.flags.acquired = ch24.DataSourceAcquiredDataFlag.SIMULATED
        pkt.flags.fragmentation = ch24.MessageFragmentationFlags.LASTFRAGMENT
        pkt.definitionid = 0x1234
        pkt.sequence = 100
        pkt.payload = struct.pack(">HH", 0x1, 0x2)
        b = pkt.pack()
        p2 = ch24.TmNSMessage()
        p2.unpack(b)
        self.assertEqual(pkt, p2)
        pcapw = pcap.Pcap(THIS_DIR + "/tmns.pcap", mode="w")
        rec = pcap.PcapRecord()
        rec.payload = getEthernetPacket(b)
        pcapw.write(rec)
        pcapw.close()

        self.assertEqual(len(pkt), 28)
