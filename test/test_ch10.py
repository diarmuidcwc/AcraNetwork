import unittest
__author__ = 'diarmuid'
import sys
sys.path.append("..")
import unittest
import AcraNetwork.Pcap as pcap
import AcraNetwork.SimpleEthernet as SimpleEthernet
import AcraNetwork.Chapter10 as ch10
import struct
import os
import random

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
    u.dstport = 6679
    u.srcport = 6679
    u.payload = data
    i.payload = u.pack()
    e.payload = i.pack()
    return e.pack()


def wrap_in_udp_and_pcap(mybuffer, pcapf, mode="w"):
    pcapw = pcap.Pcap(pcapf, mode=mode)
    pcapw.write_global_header()
    rec = pcap.PcapRecord()
    rec.payload = getEthernetPacket(mybuffer)
    pcapw.write(rec)
    pcapw.close()
    return True

class CH10UDPTest(unittest.TestCase):
    def setUp(self):

        self.full = ch10.Chapter10UDP()
        self.full.type = ch10.Chapter10UDP.TYPE_FULL
        self.full.sequence = 1
        self.full.chapter10.channelID = 1
        self.full.chapter10.datatypeversion = 2
        self.full.chapter10.sequence = 3
        self.full.chapter10.packetflag = 0 # No secondary
        self.full.chapter10.datatype = 4
        self.full.chapter10.relativetimecounter = 100

        self.seg = ch10.Chapter10UDP()
        self.seg.sequence = 2
        self.seg.type = ch10.Chapter10UDP.TYPE_SEG
        self.seg.channelID = 0x232
        self.seg.channelsequence = 100
        self.seg.segmentoffset = 3
        self.seg.chapter10.channelID = 1
        self.seg.chapter10.datatypeversion = 2
        self.seg.chapter10.sequence = 3
        self.seg.chapter10.packetflag = 0 # No secondary
        self.seg.chapter10.datatype = 4
        self.seg.chapter10.relativetimecounter = 100

        self.c = ch10.Chapter10()
        self.c.channelID = 1
        self.c.datatypeversion = 2
        self.c.sequence = 3
        self.c.packetflag = 0 # No secondary
        self.c.datatype = 4
        self.c.relativetimecounter = 100

    def test_ch10_to_pcap(self):
        #self.full._payload = struct.pack(">II", 33, 44)
        full_payload = getEthernetPacket(self.full.pack())
        self.pcapw = pcap.Pcap("test_ch10.pcap", mode="w")
        self.pcapw.write_global_header()
        self.rec = pcap.PcapRecord()
        self.rec.payload = full_payload
        self.assertIsNone(self.pcapw.write(self.rec))
        #self.seg._payload = struct.pack(">II", 55, 66)
        seg_payload = getEthernetPacket(self.seg.pack())
        self.rec.payload = seg_payload
        self.assertIsNone(self.pcapw.write(self.rec))
        self.pcapw.close()

    def test_ch10_eq(self):
        full = ch10.Chapter10UDP()
        full.type = ch10.Chapter10UDP.TYPE_FULL
        full.sequence = 1
        #full._payload = struct.pack(">II", 33, 44)

        #self.full._payload = struct.pack(">II", 33, 44)

        self.assertTrue(full==self.full)

    def test_unpack(self):
        #self.full._payload = struct.pack(">II", 33, 44)
        #self.seg._payload = struct.pack(">II", 33, 44)

        full_unpack = ch10.Chapter10UDP()
        self.assertTrue(full_unpack.unpack(self.full.pack()))

        self.assertTrue(full_unpack == self.full)
        self.assertFalse(full_unpack == self.seg)

    def test_ch10_eqseg(self):
        seg = ch10.Chapter10UDP()
        seg.type = ch10.Chapter10UDP.TYPE_SEG
        seg.sequence = 2
        seg.channelID = 0x232
        seg.channelsequence = 100
        seg.segmentoffset = 3
        #seg._payload = struct.pack(">II", 33, 44)

        #self.seg._payload = struct.pack(">II", 33, 44)

        self.assertTrue(seg==self.seg)

    def test_ch10pay_to_pcap(self):
        self.c.payload = struct.pack(">II", 33, 44)
        #self.full._payload = self.c.pack()
        full_payload = getEthernetPacket(self.full.pack())
        self.pcapw = pcap.Pcap("test_ch10_2.pcap", mode="w")
        self.pcapw.write_global_header()
        self.rec = pcap.PcapRecord()
        self.rec.payload = full_payload
        self.assertIsNone(self.pcapw.write(self.rec))
        self.pcapw.close()

    def test_ch10_comp(self):
        ref = ch10.Chapter10()
        #self.c._payload = struct.pack(">II", 33, 44)
        pay = self.c.pack()
        ref.unpack(pay)
        self.assertTrue(ref == self.c)

    def test_ch10_sec_hdr(self):
        c = ch10.Chapter10UDP()
        c.type = ch10.Chapter10UDP.TYPE_FULL
        c.sequence = 1
        c.chapter10.channelID = 1
        c.chapter10.datatypeversion = 2
        c.chapter10.sequence = 3
        c.chapter10.packetflag = ch10.Chapter10.PKT_FLAG_SECONDARY
        c.chapter10.datatype = 4
        c.chapter10.ts_source = "ieee1588"
        c.chapter10.ptptimeseconds = 101
        c.chapter10.ptptimenanoseconds = int(200e6)
        c.chapter10.relativetimecounter = 0x0
        c.chapter10.payload = struct.pack(">QQ", 33, 44)
        full_payload = getEthernetPacket(c.pack())
        self.pcapw = pcap.Pcap("test_ch10_3.pcap", mode="w")
        self.pcapw.write_global_header()
        self.rec = pcap.PcapRecord()
        self.rec.payload = full_payload
        self.assertIsNone(self.pcapw.write(self.rec))
        self.pcapw.close()

    def test_arinc_payload(self):
        p = pcap.Pcap(os.path.join(THIS_DIR, "ch10_arinc.pcap"))
        mypcaprecord = p[0]
        p.close()
        e = SimpleEthernet.Ethernet()
        e.unpack(mypcaprecord.packet)
        ip = SimpleEthernet.IP()
        ip.unpack(e.payload)
        u = SimpleEthernet.UDP()
        u.unpack(ip.payload)
        # Now I have a _payload that will be an inetx packet
        c = ch10.Chapter10UDP()
        self.assertTrue(c.unpack(u.payload))

        # Check the Ch10 packets
        self.assertEqual(c.chapter10.syncpattern, 0xeb25)
        self.assertEqual(c.chapter10.channelID, 0x000080d6)
        self.assertEqual(c.chapter10.datatypeversion, 0x44)
        # nanoseconds and seconds
        self.assertEqual(c.chapter10.ptptimenanoseconds, 1237463)
        self.assertEqual(c.chapter10.ptptimeseconds, 0)

        self.assertEqual(repr(c), "CH10 UDP Full Packet: Version=1 Sequence=0 Payload=Chapter 10: ChannelID=32982 Sequence=0 DataLen=88")
        arinc_p = ch10.ARINC429DataPacket()
        self.assertTrue(arinc_p.unpack(c.chapter10.payload))
        self.assertEqual(len(arinc_p.arincwords), 11)
        self.assertEqual(arinc_p.arincwords[0].payload, struct.pack(">I", 0x4bd91e2e))

        arinc2 = ch10.ARINC429DataPacket()
        self.assertTrue(arinc2.unpack(arinc_p.pack()))
        self.assertTrue(arinc_p == arinc2)
        #print(arinc2)


class Ch10UARTTest(unittest.TestCase):
    def setUp(self):

        self.full = ch10.Chapter10UDP()
        self.full.type = ch10.Chapter10UDP.TYPE_FULL
        self.full.sequence = 10
        self.full.chapter10.channelID = 23
        self.full.chapter10.datatypeversion = 2
        self.full.chapter10.sequence = 3
        self.full.chapter10.packetflag = 0xC4  # Secondary time + PTP
        self.full.chapter10.datatype = 0x50
        self.full.chapter10.relativetimecounter = 100
        self.full.chapter10.ptptimeseconds = 22
        self.full.chapter10.ptptimenanoseconds = 250000

    def test_basic_uart(self):
        udp = ch10.UARTDataPacket()
        for i in range(5):
            udw = ch10.UARTDataWord()
            udw.ptptimeseconds = 22*i
            udw.ptptimenanoseconds = 250000+i
            udw.subchannel = 52 + 2*i
            udw.parity_error = random.choice([True, False])
            udw.payload = os.urandom(random.randint(15, 220))
            #udw.payload = os.urandom(16)

            self.assertIsNone(udp.append(udw))

        self.full.chapter10.payload = udp.pack()
        self.assertTrue(wrap_in_udp_and_pcap(self.full.pack(), "ch10_uart.pcap"))

        # Test unpack and comparsion
        dummy_ch10 = ch10.Chapter10UDP()
        dummy_ch10.unpack(self.full.pack())
        self.assertTrue(dummy_ch10 == self.full)
        self.assertEqual(repr(udp[0]), "UARTDataWord: PTPSec=0 PTPNSec=250000 ParityError={} DataLen={} "
                                       "SubChannel=52".format(udp[0].parity_error, udp[0].datalength))

    def test_uart_unpack(self):
        p = pcap.Pcap(os.path.join(THIS_DIR, "ch10_uart2.pcap"))
        mypcaprecord = p[0]
        ch10pkt = ch10.Chapter10UDP()
        ch10pkt.unpack(mypcaprecord.payload[0x2a:-4]) # FCS
        self.assertEqual(ch10pkt.chapter10.packetflag, 0xc4)
        uart = ch10.UARTDataPacket()
        uart.unpack(ch10pkt.chapter10.payload)
        self.assertEqual(len(uart), 1)
        (b1,b2) = struct.unpack_from("<BB", uart[0].payload)
        self.assertEqual(b1, 0xd5)
        p.close()
        for idx, uartdw in enumerate(uart):
            for s_idx in range(len(uartdw.payload)):
                pass
                #print("{}:{}:{}".format(idx,s_idx,0))

if __name__ == '__main__':
    unittest.main()
