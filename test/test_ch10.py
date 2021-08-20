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
import copy
import datetime


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

arinc_packet="""ARINCPayload: MessageCount=11
  ARINCData: GapTime=0 FormatError=False ParityError=False BusSpeed=0 Bus=23
  ARINCData: GapTime=4000 FormatError=False ParityError=False BusSpeed=0 Bus=23
  ARINCData: GapTime=3900 FormatError=False ParityError=False BusSpeed=0 Bus=23
  ARINCData: GapTime=3600 FormatError=False ParityError=False BusSpeed=0 Bus=23
  ARINCData: GapTime=4100 FormatError=False ParityError=False BusSpeed=0 Bus=23
  ARINCData: GapTime=4000 FormatError=False ParityError=False BusSpeed=0 Bus=23
  ARINCData: GapTime=3700 FormatError=False ParityError=False BusSpeed=0 Bus=23
  ARINCData: GapTime=3600 FormatError=False ParityError=False BusSpeed=0 Bus=23
  ARINCData: GapTime=4000 FormatError=False ParityError=False BusSpeed=0 Bus=23
  ARINCData: GapTime=3600 FormatError=False ParityError=False BusSpeed=0 Bus=23
  ARINCData: GapTime=3900 FormatError=False ParityError=False BusSpeed=0 Bus=23
"""



def get_ch10(len=4):
    c = ch10.Chapter10()
    c.channelID = 1
    c.datatypeversion = 2
    c.sequence = 3
    c.packetflag = 0  # No secondary
    c.datatype = 4
    c.relativetimecounter = 100
    c.payload = os.urandom(len)
    return c


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
        #print(len(self.full.payload))
        #print(len(full_unpack.payload))

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

    def test_ch10_format2(self):
        self.pcapw = pcap.Pcap("test_ch10_format2.pcap", mode="w")
        self.pcapw.write_global_header()
        self.rec = pcap.PcapRecord()
        c = ch10.Chapter10UDP()
        c.format = 2
        c.type = ch10.Chapter10UDP.TYPE_FULL
        c.sequence = 10
        c.segmentoffset = 5000
        c.channelID = 20
        c.chapter10 = get_ch10(16)
        self.assertTrue(c.pack())

        full_payload = getEthernetPacket(c.pack())
        self.rec.payload = full_payload
        self.assertIsNone(self.pcapw.write(self.rec))
        self.pcapw.close()

        c2 = ch10.Chapter10UDP()
        c2.unpack(c.pack())
        self.assertTrue(c2==c)


    def test_ch10_format3(self):
        pcapw = pcap.Pcap("test_ch10_format3.pcap", mode="w")
        pcapw.write_global_header()
        rec = pcap.PcapRecord()
        for len in range(5):
            c = ch10.Chapter10UDP()

            c.format = 3
            c.sourceid_len = len
            if len > 0:
                c.sourceid = 0x4
            c.offset_pkt_start = 4
            c.sequence = 0x15
            c.chapter10 = get_ch10(16)
            self.assertTrue(c.pack())
            c2 = ch10.Chapter10UDP()
            c2.unpack(c.pack())
            self.assertTrue(c2 == c)
            for packet in [c, c2]:
                full_payload = getEthernetPacket(packet.pack())
                rec.payload = full_payload
                self.assertIsNone(pcapw.write(rec))
        pcapw.close()

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

        self.assertEqual(repr(c), "CH10 UDP Full Packet: Format=1 Sequence=0 Payload=Chapter 10: ChannelID=32982 Sequence=0 DataLen=88")
        arinc_p = ch10.ARINC429DataPacket()
        self.assertTrue(arinc_p.unpack(c.chapter10.payload))
        self.assertEqual(len(arinc_p.arincwords), 11)
        self.assertEqual(arinc_p.arincwords[0].payload, struct.pack(">I", 0x4bd91e2e))

        arinc2 = ch10.ARINC429DataPacket()
        self.assertTrue(arinc2.unpack(arinc_p.pack()))
        self.assertTrue(arinc_p == arinc2)

        self.assertEqual(repr(arinc2), arinc_packet)
        for idx, aw in enumerate(arinc2):
            if idx == 2:
                self.assertEqual(repr(aw), "ARINCData: GapTime=3900 FormatError=False ParityError=False BusSpeed=0 Bus=23")

    def test_format1_looks_like_2(self):
        p = pcap.Pcap(os.path.join(THIS_DIR, "ch10_format_1_looks_like2.pcap"))
        for r in p:
            c = ch10.Chapter10UDP()
            c.unpack(r.payload[0x2a:])
            self.assertEqual(c.format, 1)
        p.close()


uart_pkt="""UARTPayload: UARTDataWordCount=1
  UARTDataWord: PTPSec=201450103 PTPNSec=10 ParityError=False DataLen=508 SubChannel=8191
"""
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
            if idx == 0:
                dw2 = copy.copy(uartdw)
                self.assertEqual(dw2, uartdw)
                #print("{}:{}:{}".format(idx,s_idx,0))

        uart2 = copy.copy(uart)
        self.assertEqual(uart, uart2)
        self.assertEqual(repr(uart2),uart_pkt)

    @unittest.skip("")
    def test_fmt2_unpack(self):
        p = pcap.Pcap(os.path.join(THIS_DIR, "ch10_fmt_1.pcap"))
        mypcaprecord = p[0]
        ch10pkt = ch10.Chapter10UDP()
        ch10pkt.unpack(mypcaprecord.payload[0x2a:-4])  # FCS
        self.assertEqual(ch10pkt.format, 1)
        #print(repr(ch10pkt.chapter10))


class Time_Test(unittest.TestCase):


    def test_playground(self):
        ms = 989
        self.assertEqual(0x98, ch10.double_digits_to_bcd(ms/10))
        self.assertEqual(0x98, ch10.double_digits_to_bcd(ms/10))

        #05/20/19 16:41:24'
        current_time = datetime.datetime.fromtimestamp(1558366884)
        self.assertEqual(0x41, ch10.double_digits_to_bcd(current_time.minute))
        self.assertEqual(0x24, ch10.double_digits_to_bcd(current_time.second))
        #self.assertEqual(0x16, ch10.double_digits_to_bcd(current_time.hour))

        self.assertEqual(99, ch10.bcd_to_int(0x99))
        self.assertEqual(9999, ch10.bcd_to_int(0x9999))

    def test_time_pkt(self):
        t = ch10.TimeDataFormat1()
        t.milliseconds = 980
        t.datetime = datetime.datetime.fromtimestamp(1558366884)

        #print(repr(t))
        t2 = ch10.TimeDataFormat1()
        t2.unpack(t.pack())
        self.assertTrue(t == t2)
        #print(repr(t))
        #print(repr(t2))

    def test_time_pkt_2(self):
        t = ch10.TimeDataFormat2()
        t.nanoseconds = 999999999
        t.datetime = datetime.datetime.fromtimestamp(1558366884)

        t2 = ch10.TimeDataFormat2()
        t2.unpack(t.pack())
        self.assertTrue(t2 == t)
        #print(repr(t))
        #self.assertEqual("TimeFormat2 ChannelSpecificWord=0X11 Time=16:41:24 05/20/19 20-May 2019 NanoSeconds=999999999", repr(t))
        #print(repr(t2))

    def test_time_to_pcap(self):
        pcapw = pcap.Pcap("test_ch10_time.pcap", mode="w")
        pcapw.write_global_header()
        rec = pcap.PcapRecord()
        cu = ch10.Chapter10UDP()
        cu.type = ch10.Chapter10UDP.TYPE_FULL
        cu.sequence = 1
        c = get_ch10()
        types = [ch10.DATA_TYPE_TIMEFMT_1, ch10.DATA_TYPE_TIMEFMT_2]
        t1 = ch10.TimeDataFormat1()
        t2 = ch10.TimeDataFormat2()
        for i,t in enumerate([t1, t2]):
            t.milliseconds = 980
            t.datetime = datetime.datetime.fromtimestamp(1558366884)
            c.payload = t.pack()
            c.datatype = types[i]
            cu.chapter10 = c
            full_payload = getEthernetPacket(cu.pack())
            rec.payload = full_payload
            self.assertIsNone(pcapw.write(rec))
        pcapw.close()

    @unittest.skip("")
    def test_ch10_fmt_pcap(self):
        p = pcap.Pcap(os.path.join(THIS_DIR, "ch10_pkt.pcap"))
        mypcaprecord = p.next()
        c = ch10.Chapter10UDP()
        c.unpack(mypcaprecord.payload[0x2a:])
        t = ch10.TimeDataFormat1()
        t.unpack(c.chapter10.payload)
        #print(t.datetime.strftime("%c"))
        mypcaprecord = p.next()
        c = ch10.Chapter10UDP()
        c.unpack(mypcaprecord.payload[0x2a:])
        t = ch10.TimeDataFormat2()
        t.unpack(c.chapter10.payload)
        #print(t.datetime.strftime("%c"))
        self.assertEqual(t.datetime, datetime.datetime.fromtimestamp(1561535306))



class GenPCAP(unittest.TestCase):

    def test_ch10_fmt1(self):
        pcapw = pcap.Pcap("test_ch10_sample.pcap", mode="w")
        pcapw.write_global_header()
        rec = pcap.PcapRecord()
        for fmt in [1, 2, 3]:
            c = get_ch10(16)
            c.ptptimeseconds = 333344
            c.ptptimenanoseconds = 42322
            c.packetflag = ch10.Chapter10.PKT_FLAG_SECONDARY + ch10.Chapter10.PKT_FLAG_SEC_HDR_TIME + ch10.Chapter10.PKT_FLAG_1588_TIME
            cu = ch10.Chapter10UDP()
            cu.type = ch10.Chapter10UDP.TYPE_FULL
            cu.sequence = 1
            cu.chapter10 = c
            # format 2
            cu.segmentoffset = 0x0
            cu.channelID = c.channelID
            # Format 3
            cu.sourceid_len = 0x1
            cu.sourceid = 0x2
            cu.sequence = 0x3
            cu.offset_pkt_start = 0x0

            cu.format = fmt

            # Write it out

            full_payload = getEthernetPacket(cu.pack())
            rec.payload = full_payload
            self.assertIsNone(pcapw.write(rec))
        pcapw.close()


class Ch10Mil(unittest.TestCase):

    def test_mil(self):

        m = ch10.MILSTD1553DataPacket()
        msg = ch10.MILSTD1553Message()
        msg.message = struct.pack(">II", 1,2)
        msg.ptptimeseconds = 100
        msg.ptptimenanoseconds = 200
        m.append(msg)
        m2 = ch10.MILSTD1553DataPacket()
        m2.unpack(m.pack())
        self.assertEqual(m2, m)


class PCMData(unittest.TestCase):

    def test_pcm(self):
        payload_len = 10
        pcapw = pcap.Pcap("test_ch10_pcm.pcap", mode="w")
        rec = pcap.PcapRecord()
        u = ch10.Chapter10UDP()
        u.type = ch10.Chapter10UDP.TYPE_FULL
        u.sequence = 0
        u.chapter10 = get_ch10()
        u.chapter10.datatype = 0x9
        pcmdf = ch10.PCMDataPacket()
        pcmdf.channel_specific_word = 0x1234
        for mfcount in range(1, 4):
            mf = ch10.PCMMinorFrame()
            mf.intra_packet_data_header = mfcount
            mf.intra_packet_sec = 2 * mfcount
            mf.intra_packet_nsec = 4 * mfcount
            mf.minor_frame_data = os.urandom(payload_len)
            pcmdf.minor_frames.append(mf)
        packed_data = pcmdf.pack()
        u.chapter10.payload = packed_data
        rec.set_current_time()
        rec.payload = getEthernetPacket(u.pack())
        pcapw.write(rec)
        pcapw.close()

        pcmdf2 = ch10.PCMDataPacket()
        pcmdf2.minor_frame_size_bytes = payload_len
        pcmdf2.unpack(packed_data)
        self.assertEqual(pcmdf, pcmdf2)

if __name__ == '__main__':
    unittest.main()
