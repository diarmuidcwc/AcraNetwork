import unittest

__author__ = "diarmuid"
import sys

sys.path.append("..")
import unittest
import AcraNetwork.Pcap as pcap
import AcraNetwork.SimpleEthernet as SimpleEthernet
import AcraNetwork.Chapter10.Chapter10 as ch10
import AcraNetwork.Chapter10.Chapter10UDP as ch10udp
import AcraNetwork.Chapter10.ARINC429 as ch10arinc
import AcraNetwork.Chapter10.UART as ch10uart
import AcraNetwork.Chapter10.TimeDataFormat as ch10time
import AcraNetwork.Chapter10.ARINC429 as ch10arinc
import AcraNetwork.Chapter10.MILSTD1553 as ch10mil
import AcraNetwork.Chapter10.PCM as ch10pcm
import AcraNetwork.Chapter10.Video as ch10video
from AcraNetwork.Chapter10 import (
    DATA_TYPE_TIMEFMT_1,
    DATA_TYPE_TIMEFMT_2,
    DATA_TYPE_PCM_DATA_FMT1,
    TS_CH4,
    TS_IEEE1558,
    RTCTime,
    PTPTime,
)
import struct
import os
import os.path
import random
import copy
import datetime
import tempfile
import logging
import csv
import AcraNetwork.MPEGTS as ampeg

THIS_DIR = os.path.dirname(os.path.abspath(__file__))
TMP_DIR = tempfile.gettempdir()


logging.basicConfig(level=logging.INFO)
logging.info(f"Temp folder={TMP_DIR}")


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
    u.dstport = 6679
    u.srcport = 6679
    u.payload = data
    i.payload = u.pack()
    e.payload = i.pack()
    return e.pack()


def wrap_in_udp_and_pcap(mybuffer, pcapf, mode="w"):
    pcapw = pcap.Pcap(pcapf, mode=mode)

    rec = pcap.PcapRecord()
    rec.payload = getEthernetPacket(mybuffer)
    pcapw.write(rec)
    pcapw.close()
    return True


arinc_packet = """ARINCPayload: MessageCount=11
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
        self.full = ch10udp.Chapter10UDP()
        self.full.type = ch10udp.Chapter10UDP.TYPE_FULL
        self.full.sequence = 1
        self.ch10 = ch10.Chapter10()
        self.ch10.channelID = 1
        self.ch10.datatypeversion = 2
        self.ch10.sequence = 3
        self.ch10.packetflag = 0  # No secondary
        self.ch10.datatype = 4
        self.ch10.relativetimecounter = 100
        self.full.payload = self.ch10.pack()

        self.seg = ch10udp.Chapter10UDP()
        self.seg.sequence = 2
        self.seg.type = ch10udp.Chapter10UDP.TYPE_SEG
        self.seg.channelID = 0x232
        self.seg.channelsequence = 100
        self.seg.segmentoffset = 3
        self.ch10seg = ch10.Chapter10()
        self.ch10seg.channelID = 1
        self.ch10seg.datatypeversion = 2
        self.ch10seg.sequence = 3
        self.ch10seg.packetflag = 0  # No secondary
        self.ch10seg.datatype = 4
        self.ch10seg.relativetimecounter = 100
        self.seg.payload = self.ch10seg.pack()

        self.c = ch10.Chapter10()
        self.c.channelID = 1
        self.c.datatypeversion = 2
        self.c.sequence = 3
        self.c.packetflag = 0  # No secondary
        self.c.datatype = 4
        self.c.relativetimecounter = 100

    def test_ch10_to_pcap(self):
        # self.full._payload = struct.pack(">II", 33, 44)
        full_payload = getEthernetPacket(self.full.pack())
        self.pcapw = pcap.Pcap(TMP_DIR + "/test_ch10.pcap", mode="w")

        self.rec = pcap.PcapRecord()
        self.rec.payload = full_payload
        self.assertIsNone(self.pcapw.write(self.rec))
        # self.seg._payload = struct.pack(">II", 55, 66)
        seg_payload = getEthernetPacket(self.seg.pack())
        self.rec.payload = seg_payload
        self.assertIsNone(self.pcapw.write(self.rec))
        self.pcapw.close()

    def test_ch10_eq(self):
        full = ch10udp.Chapter10UDP()
        full.type = ch10udp.Chapter10UDP.TYPE_FULL
        full.sequence = 1
        full.payload = self.full.payload
        # full._payload = struct.pack(">II", 33, 44)

        # self.full._payload = struct.pack(">II", 33, 44)

        self.assertTrue(full == self.full)

    def test_unpack(self):
        # self.full._payload = struct.pack(">II", 33, 44)
        # self.seg._payload = struct.pack(">II", 33, 44)

        full_unpack = ch10udp.Chapter10UDP()
        self.assertTrue(full_unpack.unpack(self.full.pack()))
        # print(len(self.full.payload))
        # print(len(full_unpack.payload))

        self.assertTrue(full_unpack == self.full)
        self.assertFalse(full_unpack == self.seg)

    def test_ch10_eqseg(self):
        seg = ch10udp.Chapter10UDP()
        seg.type = ch10udp.Chapter10UDP.TYPE_SEG
        seg.sequence = 2
        seg.channelID = 0x232
        seg.channelsequence = 100
        seg.segmentoffset = 3
        seg.payload = self.ch10seg.pack()
        # seg._payload = struct.pack(">II", 33, 44)

        # self.seg._payload = struct.pack(">II", 33, 44)

        self.assertTrue(seg == self.seg)

    def test_ch10pay_to_pcap(self):
        self.c.payload = struct.pack(">II", 33, 44)
        # self.full._payload = self.c.pack()
        full_payload = getEthernetPacket(self.full.pack())
        self.pcapw = pcap.Pcap(TMP_DIR + "/test_ch10_2.pcap", mode="w")

        self.rec = pcap.PcapRecord()
        self.rec.payload = full_payload
        self.assertIsNone(self.pcapw.write(self.rec))
        self.pcapw.close()

    def test_ch10_comp(self):
        ref = ch10.Chapter10()
        # self.c._payload = struct.pack(">II", 33, 44)
        pay = self.c.pack()
        ref.unpack(pay)
        self.assertTrue(ref == self.c)

    def test_ch10_sec_hdr(self):
        c = ch10udp.Chapter10UDP()
        c.type = ch10udp.Chapter10UDP.TYPE_FULL
        c.sequence = 1
        d = ch10.Chapter10()
        d.channelID = 1
        d.datatypeversion = 2
        d.sequence = 3
        d.packetflag = ch10.Chapter10.PKT_FLAG_SECONDARY
        d.datatype = 4
        d.ts_source = ch10.TS_IEEE1558
        d.ptptime = PTPTime(101, int(200e6))
        d.relativetimecounter = 0x0
        d.payload = struct.pack(">QQ", 33, 44)
        full_payload = getEthernetPacket(c.pack())
        self.pcapw = pcap.Pcap(TMP_DIR + "/test_ch10_3.pcap", mode="w")

        self.rec = pcap.PcapRecord()
        self.rec.payload = full_payload
        self.assertIsNone(self.pcapw.write(self.rec))
        self.pcapw.close()

    def test_ch10_format2(self):
        self.pcapw = pcap.Pcap(TMP_DIR + "/test_ch10_format2.pcap", mode="w")

        self.rec = pcap.PcapRecord()
        c = ch10udp.Chapter10UDP()
        c.format = 2
        c.type = ch10udp.Chapter10UDP.TYPE_FULL
        c.sequence = 10
        c.segmentoffset = 5000
        c.channelID = 20
        d = get_ch10(16)
        self.assertTrue(c.pack())

        full_payload = getEthernetPacket(c.pack())
        self.rec.payload = full_payload
        self.assertIsNone(self.pcapw.write(self.rec))
        self.pcapw.close()

        c2 = ch10udp.Chapter10UDP()
        c2.unpack(c.pack())
        self.assertTrue(c2 == c)

    def test_ch10_format3(self):
        pcapw = pcap.Pcap(TMP_DIR + "/test_ch10_format3.pcap", mode="w")

        rec = pcap.PcapRecord()
        for len in range(5):
            c = ch10udp.Chapter10UDP()

            c.format = 3
            c.sourceid_len = len
            if len > 0:
                c.sourceid = 0x4
            c.offset_pkt_start = 4
            c.sequence = 0x15
            c.payload = get_ch10(16).pack()
            self.assertTrue(c.pack())
            print(repr(c))
            c2 = ch10udp.Chapter10UDP()
            c2.unpack(c.pack())
            rec.payload = getEthernetPacket(c.pack())
            pcapw.write(rec)
            rec.payload = getEthernetPacket(c2.pack())
            pcapw.write(rec)
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
        c = ch10udp.Chapter10UDP()
        self.assertTrue(c.unpack(u.payload))
        d = ch10.Chapter10()
        d.unpack(c.payload)

        # Check the Ch10 packets
        self.assertEqual(d.syncpattern, 0xEB25)
        self.assertEqual(d.channelID, 0x000080D6)
        self.assertEqual(d.datatypeversion, 0x44)
        # nanoseconds and seconds
        self.assertEqual(d.ptptime.nanoseconds, 1237463)
        self.assertEqual(d.ptptime.seconds, 0)

        self.assertEqual(repr(c), "CH10 UDP Full Packet: Format=1 Sequence=0")
        arinc_p = ch10arinc.ARINC429DataPacket()
        self.assertTrue(arinc_p.unpack(d.payload))
        self.assertEqual(len(arinc_p.arincwords), 11)
        self.assertEqual(arinc_p.arincwords[0].payload, struct.pack(">I", 0x4BD91E2E))

        arinc2 = ch10arinc.ARINC429DataPacket()
        self.assertTrue(arinc2.unpack(arinc_p.pack()))
        self.assertTrue(arinc_p == arinc2)

        self.assertEqual(repr(arinc2), arinc_packet)
        for idx, aw in enumerate(arinc2):
            if idx == 2:
                self.assertEqual(
                    repr(aw), "ARINCData: GapTime=3900 FormatError=False ParityError=False BusSpeed=0 Bus=23"
                )

    @unittest.skip("No trying to guess format1")
    def test_format1_looks_like_2(self):
        p = pcap.Pcap(os.path.join(THIS_DIR, "ch10_format_1_looks_like2.pcap"))
        for r in p:
            c = ch10udp.Chapter10UDP()
            c.unpack(r.payload[0x2A:])
            self.assertEqual(c.format, 1)
        p.close()


uart_pkt = """UARTPayload: UARTDataWordCount=1
  UARTDataWord: Time=PTP: 14:21:43 20-May 1976 nanosec=10 ParityError=False DataLen=508 SubChannel=8191 Endianness=<Endianness.BIG: 0>
"""


class Ch10UARTTest(unittest.TestCase):
    def setUp(self):
        self.full = ch10udp.Chapter10UDP()
        self.full.type = ch10udp.Chapter10UDP.TYPE_FULL
        self.full.sequence = 10
        self.chfull = ch10.Chapter10()
        self.chfull.channelID = 23
        self.chfull.datatypeversion = 2
        self.chfull.sequence = 3
        self.chfull.packetflag = 0xC4  # Secondary time + PTP
        self.chfull.datatype = 0x50
        self.chfull.relativetimecounter = 100
        self.chfull.ptptime = PTPTime(22, 250000)
        self.full.payload = self.chfull.pack()

    def test_basic_uart(self):
        udp = ch10uart.UARTDataPacket(TS_IEEE1558)
        for i in range(5):
            udw = ch10uart.UARTDataWord()
            udw.ipts.seconds = 22 * i
            udw.ipts.nanoseconds = 250000 + i
            udw.subchannel = 52 + 2 * i
            udw.parity_error = random.choice([True, False])
            udw.payload = os.urandom(random.randint(15, 220))
            # udw.payload = os.urandom(16)

            self.assertIsNone(udp.append(udw))

        self.chfull.payload = udp.pack()
        self.assertTrue(wrap_in_udp_and_pcap(self.full.pack(), "ch10_uart.pcap"))

        # Test unpack and comparsion
        dummy_ch10 = ch10udp.Chapter10UDP()
        dummy_ch10.unpack(self.full.pack())
        self.assertTrue(dummy_ch10 == self.full)
        self.assertEqual(
            repr(udp[0]),
            "UARTDataWord: Time=RTC: count=0 ParityError={} DataLen={} "
            "SubChannel=52 Endianness=<Endianness.BIG: 0>".format(udp[0].parity_error, udp[0].datalength),
        )

    def test_uart_unpack(self):
        p = pcap.Pcap(os.path.join(THIS_DIR, "ch10_uart2.pcap"))
        mypcaprecord = p[0]
        ch10udppkt = ch10udp.Chapter10UDP()
        ch10udppkt.unpack(mypcaprecord.payload[0x2A:-4])  # FCS
        ch10pkt = ch10.Chapter10()
        ch10pkt.unpack(ch10udppkt.payload)
        self.assertEqual(ch10pkt.packetflag, 0xC4)
        uart = ch10uart.UARTDataPacket(TS_IEEE1558)
        uart.unpack(ch10pkt.payload)
        self.assertEqual(len(uart), 1)
        (b1, b2) = struct.unpack_from("<BB", uart[0].payload)
        self.assertEqual(b1, 0xD5)
        p.close()
        for idx, uartdw in enumerate(uart):
            if idx == 0:
                dw2 = copy.copy(uartdw)
                self.assertEqual(dw2, uartdw)
                # print("{}:{}:{}".format(idx,s_idx,0))

        uart2 = copy.copy(uart)
        self.assertEqual(uart, uart2)
        self.assertEqual(repr(uart2), uart_pkt)

    def test_uart_le_unpack(self):
        p = pcap.Pcap(os.path.join(THIS_DIR, "ch10_uart_le.pcap"))
        mypcaprecord = p[0]
        ch10pkt = ch10.Chapter10()
        ch10pkt.unpack(mypcaprecord.payload[0x2E:-4])
        uart = ch10uart.UARTDataPacket(TS_IEEE1558, ch10uart.Endianness.LITTLE)
        uart.unpack(ch10pkt.payload)
        self.assertEqual(len(uart), 3)
        for idx, dw in enumerate(uart):
            if idx == 0:
                self.assertEqual(dw.datalength, 365)
                self.assertEqual(len(dw.payload), 365)
                (last_byte,) = struct.unpack_from(">B", dw.payload, 365 - 1)
                self.assertEqual(last_byte, 0x4B)

    @unittest.skip("")
    def test_fmt2_unpack(self):
        p = pcap.Pcap(os.path.join(THIS_DIR, "ch10_fmt_1.pcap"))
        mypcaprecord = p[0]
        ch10pkt = ch10udp.Chapter10UDP()
        ch10pkt.unpack(mypcaprecord.payload[0x2A:-4])  # FCS
        self.assertEqual(ch10pkt.format, 1)
        # print(repr(ch10pkt.chapter10))


class Time_Test(unittest.TestCase):
    def test_playground(self):
        ms = 989
        self.assertEqual(0x98, ch10time.double_digits_to_bcd(ms / 10))
        self.assertEqual(0x98, ch10time.double_digits_to_bcd(ms / 10))

        # 05/20/19 16:41:24'
        current_time = datetime.datetime.fromtimestamp(1558366884)
        self.assertEqual(0x41, ch10time.double_digits_to_bcd(current_time.minute))
        self.assertEqual(0x24, ch10time.double_digits_to_bcd(current_time.second))
        # self.assertEqual(0x16, ch10.double_digits_to_bcd(current_time.hour))

        self.assertEqual(99, ch10time.bcd_to_int(0x99))
        self.assertEqual(9999, ch10time.bcd_to_int(0x9999))

    def test_time_pkt(self):
        t = ch10time.TimeDataFormat1()
        t.ptptime = PTPTime(1558366884, 980000000)
        # t.milliseconds = 980
        # t.datetime = datetime.datetime.fromtimestamp(1558366884)

        # print(repr(t))
        t2 = ch10time.TimeDataFormat1()
        t2.unpack(t.pack())
        self.assertTrue(t == t2)
        # print(repr(t))
        # print(repr(t2))

    def test_time_pkt_2(self):
        t = ch10time.TimeDataFormat2()
        t.ptptime = PTPTime(1558366884, 999999999)
        # t.nanoseconds = 999999999
        # t.datetime = datetime.datetime.fromtimestamp(1558366884)

        t2 = ch10time.TimeDataFormat2()
        t2.unpack(t.pack())
        self.assertTrue(t2 == t)
        # print(repr(t))
        # self.assertEqual("TimeFormat2 ChannelSpecificWord=0X11 Time=16:41:24 05/20/19 20-May 2019 NanoSeconds=999999999", repr(t))
        # print(repr(t2))

    def test_time_pkt_1_decom(self):
        t = ch10time.TimeDataFormat1()
        # 0000   11 00 00 00 99 09 13 14 06 02
        # Tue, 25 Jul 2023 14:13:09 GMT
        t.unpack(struct.pack(">HHHHH", 0x1100, 0x0, 0x9909, 0x1314, 0x0602))
        _t = repr(t)
        ref_t = PTPTime(17763189, 990_000_000)
        self.assertEqual(t.ptptime, ref_t)
        # self.assertEqual(t.nanoseconds, 990_000_000)
        self.assertEqual(
            "TimeFormat1 ChannelSpecificWord=0X11 Time=PTP: 14:13:09 25-Jul 1970 nanosec=990000000", repr(t)
        )

    def test_time_to_pcap(self):
        pcapw = pcap.Pcap(TMP_DIR + "/test_ch10_time.pcap", mode="w")

        rec = pcap.PcapRecord()
        cu = ch10udp.Chapter10UDP()
        cu.type = ch10udp.Chapter10UDP.TYPE_FULL
        cu.sequence = 1
        c = get_ch10()
        types = [DATA_TYPE_TIMEFMT_1, DATA_TYPE_TIMEFMT_2]
        t1 = ch10time.TimeDataFormat1()
        t2 = ch10time.TimeDataFormat2()
        for i, t in enumerate([t1, t2]):
            t.ptptime = PTPTime(1558366884, 980_000_000)
            c.payload = t.pack()
            c.datatype = types[i]
            full_payload = getEthernetPacket(cu.pack())
            rec.payload = full_payload
            self.assertIsNone(pcapw.write(rec))
        pcapw.close()

    @unittest.skip("")
    def test_ch10_fmt_pcap(self):
        p = pcap.Pcap(os.path.join(THIS_DIR, "ch10_pkt.pcap"))
        mypcaprecord = p.next()
        c = ch10udp.Chapter10UDP()
        c.unpack(mypcaprecord.payload[0x2A:])
        t = ch10time.TimeDataFormat1()
        t.unpack(c.chapter10.payload)
        # print(t.datetime.strftime("%c"))
        mypcaprecord = p.next()
        c = ch10udp.Chapter10UDP()
        c.unpack(mypcaprecord.payload[0x2A:])
        t = ch10time.TimeDataFormat2()
        t.unpack(c.chapter10.payload)
        # print(t.datetime.strftime("%c"))
        self.assertEqual(t.datetime, datetime.datetime.fromtimestamp(1561535306))


class GenPCAP(unittest.TestCase):
    def test_ch10_fmt1(self):
        pcapw = pcap.Pcap(TMP_DIR + "/test_ch10_sample.pcap", mode="w")

        rec = pcap.PcapRecord()
        for fmt in [1, 2, 3]:
            c = get_ch10(16)
            c.ptptime = PTPTime(333344, 42322)
            c.packetflag = (
                ch10.Chapter10.PKT_FLAG_SECONDARY
                + ch10.Chapter10.PKT_FLAG_SEC_HDR_TIME
                + ch10.Chapter10.PKT_FLAG_1588_TIME
            )
            cu = ch10udp.Chapter10UDP()
            cu.type = ch10udp.Chapter10UDP.TYPE_FULL
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
        m = ch10mil.MILSTD1553DataPacket(TS_IEEE1558)
        msg = ch10mil.MILSTD1553Message()
        msg.message = struct.pack(">II", 1, 2)
        msg.ipts = PTPTime(100, 200)
        m.append(msg)
        m2 = ch10mil.MILSTD1553DataPacket(TS_IEEE1558)
        m2.unpack(m.pack())
        self.assertEqual(m2, m)


class PCMData(unittest.TestCase):
    def test_pcm(self):
        payload_len = 100
        sync_word = 0xFE6B_2842
        pcapw = pcap.Pcap(TMP_DIR + "/test_ch10_pcm.pcap", mode="w")
        rec = pcap.PcapRecord()
        u = ch10udp.Chapter10UDP()
        c = ch10.Chapter10()
        u.type = ch10udp.Chapter10UDP.TYPE_FULL
        u.sequence = 0
        c = get_ch10()
        c.datatype = 0x9
        pcmdf = ch10pcm.PCMDataPacket()
        pcmdf.channel_specific_word = 0x7F080000
        for mfcount in range(1, 4):
            mf = ch10pcm.PCMMinorFrame()
            mf.intra_packet_data_header = mfcount
            mf.ipts.count = 2 * mfcount
            mf.minor_frame_data = struct.pack(">I", sync_word) + os.urandom(payload_len - 4)
            pcmdf.minor_frames.append(mf)
        packed_data = pcmdf.pack()
        c.payload = packed_data
        u.payload = c.pack()
        rec.set_current_time()
        rec.payload = getEthernetPacket(u.pack())
        pcapw.write(rec)
        pcapw.close()

        pcmdf2 = ch10pcm.PCMDataPacket(syncword=sync_word)
        # pcmdf2.minor_frame_size_bytes = payload_len
        pcmdf2.unpack(packed_data)
        self.assertEqual(pcmdf, pcmdf2)
        pcmdf3 = ch10pcm.PCMDataPacket(syncword=None)
        self.assertTrue(pcmdf3.unpack(packed_data))
        print(pcmdf3)

    def test_pcm_throughput(self):
        pcmdf = ch10pcm.PCMDataPacket()
        pcmdf.channel_specific_word = 0x100000  #
        mf = ch10pcm.PCMMinorFrame(throughput=True)
        mf.minor_frame_data = struct.pack("<HH", 0xFE6B, 0x2840)
        pcmdf.minor_frames.append(mf)
        packed = pcmdf.pack()
        pcmdf2 = ch10pcm.PCMDataPacket()
        pcmdf2.unpack(packed)
        self.assertEqual(pcmdf, pcmdf2)
        self.assertEqual(
            repr(pcmdf2),
            "PCM Data Packet Format 1. Channel Specific Word =0X100000\nMinor Frame Throughput mode Time=None Payload_len=4\n",
        )

    def test_pcm_endianness(self):
        mf = ch10pcm.PCMMinorFrame(throughput=True)
        mf.minor_frame_data = struct.pack("<I", 0xFE6B2840) + struct.pack(">I", 0xFE6B2840)
        f = open("mf.hex", mode="wb")
        f.write(mf.pack())
        f.close()


class MnACQData(unittest.TestCase):
    def test_pcap(self):
        p = pcap.Pcap(os.path.join(THIS_DIR, "mnacq2.pcap"))
        ch10_payload = b""
        cf = open("{}/mnacq.csv".format(THIS_DIR), mode="w", newline="")
        csvf = csv.writer(cf)

        for pkt_count, rec in enumerate(p):
            wrapper = ch10udp.Chapter10UDP()
            pkt = ch10.Chapter10()
            wrapper.unpack(rec.payload[0x2A:])

            if wrapper.type == ch10udp.Chapter10UDP.TYPE_SEG and wrapper.segmentoffset == 0 and ch10_payload != b"":
                # segmented packet with existing payload
                self.assertTrue(pkt.unpack(ch10_payload))
                print(repr(pkt))
                ch10_payload = b""
                self.assertEqual(pkt.datatype, DATA_TYPE_PCM_DATA_FMT1)
                pcm = ch10pcm.PCMDataPacket()
                pcm.minor_frame_size_bytes = 64
                try:
                    s = pcm.unpack(pkt.payload, extract_sync_sfid=False)
                except Exception as e:
                    print("At packet count {}. failed to unpack pcmd data. Err={}".format(pkt_count + 1, e))
                    self.assertTrue(False)
                else:
                    self.assertTrue(s)
                first_minor_frame = pcm.minor_frames[0]
                if pkt_count == 62:
                    self.assertEqual(68676670524492, first_minor_frame.ipts.count)
                for mf in pcm.minor_frames:
                    num_words = int(len(mf.minor_frame_data) / 2)
                    dw = struct.unpack(f"<{num_words}H", mf.minor_frame_data)
                    csvf.writerow(list(dw))

            if wrapper.type == ch10udp.Chapter10UDP.TYPE_SEG:
                ch10_payload += wrapper.payload
            else:
                pkt.unpack(wrapper.payload)
                print(repr(pkt))

        cf.close()
        p.close()


class CH10SampleFile(unittest.TestCase):
    @unittest.skip("sample file too big at the moment")
    def test_dotch10(self):
        fileparser = ch10.FileParser(THIS_DIR + "/ch10.ch10")
        total_len = 0
        with fileparser as chf:
            for pkt in chf:
                print(repr(pkt))
                total_len += pkt.packetlen
                # self.assertTrue(False)
        print(f"{total_len:,d}")

    @unittest.skip("Not a test")
    def test_read_ch10(self):
        fileparser = ch10.FileParser("C://ACRA//WORK//AcraNetwork_git//examples//ch10//out.ch10")
        total_len = 0
        with fileparser as chf:
            for pkt in chf:
                pkt_repr = repr(pkt)
                total_len += pkt.packetlen
                # self.assertTrue(False)
        print(f"{total_len:,d}")

    @unittest.skip("Not a test")
    def test_extract_tmats(self):
        fileparser = ch10.FileParser("C://ACRA//WORK//AcraNetwork_git//examples//ch10//Kulite Recording.ch10")
        tmats_f = open("C://ACRA//WORK//AcraNetwork_git//examples//ch10//Kulite.tmats", mode="wb")
        with fileparser as chf:
            for idx, pkt in enumerate(chf):
                if idx == 0:
                    tmats_f.write(pkt.payload[4:])
                    break


class PTPRTCTime(unittest.TestCase):
    def test_ptptime(self):
        t0 = PTPTime(0, 0)
        t0b = PTPTime(0, 0)
        t1 = PTPTime(2, 1)
        t2 = PTPTime(1, 999_999_999)
        t2b = PTPTime(1, 999_999_999)
        dlt = PTPTime(0, 22)
        t3 = PTPTime(1, 0)

        self.assertTrue(t0 == t0b)
        self.assertTrue(t1 > t0)
        self.assertTrue(t2 < t1)
        self.assertTrue(t0 >= t0)
        self.assertTrue(t0 <= t0)
        self.assertEqual(t1 + t2, PTPTime(4, 0))
        self.assertEqual(t1 - t2, PTPTime(0, 2))
        self.assertEqual(t2 + t2, PTPTime(3, 999_999_998))
        self.assertEqual(t2 - t2b, PTPTime(0, 0))
        self.assertFalse(dlt >= t3)

    def test_ptptime_conversion(self):
        F8BITS = pow(2, 48) - 1
        t0 = PTPTime(0, 0)
        self.assertEqual(t0.to_pinksheet_rtc(), 0)
        self.assertEqual(t0.to_rtc(), 0)
        t1 = PTPTime(4096, 1)

        time_vector = struct.pack(">II", 4096, 1)
        (sec, nsec) = struct.unpack(">II", time_vector)
        trunc = int((sec * 1e9 + nsec) // 100) & F8BITS
        self.assertEqual(t1.to_pinksheet_rtc(), trunc)

    def test_accuracy_conversion(self):
        t0 = PTPTime(1704299074, 472711723)
        rtc_time = int(1.54492142087757e14)
        self.assertEqual(rtc_time, t0.to_pinksheet_rtc())


class Video(unittest.TestCase):
    def test_video(self):
        vid = ch10video.VideoFormat2()
        vid.channel_specific_word = 0x0
        mpgsts = ampeg.MPEGTS()
        for _i in range(1):
            mpegp = ampeg.MPEGPacket()
            mpegp.sync = 0x47
            mpegp.adaption_ctrl = ampeg.ADAPTION_PAYLOAD_ONLY
            mpegp.pid = _i
            mpegp.payload = struct.pack(f"{92}H", *range(92))
            mpgsts.append(mpegp)
        vid.mpegts = mpgsts
        buf = vid.pack()
        print(repr(buf))
        vid2 = ch10video.VideoFormat2()
        vid2.unpack(buf)
        self.assertEqual(vid, vid2)


if __name__ == "__main__":
    unittest.main()
