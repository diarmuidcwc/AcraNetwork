__author__ = "DCollins"

import sys

# sys.path.append("../AcraNetwork")
import os

import unittest
import AcraNetwork.Pcap as pcap
import AcraNetwork.SimpleEthernet as SimpleEthernet
import AcraNetwork.iNetX as inetx
import AcraNetwork.MPEGTS as MPEGTS
import base64
import AcraNetwork.MPEG.PMT as MPEGPMT
import AcraNetwork.MPEG.PES as pes
import struct
import datetime
import logging
import random

THIS_DIR = os.path.dirname(os.path.abspath(__file__))


mpeg_ts_repr = """PID=0X0 PUSI=True TSC=Not Scrambled Adaption=Payload Only
PID=0X1000 PUSI=True TSC=Not Scrambled Adaption=Payload Only
PID=0X100 PUSI=True TSC=Not Scrambled Adaption=Adaption and Payload
 Adaption=Discontunity=False, random=True Elementary Stream Indicator=False PCR=True OPCR=False Splicing Point Flag=False Transport Private Data=False, Adaption Extension=False
PID=0X100 PUSI=False TSC=Not Scrambled Adaption=Payload Only
PID=0X100 PUSI=False TSC=Not Scrambled Adaption=Payload Only
PID=0X100 PUSI=False TSC=Not Scrambled Adaption=Payload Only
PID=0X100 PUSI=False TSC=Not Scrambled Adaption=Payload Only
"""


class MPEGTSBasicTest(unittest.TestCase):

    ######################
    # Read a complete pcap file
    ######################

    def test_readFirstMPEGTS(self):
        """
        Very simple test that reads a pcap file with mpegts packets.
        Takes the first packet in there and decoms the mpegts blocks
        Verifies each block in that first packet
        """
        p = pcap.Pcap(os.path.join(THIS_DIR, "mpegts_input.pcap"))
        mypcaprecord = p[0]

        ethpacket = SimpleEthernet.Ethernet()  # Create an Ethernet object
        ethpacket.unpack(mypcaprecord.packet)  # Unpack the pcap record into the eth object
        ippacket = SimpleEthernet.IP()  # Create an IP packet
        ippacket.unpack(ethpacket.payload)  # Unpack the ethernet _payload into the IP packet
        udppacket = SimpleEthernet.UDP()  # Create a UDP packet
        udppacket.unpack(ippacket.payload)  # Unpack the IP _payload into the UDP packet
        inetxpacket = inetx.iNetX()  # Create an iNetx object
        inetxpacket.unpack(udppacket.payload)  # Unpack the UDP _payload into this iNetX object

        mpegts = MPEGTS.MPEGTS()
        mpegts.unpack(inetxpacket.payload)
        self.assertEqual(len(mpegts), 7)
        for packet_index in list(range(7)):
            if packet_index == 0:
                self.assertEqual(mpegts.blocks[packet_index].pid, 0)
                self.assertEqual(mpegts.blocks[packet_index].sync, 0x47)
            elif packet_index == 1:
                self.assertEqual(mpegts.blocks[packet_index].pid, 4096)
                self.assertEqual(mpegts.blocks[packet_index].sync, 0x47)
            else:
                self.assertEqual(mpegts.blocks[packet_index].pid, 256)
                self.assertEqual(mpegts.blocks[packet_index].sync, 0x47)
        p.close()

    def test_pack_unpack_adaption(self):
        ad = MPEGTS.MPEGAdaption()
        adex = MPEGTS.MPEGAdaptionExtension()
        ad.adaption_extension = adex
        packed = ad.pack()
        ad2 = MPEGTS.MPEGAdaption()
        ad2.unpack(packed)
        self.assertEqual(ad2, ad)

    def test_pack_unpack(self):
        """
        Very simple test that reads a pcap file with mpegts packets.
        Takes the first packet in there and decoms the mpegts blocks
        Verifies each block in that first packet
        """
        p = pcap.Pcap(os.path.join(THIS_DIR, "mpegts_input.pcap"))
        mypcaprecord = p[0]
        self.maxDiff = None
        mpegts = MPEGTS.MPEGTS()
        payload = mypcaprecord.payload[0x46:]
        mpegts.unpack(payload)
        self.assertEqual(mpeg_ts_repr, repr(mpegts))
        self.assertEqual(len(mpegts), 7)
        p.close()
        for block in mpegts:
            if block.adaption_field is not None:
                pass
        packed = mpegts.pack()
        self.assertEqual(packed, payload)

        mpegts2 = MPEGTS.MPEGTS()
        mpegts2.unpack(packed)
        self.assertEqual(mpegts, mpegts2)

    def test_readAllMPEGTS(self):
        """
        Reads the same mpeg ts file as previously but reads all the data
        in the file and checks for any continuity errors
        :return:
        """
        p = pcap.Pcap(os.path.join(THIS_DIR, "mpegts_input.pcap"))
        for mypcaprecord in p:

            ethpacket = SimpleEthernet.Ethernet()  # Create an Ethernet object
            ethpacket.unpack(mypcaprecord.packet)  # Unpack the pcap record into the eth object
            ippacket = SimpleEthernet.IP()  # Create an IP packet
            ippacket.unpack(ethpacket.payload)  # Unpack the ethernet _payload into the IP packet
            udppacket = SimpleEthernet.UDP()  # Create a UDP packet
            udppacket.unpack(ippacket.payload)  # Unpack the IP _payload into the UDP packet
            inetxpacket = inetx.iNetX()  # Create an iNetx object
            inetxpacket.unpack(udppacket.payload)  # Unpack the UDP _payload into this iNetX object
            mpegts = MPEGTS.MPEGTS()
            mpegts.unpack(inetxpacket.payload)
            self.assertEqual(len(mpegts), 7)

        p.close()

    @unittest.skip("Broken")
    def test_stanag(self):
        ts_file = open(os.path.join(THIS_DIR, "stanag_sample.ts"), mode="rb")
        h264_data = MPEGTS.H264()
        self.assertTrue(h264_data.unpack(ts_file.read()))
        ts_file.close()
        self.assertEqual(len(h264_data.nals), 258)
        nal_counts = {}
        for nal in h264_data.nals:
            if not nal.type in nal_counts:
                nal_counts[nal.type] = 1
            else:
                nal_counts[nal.type] += 1
        self.assertEqual(nal_counts[0], 35)
        self.assertEqual(nal_counts[6], 70)

    @unittest.skip("Missing input ts")
    def test_capture(self):
        ts_f = open(os.path.join(THIS_DIR, "capture_0XDC1.ts"), mode="rb")
        pids = {}
        PMT_PID = 256
        while True:
            ts_block = ts_f.read(188)
            if not ts_block:
                break
            mpeg_pkt = MPEGTS.MPEGPacket()
            try:
                mpeg_pkt.unpack(ts_block)
            except Exception as e:
                logging.error(e)
                # self.assertTrue(False)
            else:
                if mpeg_pkt.pid not in pids:
                    pids[mpeg_pkt.pid] = 0
                pids[mpeg_pkt.pid] += 1

                if mpeg_pkt.pid == PMT_PID:
                    pmt_pkt = MPEGPMT.MPEGPacketPMT()
                    try:
                        pmt_pkt.unpack(ts_block)
                    except Exception as e:
                        logging.error(f"Failed to unpack offset {ts_f.tell():#0X} as PMT")
                        sys.exit(1)
                    else:
                        # print(f"PMT={repr(pmt_pkt)}")
                        pass

        ts_f.close()
        for pid, count in sorted(pids.items()):
            logging.info(f"PID={pid:#0X} Count={count}")


# Take from Wireshar - > cop
pmt_payload = base64.b64decode(
    "R0EAGQACsDgAAcEAAOEB8AAb4QLwAAPhA/AAFeEE8BwFBEtMVkEmCQEA/0tMVkEADycJwQAAwIAAwQAAX+WEI/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////8="
)

# Two descriptor tags + twp streams
pmt2_payload = base64.b64decode(
    "R0EAEQACsCMAAcEAAPAA8AwFBEhETVaIBA///Pwb8QDwAA/xEPAAn17xO/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////8="
)


class MPEGPMTTest(unittest.TestCase):
    def test_pmt_unpack(self):
        pmt = MPEGPMT.MPEGPacketPMT()
        pmt.unpack(pmt_payload)

        pmt2 = MPEGPMT.MPEGPacketPMT()
        pmt2.unpack(pmt.pack())
        self.assertEqual(pmt, pmt2)
        self.assertEqual(pmt_payload, pmt2.pack())

    def test_pmt2_unpack(self):
        pmt = MPEGPMT.MPEGPacketPMT()
        pmt.unpack(pmt2_payload)

    def test_pmt_random(self):
        pmt = MPEGPMT.MPEGPacketPMT()
        pmt.sync = 0x47
        pmt.adaption_ctrl = MPEGTS.ADAPTION_PAYLOAD_ONLY
        pmt.pid = 0x100
        pmt.continuitycounter = 7
        pmt.last_section = 0xE
        pmt.section = 0xD
        pmt.program_number = 0xDEAD
        t = MPEGPMT.DescriptorTag()
        t.data = struct.pack(">5H", *(list(range(5))))
        t.tag = 0xA
        s = MPEGPMT.PMTStream()
        pmt.descriptor_tags = [t]
        s.elementary_pid = 0x1FEF
        pmt.streams = [s]
        _packed = pmt.pack()

        pmt2 = MPEGPMT.MPEGPacketPMT()
        self.assertTrue(pmt2.unpack(_packed))
        self.assertEqual(pmt, pmt2)


pes_packet = base64.b64decode(
    "R0EEP4UA////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////AAAB/AAsgYAFIQQD/tEAD98AHwYOKzQCCwEBDgEDAQEAAAAOAggABg/Gi5FmYwECH1M="
)
stanag_packet = base64.b64decode(
    "R0EEMYUA////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////AAAB/AAsgYAFAQQF2TcAAd8AHwYOKzQCCwEBDgEDAQEAAAAOAggABhTIE/mO6QECDwg="
)


class MPEG_PES(unittest.TestCase):
    def test_pes_unpack(self):
        self.assertEqual(188, len(pes_packet))  # Verify the length
        p = pes.PES()
        p.unpack(pes_packet)  # unpack as PES
        self.assertEqual(50, len(p.payload))
        # print(repr(p))

        self.assertEqual(36, len(p.pesdata))  # Verify the pes payload
        self.assertEqual(pes_packet, p.pack())  # Verify that pack turns it back exactly into the same packet
        p2 = pes.PES()
        p2.unpack(p.pack())  # Unpack it again
        self.assertEqual(p, p2)  # Compre packets
        self.assertEqual(p2.pack(), pes_packet)  # Verify packing

    def test_stanag_unpack(self):
        p = pes.STANAG4609()
        p.unpack(pes_packet)
        # print(repr(p))
        self.assertEqual(36, len(p.pesdata))
        self.assertEqual(len(p.pack()), 188)
        self.assertEqual(p.pack(), pes_packet)
        # print(repr(p.time))

    def test_stanag2_unpack(self):
        p = pes.STANAG4609()
        p.unpack(stanag_packet)
        # print(repr(p))
        self.assertEqual(36, len(p.pesdata))
        self.assertEqual(len(p.pack()), 188)
        self.assertEqual(p.pack(), stanag_packet)
        # print(repr(p.time))

    def test_stanag_create(self):
        ref = pes.STANAG4609()
        ref.unpack(pes_packet)
        # Build a packet from scratch that matches the refernce packet
        p = pes.STANAG4609()
        p.pid = pes.STANAG4609_PID
        p.adaption_ctrl = MPEGTS.ADAPTION_PAYLOAD_AND_ADAPTION
        p.adaption_field = MPEGTS.MPEGAdaption()
        p.adaption_field.length = 133
        p.time = datetime.datetime(2024, 1, 25, 15, 7, 59, 767139, tzinfo=datetime.timezone.utc)
        p.header_data = pes.ts_to_buf(187.14)
        p.extension_w1 = pes.PES_EXTENSION_W1
        p.extension_w2 = pes.PES_EXTENSION_W2
        p.streamid = 0xFC
        p.stanag_counter = 15
        p.continuitycounter = 15
        p.pack()
        self.assertEqual(p, ref)
        self.assertEqual(p.pack(), pes_packet)

    def test_stanag_pts(self):
        ts = 0x210403FED1
        exp = 187.14
        self.assertEqual(pes.pts_to_ts(ts), exp)
        _conv = pes.ts_to_pts(exp)
        # print(f"{_conv:#0X}")
        self.assertEqual(_conv, ts)


corrupt_vid_ = base64.b64decode(
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAEdAEREABBYXGBkaGxwdHh8gISIjJCUmJygpKissLS4vMDEyMzQ1Njc4OTo7PD0+P0BBQkNERUZHSElKS0xNTk9QUVJTVFVWV1hZWltcXV5fYGFiY2RlZmdoaWprbG1ub3BxcnN0dXZ3eHl6e3x9fn+AgYKDhIWGh4iJiouMjY6PkJGSk5SVlpeYmZqbnJ2en6ChoqOkpaanqKmqq6ytrq+wsbKztLW2t7i5uru8vb6/wMHCw8TFxsdeSR2TR0AQEQAFyMnKy8zNzs/Q0dLT1NXW19jZ2tvc3d7f4OHi4+Tl5ufo6err7O3u7/Dx8vP09fb3+Pn6+/z9/v8AAQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyAhIiMkJSYnKCkqKywtLi8wMTIzNDU2Nzg5Ojs8PT4/QEFCQ0RFRkdISUpLTE1OT1BRUlNUVVZXWFlaW1xdXl9gYWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eRnP0dRHH/8QAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAEcf/xAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAARx//EAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABHH/8QAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAEcf/xAAAAAAAAAAAAAAAAAAAAAA"
)


def gen_random_adaption() -> MPEGTS.MPEGAdaption:
    """Generate a random Adaption block

    Returns:
        mpegts.MPEGAdaption: _description_
    """
    adaption = MPEGTS.MPEGAdaption()
    adaption_ext = MPEGTS.MPEGAdaptionExtension()
    adaption_ext.ltw = struct.pack(">H", 0x1)
    adaption.adaption_extension = adaption_ext
    adaption.pcr = struct.pack(">HI", 0xDC, 0xA)
    private_data_len = 8  # random.randint(4, 10)
    adaption.private_data = struct.pack(f">{private_data_len}B", *range(private_data_len))
    return adaption


AUD_WIRESHARK = base64.b64decode(
    "R1EQNAAAAAHAALGBwAohAYttlxEBi22X//lMgBSf/CEWzYAAAJGxQZJoFN2gK0IqYD978ffG6HO42VQXy00TEmkAPFSnXfBXIe2Iq9aWg0UiXK5OXAUO1U3QmVYV5t3JdDMqertkQROtoUFHQrF3eSojHSC6qoVwBSICg5qfL+OhrglxPOQMYCYb2uchqrcVY9Jztkq9mJA5SZbxyBwLAVqbVR64t7xX3eRlyO2UTpnssSgU0sUFHQqfF34="
)
AUD_PAYLOAD = base64.b64decode(
    "//lMgBSf/CEWzYAAAJGxQZJoFN2gK0IqYD978ffG6HO42VQXy00TEmkAPFSnXfBXIe2Iq9aWg0UiXK5OXAUO1U3QmVYV5t3JdDMqertkQROtoUFHQrF3eSojHSC6qoVwBSICg5qfL+OhrglxPOQMYCYb2uchqrcVY9Jztkq9mJA5SZbxyBwLAVqbVR64t7xX3eRlyO2UTpnssSgU0sUFHQqfF34="
)

AUD_WIRESHARK2 = base64.b64decode(
    "R1EQOC4A////////////////////////////////////////////////////////////AAABwACDgcAKIQGNjXkRAY2Nef/5TIAO3/whFs/V/++SoqIYaLUKxbLXVWoq5AYet7svXAIhmHcsb64qz2LtaB5KVl4xYGSCUtowuItllZjKsAQJWCYTNB99yj5UGUVa3Ar4V1XHaw4aUzFjjQx3k2UDECBEsJVUMLPvWs7VhHRgCLxSkKD77lw="
)

PAT_PKT = base64.b64decode(
    "R0AAHAAAsA0ACMEAAAAB4QBn1F+J//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////8="
)
PMT_PKT = base64.b64decode(
    "R0EAHAACsEQAAcEAAPAA8AwFBEhETVaIBA///Pwb8QDwAATxEPAAFeEE8BwFBEtMVkEmCQEA/0tMVkEADycJwQAAwIAAwQAA7IayY/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////8="
)

AUD_PAYLOAD2 = base64.b64decode(
    "//lMgA7f/CEWz9X/75KiohhotQrFstdVairkBh63uy9cAiGYdyxvrirPYu1oHkpWXjFgZIJS2jC4i2WVmMqwBAlYJhM0H33KPlQZRVrcCvhXVcdrDhpTMWONDHeTZQMQIESwlVQws+9aztWEdGAIvFKQoPvuXA=="
)


class MPEGAdaptionFullTest(unittest.TestCase):

    def test_fromsim(self):
        f = open(THIS_DIR + "/mpegs_ch0.ts", mode="br")
        f.seek(752)
        while True:
            print(f"Reading from offset {f.tell()}")
            buf = f.read(188)
            if len(buf) == 0:
                break
            mp = MPEGTS.MPEGPacket()
            try:
                mp.unpack(buf)
            except Exception as e:
                print(e)
                self.assertTrue(False)

    def test_pack_and_unpack(self):
        for _iter in range(1 - 0):
            mpeg_pkt = MPEGTS.MPEGPacket()
            mpeg_pkt.sync = 0x47
            mpeg_pkt.transport_priority = random.choice([0, 1])  # 1 in 10
            mpeg_pkt.tei = not random.randint(0, 100)  # 1 in 100
            mpeg_pkt.pid = random.randint(1, 5000)  # Select a PID
            mpeg_pkt.pusi = random.choice([True, False])
            mpeg_pkt.continuitycounter = random.randint(1, 6)
            mpeg_pkt.adaption_ctrl = random.choice([1, 2])
            adaption_field_len = 0
            if mpeg_pkt.adaption_ctrl == 0x2 or mpeg_pkt.adaption_ctrl == 0x3:
                mpeg_pkt.adaption_field = gen_random_adaption()
                adaption_field_len = len(mpeg_pkt.adaption_field.pack())
            payload_len = 188 - 4 - adaption_field_len
            if mpeg_pkt.adaption_ctrl != MPEGTS.ADAPTION_ADAPTION_ONLY:
                mpeg_pkt.payload = struct.pack(f"{payload_len}B", *range(payload_len))

            buf = mpeg_pkt.pack()

            mp = MPEGTS.MPEGPacket()
            self.assertIsNone(mp.unpack(buf))
            self.assertEqual(mp, mpeg_pkt)

    def test_unpack_audio_adaption(self):
        pkt = pes.PES()
        pkt.unpack(AUD_WIRESHARK)
        self.assertEqual(len(pkt.header_data), 10)
        pts = pes.buf_to_ts(pkt.header_data[:5])
        dts = pes.buf_to_ts(pkt.header_data[5:])
        self.assertAlmostEqual(pts, 71.881366666)
        self.assertAlmostEqual(dts, 71.881366666)

        pkt2 = pes.PES()
        pkt2.tei = False
        pkt2.pusi = True
        pkt2.transport_priority = 0
        pkt2.pid = 0x1110
        pkt2.continuitycounter = 4
        pkt2.tsc = 0
        pkt2.adaption_ctrl = MPEGTS.ADAPTION_PAYLOAD_AND_ADAPTION
        pkt2.streamid = 0xC0
        pkt2.extension_w1 = 0x81
        pkt2.extension_w2 = 0xC0
        pkt2.header_data = pes.ts_to_buf(71.881366666) + pes.ts_to_buf(71.881366666)
        pkt2.pesdata = AUD_PAYLOAD

        buf = pkt2.pack()
        # self.assertEqual(buf, AUD_WIRESHARK)
        f = open(THIS_DIR + "/audio_gen.ts", mode="bw")
        f.write(PAT_PKT)
        f.write(PMT_PKT)
        # f.write(AUD_WIRESHARK)
        f.write(buf)
        f.close()

    def test_unpack_audio_adaption2(self):
        pkt = pes.PES()
        pkt.unpack(AUD_WIRESHARK2)
        self.assertEqual(len(pkt.header_data), 10)
        pts = pes.buf_to_ts(pkt.header_data[:5])
        dts = pes.buf_to_ts(pkt.header_data[5:])
        self.assertAlmostEqual(pts, 72.290800000)
        self.assertAlmostEqual(dts, 72.290800000)

        pkt2 = pes.PES()
        pkt2.tei = False
        pkt2.pusi = True
        pkt2.transport_priority = 0
        pkt2.pid = 0x1110
        pkt2.continuitycounter = 8
        pkt2.tsc = 0
        pkt2.adaption_ctrl = MPEGTS.ADAPTION_PAYLOAD_AND_ADAPTION
        pkt2.adaption_field = MPEGTS.MPEGAdaption()
        pkt2.adaption_field.length = 46

        pkt2.streamid = 0xC0
        pkt2.extension_w1 = 0x81
        pkt2.extension_w2 = 0xC0
        pkt2.header_data = pes.ts_to_buf(72.290800000) + pes.ts_to_buf(72.290800000)
        pkt2.pesdata = AUD_PAYLOAD2

        buf = pkt2.pack()
        f = open(THIS_DIR + "/audio_gen2.ts", mode="bw")
        f.write(PAT_PKT)
        f.write(PMT_PKT)
        # f.write(AUD_WIRESHARK)
        f.write(buf)
        f.close()

    def test_random_pes(self):

        for _i in range(100):
            pkt2 = pes.PES()
            pkt2.tei = False
            pkt2.pusi = True
            pkt2.transport_priority = 0
            pkt2.pid = 1
            pkt2.continuitycounter = 2
            pkt2.tsc = 0
            pkt2.adaption_ctrl = MPEGTS.ADAPTION_PAYLOAD_AND_ADAPTION
            adaption = random.choice([0, 12, 25, 44])
            if adaption != 0:
                pkt2.adaption_field = MPEGTS.MPEGAdaption()
                pkt2.adaption_field.length = adaption
            pkt2.streamid = 0xC0
            pkt2.extension_w1 = 0x81
            pkt2.extension_w2 = 0xC0
            pkt2.header_data = pes.ts_to_buf(44) + pes.ts_to_buf(44)
            pkt2.pesdata = struct.pack(f">{164 - adaption}B", *range(164 - adaption))
            if len(pkt2.pack()) != 188:
                pass
            self.assertEqual(len(pkt2.pack()), 188)


class MPEGAdaptionExtensionTestcase(unittest.TestCase):
    def test_basic(self):
        for _i in range(100):
            _e = MPEGTS.MPEGAdaptionExtension()
            _e.ltw = random.choice([bytes(), b"\x00\x00"])
            _e.piecewise = random.choice([bytes(), b"\x00\x00\x00"])
            _e.seamless_splice = random.choice([bytes(), b"\x00\x00\x00\x00\x00"])

            _d = MPEGTS.MPEGAdaptionExtension()
            _d.unpack(_e.pack())
            self.assertEqual(_d, _e)


class MPEGAdaptionTestcase(unittest.TestCase):
    def test_basic(self):
        for _i in range(100):
            _e = MPEGTS.MPEGAdaption()
            adaption_ext = MPEGTS.MPEGAdaptionExtension()
            adaption_ext.ltw = struct.pack(">H", 0x1)
            _e.adaption_extension = adaption_ext
            _e.pcr = random.choice([struct.pack(">HI", 0xDC, 0xA), bytes()])
            private_data_len = random.randint(4, 10)
            _e.private_data = random.choice([struct.pack(f">{private_data_len}B", *range(private_data_len)), bytes()])

            _d = MPEGTS.MPEGAdaption()
            _b = _e.pack()
            _d.unpack(_b)
            self.assertEqual(_e, _d)


class CorruptVid(unittest.TestCase):
    def test_basic(self):
        f = open(THIS_DIR + "/audio_pkt.ts", mode="bw")
        f.write(PAT_PKT)
        f.write(PMT_PKT)
        for _iter in range(1):
            mpeg_pkt = MPEGTS.MPEGPacket()
            mpeg_pkt.sync = 0x47
            mpeg_pkt.transport_priority = random.choice([0, 1])  # 1 in 10
            mpeg_pkt.tei = not random.randint(0, 100)  # 1 in 100
            mpeg_pkt.pid = 0x1110  # Select a PID
            mpeg_pkt.pusi = False
            mpeg_pkt.continuitycounter = random.randint(1, 6)
            mpeg_pkt.adaption_ctrl = random.choice([1, 2])
            adaption_field_len = 0
            if mpeg_pkt.adaption_ctrl == 0x2 or mpeg_pkt.adaption_ctrl == 0x3:
                mpeg_pkt.adaption_field = gen_random_adaption()
                adaption_field_len = len(mpeg_pkt.adaption_field.pack())
            payload_len = 188 - 4 - adaption_field_len
            if mpeg_pkt.adaption_ctrl != MPEGTS.ADAPTION_ADAPTION_ONLY:
                mpeg_pkt.payload = struct.pack(f"{payload_len}B", *range(payload_len))

            buf = mpeg_pkt.pack()
            f.write(buf)
        f.close()


if "unittest.util" in __import__("sys").modules:
    # Show full diff in self.assertEqual.
    __import__("sys").modules["unittest.util"]._MAX_LENGTH = 999999999

if __name__ == "__main__":
    unittest.main()
