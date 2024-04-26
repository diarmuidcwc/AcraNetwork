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


# Take from Wireshar - > cop
pmt_payload = base64.b64decode(
    "R0EAGQACsDgAAcEAAOEB8AAb4QLwAAPhA/AAFeEE8BwFBEtMVkEmCQEA/0tMVkEADycJwQAAwIAAwQAAX+WEI/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////8="
)


class MPEGPNT(unittest.TestCase):
    def test_pmt_unpack(self):
        pmt = MPEGPMT.MPEGPacketPMT()
        pmt.unpack(pmt_payload)

        pmt2 = MPEGPMT.MPEGPacketPMT()
        pmt2.unpack(pmt.pack())
        self.assertEqual(pmt, pmt2)
        self.assertEqual(pmt_payload, pmt2.pack())

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
        s.descriptor_tags = [t]
        s.elementary_pid = 0x1FEF
        pmt.streams = [s]
        _packed = pmt.pack()

        pmt2 = MPEGPMT.MPEGPacketPMT()
        self.assertTrue(pmt2.unpack(_packed))
        self.assertEqual(pmt, pmt2)


pes_packet = base64.b64decode(
    "R0EEP4UA////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////AAAB/AAsgYAFIQQD/tEAD98AHwYOKzQCCwEBDgEDAQEAAAAOAggABg/Gi5FmYwECH1M="
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
        print(repr(p))
        self.assertEqual(36, len(p.pesdata))
        self.assertEqual(len(p.pack()), 188)
        self.assertEqual(p.pack(), pes_packet)
        print(repr(p.time))

    def test_stanag_create(self):
        ref = pes.STANAG4609()
        ref.unpack(pes_packet)
        # Build a packet from scratch that matches the refernce packet
        p = pes.STANAG4609()
        p.pid = pes.STANAG4609_PID
        p.adaption_ctrl = MPEGTS.ADAPTION_PAYLOAD_AND_ADAPTION
        p.adaption_field = MPEGTS.MPEGAdaption()
        p.adaption_field.length = 133
        p.time = datetime.datetime(2024, 1, 25, 15, 7, 59, 767139)
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
        print(f"{_conv:#0X}")
        self.assertEqual(_conv, ts)


if "unittest.util" in __import__("sys").modules:
    # Show full diff in self.assertEqual.
    __import__("sys").modules["unittest.util"]._MAX_LENGTH = 999999999

if __name__ == "__main__":
    unittest.main()
