import unittest
import AcraNetwork.IRIG106.Chapter7 as ch7
import AcraNetwork.SimpleEthernet as eth
import AcraNetwork.Pcap as pcap
import os
import copy
import struct
import logging
from pstats import Stats
import cProfile
import typing
import random


THIS_DIR = os.path.dirname(os.path.abspath(__file__))

logging.basicConfig(level=logging.INFO, format="%(levelname)s:%(funcName)s:%(lineno)s:%(message)s")


def buf_generator(count, llp_count=0):
    running_count = 0
    while running_count < count:
        buf_len = os.urandom((running_count + 1) * 128)
        running_count += 1
        if running_count <= llp_count:
            low_latency = True
        else:
            low_latency = False
        yield buf_len, low_latency


def ptfr_to_pcm_frame(
    count: int,
):
    remainder = bytes()
    pcm_frame_len = 1024
    offset_ptfr = 30
    zero_buf = struct.pack(">B", 0) * offset_ptfr
    pcm_frame = zero_buf
    for ptfr in ch7.datapkts_to_ptfr(buf_generator(count)):
        pcm_frame += ptfr.pack()
        if len(pcm_frame) >= pcm_frame_len:
            remainder = pcm_frame[pcm_frame_len:]
            pcm_frame = pcm_frame[:pcm_frame_len]
            yield pcm_frame
            pcm_frame = zero_buf + remainder


class TestCaseCh7(unittest.TestCase):
    def test_basic(self):
        ch7_pkt = ch7.PTFR()
        ch7_pkt.length = 132
        ch7_pkt.llp = 0
        remainder = bytes()
        while remainder == bytes():
            ch7_pd = ch7.PTDP()
            ch7_pd.content = ch7.PTDPContent.ETHERNET_MAC
            ch7_pd.fragment = ch7.PTDPFragment.COMPLETE
            ch7_pd.payload = os.urandom(58)
            remainder = ch7_pkt.add_payload(ch7_pd.pack())
            # print("Packet added")
        buf = ch7_pkt.pack()
        # print("Len Buf={} Len Rem={}".format(len(buf), len(remainder)))
        # Check the comparsion
        ch7_pkt_copy = copy.deepcopy(ch7_pkt)
        self.assertTrue(ch7_pkt == ch7_pkt_copy)

        ch7_unpack = ch7.PTFR()
        ch7_unpack.length = 132
        self.assertTrue(ch7_unpack.unpack(buf))
        self.assertTrue(ch7_unpack == ch7_pkt)

    def test_partial_fill(self):
        ch7_pkt = ch7.PTFR()
        ch7_pkt.length = 140
        ch7_pkt.llp = 0
        remainder = bytes()
        while remainder == bytes():
            ch7_pd = ch7.PTDP()
            ch7_pd.content = ch7.PTDPContent.ETHERNET_MAC
            ch7_pd.fragment = ch7.PTDPFragment.COMPLETE
            ch7_pd.payload = os.urandom(58)
            remainder = ch7_pkt.add_payload(ch7_pd.pack())
            # print("Packet added")
        buf = ch7_pkt.pack()
        ch7_unpack = ch7.PTFR()
        ch7_unpack.length = 140
        self.assertTrue(ch7_unpack.unpack(buf))
        # print(repr(ch7_pkt))
        # print(repr(ch7_unpack))
        self.assertEqual(52, len(remainder))
        self.assertTrue(ch7_unpack == ch7_pkt)

    def test_comparsion(self):
        ch7_pd = ch7.PTDP()
        ch7_pd.content = ch7.PTDPContent.ETHERNET_MAC
        ch7_pd.fragment = ch7.PTDPFragment.COMPLETE
        ch7_pd.payload = os.urandom(60)
        ch_pd_copy = copy.deepcopy(ch7_pd)
        self.assertTrue(ch7_pd == ch_pd_copy)


class TestGenerators(unittest.TestCase):
    def test_ptdp_generator(self):
        for ptdp_pkt in ch7.datapkts_to_ptdp(buf_generator(5)):
            # print(repr(ptdp_pkt))
            self.assertIsInstance(ptdp_pkt, ch7.PTDP)

    def test_ptfr_generator(self):
        remainder = bytes()
        for ptfr in ch7.datapkts_to_ptfr(buf_generator(5), ptfr_len=200):
            # print(repr(ptfr))
            ch7_pkt = ch7.PTFR()
            ch7_pkt.length = 800
            ch7_pkt.unpack(ptfr.pack())
            for p, remainder, e in ch7_pkt.get_aligned_payload(remainder):
                if p is None:
                    continue
                else:
                    # print(repr(p))
                    self.assertEqual(0, p.length % 128)


class TestRealEthernet(unittest.TestCase):
    def setUp(self):
        self.pr = cProfile.Profile()
        self.pr.enable()

    def tearDown(self):
        p = Stats(self.pr)
        p.sort_stats("cumtime")
        # p.print_stats()

    pkts_sent = []

    @staticmethod
    def eth_gen(count, low_latency_pkts=None, size_mult=128):
        """

        :param count:
        :param low_latency_pkts:
        :param size_mult:
        :rtype:  collections.Iterable[bytes, bool]
        """

        pf = pcap.Pcap(THIS_DIR + "/generated_eth.pcap", mode="w")
        r = pcap.PcapRecord()
        for i in range(1, count + 1):
            e = eth.Ethernet()
            e.dstmac = 0xABABABABABAB
            e.srcmac = 0xDCDCDCDCDCDC
            e.type = e.TYPE_IP
            ip = eth.IP()
            ip.srcip = "192.168.28.3"
            ip.dstip = "192.168.28.1"
            u = eth.UDP()
            u.dstport = i
            u.srcport = i
            if size_mult == 0:
                u.payload = struct.pack(">{}H".format(64), *([0xA5A5] * (64)))
            else:
                u.payload = struct.pack(">{}H".format(i * size_mult), *([0xA5A5] * (i * size_mult)))
            ip.payload = u.pack()
            e.payload = ip.pack()

            if low_latency_pkts is None:
                low_latency = False
            elif i in low_latency_pkts:
                low_latency = True
            else:
                low_latency = False
            r.setCurrentTime()
            r.payload = e.pack()
            pf.write(r)
            TestRealEthernet.pkts_sent.append(e.pack())
            yield e.pack(), low_latency
        pf.close()

    def test_eth_in_packets(self):
        pf = pcap.Pcap(THIS_DIR + "/gen.pcap", mode="w")
        r = pcap.PcapRecord()
        remainder = bytes()
        eth_p = bytes()
        pkt_count = 1
        for ptfr in ch7.datapkts_to_ptfr(TestRealEthernet.eth_gen(3), ptfr_len=200):
            ch7_pkt = ch7.PTFR()
            ch7_pkt.length = 200
            ch7_pkt.unpack(ptfr.pack())
            for p, remainder, e in ch7_pkt.get_aligned_payload(remainder):
                if p is None:
                    continue
                else:
                    eth_p += p.payload
                    if p.fragment == ch7.PTDPFragment.COMPLETE or p.fragment == ch7.PTDPFragment.LAST:
                        r.setCurrentTime()
                        r.payload = eth_p
                        # Verify the size of the packets and it's probably good. I could unpack them here too
                        self.assertEqual(
                            pkt_count * 2 * 128
                            + eth.UDP.UDP_HEADER_SIZE
                            + eth.IP.IP_HEADER_SIZE
                            + eth.Ethernet.HEADERLEN,
                            len(eth_p),
                        )
                        pkt_count += 1
                        pf.write(r)
                        eth_p = bytes()

                    # self.assertEqual(0, p.length % 128)
                    # self.assertTrue(p.length <= 1024)
        pf.close()

    def test_eth_in_packets_low_latency(self):
        # logging.basicConfig(level=logging.DEBUG)
        pf = pcap.Pcap(THIS_DIR + "/captured_llp.pcap", mode="w")
        r = pcap.PcapRecord()
        remainder = bytes()
        eth_p = bytes()
        pkt_count = 1
        ptfr_idx = 0
        ptdp_idx = 0
        pkt_size_mult = 16
        for ptfr in ch7.datapkts_to_ptfr(
            TestRealEthernet.eth_gen(20, low_latency_pkts=[2, 4, 10], size_mult=8), ptfr_len=400
        ):
            ch7_pkt = ch7.PTFR()
            ch7_pkt.length = 400
            ch7_pkt.unpack(ptfr.pack())
            # b = open("gen_llp_{}.bin".format(ptfr_idx), mode="wb")
            ptfr_idx += 1
            # b.write(ptfr.pack())
            # b.close()
            # print(repr(ptfr))
            for p, remainder, e in ch7_pkt.get_aligned_payload(remainder):
                if p is None:
                    continue
                else:
                    # print(repr(p))
                    eth_p += p.payload
                    if p.fragment == ch7.PTDPFragment.COMPLETE or p.fragment == ch7.PTDPFragment.LAST:
                        if ptdp_idx == 0:
                            self.assertEqual(p.low_latency, True)
                        r.setCurrentTime()
                        r.payload = eth_p
                        # Verify the size of the packets and it's probably good. I could unpack them here too
                        # self.assertEqual(2*64+eth.UDP.UDP_HEADER_SIZE+eth.IP.IP_HEADER_SIZE+eth.Ethernet.HEADERLEN, len(eth_p))
                        if p.content != ch7.PTDPContent.FILL:
                            if eth_p not in TestRealEthernet.pkts_sent:
                                self.assertTrue(False)
                            pkt_count += 1
                        pf.write(r)
                        eth_p = bytes()
                    ptdp_idx += 1
        self.assertEqual(pkt_count, 11)

        # self.assertEqual(0, p.length % 128)
        # self.assertTrue(p.length <= 1024)
        pf.close()

    def test_llc(self):
        llc_count = 0
        fill_count = 0
        mac_count = 0
        remainder = b""
        for i in range(3, 6):
            f = open(THIS_DIR + "/ptfr_{}.bin".format(i), "rb")
            ptfr_data = f.read()
            f.close()

            ch7_pkt = ch7.PTFR()
            ch7_pkt.length = len(ptfr_data)
            eth_p = b""
            ch7_pkt.unpack(ptfr_data)
            # print repr(ch7_pkt)

            for p, remainder, e in ch7_pkt.get_aligned_payload(remainder):
                if p is not None:
                    if p.content != ch7.PTDPContent.FILL:
                        mac_count += 1
                        # print(repr(p))
                    if p.low_latency:
                        llc_count += 1
                    if p.content == ch7.PTDPContent.FILL:
                        fill_count += 1
        # print("{} {} {}".format(llc_count, fill_count, mac_count))
        self.assertEqual(4, llc_count)
        self.assertEqual(164, fill_count)
        self.assertEqual(4, mac_count)


def get_pkts(some_low_latency: bool = False, max_len: int = 178) -> typing.Generator[tuple[bytes, bool], None, None]:

    count = 0
    while True:
        # pkt_len = random.randint(2, 180)
        pkt_len = (count % max_len) + 2
        paylaod_int = [pkt_len] + [count] * (pkt_len - 1)
        payload = struct.pack(f">{pkt_len}Q", *paylaod_int)
        count += 1
        llc_pkts = [True, False, False, False, False, False, False]
        # llc_pkts = [True, True, True, True, True, True, True]
        if some_low_latency:
            low_latency = llc_pkts[count % 7]
        else:
            low_latency = False
        logging.debug(f"TX: Generated payload of length {pkt_len*8} count={count}")
        yield payload, low_latency


def get_pcm_frame(offset_ptfr: int = 0, some_low_latency: bool = False, max_len: int = 178):
    pcm_frame_len = 1024
    ptfr_len = pcm_frame_len - offset_ptfr - 4
    zero_buf = struct.pack(">B", 0) * offset_ptfr
    for ptfr in ch7.datapkts_to_ptfr(get_pkts(some_low_latency, max_len), ptfr_len=ptfr_len):
        pcm_frame = zero_buf + ptfr.pack()
        logging.debug(f"TX pcm_frame_len={len(pcm_frame)} ptfr_len={ptfr_len}")
        yield pcm_frame


def missing_elements(L):
    start, end = L[0], L[-1]
    return sorted(set(range(start, end + 1)).difference(L))


class TestRandomSizedDecom(unittest.TestCase):
    def test_no_llc(self):
        offset = 0
        first_PTFR = True
        eth_p = bytes()
        prev_eth_count = None
        remainder = None
        count = 0
        for frame in get_pcm_frame(offset, some_low_latency=False):
            ch7_pkt = ch7.PTFR()
            ch7_buffer = frame[offset:]
            ch7_pkt.length = len(ch7_buffer)
            ch7_pkt.unpack(ch7_buffer)
            count += 1
            if count > 10000:
                return

            for p, remainder, e in ch7_pkt.get_aligned_payload(first_PTFR, remainder):
                first_PTFR = False
                if p is not None:
                    if p.length != 0:
                        if p.fragment == ch7.PTDPFragment.COMPLETE or p.fragment == ch7.PTDPFragment.LAST:
                            eth_p += p.payload
                            logging.debug(repr(p))
                            self.assertGreaterEqual(len(eth_p), 16)
                            (expected_len, count) = struct.unpack_from(">QQ", eth_p, 0x0)
                            logging.debug(f"RX payload count={count} len={len(eth_p)}")
                            if prev_eth_count is not None:
                                if prev_eth_count + 1 != count:
                                    self.assertEqual(prev_eth_count + 1, count)
                                self.assertEqual(expected_len * 8, len(eth_p))

                            prev_eth_count = count
                            eth_p = bytes()

    def test_some_llc(self):
        offset = 0
        first_PTFR = True
        eth_p = bytes()
        remainder = None
        golay = ch7.Golay.Golay()
        count = 0
        numbers_found = []
        for frame in get_pcm_frame(offset, some_low_latency=True, max_len=50):
            ch7_pkt = ch7.PTFR(golay)
            ch7_buffer = frame[offset:]
            ch7_pkt.length = len(ch7_buffer)
            ch7_pkt.unpack(ch7_buffer)
            count += 1
            if count > 10000:
                return

            for p, remainder, e in ch7_pkt.get_aligned_payload(first_PTFR, remainder):
                first_PTFR = False
                if p is not None:
                    if p.length != 0:
                        if p.fragment == ch7.PTDPFragment.COMPLETE or p.fragment == ch7.PTDPFragment.LAST:
                            eth_p += p.payload
                            logging.debug(repr(p))
                            if p.content != ch7.PTDPContent.FILL:
                                self.assertGreaterEqual(len(eth_p), 16)
                                (expected_len, count) = struct.unpack_from(">QQ", eth_p, 0x0)
                                logging.debug(f"RX payload count={count} len={len(eth_p)}")
                                numbers_found.append(count)
                                self.assertEqual(expected_len * 8, len(eth_p))

                            eth_p = bytes()

        numbers_found.sort()
        self.assertEqual(missing_elements(numbers_found), [])


if __name__ == "__main__":
    unittest.main()
