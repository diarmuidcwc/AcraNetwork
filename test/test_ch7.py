import sys
sys.path.append("../")
import unittest
import AcraNetwork.Chapter7 as ch7
import AcraNetwork.SimpleEthernet as eth
import AcraNetwork.Pcap as pcap
import os
import copy
import struct
import logging
from pstats import Stats
import cProfile


THIS_DIR = os.path.dirname(os.path.abspath(__file__))


def buf_generator(count, llp_count=0):
    running_count = 0
    while running_count < count:
        buf_len = os.urandom((running_count+1) * 128)
        running_count += 1
        if running_count <= llp_count:
            low_latency = True
        else:
            low_latency = False
        yield buf_len, low_latency


class TestCaseCh7(unittest.TestCase):

    def test_basic(self):
        ch7_pkt = ch7.PTFR()
        ch7_pkt.length = 132
        ch7_pkt.llp = 0
        remainder = bytes()
        while remainder == bytes():
            ch7_pd = ch7.PTDP()
            ch7_pd.content = ch7.PTDP_CONTENT_MAC
            ch7_pd.fragment = ch7.PTDP_FRAGMENT_COMPLETE
            ch7_pd.payload = os.urandom(58)
            remainder = ch7_pkt.add_payload(ch7_pd.pack())
            #print("Packet added")
        buf = ch7_pkt.pack()
        #print("Len Buf={} Len Rem={}".format(len(buf), len(remainder)))
        # Check the comparsion
        ch7_pkt_copy = copy.deepcopy(ch7_pkt)
        self.assertTrue(ch7_pkt==ch7_pkt_copy)

        ch7_unpack = ch7.PTFR()
        ch7_unpack.length = 132
        self.assertTrue(ch7_unpack.unpack(buf))
        self.assertTrue(ch7_unpack==ch7_pkt)

    def test_partial_fill(self):
        ch7_pkt = ch7.PTFR()
        ch7_pkt.length = 140
        ch7_pkt.llp = 0
        remainder = bytes()
        while remainder == bytes():
            ch7_pd = ch7.PTDP()
            ch7_pd.content = ch7.PTDP_CONTENT_MAC
            ch7_pd.fragment = ch7.PTDP_FRAGMENT_COMPLETE
            ch7_pd.payload = os.urandom(58)
            remainder = ch7_pkt.add_payload(ch7_pd.pack())
            #print("Packet added")
        buf = ch7_pkt.pack()
        ch7_unpack = ch7.PTFR()
        ch7_unpack.length = 140
        self.assertTrue(ch7_unpack.unpack(buf))
        #print(repr(ch7_pkt))
        #print(repr(ch7_unpack))
        self.assertEqual(52, len(remainder))
        self.assertTrue(ch7_unpack == ch7_pkt)


    def test_comparsion(self):
        ch7_pd = ch7.PTDP()
        ch7_pd.content = ch7.PTDP_CONTENT_MAC
        ch7_pd.fragment = ch7.PTDP_FRAGMENT_COMPLETE
        ch7_pd.payload = os.urandom(60)
        ch_pd_copy = copy.deepcopy(ch7_pd)
        self.assertTrue(ch7_pd==ch_pd_copy)


class TestGenerators(unittest.TestCase):

    def test_ptdp_generator(self):
        for ptdp_pkt in ch7.datapkts_to_ptdp(buf_generator(5)):
            #print(repr(ptdp_pkt))
            self.assertIsInstance(ptdp_pkt, ch7.PTDP)

    def test_ptfr_geenerator(self):
        remainder = bytes()
        for ptfr in ch7.datapkts_to_ptfr(buf_generator(5), ptfr_len=200):
            #print(repr(ptfr))
            ch7_pkt = ch7.PTFR()
            ch7_pkt.length = 800
            ch7_pkt.unpack(ptfr.pack())
            for (p, remainder, e) in ch7_pkt.get_aligned_payload(remainder):
                if p is None:
                    continue
                else:
                    #print(repr(p))
                    self.assertEqual(0, p.length % 128)



class TestRealEthernet(unittest.TestCase):

    def setUp(self):
        self.pr = cProfile.Profile()
        self.pr.enable()

    def tearDown(self):
        p = Stats(self.pr)
        p.sort_stats('cumtime')
        #p.print_stats()


    pkts_sent = []
    @staticmethod
    def eth_gen(count, low_latency_pkts=None, size_mult=128):
        """

        :param count:
        :param low_latency_pkts:
        :param size_mult:
        :rtype:  collections.Iterable[bytes, bool]
        """

        pf = pcap.Pcap(THIS_DIR+"/generated_eth.pcap", mode="w")
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
        pf = pcap.Pcap(THIS_DIR+"/gen.pcap", mode="w")
        r = pcap.PcapRecord()
        remainder = bytes()
        eth_p = bytes()
        pkt_count = 1
        for ptfr in ch7.datapkts_to_ptfr(TestRealEthernet.eth_gen(3), ptfr_len=200):
            ch7_pkt = ch7.PTFR()
            ch7_pkt.length = 200
            ch7_pkt.unpack(ptfr.pack())
            for (p, remainder, e) in ch7_pkt.get_aligned_payload(remainder):
                if p is None:
                    continue
                else:
                    eth_p += p.payload
                    if p.fragment == ch7.PTDP_FRAGMENT_COMPLETE or  p.fragment == ch7.PTDP_FRAGMENT_LAST:
                        r.setCurrentTime()
                        r.payload = eth_p
                        # Verify the size of the packets and it's probably good. I could unpack them here too
                        self.assertEqual(pkt_count*2*128+eth.UDP.UDP_HEADER_SIZE+eth.IP.IP_HEADER_SIZE+eth.Ethernet.HEADERLEN, len(eth_p))
                        pkt_count += 1
                        pf.write(r)
                        eth_p = bytes()


                    #self.assertEqual(0, p.length % 128)
                    #self.assertTrue(p.length <= 1024)
        pf.close()

    def test_eth_in_packets_low_latency(self):
        #logging.basicConfig(level=logging.DEBUG)
        pf = pcap.Pcap(THIS_DIR+"/captured_llp.pcap", mode="w")
        r = pcap.PcapRecord()
        remainder = bytes()
        eth_p = bytes()
        pkt_count = 1
        ptfr_idx = 0
        ptdp_idx = 0
        pkt_size_mult = 16
        for ptfr in ch7.datapkts_to_ptfr(TestRealEthernet.eth_gen(20, low_latency_pkts=[2, 4, 10], size_mult=8), ptfr_len=400):
            ch7_pkt = ch7.PTFR()
            ch7_pkt.length = 400
            ch7_pkt.unpack(ptfr.pack())
            #b = open("gen_llp_{}.bin".format(ptfr_idx), mode="wb")
            ptfr_idx += 1
            #b.write(ptfr.pack())
            #b.close()
            #print(repr(ptfr))
            for (p, remainder, e) in ch7_pkt.get_aligned_payload(remainder):
                if p is None:
                    continue
                else:
                    #print(repr(p))
                    eth_p += p.payload
                    if p.fragment == ch7.PTDP_FRAGMENT_COMPLETE or  p.fragment == ch7.PTDP_FRAGMENT_LAST:
                        if ptdp_idx == 0 :
                            self.assertEqual(p.low_latency, True)
                        r.setCurrentTime()
                        r.payload = eth_p
                        # Verify the size of the packets and it's probably good. I could unpack them here too
                        #self.assertEqual(2*64+eth.UDP.UDP_HEADER_SIZE+eth.IP.IP_HEADER_SIZE+eth.Ethernet.HEADERLEN, len(eth_p))
                        if eth_p not in TestRealEthernet.pkts_sent:
                            self.assertTrue(False)
                        pkt_count += 1
                        pf.write(r)
                        eth_p = bytes()
                    ptdp_idx += 1
        self.assertEqual(pkt_count, 11)


                    #self.assertEqual(0, p.length % 128)
                    #self.assertTrue(p.length <= 1024)
        pf.close()

    def test_llc(self):
        llc_count = 0
        fill_count = 0
        mac_count = 0
        logging.basicConfig(level=logging.WARN)
        remainder = b""
        for i in range(3, 6):
            f = open(THIS_DIR+"/ptfr_{}.bin".format(i), "rb")
            ptfr_data = f.read()
            f.close()

            ch7_pkt = ch7.PTFR()
            ch7_pkt.length = len(ptfr_data)
            eth_p = b""
            ch7_pkt.unpack(ptfr_data)
            #print repr(ch7_pkt)

            for (p, remainder, e) in ch7_pkt.get_aligned_payload(remainder):
                if p is not None:

                    if p.content != ch7.PTDP_CONTENT_FILL:
                        mac_count += 1
                        #print(repr(p))
                    if p.low_latency:
                        llc_count += 1
                    if p.content == ch7.PTDP_CONTENT_FILL:
                        fill_count += 1
        #print("{} {} {}".format(llc_count, fill_count, mac_count))
        self.assertEqual(4, llc_count)
        self.assertEqual(164, fill_count)
        self.assertEqual(4, mac_count)

if __name__ == '__main__':
    unittest.main()
