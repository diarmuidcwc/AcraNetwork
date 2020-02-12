import unittest
import AcraNetwork.Chapter7 as ch7
import AcraNetwork.SimpleEthernet as eth
import AcraNetwork.Pcap as pcap
import os
import copy
import struct

def buf_generator(count):
    running_count = 0
    while running_count < count:
        buf_len = os.urandom((running_count+1) * 128)
        running_count += 1
        yield buf_len


class TestCaseCh7(unittest.TestCase):

    def test_basic(self):
        ch7_pkt = ch7.PDFR()
        ch7_pkt.length = 132
        ch7_pkt.llp = 0
        remainder = bytes()
        while remainder == bytes():
            ch7_pd = ch7.PTDP()
            ch7_pd.content = ch7.PTDP_CONTENT_MAC
            ch7_pd.fragment = ch7.PTDP_FRAGMENT_COMPLETE
            ch7_pd.payload = os.urandom(58)
            remainder = ch7_pkt.add_payload(ch7_pd.pack())
            print("Packet added")
        buf = ch7_pkt.pack()
        print("Len Buf={} Len Rem={}".format(len(buf), len(remainder)))
        # Check the comparsion
        ch7_pkt_copy = copy.deepcopy(ch7_pkt)
        self.assertTrue(ch7_pkt==ch7_pkt_copy)

        ch7_unpack = ch7.PDFR()
        ch7_unpack.length = 132
        self.assertTrue(ch7_unpack.unpack(buf))
        self.assertTrue(ch7_unpack==ch7_pkt)

    def test_partial_fill(self):
        ch7_pkt = ch7.PDFR()
        ch7_pkt.length = 140
        ch7_pkt.llp = 0
        remainder = bytes()
        while remainder == bytes():
            ch7_pd = ch7.PTDP()
            ch7_pd.content = ch7.PTDP_CONTENT_MAC
            ch7_pd.fragment = ch7.PTDP_FRAGMENT_COMPLETE
            ch7_pd.payload = os.urandom(58)
            remainder = ch7_pkt.add_payload(ch7_pd.pack())
            print("Packet added")
        buf = ch7_pkt.pack()
        ch7_unpack = ch7.PDFR()
        ch7_unpack.length = 140
        self.assertTrue(ch7_unpack.unpack(buf))
        print(repr(ch7_pkt))
        print(repr(ch7_unpack))
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
            print(repr(ptdp_pkt))

    def test_pdfr_geenerator(self):
        remainder = bytes()
        for pdfr in ch7.datapkts_to_pdfr(buf_generator(5), pdfr_len=200):
            print(repr(pdfr))
            ch7_pkt = ch7.PDFR()
            ch7_pkt.length = 800
            ch7_pkt.unpack(pdfr.pack())
            for (p, remainder, e) in ch7_pkt.get_aligned_payload(remainder):
                if p is None:
                    continue
                else:
                    print(repr(p))
                    self.assertEqual(0, p.length % 128)



def eth_gen(count):
    for i in range(1, count+1):
        e = eth.Ethernet()
        e.dstmac = 0x1234
        e.srcmac = 0x4321
        e.type = e.TYPE_IP
        ip = eth.IP()
        ip.srcip = "192.168.28.3"
        ip.dstip = "192.168.28.1"
        u = eth.UDP()
        u.dstport = i
        u.srcport = i
        u.payload = struct.pack(">{}H".format(i*128), *range(i*128))
        ip.payload = u.pack()
        e.payload = ip.pack()
        yield e.pack()


class TestRealEthernet(unittest.TestCase):

    def test_eth_in_packets(self):
        pf = pcap.Pcap("gen.pcap", mode="w")
        r = pcap.PcapRecord()
        remainder = bytes()
        eth_p = bytes()
        pkt_count = 1
        for pdfr in ch7.datapkts_to_pdfr(eth_gen(3), pdfr_len=200):
            ch7_pkt = ch7.PDFR()
            ch7_pkt.length = 200
            ch7_pkt.unpack(pdfr.pack())
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

if __name__ == '__main__':
    unittest.main()
