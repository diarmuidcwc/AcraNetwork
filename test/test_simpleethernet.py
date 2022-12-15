__author__ = 'diarmuid'
import sys
sys.path.append("..")
import os

import unittest
import AcraNetwork.SimpleEthernet as SimpleEthernet
import AcraNetwork.Pcap as pcap
import struct

THIS_DIR = os.path.dirname(os.path.abspath(__file__))

class SimpleEthernetTest(unittest.TestCase):

    ######################
    # Ethernet
    ######################
    def test_DefaultEthernet(self):
        e = SimpleEthernet.Ethernet()
        self.assertEqual(e.dstmac,None)
        self.assertEqual(e.srcmac,None)
        self.assertEqual(e.type, SimpleEthernet.Ethernet.TYPE_IP)
        self.assertEqual(e.payload,None)

    def test_basicEthernet(self):
        '''Create an ethernet frame, then unpack it to a new object'''
        e = SimpleEthernet.Ethernet()
        e.srcmac = 0x001122334455
        e.dstmac = 0x998877665544
        e.type = SimpleEthernet.Ethernet.TYPE_IP
        e.payload = struct.pack("H",0xa)
        ethbuf = e.pack()

        e2  = SimpleEthernet.Ethernet()
        e2.unpack(ethbuf)

        self.assertEqual(e2.dstmac,0x998877665544)
        self.assertEqual(e2.type,SimpleEthernet.Ethernet.TYPE_IP)
        self.assertEqual(e2.srcmac,0x001122334455)

    def test_buildEmptyEthernet(self):
        '''Try and create an empty ethernet frame'''
        e = SimpleEthernet.Ethernet()
        self.assertRaises(ValueError,lambda: e.pack())

    def test_non_def_type(self):
        e = SimpleEthernet.Ethernet()
        e.type = SimpleEthernet.Ethernet.TYPE_PAUSE
        e.dstmac = 0x0180c2000001
        e.srcmac = 0x1
        e.payload = struct.pack(">HH", 0x1, 0x2)
        e2 = SimpleEthernet.Ethernet()
        e2.unpack(e.pack())
        self.assertEqual(e, e2)
        self.assertEqual("SRCMAC=00:00:00:00:00:01 DSTMAC=01:80:C2:00:00:01 TYPE=0X8808", repr(e))

    def test_ethernet_fcs(self):
        e = SimpleEthernet.Ethernet()
        e.type = SimpleEthernet.Ethernet.TYPE_IP
        e.dstmac = 0x0180c2000001
        e.srcmac = 0x1
        e.payload = struct.pack(">HH", 0x1, 0x2)
        ex_fcs = struct.pack(">I", 0x6ed798bf)
        self.assertEqual(e.pack(fcs=True)[-4:], ex_fcs)
        e2 = SimpleEthernet.Ethernet()
        e2.unpack(e.pack(fcs=True), fcs=True)
        self.assertEqual(e, e2)



    ######################
    # IP
    ######################
    def test_defaultIP(self):
        i = SimpleEthernet.IP()
        self.assertRaises(ValueError, lambda : i.pack())

    def test_basicIP(self):
        i = SimpleEthernet.IP()
        i.dstip = "235.0.0.1"
        i.srcip = "192.168.1.1"
        i.payload = struct.pack(">H",0xa5)
        ippayload = i.pack()

        i2 = SimpleEthernet.IP()
        i2.unpack(ippayload)
        self.assertEqual(i2.srcip,"192.168.1.1")
        self.assertEqual(i2.dstip,"235.0.0.1")
        self.assertEqual(i2.payload,struct.pack(">H",0xa5))

    def test_unpackIPShort(self):
        i = SimpleEthernet.IP()
        dummypayload = struct.pack('H',0xa5)
        self.assertRaises(ValueError, lambda : i.unpack(dummypayload))

    ######################
    # UDP
    ######################

    def test_defaultUDP(self):
        u = SimpleEthernet.UDP()
        self.assertRaises(ValueError,lambda :u.pack())

    def test_basicUDP(self):
        u = SimpleEthernet.UDP()
        u.dstport = 5500
        u.srcport = 4400
        u.payload = struct.pack('B',0x5)
        mypacket = u.pack()
        self.assertEqual(mypacket,struct.pack('>HHHHB',4400,5500,9,0,0x5))
        self.assertEqual(repr(u), "SRCPORT=4400 DSTPORT=5500")

    def test_unpackUDPShort(self):
        u = SimpleEthernet.UDP()
        dymmypayload =  struct.pack('H',0xa5)
        self.assertRaises(ValueError,lambda : u.unpack(dymmypayload))


    ######################
    # ICMP
    ######################

    def test_defICMP(self):
        i = SimpleEthernet.ICMP()
        self.assertRaises(ValueError, lambda: i.pack())

    ######################
    # Read a complete pcap file
    ######################
    def test_readUDP(self):
        p = pcap.Pcap(os.path.join(THIS_DIR, "test_input.pcap"))
        mypcaprecord = p[0]
        p.close()
        e = SimpleEthernet.Ethernet()
        e.unpack(mypcaprecord.packet)
        self.assertEqual(e.srcmac,0x0018f8b84454)
        self.assertEqual(e.dstmac,0xe0f847259336)
        self.assertEqual(e.type,0x0800)
        self.assertEqual(repr(e), "SRCMAC=00:18:F8:B8:44:54 DSTMAC=E0:F8:47:25:93:36 TYPE=0X800")

        # checksum test
        (exp_checksum,) = struct.unpack_from("<H", e.payload, 10)
        ip_hdr_checksum = SimpleEthernet.ip_calc_checksum(e.payload[:10] + e.payload[12:20])
        self.assertEqual(exp_checksum, ip_hdr_checksum)
        i = SimpleEthernet.IP()
        i.unpack(e.payload)
        self.assertEqual(i.dstip, "192.168.1.110")
        self.assertEqual(i.srcip, "213.199.179.165")
        self.assertEqual(i.protocol, 0x6)
        self.assertEqual(i.ttl, 48)
        self.assertEqual(i.flags, 0x2)
        self.assertEqual(i.id, 0x4795)
        self.assertEqual(i.len, 56)
        self.assertEqual(i.version, 4)
        #print i
        self.assertEqual(repr(i), "SRCIP=213.199.179.165 DSTIP=192.168.1.110 PROTOCOL=TCP LEN=56")

    def test_ipv4fragment(self):
        p = pcap.Pcap(os.path.join(THIS_DIR, "ipv4frags.pcap"))
        pw = pcap.Pcap(os.path.join(THIS_DIR, "combined.pcap"), mode="w")
        pw.write_global_header()
        r = pcap.PcapRecord()
        e = SimpleEthernet.Ethernet()
        e.unpack(p[0].packet)
        i1 = SimpleEthernet.IP()
        i1.unpack(e.payload)
        e.unpack(p[1].packet)
        p.close()
        i2 = SimpleEthernet.IP()
        i2.unpack(e.payload)
        self.assertEqual(i1.id, i2.id)
        combined = SimpleEthernet.combine_ip_fragments([i1,i2])
        e.payload = combined.pack()
        self.assertEqual(1428, len(combined.pack()))
        r.payload = e.pack()
        pw.write(r)
        pw.close()




    # Write an ICMP
    def test_writeICMP(self):

        p = pcap.Pcap("_icmp.pcap",mode='w')
        p.write_global_header()
        r = pcap.PcapRecord()
        r.setCurrentTime()

        ping_req = SimpleEthernet.ICMP()
        ping_req.type = SimpleEthernet.ICMP.TYPE_REQUEST
        ping_req.code = 0
        ping_req.request_id = 0x100
        ping_req.request_sequence = 123
        ping_req.payload = struct.pack(">32B", *range(32))

        e = SimpleEthernet.Ethernet()
        e.srcmac = 0x001122334455
        e.dstmac = 0x998877665544
        e.type = SimpleEthernet.Ethernet.TYPE_IP

        i = SimpleEthernet.IP()
        i.dstip = "235.0.0.1"
        i.srcip = "192.168.1.1"
        i.protocol = SimpleEthernet.IP.PROTOCOLS["ICMP"]
        i.payload = ping_req.pack()
        e.payload = i.pack()
        r.packet = e.pack()
        p.write(r)
        ping_req.type = SimpleEthernet.ICMP.TYPE_REPLY
        i.payload = ping_req.pack()
        e.payload = i.pack()
        p.close()

        p = pcap.Pcap("_icmp.pcap",mode='w')
        p.write_global_header()
        r = pcap.PcapRecord()
        r.setCurrentTime()
        r.packet = e.pack()
        p.write(r)
        p.close()


    def test_readIPchecksum(self):
        p = pcap.Pcap(os.path.join(THIS_DIR, "inetx_test.pcap"))
        mypcaprecord = p[0]
        e = SimpleEthernet.Ethernet()
        e.unpack(mypcaprecord.packet)
        i = SimpleEthernet.IP()
        self.assertTrue(i.unpack(e.payload))
        p.close()

    @unittest.skip("AFDX broken")
    def test_afdx(self):
        af = SimpleEthernet.AFDX()
        af.type = 1
        af.networkID = 2
        af.equipmentID = 3
        af.interfaceID = 4
        af.vlink = 5
        af.sequencenum = 0
        af.payload = struct.pack(">50B", * range(50))
        self.assertEqual(len(af.pack()), 65)
        b = af.pack()
        af2 = SimpleEthernet.AFDX()
        af2.unpack(b)
        self.assertTrue(af == af2)

    def test_igmp(self):
        #https://www.cloudshark.org/captures/b2e93fcea0c2
        exp_b = struct.pack(">HHHHHHHH", 0x2200, 0xe338, 0x0, 0x1, 0x400, 0x0, 0xefc3, 0x702)
        act_b = SimpleEthernet.IGMPv3.join_groups(["239.195.7.2"])
        self.assertEqual(exp_b, act_b)
        exp_b = struct.pack(">6I", 0x2200f33c, 0x2, 0x2000000, 0xefc30702, 0x2000000, 0xeffffffa)
        act_b = SimpleEthernet.IGMPv3.join_groups(["239.195.7.2", "239.255.255.250"])
        self.assertEqual(exp_b, act_b)

    def test_writeIGMP(self):

        p = pcap.Pcap("_igmp.pcap",mode='w')
        r = pcap.PcapRecord()
        act_b = SimpleEthernet.IGMPv3.join_groups(["239.195.7.2", "239.255.255.250"])

        e = SimpleEthernet.Ethernet()
        e.srcmac = 0x001122334455
        e.dstmac = SimpleEthernet.IGMPv3.MAC_ADDR[SimpleEthernet.IGMPv3.IP_ADDR_JOIN]
        e.type = SimpleEthernet.Ethernet.TYPE_IP

        i = SimpleEthernet.IP()
        i.dstip = SimpleEthernet.IGMPv3.IP_ADDR_JOIN
        i.srcip = "192.168.1.1"
        i.protocol = SimpleEthernet.IP.PROTOCOLS["IGMP"]
        FCS_LEN = 4
        pad_len = 64 - (len(act_b) + SimpleEthernet.Ethernet.HEADERLEN + SimpleEthernet.IP.IP_HEADER_SIZE + FCS_LEN)
        i.payload = act_b + struct.pack(">{}B".format(pad_len), *([0] * pad_len))
        e.payload = i.pack()
        r.packet = e.pack(fcs=True)
        p.write(r)
        p.close()



if __name__ == '__main__':
    unittest.main()
