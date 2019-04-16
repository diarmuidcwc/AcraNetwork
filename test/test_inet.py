import unittest
import AcraNetwork.iNET as iNET
import os
import AcraNetwork.SimpleEthernet as SimpleEthernet
import AcraNetwork.Pcap as pcap
import struct

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
    u.dstport = 6678
    u.srcport = 6678
    u.payload = data
    i.payload = u.pack()
    e.payload = i.pack()
    return e.pack()


class testINET(unittest.TestCase):

    def setUp(self):

        self.pkg = iNET.iNETPackage()
        self.pkg.definitionID = 7
        self.pkg.flags = 8
        self.pkg.timedelta = 99
        self.pkg.payload = struct.pack(">B", 0xA)

        self.i = iNET.iNET()
        self.i.flags = 0
        self.i.type = 1
        self.i.definition_ID = 0xdc
        self.i.sequence = 3
        self.i.ptptimeseconds = 100
        self.i.ptptimenanoseconds = 1000
        self.i.app_fields = [0x30, 0x40]
        self.i.packages.append(self.pkg)

        for pkg_idx in range(2,5):
            pkg = iNET.iNETPackage()
            pkg.definitionID = 7
            pkg.flags = 8
            pkg.timedelta = 0x99
            payload = list(range(pkg_idx))
            pkg.payload = struct.pack(">{}B".format(pkg_idx), *payload )
            self.i.packages.append(pkg)

    def test_unpack_compare(self):

        d= iNET.iNET()
        d.unpack(self.i.pack())
        self.assertEqual(d.flags, self.i.flags)
        self.assertEqual(d.type, self.i.type)
        self.assertEqual(d.type, self.i.type)
        self.assertEqual(d.definition_ID, self.i.definition_ID)
        self.assertEqual(d.sequence, self.i.sequence)
        self.assertEqual(d.ptptimeseconds, self.i.ptptimeseconds)
        self.assertEqual(d.ptptimenanoseconds, self.i.ptptimenanoseconds)
        self.assertEqual(d.app_fields, self.i.app_fields)
        self.assertEqual(d._payload, self.i._payload)
        for idx, pkg in enumerate(d.packages):
            self.assertEqual(pkg.payload, self.i.packages[idx].payload)
            self.assertEqual(pkg.definitionID, self.i.packages[idx].definitionID)
            self.assertEqual(pkg.timedelta, self.i.packages[idx].timedelta)
            self.assertEqual(pkg.flags, self.i.packages[idx].flags)

        self.assertTrue(self.i == d)

    def test_topcap(self):
        pcapw = pcap.Pcap(os.path.join(THIS_DIR, "test_inet.pcap"), mode="w")
        pcapw.write_global_header()
        rec = pcap.PcapRecord()
        for pkg_idx in range(2,5):
            pkg = iNET.iNETPackage()
            pkg.definitionID = 7
            pkg.flags = 8
            pkg.timedelta = 99
            payload = list(range(pkg_idx))
            pkg.payload = struct.pack(">{}B".format(pkg_idx), *payload )
            self.i.packages.append(pkg)
        rec.payload = getEthernetPacket(self.i.pack())
        pcapw.write(rec)
        pcapw.close()


    def test_print(self):
        self.assertEqual(repr(self.i), "MessageDefinitionID=0XDC Sequence=3 Type=1 TimeStamp(s)=100 TimeStamp(ns)=1000 OptionWordCount=0")

    def test_len(self):

        self.assertEqual(len(self.i), 96)

    def test_pack(self):

        ref_str = self.i.pack()
        i2 = iNET.iNET()
        i2.unpack(ref_str)

        self.assertEqual(self.i, i2)


if __name__ == '__main__':
    unittest.main()
