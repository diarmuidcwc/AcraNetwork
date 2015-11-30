__author__ = 'DCollins'
import sys
sys.path.append("..")

import unittest
import AcraNetwork.SimpleEthernet as SimpleEthernet
import AcraNetwork.Pcap as pcap

class afdxTest(unittest.TestCase):
    def test_defaultAFDX(self):
        a = SimpleEthernet.AFDX()
        self.assertEqual(a.equipmentID,None)
        self.assertEqual(a.interfaceID,None)
        self.assertEqual(a.networkID,None)
        self.assertEqual(a.payload,None)
        self.assertEqual(a.sequencenum,None)
        self.assertEqual(a.vlink,None)



if __name__ == '__main__':
    unittest.main()
