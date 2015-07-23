#!/usr/bin/env python
"""
This is the front end to the pcapfile test SUITE.
"""

import unittest


from AcraNetwork.test.test_pcap import PcapBasicTest as PcapBasicTest 
from AcraNetwork.test.test_ethernet import EthernetTest as EthernetTest
from AcraNetwork.test.test_iena import IENATest as IENATest
from AcraNetwork.test.test_inetx import iNetXTest as iNetXTest
#from AcraNetwork.test.test_mpegts import MPEGTSBasicTest as MPEGTSBasicTest

if __name__ == '__main__':
    TEST_CLASSES = [PcapBasicTest, EthernetTest, IENATest, iNetXTest,]
    SUITE = unittest.TestSuite()
    LOADER = unittest.TestLoader()
    for test_class in TEST_CLASSES:
        SUITE.addTests(LOADER.loadTestsFromTestCase(test_class))
    unittest.TextTestRunner(verbosity=2).run(SUITE)
