import sys
sys.path.append("..")

import unittest
from AcraNetwork.ptptime import ptptime, timefromsbi


class PTPTestCase(unittest.TestCase):

    def test_something(self):

        t = ptptime(2000,1,2,0,0,0,0)
        #print(t.irigtime())

        t2 = ptptime(year=1970, month=1, day=1, hour=23, minute=1, second=20, microsecond=100, nanosecond=1)
        #print t2
        (hi, lo ,mu) = t2.irigtime()
        #print "hi={:#0X} lo={:#0X} mu={:#0X}".format(hi, lo, mu)
        #print "hr={:#0X} min={:#0X} lo={:#0X} mu={:#0X}".format(hi>>7, hi&0x7F, lo, mu)

    def test_irig(self):
        s = 0x123456
        t = timefromsbi(s)
        #print(t.microsecond)

if __name__ == '__main__':
    unittest.main()
