import sys
sys.path.append("..")
import unittest
import AcraNetwork.Golay as Golay
from pstats import Stats
import cProfile
import random
import logging
import timeit

logging.basicConfig(level=logging.INFO)


class GolayTestCase(unittest.TestCase):

    def test_encode(self):
        g = Golay.Golay()
        for attempt in range(20):
            input = random.randint(0, 0xFFF)
            #print("{:0X}".format(g2.decode(g.encode(raw))))
            self.assertEqual(input, g.decode(g.encode(input)))

    def test_encode_string(self):
        g = Golay.Golay()
        v = 0x101
        s = g.encode(v, as_string=True)
        self.assertEqual(3, len(s))
        dec = g.decode(s)
        self.assertEqual(v, dec)

    def test_decode(self):
        g = Golay.Golay()
        v = 0x1007B408A722
        #print(repr(g.decode(v)))

    def test_with_error(self):
        g = Golay.Golay()
        for attempt in range(6):
            for error_bits in range(0, 7):
                logging.debug("----{}----".format(error_bits))
                input = random.randint(0, 0xFFF)
                encoded = g.encode(input)
                logging.debug("Raw={:#0X} Encoded={:#0X}".format(input, encoded))
                # Introduce errors
                bits_to_flip = random.sample(range(16), error_bits)
                for b in bits_to_flip:
                    encoded ^= (1 << b)
                logging.debug("Errorbits={} {:#0X}".format(bits_to_flip, encoded))
                decoded = g.decode(encoded)
                logging.debug("Decoded={:#X} Errors={}".format(g.decode(encoded), g._errors(encoded)))
                if error_bits < 4:
                    self.assertEqual(input, decoded)
                else:
                    self.assertNotEqual(input, decoded)



class GolayProfile(unittest.TestCase):

    def setUp(self):
        self.pr = cProfile.Profile()
        self.pr.enable()

    def tearDown(self):
        p = Stats(self.pr)
        p.sort_stats('cumtime')
        #p.print_stats()

    def test_profile(self):
        g = Golay.Golay()
        g2 = Golay.Golay()
        for val in range(100, 2000):
            #val = 100
            
            #print("{:0X}".format(g2.decode(g.encode(raw))))
            self.assertEqual(val, g2.decode(g.encode(val)))
        # Original implementation
        #         ncalls  tottime  percall  cumtime  percall filename:lineno(function)
        #         1    0.002    0.002    1.063    1.063 C:\ACRA\WORK\AXN_ENC_402\TICAD021\TICAD021\testbench\AcraNetwork\test\test_golay.py:69(test_profile)
        #     20    0.000    0.000    0.847    0.042 ..\AcraNetwork\Golay.py:70(decode)
        #     20    0.511    0.026    0.847    0.042 ..\AcraNetwork\Golay.py:121(_initgolaydecode)
        #     20    0.000    0.000    0.213    0.011 ..\AcraNetwork\Golay.py:53(encode)
        #     20    0.213    0.011    0.213    0.011 ..\AcraNetwork\Golay.py:42(_init_Table)
        # 276480    0.111    0.000    0.194    0.000 ..\AcraNetwork\Golay.py:106(_onesincode)
        # 276480    0.097    0.000    0.142    0.000 ..\AcraNetwork\Golay.py:94(_syndrome)
        # 276480    0.046    0.000    0.046    0.000 {method 'count' of 'str' objects}
        # 276500    0.045    0.000    0.045    0.000 ..\AcraNetwork\Golay.py:91(_syndrome2)
        # 276480    0.037    0.000    0.037    0.000 {built-in method builtins.bin}
        #     40    0.001    0.000    0.001    0.000 ..\AcraNetwork\Golay.py:37(__init__)

    def test_bits(self):
        error = 0x3
        size = 24
        for code in [0x0, 0x1, 0x37, 0xFFFFFF]:
            self.assertEqual(Golay.Golay._onesincode_old(code, size), Golay.Golay._onesincode(code, size))

        #print timeit.timeit('import AcraNetwork.Golay as Golay; Golay.Golay._onesincode(0x2, 24)', number=10000)
        #print timeit.timeit('import AcraNetwork.Golay as Golay; Golay.Golay._onesincode2(0x2, 24)', number=10000)

if __name__ == '__main__':
    unittest.main()
