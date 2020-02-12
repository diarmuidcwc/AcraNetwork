import unittest
import AcraNetwork.Golay as Golay
from pstats import Stats
import cProfile
import random
import logging

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

        val = 100
        g = Golay.Golay()
        g2 = Golay.Golay()
        # print("{:0X}".format(g2.decode(g.encode(raw))))
        self.assertEqual(val, g2.decode(g.encode(val)))

if __name__ == '__main__':
    unittest.main()
