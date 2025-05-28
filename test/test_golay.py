import unittest
import AcraNetwork.IRIG106.Chapter7.Golay as Golay
from pstats import Stats
import cProfile
import random
import logging
import timeit

logging.basicConfig(level=logging.DEBUG)


vectors = [
    (137, 562935),
    (2513, 10296846),
    (1614, 6613669),
    (3049, 12491018),
    (3151, 12906835),
    (2962, 12135722),
    (3708, 15190596),
    (1833, 7511303),
    (1498, 6137939),
    (735, 3011784),
    (730, 2991796),
    (3951, 16187202),
    (3638, 14902053),
    (1344, 5508118),
    (2098, 8593633),
    (1865, 7640659),
    (997, 4084270),
    (1064, 4361520),
    (2877, 11787961),
    (2249, 9213723),
    (1380, 5652556),
    (1452, 5948361),
    (2425, 9934559),
    (545, 2232654),
    (3946, 16166206),
    (412, 1687640),
    (461, 1889869),
    (2184, 8946281),
    (788, 3227948),
    (3083, 12629597),
    (2032, 8324366),
    (1647, 6747267),
    (3374, 13821272),
    (3837, 15716725),
    (423, 1735137),
    (509, 2085863),
    (2274, 9317829),
    (1078, 4415544),
    (3642, 14918772),
    (1872, 7667737),
    (2791, 11432145),
    (3293, 13490384),
    (1724, 7063666),
    (1678, 6874342),
    (184, 756662),
    (696, 2852062),
    (4070, 16673205),
    (1843, 7551640),
    (3993, 16357122),
    (3192, 13078459),
    (1468, 6013102),
    (919, 3765027),
    (2946, 12070477),
    (1280, 5243279),
    (1220, 4997871),
    (774, 3173237),
    (1084, 4441280),
    (2609, 10690140),
    (459, 1881572),
    (2261, 9261869),
    (3301, 13521084),
    (159, 652857),
    (391, 1605420),
    (2074, 8498154),
    (1927, 7894655),
    (2079, 8518038),
    (470, 1927481),
    (2780, 11389288),
    (1507, 6174932),
    (3026, 12394675),
    (1354, 5548270),
    (338, 1384564),
    (2239, 9174145),
    (3098, 12692945),
    (2216, 9077924),
    (310, 1270199),
    (2393, 9801746),
    (597, 2446314),
    (2208, 9046370),
    (2443, 10007560),
    (2704, 11076512),
    (1162, 4759833),
    (2032, 8324366),
    (2023, 8289579),
    (3925, 16080400),
    (2922, 11971333),
    (3804, 15585107),
    (3219, 13187878),
    (3018, 12365330),
    (4006, 16409644),
    (3230, 13231260),
    (1846, 7563492),
    (1107, 4536592),
    (3734, 15296050),
    (851, 3487735),
    (420, 1722420),
    (2863, 11728096),
    (2480, 10161585),
    (3151, 12906835),
    (2070, 8481979),
    (2998, 12280176),
    (1761, 7215414),
    (2206, 9036455),
    (4025, 16486863),
    (1393, 5706071),
    (1643, 6733332),
    (3568, 14616083),
    (524, 2148409),
    (308, 1263753),
    (3881, 15896946),
    (2813, 11523918),
    (141, 580704),
    (1513, 6200364),
    (2528, 10355535),
    (2814, 11527835),
    (3189, 13062145),
    (1648, 6750560),
    (4039, 16545683),
    (1475, 6045209),
    (813, 3330475),
    (2210, 9052252),
    (2682, 10989526),
    (2011, 8241104),
    (886, 3629894),
    (626, 2567781),
    (1522, 6234968),
    (4020, 16469621),
    (166, 681662),
    (2145, 8789962),
    (1855, 7601609),
    (3758, 15396446),
    (2886, 11823769),
    (258, 1060490),
    (1049, 4296817),
    (343, 1405448),
    (2479, 10156114),
    (523, 2143099),
    (944, 3870380),
    (2698, 11052095),
    (935, 3831433),
    (4019, 16463159),
    (2339, 9583833),
    (3916, 16042074),
    (509, 2085863),
    (1693, 6936148),
    (388, 1593081),
    (2773, 11361349),
    (1936, 7933530),
    (1759, 7205619),
    (2816, 11535529),
    (1141, 4676724),
    (2264, 9276567),
    (3630, 14871940),
    (2891, 11842851),
    (475, 1947267),
    (2224, 9112069),
    (371, 1523282),
    (1942, 7958003),
    (894, 3665536),
    (92, 379311),
    (477, 1955114),
    (120, 493045),
    (1959, 8024242),
    (1483, 6075359),
    (766, 3140334),
    (1043, 4273289),
    (2056, 8421811),
    (3520, 14418873),
    (1773, 7265895),
    (2736, 11208045),
    (2854, 11690445),
    (1115, 4568278),
    (4052, 16598305),
    (993, 4069561),
    (1472, 6033356),
    (3170, 12986404),
    (3997, 16375189),
    (3554, 14560330),
    (2667, 10925146),
    (833, 3415470),
    (1862, 7626967),
    (206, 843820),
    (2687, 11009450),
    (2781, 11391363),
    (2535, 10385421),
    (366, 1499791),
    (2783, 11401405),
    (2990, 12251089),
    (276, 1134148),
    (1748, 7163616),
    (760, 3115335),
    (1261, 5165327),
    (2148, 8801718),
    (2842, 11641654),
    (3912, 16024269),
    (1626, 6660949),
    (2385, 9772500),
    (704, 2883883),
    (2593, 10624315),
    (1178, 4825726),
]


class GolayTestCase(unittest.TestCase):

    def test_encode(self):
        g = Golay.Golay()
        for attempt in range(200):
            input = random.randint(0, 0xFFF)
            # print("{:0X}".format(g2.decode(g.encode(raw))))
            self.assertEqual(input, g.decode(g.encode(input)))
            # print(f"({input}, {g.encode(input)}),", end="")

    def test_encode_vectors(self):
        g = Golay.Golay()
        for input, output in vectors:
            self.assertEqual(output, g.encode(input))

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
        # print(repr(g.decode(v)))

    @unittest.skip("Not working in c")
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
                    encoded ^= 1 << b
                logging.debug("Errorbits={} {:#0X}".format(bits_to_flip, encoded))
                decoded = g.decode(encoded)
                logging.debug("Decoded={:#X} Errors={}".format(g.decode(encoded), g.errors(encoded)))
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
        p.sort_stats("cumtime")
        # p.print_stats()

    def test_profile(self):
        g = Golay.Golay()
        g2 = Golay.Golay()
        for val in range(100, 2000):
            # val = 100

            # print("{:0X}".format(g2.decode(g.encode(raw))))
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

        # print timeit.timeit('import AcraNetwork.Golay as Golay; Golay.Golay._onesincode(0x2, 24)', number=10000)
        # print timeit.timeit('import AcraNetwork.Golay as Golay; Golay.Golay._onesincode2(0x2, 24)', number=10000)

    @unittest.skip("Don't include profiling")
    def test_timeit(self):
        print("timed=")
        print(
            timeit.timeit(
                "g.decode(g.encode(100))",
                setup="import AcraNetwork.IRIG106.Chapter7.Golay as Golay; g=Golay.Golay()",
                number=100000,
            )
        )


if __name__ == "__main__":
    unittest.main()
