import sys
sys.path.append("..")

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

# Test data for decode.
# Elements are (codeword, dataword, clean, bit_err).
#   codeword = value to put into decoder
#   dataword = expected output from decoder
#   clean    = dataword, encoded, with no bits flipped
#   bit_err  = count of bit differences beetween codeword and clean
# Golay can correct up to 3 bit errors. If bit_err > 3 then codeword is
# actually the encoding of a different dataword, but with 4 bit errors.
# That dataword cannot be determined.
# Generated by decode.py on 2025-06-30 17:37:36.881539.
testdata_decode = (
                    (0x00000000,    0, 0x00000000,   0 ),
                    (0x0002BADE,   43, 0x0002BADE,   0 ),
                    (0x00055882,   85, 0x00055C82,   1 ),
                    (0x0007C98F,   92, 0x0005C9AF,   2 ),
                    (0x000A6BF3,   34, 0x00022FF3,   3 ),
                    (0x000CDDAF, 3890, 0x00F32E06,  18 ),
                    (0x000F70AB,  247, 0x000F70AB,   0 ),
                    (0x0011E6C9, 2334, 0x0091E6C9,   1 ),
                    (0x00147607,  839, 0x00347E07,   2 ),
                    (0x001716EB, 1137, 0x004716E3,   3 ),
                    (0x00198CB2, 3687, 0x00E67530,  16 ),
                    (0x001C09F7,  448, 0x001C09F7,   0 ),
                    (0x001E8BC2,  490, 0x001EABC2,   1 ),
                    (0x0020FF97, 1551, 0x0060FFD7,   2 ),
                    (0x00237D59,  631, 0x00277C19,   3 ),
                    (0x0025EABB, 3489, 0x00DA1006,  20 ),
                    (0x002877F0,  647, 0x002877F0,   0 ),
                    (0x002B1229,  561, 0x00231229,   1 ),
                    (0x002DBE9F,  731, 0x002DBE5F,   2 ),
                    (0x00305AD5, 2821, 0x00B056D5,   3 ),
                    (0x0032F24D, 3280, 0x00CD076A,  18 ),
                    (0x0035A2DA,  858, 0x0035A2DA,   0 ),
                    (0x003835BB,  387, 0x001835BB,   1 ),
                    (0x003ABE87,  682, 0x002AAE87,   2 ),
                    (0x003D6E15,  982, 0x003D6651,   3 ),
                    (0x003FF006, 3072, 0x00C00A4E,  16 ),
                    (0x0042A40E, 1066, 0x0042A40E,   0 ),
                    (0x00454469,   84, 0x00054469,   1 ),
                    (0x0047C77F, 1117, 0x0045D77F,   2 ),
                    (0x004A68FB, 1188, 0x004A49BB,   3 ),
                    (0x004CD18C, 2866, 0x00B3283D,  18 ),
                    (0x004F7690, 1271, 0x004F7690,   0 ),
                    (0x0052126F, 1321, 0x0052926F,   1 ),
                    (0x0054BB6D, 1867, 0x0074BF6D,   2 ),
                    (0x00575EDA, 1661, 0x0067DEDA,   3 ),
                    (0x0059DD7B, 2658, 0x00A62177,  16 ),
                    (0x005C820A, 1480, 0x005C820A,   0 ),
                    (0x005F108D, 1521, 0x005F128D,   1 ),
                    (0x0061C2FC, 1628, 0x0065C0FC,   2 ),
                    (0x006450FF, 1637, 0x0066507B,   3 ),
                    (0x0066BC37, 2452, 0x009941EB,  20 ),
                    (0x0069383B, 1683, 0x0069383B,   0 ),
                    (0x006BD343, 1597, 0x0063D343,   1 ),
                    (0x006E4F4E, 1764, 0x006E4B4A,   2 ),
                    (0x0070FB94, 1823, 0x0071FB04,   3 ),
                    (0x0073B104, 2244, 0x008C48A1,  18 ),
                    (0x00762C8D, 1890, 0x00762C8D,   0 ),
                    (0x0078ADC5, 1930, 0x0078A9C5,   1 ),
                    (0x007B4893, 1968, 0x007B0897,   2 ),
                    (0x007DE941, 2046, 0x007FEB61,   3 ),
                    (0x0080761B, 2040, 0x007F88C8,  20 ),
                    (0x008309DF, 2096, 0x008309DF,   0 ),
                    (0x00857FF2, 3159, 0x00C57FF2,   1 ),
                    (0x00882F2F, 2176, 0x00880FAF,   2 ),
                    (0x008ADD06, 2093, 0x0082D502,   3 ),
                    (0x008D9305, 1830, 0x00726B83,  16 ),
                    (0x00900BC1, 2304, 0x00900BC1,   0 ),
                    (0x0092A69C, 2858, 0x00B2A69C,   1 ),
                    (0x00955B26,  341, 0x00155B36,   2 ),
                    (0x0097CCBD, 2430, 0x0097ED9D,   3 ),
                    (0x009A3D25, 1628, 0x0065C0FC,  20 ),
                    (0x009CB991, 2507, 0x009CB991,   0 ),
                    (0x009F48BF, 2548, 0x009F4ABF,   1 ),
                    (0x00A1F469, 2587, 0x00A1BC69,   2 ),
                    (0x00A49E40, 3785, 0x00EC9E48,   3 ),
                    (0x00A7088E, 1423, 0x0058F4D1,  20 ),
                    (0x00A9BFB3, 2715, 0x00A9BFB3,   0 ),
                    (0x00AC71A8, 3015, 0x00BC71A8,   1 ),
                    (0x00AEFECF, 2671, 0x00A6FECD,   2 ),
                    (0x00B18AF3, 2841, 0x00B192E3,   3 ),
                    (0x00B40E54, 1215, 0x004BF6CF,  18 ),
                    (0x00B6823B, 2920, 0x00B6823B,   0 ),
                    (0x00B8F5F7, 2959, 0x00B8F1F7,   1 ),
                    (0x00BBA1D5, 2746, 0x00ABA195,   2 ),
                    (0x00BE1D9E, 3553, 0x00DE1D9F,   3 ),
                    (0x00C0AF06, 1013, 0x003F5149,  20 ),
                    (0x00C33E31, 3123, 0x00C33E31,   0 ),
                    (0x00C5A976, 3160, 0x00C58976,   1 ),
                    (0x00C82555, 3718, 0x00E86555,   2 ),
                    (0x00CAC899, 3244, 0x00CAC808,   3 ),
                    (0x00CD4617,  811, 0x0032B202,  16 ),
                    (0x00CFBDB4, 3323, 0x00CFBDB4,   0 ),
                    (0x00D23697, 1315, 0x00523697,   1 ),
                    (0x00D4C4C8, 3532, 0x00DCC4E8,   2 ),
                    (0x00D75519, 3965, 0x00F7D51B,   3 ),
                    (0x00D9F428,  608, 0x0026043C,  14 ),
                    (0x00DC8E7F, 3528, 0x00DC8E7F,   0 ),
                    (0x00DF22B4, 3506, 0x00DB22B4,   1 ),
                    (0x00E193E4, 3609, 0x00E1936C,   2 ),
                    (0x00E44500, 3140, 0x00C44D40,   3 ),
                    (0x00E6EF11,  401, 0x00191FE2,  18 ),
                    (0x00E97ED9, 3735, 0x00E97ED9,   0 ),
                    (0x00EC01F2, 3780, 0x00EC41F2,   1 ),
                    (0x00EE95ED, 3305, 0x00CE97ED,   2 ),
                    (0x00F10438, 3888, 0x00F30738,   3 ),
                    (0x00F3A021,  197, 0x000C5C3F,  18 ),
                    (0x00F65BBA, 3941, 0x00F65BBA,   0 ),
                    (0x00F8EF07, 3982, 0x00F8EF27,   1 ),
                    (0x00FB822F, 3984, 0x00F9022F,   2 ),
                    (0x00FE2EB7, 4002, 0x00FA2EBB,   3 ),
                    (0x00FFFFFF, 4095, 0x00FFFFFF,   0 ),
                  # 101 entries in list
                  #  21 values with 0 bit errors
                  #  20 values with 1 bit errors
                  #  20 values with 2 bit errors
                  #  20 values with 3 bit errors
                  #  19 values with >= 4 bit errors
                  )



class GolayTestCase(unittest.TestCase):

    def test_encode(self):
        g = Golay.Golay()
        for attempt in range(200):
            input = random.randint(0, 0xFFF)
            # print("{:0X}".format(g2.decode(g.encode(raw))))
            self.assertEqual(input, g.decode(g.encode(input)))
            # print(f"({input}, {g.encode(input)}),", end="")
            
    def test_encode_too_big(self):
        g = Golay.Golay()
        # Attempting to encode a value > 0xFFF should raise an exception
        # a) last legal value does not raise an exception
        #    Using the C reference code, 0xFFF encodes to 0xFFFFFF
        exc = None
        v = None
        try:
            v = g.encode(0xFFF) # no exception
        except ValueError as e:
            exc = str(e)
        self.assertIs(exc, None) 
        self.assertEqual(v, 0xFFFFFF) 
        
        # b) illegal value does raise an exception
        exc = None
        v = None
        try:
            v = g.encode(0xFFF + 1) # raises exception
        except ValueError as e:
            exc = str(e)
        self.assertEqual(exc, "Only 12-bit unsigned values allowed") 
        self.assertIs(v, None)

    def test_encode_vectors(self):
        g = Golay.Golay()
        for input, output in vectors:
            self.assertEqual(output, g.encode(input))

    def test_encode_string(self):
        # Encode with as_string=True; actually returns bytes, not string
        g = Golay.Golay()
        v = 0x101
        s = g.encode(v, as_string=True)
        self.assertEqual(3, len(s))
        dec = g.decode(s)
        self.assertEqual(v, dec)

    def test_errors(self):
        # Check that up to 4 bit errors can be detected and that up to 3
        # bit errors will be corrected.
        g = Golay.Golay()
        for check in testdata_decode:
            dataword  = check[1] # value to be encoded
            codeword  = check[2] # this is the encoding with no bit errors
            
            # Golay should correct up to 3 bit errors, detect up to 4.
            flipped = [] # bits that have been flipped
            
            # # Print the codeword before it gets corrupted...
            # print(f"{dataword}: {codeword:6X} ", end="")
            
            while len(flipped) < 4:
                # find a bit to flip that has not already been flipped
                while 1:
                    err_bit = random.randint(0,23)
                    if err_bit not in flipped:
                        break
                flipped.append(err_bit)
                codeword ^= 1<<err_bit
                
                # # ...and print the codeword AS it gets corrupted
                # print(f"-> {flipped}:{codeword:6X} ", end="")
                
                self.assertEqual(g.errors(codeword), len(flipped))
                
                if len(flipped) <= 3:
                    # print("(dec) ", end="")
                    self.assertEqual(g.decode(codeword), dataword)
                    
            # # end the print line with the codeword getting corrupted
            # print()
    
    def test_decode_bytearray(self):
        # decode can now take bytearray(), bytes() or integer
        g = Golay.Golay()
        for dataword, codeword in vectors:
            cw_b = codeword.to_bytes(3, "big") # codeword, as bytes 
            cw_ba = bytearray(cw_b)     # codeword, as a bytearray object
            self.assertEqual(dataword, g.decode(codeword))
            self.assertEqual(dataword, g.decode(cw_b)    )
            self.assertEqual(dataword, g.decode(cw_ba)   )


    def test_decode(self):
        g = Golay.Golay()
        for check in testdata_decode:
            # check[0] is a codeword that may have bit errors
            # check[1] is the decoded value of check[0]
            # check[2] is the codeword for check[1], with no bit errors
            # check[3] is the number of bit differences between check [0] 
            # and check[2]. If this is > 3 then there are 4 bit errors but
            # the dataword cannot be determined; it is not check[1] and so
            # the count in check[3] corresponds to errors()==4
            dec_input = check[0] # decoder should output dataword for this
            dataword  = check[1] # expected decoder output
            codeword  = check[2] # encoding of dataword, with no bit errors
            err_bits  = check[3]
            decoded1 = g.decode(dec_input)
            decoded2 = g.decode(codeword)
            self.assertEqual(decoded1, dataword)
            self.assertEqual(decoded2, dataword)
            
            # just an extra check of testdata_decode
            self.assertEqual(g.encode(dataword), codeword)
            
            # Expected return value of the errors() function
            exp_err = err_bits if err_bits <= 3 else 4
            self.assertEqual(g.errors(dec_input), exp_err)
            
            # Up to 3 error bits, the decoding should be ok
            # That means for up to 3 corruptions of the 24-bit 'codeword', it
            # should still decode to 'dataword'
            # Start with codeword which has no bit errors            
            self.assertEqual(g.errors(codeword), 0)
            flipped = []
            for i in range(3):
                # Pick a bit to flip, but be sure to pick one that was not 
                # already flipped! That would make errors() decrease, because
                # it would be a correction of a previous error
                while True:
                    to_flip = random.randint(0,23)
                    if to_flip not in flipped:
                        break
                flipped.append(to_flip)
                
                codeword ^= 1<<to_flip
                self.assertEqual(g.errors(codeword), i+1)
                self.assertEqual(g.decode(codeword), dataword)
                
    def test_decode_too_big(self):
        g = Golay.Golay()
        # Attempting to decode a bytes value that is not exactly 3 bytes
        # or an integer value < 0xFFFFFF should raise an exception
        
        # From the reference encoder, dataword 3361 encodes as 0x00D213DC
        dataword = 3361
        codeword_b_too_long  = bytes((0x00, 0xD2, 0x13, 0xDC))
        codeword_b_ok        = codeword_b_too_long[1:]
        codeword_b_too_short = codeword_b_too_long[2:]

        # a) passing an array of bytes
        exc = None
        v = None
        try:
            v = g.decode(codeword_b_too_long)
        except ValueError as e:
            exc = str(e)
        self.assertIs(v, None) 
        self.assertEqual(exc, "3-byte input required") 

        exc = None
        v = None
        try:
            v = g.decode(codeword_b_ok)
        except ValueError as e:
            exc = str(e)
        self.assertEqual(v, dataword) 
        self.assertIs(exc, None) 

        exc = None
        v = None
        try:
            v = g.decode(codeword_b_too_short)
        except ValueError as e:
            exc = str(e)
        self.assertIs(v, None) 
        self.assertEqual(exc, "3-byte input required") 

        
        # b) passing an integer value
        # From the reference decoder we know 0xFFFFFF decodes as 0xFFF
        dataword = 0xFFF
        codeword_i_ok      = 0x00FFFFFF
        codeword_i_too_big = 0x01000000
        
        exc = None
        v = None
        try:
            v = g.decode(codeword_i_ok)
        except ValueError as e:
            exc = str(e)
        self.assertIs(exc, None) 
        self.assertEqual(v, dataword) 
        
        exc = None
        v = None
        try:
            v = g.decode(codeword_i_too_big)
        except ValueError as e:
            exc = str(e)
        self.assertIs(v, None) 
        self.assertEqual(exc, "Only 24-bit unsigned values supported") 


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
