__author__ = "diarmuid"
import unittest
from AcraNetwork import endianness_swap
import struct
import timeit


class MiscTest(unittest.TestCase):
    def test_endianness(self):
        buf = struct.pack(">BBBB", 1, 2, 3, 4)
        swap2 = struct.pack(">BBBB", 2, 1, 4, 3)
        swap4 = struct.pack(">BBBB", 4, 3, 2, 1)
        self.assertEqual(endianness_swap(buf), swap2)
        self.assertEqual(endianness_swap(buf, 4), swap4)

    def test_endianness_wrong_size(self):
        buf = struct.pack(">BBB", 1, 2, 3)
        try:
            endianness_swap(buf, 4)
        except:
            self.assertTrue(True)
        else:
            self.assertTrue(False)

    @unittest.skip("Performance check")
    def test_endiannessperf(self):
        rt = timeit.timeit(
            "endianness_swap(b'\x01\x02\x03\x04', 2)",
            number=1_000_000,
            setup="from AcraNetwork import endianness_swap",
        )
        print(rt)
