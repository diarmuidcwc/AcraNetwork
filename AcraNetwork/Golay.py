"""
.. module:: Golay
    :platform: Unix, Windows
    :synopsis: Encode and decode Golay Codes based on IRIG106 Standard http://www.irig106.org/docs/106-17/chapter7.pdf

.. moduleauthor:: Diarmuid Collins <dcollins@curtisswright.com>

"""
__author__ = "Diarmuid Collins"
__copyright__ = "Copyright 2020"
__maintainer__ = "Diarmuid Collins"
__email__ = "dcollins@curtisswright.com"
__status__ = "Production"


# This is a direct porting of the C code from the IRIG106 starndard.
import struct
try:
    from functools import lru_cache
except:
    from functools import wraps
    # Python2 compatiabilitu
    def lru_cache(_func=None, maxsize=2):
        def decorator_repeat(func):
            @wraps(func)
            def wrapper_repeat(*args, **kwargs):
                return func(*args, **kwargs)
            return wrapper_repeat

        if _func is None:
            return decorator_repeat
        else:
            return decorator_repeat(_func)

GOLAY_SIZE = 0x1000

G_P = [
0xc75, 0x63b, 0xf68, 0x7b4,
0x3da, 0xd99, 0x6cd, 0x367,
0xdc6, 0xa97, 0x93e, 0x8eb]

H_P = [
0xa4f, 0xf68, 0x7b4, 0x3da,
0x1ed, 0xab9, 0xf13, 0xdc6,
0x6e3, 0x93e, 0x49f, 0xc75
]


class Golay():
    """
    Encode and Decode Golay numbers
    """
    def __init__(self):
        self.SyndromeTable = [0] * GOLAY_SIZE
        self.CorrectTable = [0] * GOLAY_SIZE
        self.ErrorTable = [0] * GOLAY_SIZE

    
    @staticmethod
    @lru_cache()
    def _init_Table():
        EncodeTable = [0] * GOLAY_SIZE
        for x in range(GOLAY_SIZE):
            EncodeTable[x] = (x << 12)
            for i in range(12):
                if (x >> (11 - i) & 1):
                    EncodeTable[x] ^= G_P[i]

        return EncodeTable

    @lru_cache(maxsize=20)
    def encode(self, raw, as_string=False):
        """
        Encode the value as a 24b code

        :type raw: int
        :return: int
        """
        if 0xFFF < raw < 0:
            raise Exception("Converestion of 12b value only")

        EncodeTable = Golay._init_Table()
        encoded = EncodeTable[raw & 0xfff]
        if as_string:
            return struct.pack(">BH", encoded >> 16, encoded & 0xFFFF)
        else:
            return encoded
            
    @lru_cache(maxsize=20)
    def decode(self, encoded):
        """
        Decode a 24b number as a golay

        :type encoded: int|bytes
        :param encoded:
        :return:
        """
        if type(encoded) is bytes:
            if len(encoded) != 3:
                raise Exception("String to decode should be 3 bytes")
            (b,w) = struct.unpack(">BH", encoded)
            v = w + (b << 16)
        elif 0xFFFFF < encoded < 0:
            raise Exception("Only supports 24b unsigned numbers")
        else:
            v = encoded

        self._initgolaydecode()
        return self._decode2(((v) >> 12) & 0xfff, (v) & 0xfff)

    def _syndrome2(self, v1, v2):
        return self.SyndromeTable[v2] ^ (v1)

    def _syndrome(self, v):
        return self._syndrome2(((v) >> 12) & 0xfff, (v) & 0xfff)

    def _errors2(self, v1, v2):
        return self.ErrorTable[self._syndrome2(v1, v2)]

    def _decode2(self, v1, v2):
        return (v1) ^ self.CorrectTable[self._syndrome2(v1, v2)]

    def _errors(self, v):
        return self._errors2(((v) >> 12) & 0xfff, (v) & 0xfff)

    @staticmethod
    def _onesincode(code, size):
        """Optimised version of the code below. Runs 2x"""
        return bin(code)[2:size+2].count('1')

    @staticmethod
    def _onesincode_old(code, size):
        ret = 0

        for t in range(size):
            if (code >> t) & 1:
                ret += 1

        return ret

    @lru_cache()
    def _initgolaydecode(self):
        for x in range(GOLAY_SIZE):
            self.SyndromeTable[x] = 0
            for i in range(12):
                if ( x >> (11-i)) & 1:
                    self.SyndromeTable[x] ^= H_P[i]
                    self.ErrorTable[x] = 4
                    self.CorrectTable[x] = 0xFFF

        self.ErrorTable[0] = 0
        self.CorrectTable[0] = 0
        for i in range(24):
            for j in range(24):
                for k in range(24):
                    error = (1 << i) | (1 << j) | (1 << k)
                    syndrom = self._syndrome(error)
                    self.CorrectTable[syndrom] = (error >> 12) & 0xfff
                    self.ErrorTable[syndrom] = Golay._onesincode(error, 24)

        return True
