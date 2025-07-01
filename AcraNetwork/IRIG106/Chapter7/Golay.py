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
from functools import lru_cache
import warnings

try:
    from . import golay_c as _golay_native

    _use_c_extension = True
except ImportError:
    warnings.warn("C extension for Golay not found. Falling back to pure Python.", RuntimeWarning)
    _use_c_extension = False


GOLAY_SIZE = 0x1000
G_P = [0xC75, 0x63B, 0xF68, 0x7B4, 0x3DA, 0xD99, 0x6CD, 0x367, 0xDC6, 0xA97, 0x93E, 0x8EB]
H_P = [0xA4F, 0xF68, 0x7B4, 0x3DA, 0x1ED, 0xAB9, 0xF13, 0xDC6, 0x6E3, 0x93E, 0x49F, 0xC75]


class Golay:
    """
    Encode and Decode Golay numbers
    """

    # Look-up tables are class variables. They will be initialised by the
    # constructor of the first instance of the Golay class to be created.
    # Set them to None here so the constructor can tell that they must be
    # set up.
    EncodeTable = None
    SyndromeTable = None
    CorrectTable = None
    ErrorTable = None

    def __init__(self):
        if _use_c_extension:
            _golay_native.golay_init_tables()
        else:
            if Golay.EncodeTable is None:        
                self._init_encode_table()
            self._initgolaydecode()


    def _init_encode_table(self):
        Golay.EncodeTable = [0] * GOLAY_SIZE
        for x in range(GOLAY_SIZE):
            Golay.EncodeTable[x] = x << 12
            for i in range(12):
                if x >> (11 - i) & 1:
                    Golay.EncodeTable[x] ^= G_P[i]

    def encode(self, raw, as_string=False):
        if not (0 <= raw <= 0xFFF):
            raise ValueError("Only 12-bit unsigned values allowed")

        if _use_c_extension:
            encoded = _golay_native.golay_encode(raw)
        else:
            encoded = self._encode_python(raw)

        if as_string:
            return encoded.to_bytes(3, "big")
        return encoded

    def decode(self, encoded):
        if _use_c_extension:
            return _golay_native.golay_decode(encoded)
        else:
            # encoded is either an integer <= 0xFFFFFF, or is a bytes-like type
            if not isinstance(encoded, int):
                if len(encoded) != 3:
                    raise ValueError("3-byte input required")
                v = int.from_bytes(encoded, "big")
            elif not (0 <= encoded <= 0xFFFFFF):
                raise ValueError("Only 24-bit unsigned values supported")
            else:
                v = encoded
            return self._decode_python(v)


    def _encode_python(self, raw):
        """
        Encode the value as a 24b code

        The leading '_' indicates this is a private method; do not call this
        directly, call encode() instead.

        :type raw: int
        :param raw: value to be encoded that is already validated to be 0..FFF
        :return: encoded value as a 24-bit integer
        """
        # self.encode() has already checked that 0 <= raw <= 0xFFF so do not 
        # check again
        # Also, there is no to_string argument because that is handled by
        # encode()

        return Golay.EncodeTable[raw & 0xFFF]

    def _decode_python(self, v):
        """
        Decode a 24b number as a golay

        The leading '_' indicates this is a private method; do not call this
        directly, call decode() instead.

        :type v: int
        :param v: integer that has already been validated to be 24bit
        :return: decoded 12-bit value
        """
        # self.decode() has converted the value to an integer and verified 
        # that it is valid. So do not repeat the check.
        
        return self._decode2(((v) >> 12) & 0xFFF, (v) & 0xFFF)

    def _syndrome2(self, v1, v2):
        return Golay.SyndromeTable[v2] ^ (v1)

    def _syndrome(self, v):
        return self._syndrome2(((v) >> 12) & 0xFFF, (v) & 0xFFF)

    def _errors2(self, v1, v2):
        return Golay.ErrorTable[self._syndrome2(v1, v2)]

    def _decode2(self, v1, v2):
        return (v1) ^ Golay.CorrectTable[self._syndrome2(v1, v2)]

    def _errors(self, v):
        return self._errors2(((v) >> 12) & 0xFFF, (v) & 0xFFF)

    def errors(self, v):
        if _use_c_extension:
            return _golay_native.golay_errors(v)
        else:
            return self._errors(v)

    @staticmethod
    def _onesincode(code, size):
        """Optimised version of the code below. Runs 2x"""
        return bin(code)[2 : size + 2].count("1")

    @staticmethod
    def _onesincode_old(code, size):
        ret = 0

        for t in range(size):
            if (code >> t) & 1:
                ret += 1

        return ret

    def _initgolaydecode(self):
        Golay.SyndromeTable = [0] * GOLAY_SIZE
        Golay.CorrectTable = [0] * GOLAY_SIZE
        Golay.ErrorTable = [0] * GOLAY_SIZE

        for x in range(GOLAY_SIZE):
            Golay.SyndromeTable[x] = 0
            for i in range(12):
                if (x >> (11 - i)) & 1:
                    Golay.SyndromeTable[x] ^= H_P[i]
                    Golay.ErrorTable[x] = 4
                    Golay.CorrectTable[x] = 0xFFF

        Golay.ErrorTable[0] = 0
        Golay.CorrectTable[0] = 0
        for i in range(24):
            for j in range(24):
                for k in range(24):
                    error = (1 << i) | (1 << j) | (1 << k)
                    syndrome = self._syndrome(error)
                    Golay.CorrectTable[syndrome] = (error >> 12) & 0xFFF
                    Golay.ErrorTable[syndrome] = Golay._onesincode(error, 24)

        return True
