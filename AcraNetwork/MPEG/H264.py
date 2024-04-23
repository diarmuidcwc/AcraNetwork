import typing
import struct
from STANAG4609 import STANAG4609_SEI
import sys

NAL_HEADER = 0x00000001
NAL_HEADER_LEN = 4
NAL_TYPES = {
    "Unspecified": 0,
    "Coded non-IDR": 1,
    "Coded partition A": 2,
    "Coded partition B": 3,
    "Coded partition C": 4,
    "Coded IDR": 5,
    "SEI": 6,
    "SPS": 7,
    "PPS": 8,
    "AUD": 9,
    "EOSeq": 10,
    "EOStream": 11,
    "Filler": 12,
    "SES": 13,
    "Prefix NAL": 14,
    "SSPS": 15,
    "Reserved": 16,
}
# Invert it to go from integer to more useful name
NAL_TYPES_INV = {v: k for k, v in list(NAL_TYPES.items())}
PY3 = sys.version_info > (3,)


class H264(object):
    """
    This class will handle H.264 _payload. It can convert a buffer of bytes into an array
    of NALs(https://en.wikipedia.org/wiki/Network_Abstraction_Layer)
    The NALs contain different data, based on their types.
    """

    def __init__(self):
        self.nals: typing.List[NAL] = []

    def unpack(self, buf: bytes) -> bool:
        """
        Split the buffer into multiple NALs and store as a H264 object

        :param buf: The buffer to unpack into a H264 object
        :type buf: str
        :rtype: bool
        """
        nal_hdr = struct.pack(">L", NAL_HEADER)
        offsets = string_matching_boyer_moore_horspool(buf.decode(), nal_hdr.decode())

        for idx, offset in enumerate(offsets):
            if idx == len(offsets) - 1:
                nal_buf = buf[offset:]
            else:
                nal_buf = buf[offset : (offsets[idx + 1])]
            nal = NAL()
            nal.unpack(nal_buf)
            nal.offset = offset
            self.nals.append(nal)

        return True


class NAL(object):
    """
    The NAL can be split into the various types of NALs.
    """

    def __init__(self):
        self.type: int = 0
        self.size: int = 0
        self.sei: typing.Optional[STANAG4609_SEI] = None
        self.offset = 0

    def unpack(self, buf: bytes):
        """
        Split the buffer into a NAL object

        :param buf: The buffer to unpack into an NAL
        :type buf: str|bytes
        :rtype: bool
        """

        # First 4 bytes are the NAL_HEADER, then forbidden + type
        (self.type,) = struct.unpack_from(">B", buf, NAL_HEADER_LEN)
        self.type = self.type & 0x1F
        self.size = len(buf)
        if self.type == NAL_TYPES["SEI"]:
            sei = STANAG4609_SEI()
            sei.unpack(buf[(NAL_HEADER_LEN + 1) :])
            self.sei = sei

    def __len__(self):
        return self.size


def string_matching_boyer_moore_horspool(text="", pattern=""):
    """
    Returns positions where pattern is found in text.
    O(n)
    Performance: ord() is slow so we shouldn't use it here
    Example: text = 'ababbababa', pattern = 'aba'
         string_matching_boyer_moore_horspool(text, pattern) returns [0, 5, 7]
    @param text text to search inside
    @param pattern string to search for
    @return list containing offsets (shifts) where pattern is found inside text
    """
    m = len(pattern)
    n = len(text)
    offsets = []
    if m > n:
        return offsets
    skip = []
    for k in range(256):
        skip.append(m)
    for k in range(m - 1):
        my = pattern[k]
        if PY3:
            skip[pattern[k]] = m - k - 1
        else:
            skip[ord(pattern[k])] = m - k - 1
    skip = tuple(skip)
    k = m - 1
    while k < n:
        j = m - 1
        i = k
        while j >= 0 and text[i] == pattern[j]:
            j -= 1
            i -= 1
        if j == -1:
            offsets.append(i + 1)
        if PY3:
            k += skip[text[k]]
        else:
            k += skip[ord(text[k])]

    return offsets
