import struct
from AcraNetwork.MPEGTS import MPEGTS
from enum import IntEnum

IPH_OFFSET = 19
TP_OFFSET = 12


class DataStream(IntEnum):
    TRANSPORT = 0x0
    PROGRAM = 0x1


class VideoFormat2(object):
    """
    Chapter 10 Video Format 2
    Object will contain some MPEG Transport streams
    """

    def __init__(self):
        self.channel_specific_word: int = 0
        self.datastream: int = DataStream.TRANSPORT
        self.mpegts: MPEGTS = MPEGTS()

    def unpack(self, buffer: bytes):
        """
        Convert a string buffer into a PCMDataPacket
        :type buffer: bytes
        :rtype: bool
        """

        (self.channel_specific_word,) = struct.unpack_from("<I", buffer, 0)
        iph = bool((self.channel_specific_word >> IPH_OFFSET) & 0x1)
        if iph:
            raise Exception("Option Intra-packet header is not supported")
        self.datastream = DataStream((self.channel_specific_word >> TP_OFFSET) & 0x1)

        self.mpegts.unpack(buffer[4:])

        return True

    def pack(self) -> bytes:
        return struct.pack("<I", self.channel_specific_word) + self.mpegts.pack()

    def __repr__(self):
        _rstr = f"Video Format2={self.channel_specific_word:#0X}\n . MPEGTS={repr(self.mpegts)}"
        return _rstr

    def __eq__(self, other):
        """

        :type other:
        :return:
        """
        if not isinstance(other, VideoFormat2):
            return False

        if self.channel_specific_word != other.channel_specific_word:
            return False

        if self.mpegts != other.mpegts:
            return False

        return True
