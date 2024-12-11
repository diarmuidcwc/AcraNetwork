from __future__ import annotations
import struct


class Analog(object):
    """
    Class to handle Chapter11 analog packets
    https://www.irig106.org/docs/106-22/chapter11.pdf
    11.2.5.2

    Unpack the chapter10 payload into this format
    """

    def __init__(self):
        self.channel_specific_word: int = 0
        self.data: bytes = bytes()

    def unpack(self, buffer: bytes):
        """
        Convert a string buffer into a Analog
        :type buffer: bytes
        :rtype: bool
        """

        (self.channel_specific_word,) = struct.unpack_from("<I", buffer, 0)
        self.data = buffer[4:]

        return True

    def pack(self):
        return struct.pack("<I", self.channel_specific_word) + self.data

    def __repr__(self):
        _rstr = "Chapter10 Analog Channel Specific Word ={:#0X}\n".format(self.channel_specific_word)
        return _rstr

    def __eq__(self, other: Analog):
        """

        :type other: Analog
        :return:
        """
        if not isinstance(other, Analog):
            return False

        if self.channel_specific_word != other.channel_specific_word:
            return False

        if len(self.data) != len(other.data):
            return False

        return True
