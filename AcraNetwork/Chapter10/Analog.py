import struct


class Analog(object):
    """
    Analog
    """

    def __init__(self):
        self.channel_specific_word = None
        self.data = bytes()

    def unpack(self, buffer):
        """
        Convert a string buffer into a PCMDataPacket
        :type buffer: bytes
        :rtype: bool
        """

        (self.channel_specific_word,) = struct.unpack_from("<I", buffer, 0)
        self.data = buffer[4:]

        return True

    def pack(self):
        return struct.pack("<I", self.channel_specific_word) + self.data

    def __repr__(self):
        _rstr = "PCM Analog Channel Specific Word ={:#0X}\n".format(self.channel_specific_word)
        return _rstr

    def __eq__(self, other):
        """

        :type other: PCMDataPacket
        :return:
        """
        if not isinstance(other, Analog):
            return False

        if self.channel_specific_word != other.channel_specific_word:
            return False

        if len(self.data) != len(other.data):
            return False

        return True
