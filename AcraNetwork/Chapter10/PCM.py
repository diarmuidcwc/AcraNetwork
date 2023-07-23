
import struct
from datetime import datetime


class PCMMinorFrame(object):

    HDR_LEN = 10
    """
    Object that represents the PCM minor frame in a PCMPayload.
    """
    def __init__(self):
        self.intra_packet_sec = 0
        self.intra_packet_nsec = 0
        self.intra_packet_data_header = 0x0
        self.minor_frame_data = b''
        self.syncword = None
        self.sfid = None

    def unpack(self, buffer, extract_sync_sfid=False):
        """
        Convert a string buffer into a PCMDataPacket
        :type buffer: str
        :rtype: bool
        """

        (self.intra_packet_nsec, self.intra_packet_sec, self.intra_packet_data_header) = \
            struct.unpack_from("<IIH", buffer)
        if extract_sync_sfid:
            (self.syncword, self.sfid) = struct.unpack_from(">IH", buffer, 10)
        self.minor_frame_data = buffer[10:]
        return True

    def pack(self):
        """
        Convert a PCMFrame object into a string buffer
        :return:
        """
        buf = struct.pack("<IIH", self.intra_packet_nsec, self.intra_packet_sec, self.intra_packet_data_header)
        if self.syncword is not None:
            buf += struct.pack(">I", self.syncword)
        if self.sfid is not None:
            buf += struct.pack(">H", self.sfid)
        buf += self.minor_frame_data

        return buf

    def __repr__(self):
        time_fmt = "%H:%M:%S %d-%b %Y"
        date_str = datetime.fromtimestamp(self.intra_packet_sec).strftime(time_fmt)
        return "Minor Frame. Sec={} ({}) NanoSec={} DataHdr={:#0X} ".format(
            self.intra_packet_sec, date_str, self.intra_packet_nsec, self.intra_packet_data_header
        )

    def __eq__(self, other):
        if not isinstance(other, PCMMinorFrame):
            return False
        for attr in ["intra_packet_sec", "intra_packet_nsec", "intra_packet_data_header", "minor_frame_data",
                     "syncword", "sfid"]:
            if getattr(self, attr) != getattr(other, attr):
                return False

        return True

    def __ne__(self, other):
        return not self.__eq__(other)

PCM_DATA_FRAME_FILL = 0x0


class PCMDataPacket(object):
    """
    This object represents the Payload to a Chapter 10 PCM packet
    The user needs to tell the object how many minor frames in Payload before unpacking a buffer.
    """
    def __init__(self):
        self.channel_specific_word = None
        self.minor_frame_size_bytes = 0
        self.minor_frames = []

    def unpack(self, buffer):
        """
        Convert a string buffer into a PCMDataPacket
        :type buffer: bytes
        :rtype: bool
        """

        (self.channel_specific_word,) = struct.unpack_from("<I", buffer, 0)
        offset = 4
        while offset < len(buffer):
            minor_frame = PCMMinorFrame()
            if (self.minor_frame_size_bytes + PCMMinorFrame.HDR_LEN) % 2 != 0:
                padding = 1
            else:
                padding = 0
            minor_frame.unpack(buffer[offset:offset+self.minor_frame_size_bytes+10])
            offset += (self.minor_frame_size_bytes+10+padding)
            self.minor_frames.append(minor_frame)

        return True

    def pack(self):
        buf = struct.pack("<I", self.channel_specific_word)
        for mf in self.minor_frames:
            buf += mf.pack()
            if len(mf.pack()) % 2 == 1:
                buf += struct.pack(">B", PCM_DATA_FRAME_FILL)

        return buf

    def __repr__(self):
        _rstr = "PCM Data Packet Format 1. Channel Specific Word ={:#0X}\n".format(self.channel_specific_word)
        for m in self.minor_frames:
            _rstr += "{}\n".format(repr(m))

        return _rstr

    def __iter__(self):
        self._index = 0
        return self

    def next(self):
        if self._index < len(self.minor_frames):
            _frame = self.minor_frames[self._index]
            self._index += 1
            return _frame
        else:
            raise StopIteration

    __next__ = next

    def __eq__(self, other):
        """

        :type other: PCMDataPacket
        :return:
        """
        if not isinstance(other, PCMDataPacket):
            return False

        if self.channel_specific_word != other.channel_specific_word:
            return False

        if len(self.minor_frames) != len(other.minor_frames):
            return False

        for idx in range(len(self.minor_frames)):
            if self.minor_frames[idx] != other.minor_frames[idx]:
                return False

        return True

