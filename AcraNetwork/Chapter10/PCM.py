
import struct
from datetime import datetime
from . import TS_RTC, TS_SECONDARY
import logging


class PTPTime(object):
    def __init__(self, sec=0, nanosec=0):
        self.sec = sec
        self.nanosec = nanosec

    def pack(self):
        return struct.pack("<II", self.nanosec, self.sec)
    
    def unpack(self, buffer):
        (self.sec, self.nanosec) = struct.unpack("<II", buffer)
        return True
    
    def __repr__(self):
        time_fmt = "%H:%M:%S %d-%b %Y"
        date_str = datetime.fromtimestamp(self.sec).strftime(time_fmt)
        return "PTP: {} nanosec={}".format(date_str, self.nanosec)
    
    def __eq__(self, __value):
        if not isinstance(__value, PTPTime):
            return False
        if self.nanosec != __value.nanosec or self.sec != __value.sec:
            return False
        return True


class RTCTime(object):
    def __init__(self, count=0):
        self.count = count

    def pack(self):
        msw = (self.count >> 32) & 0xFFFF
        lsw = self.count & 0xFFFFFFFF
        return struct.pack("<IHH", lsw, msw, 0)
    
    def unpack(self, buffer):
        (lsw, msw, _zero) = struct.unpack("<IHH", buffer)
        self.count = lsw + (msw << 32)
        return True
    
    def __repr__(self):
        return "RTC: count={}".format(self.count)
    
    def __eq__(self, __value):
        if not isinstance(__value, RTCTime):
            return False
        if self.count != __value.count:
            return False
        return True


class PCMMinorFrame(object):

    HDR_LEN = 10
    """
    Object that represents the PCM minor frame in a PCMPayload.
    """
    def __init__(self, ipts_source=TS_RTC):
        if ipts_source == TS_RTC:
            self.ipts = RTCTime()
        else:
            self.ipts = PTPTime()
        self._ipts_source = ipts_source
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
        if self._ipts_source == TS_RTC:
            self.ipts = RTCTime()
        else:
            self.ipts = PTPTime()

        self.ipts.unpack(buffer[:8])
        (self.intra_packet_data_header,) = struct.unpack_from("<H", buffer, 8)
        if extract_sync_sfid:
            (msw, lsw, self.sfid) = struct.unpack_from("<HHH", buffer, 10)
            self.syncword = lsw + (msw << 16)
        self.minor_frame_data = buffer[PCMMinorFrame.HDR_LEN:]
        return True

    def pack(self):
        """
        Convert a PCMFrame object into a string buffer
        :return:
        """
        if self.ipts is None:
            raise Exception("Timestamp should be defined")
        buf = self.ipts.pack() + struct.pack("<H", self.intra_packet_data_header)
        if self.syncword is not None:
            buf += struct.pack(">I", self.syncword)
        if self.sfid is not None:
            buf += struct.pack(">H", self.sfid)
        buf += self.minor_frame_data

        return buf

    def __repr__(self):
        
        return "Minor Frame. Time={} DataHdr={:#0X} Payload_len={}".format(
            self.ipts, self.intra_packet_data_header, len(self.minor_frame_data)
        )

    def __eq__(self, other):
        if not isinstance(other, PCMMinorFrame):
            return False
        for attr in ["ipts", "intra_packet_data_header", "minor_frame_data",
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
    :type minor_frames: [PCMMinorFrame]
    """
    def __init__(self, ipts_source=TS_RTC):
        self.channel_specific_word = None
        self.ipts_source = ipts_source
        self.minor_frame_size_bytes = 0
        self.minor_frames = []

    def unpack(self, buffer, extract_sync_sfid=False):
        """
        Convert a string buffer into a PCMDataPacket
        :type buffer: bytes
        :rtype: bool
        """

        (self.channel_specific_word,) = struct.unpack_from("<I", buffer, 0)
        offset = 4
        _byte_count_req = self.minor_frame_size_bytes + PCMMinorFrame.HDR_LEN
        while offset + _byte_count_req <= len(buffer):
            minor_frame = PCMMinorFrame()
            if (_byte_count_req) % 2 != 0:
                padding = 1
            else:
                padding = 0
            try:
                minor_frame.unpack(buffer[offset : offset + _byte_count_req], extract_sync_sfid=extract_sync_sfid)
            except Exception as e:
                raise Exception("Unpacking payload at offset {} of {} failed. Err={}".format(
                    offset, len(buffer), e))
            offset += (_byte_count_req + padding)
            self.minor_frames.append(minor_frame)

        return True

    def pack(self):
        buf = struct.pack("<I", self.channel_specific_word)
        for mf in self.minor_frames:
            buf += mf.pack()
            if len(mf.pack()) % 2 == 1:
                buf += struct.pack(">B", PCM_DATA_FRAME_FILL)

        return buf
    
    def append(self, minorframe):
        self.minor_frames.append(minorframe)

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

