import struct
from AcraNetwork import KMP
from AcraNetwork.IRIG106.Chapter11 import TS_CH4, TS_IEEE1558, PTPTime, RTCTime
import logging
import typing

DFLT_SYNC_WORD = 0xFE6B_2840

logger = logging.getLogger(__name__)
# logger.setLevel(logging.INFO)


class PCMMinorFrame(object):
    """
    Object that represents the PCM minor frame in a PCMPayload.
    """

    TS_LEN = 8
    ALIGN_16b = 0
    ALIGN_32b = 1
    DATA_HEADER_LEN = {ALIGN_16b: 2, ALIGN_32b: 4}
    DATA_HEADER_FORMAT = {ALIGN_16b: "<H", ALIGN_32b: "<I"}

    def __init__(
        self, ipts_source: typing.Optional[int] = TS_CH4, throughput: bool = False, alignment: int = ALIGN_16b
    ):
        if throughput:
            self.ipts = None
        elif ipts_source == TS_CH4:
            self.ipts = RTCTime()
        else:
            self.ipts = PTPTime()
        self._ipts_source = ipts_source
        self.throughput = throughput
        self.intra_packet_data_header = None
        self.minor_frame_data = bytes()
        self.alignment = alignment
        self.syncword = None
        self.sfid = None

    @property
    def payload(self) -> bytes:
        return self.minor_frame_data

    def unpack(self, buffer, extract_sync_sfid=False):
        """
        Convert a string buffer into a PCMDataPacket
        :type buffer: str
        :rtype: bool
        """
        if self.ipts is not None:
            self.ipts.unpack(buffer[:8])
        if not self.throughput:
            (self.intra_packet_data_header,) = struct.unpack_from(
                PCMMinorFrame.DATA_HEADER_FORMAT[self.alignment], buffer, 8
            )
            if extract_sync_sfid:
                (msw, lsw, self.sfid) = struct.unpack_from(
                    "<HHH", buffer, 8 + PCMMinorFrame.DATA_HEADER_LEN[self.alignment]
                )
                self.syncword = lsw + (msw << 16)
            self.minor_frame_data = buffer[PCMMinorFrame.DATA_HEADER_LEN[self.alignment] + PCMMinorFrame.TS_LEN :]
        else:
            self.minor_frame_data = buffer
        return True

    def pack(self):
        """
        Convert a PCMFrame object into a string buffer
        :return:
        """
        if self.throughput:
            buf = self.minor_frame_data
        else:
            if self.ipts is None:
                raise Exception("Timestamp should be defined in non-throughput mode")
            buf = self.ipts.pack() + struct.pack(
                PCMMinorFrame.DATA_HEADER_FORMAT[self.alignment], self.intra_packet_data_header
            )
            if self.syncword is not None:
                buf += struct.pack(">I", self.syncword)
            if self.sfid is not None:
                buf += struct.pack(">H", self.sfid)
            buf += self.minor_frame_data

        return buf

    def __repr__(self):
        if self.throughput:
            _str = f"Minor Frame Throughput mode Time={self.ipts} Payload_len={len(self.minor_frame_data)}"
        else:
            _str = "Minor Frame. Time={} DataHdr={:#0X} Payload_len={}".format(
                self.ipts, self.intra_packet_data_header, len(self.minor_frame_data)
            )
        return _str

    def __eq__(self, other):
        if not isinstance(other, PCMMinorFrame):
            return False
        for attr in ["ipts", "intra_packet_data_header", "minor_frame_data", "syncword", "sfid", "throughput"]:
            if getattr(self, attr) != getattr(other, attr):
                return False

        return True

    def __ne__(self, other):
        return not self.__eq__(other)


PCM_DATA_FRAME_FILL = 0x0
MODE_THROUGHPUT = 0x1 << 20
MODE_ALIGNMENT = 0x1 << 21


class PCMDataPacket(object):
    """
    This object represents the Payload to a Chapter 10 PCM packet

    The user needs to tell the object how many minor frames in Payload before unpacking a buffer.
    :type minor_frames: [PCMMinorFrame]


    >>> from base64 import b64decode
    >>> buffer = b64decode('AAAQAGv+QCg=')
    >>> p = PCMDataPacket(syncword=DFLT_SYNC_WORD)
    >>> p.unpack(buffer)
    True
    >>> print(p)
    PCM Data Packet Format 1. Channel Specific Word =0X100000
    Minor Frame Throughput mode Time=None Payload_len=4
    <BLANKLINE>
    """

    def __init__(
        self,
        ipts_source: typing.Optional[int] = TS_CH4,
        syncword: typing.Optional[int] = None,
        minor_frame_size_bytes: typing.Optional[int] = None,
    ):
        self.channel_specific_word: int = 0
        self._ipts_source: typing.Optional[int] = ipts_source
        self.minor_frame_size_bytes: typing.Optional[int] = minor_frame_size_bytes
        self.syncword = syncword
        self.minor_frames: typing.List[PCMMinorFrame] = []

    def unpack(self, buffer: bytes, extract_sync_sfid: bool = False) -> bool:
        """
        Convert a string buffer into a PCMDataPacket
        :type buffer: bytes
        :rtype: bool
        """

        (self.channel_specific_word,) = struct.unpack_from("<I", buffer, 0)
        channel_specific_len = 4
        throughput_mode = bool(self.channel_specific_word & MODE_THROUGHPUT == MODE_THROUGHPUT)
        alignment_mode = int(self.channel_specific_word & MODE_ALIGNMENT == MODE_ALIGNMENT)
        if throughput_mode:
            minor_frame = PCMMinorFrame(throughput=True, alignment=alignment_mode)
            minor_frame.unpack(buffer[channel_specific_len:])
            self.minor_frames.append(minor_frame)
        else:
            offset = channel_specific_len
            if self.minor_frame_size_bytes is None and self.syncword is None:
                self.minor_frame_size_bytes = (
                    len(buffer)
                    - PCMMinorFrame.TS_LEN
                    - PCMMinorFrame.DATA_HEADER_LEN[alignment_mode]
                    - channel_specific_len
                )
            elif self.minor_frame_size_bytes is None:
                # Search the payload for some sync words
                kmp = KMP()
                sync_word_offsets = kmp.search(buffer, struct.pack(">I", self.syncword))
                # More than one sync word. So split the payload
                if len(sync_word_offsets) < 2:
                    self.minor_frame_size_bytes = (
                        len(buffer)
                        - PCMMinorFrame.TS_LEN
                        - PCMMinorFrame.DATA_HEADER_LEN[alignment_mode]
                        - channel_specific_len
                    )
                else:
                    self.minor_frame_size_bytes = (
                        sync_word_offsets[1]
                        - sync_word_offsets[0]
                        - PCMMinorFrame.TS_LEN
                        - PCMMinorFrame.DATA_HEADER_LEN[alignment_mode]
                    )
                    logger.debug(
                        f"Found multiple sync words. Getting minor frame size as {self.minor_frame_size_bytes}"
                    )

            _byte_count_req = (
                self.minor_frame_size_bytes + PCMMinorFrame.TS_LEN + PCMMinorFrame.DATA_HEADER_LEN[alignment_mode]
            )
            while offset + _byte_count_req <= len(buffer):
                minor_frame = PCMMinorFrame(self._ipts_source, alignment=alignment_mode)
                if (_byte_count_req) % 2 != 0:
                    padding = 1
                else:
                    padding = 0
                try:
                    minor_frame.unpack(buffer[offset : offset + _byte_count_req], extract_sync_sfid=extract_sync_sfid)
                except Exception as e:
                    raise Exception(
                        "Unpacking payload at offset {} of {} failed. Err={}".format(offset, len(buffer), e)
                    )
                offset += _byte_count_req + padding
                self.minor_frames.append(minor_frame)

        return True

    def pack(self):
        buf = struct.pack("<I", self.channel_specific_word)
        throughput_mode = bool(self.channel_specific_word & MODE_THROUGHPUT == MODE_THROUGHPUT)
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

    def __getitem__(self, key):
        return self.minor_frames[key]

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
