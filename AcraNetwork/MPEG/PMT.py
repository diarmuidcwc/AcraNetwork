"""
.. module:: MPEG.PMT
    :platform: Unix, Windows
    :synopsis: Manage PMT packet formats https://en.wikipedia.org/wiki/Program-specific_information#

.. moduleauthor:: Diarmuid Collins <dcollins@curtisswright.com>

"""

__author__ = "Diarmuid Collins"
__maintainer__ = "Diarmuid Collins"
__email__ = "dcollins@curtisswright.com"
__status__ = "Production"


import typing
import struct
from AcraNetwork.MPEGTS import MPEGPacket
from zlib import crc32
import logging

logger = logging.getLogger(__name__)


def bytes_to_ascii(buffer: bytes) -> str:
    r = ""
    for _b in buffer:
        r += chr(_b)
    return r


class DescriptorTag(object):
    """Descriptor tag fields in the PAT / PMT packets
    https://en.wikipedia.org/wiki/Program-specific_information#Descriptor

    Args:
        object (_type_): _description_

    Returns:
        _type_: _description_
    """

    FMT = ">BB"

    def __init__(self) -> None:
        self.tag: int = None
        self.data: bytes = bytes()

    def unpack(self, buffer: bytes) -> bytes:
        """Unpack the buffer into a descriptor and return any remainder

        Args:
            buffer (bytes): _description_

        Returns:
            : _description_
        """
        hdr_len = struct.calcsize(DescriptorTag.FMT)
        (self.tag, _len) = struct.unpack_from(DescriptorTag.FMT, buffer)
        self.data = buffer[hdr_len : hdr_len + _len]
        return buffer[hdr_len + _len :]

    def pack(self) -> bytes:
        """Convert the DescriptorTag into bytes"""
        return struct.pack(DescriptorTag.FMT, self.tag, len(self.data)) + self.data

    def __len__(self) -> int:
        if self.tag is None:
            return 0
        return 2 + len(self.data)

    def __eq__(self, value: object) -> bool:
        if not isinstance(value, DescriptorTag):
            return False
        if self.tag != value.tag or self.data != value.data:
            return False
        return True

    def __repr__(self) -> str:
        return f"Tag={self.tag:#0X} Length={len(self.data)}"


MIN_STREAM_LEN = 5


class PMTStream(object):
    """Elementary Stream specific data
    https://en.wikipedia.org/wiki/Program-specific_information#PMT_(Program_map_specific_data)

    Args:
        object (_type_): _description_

    Returns:
        _type_: _description_
    """

    FMT = ">BHH"

    def __init__(self) -> None:
        self.streamtype: int = 0x0
        self.elementary_pid: int = 0
        self.descriptor_tags: typing.List[DescriptorTag] = []

    def unpack(self, buffer: bytes) -> bytes:
        """Extract a stream from the specified buffer and return the remainder bytes
        Iterate through a buffer until all the payload has been exhausted"""
        (self.streamtype, _pid, _len) = struct.unpack_from(PMTStream.FMT, buffer)
        self.elementary_pid = _pid & 0x1FFF
        es_len = _len & 0xFFF
        es_buffer = buffer[MIN_STREAM_LEN : es_len + MIN_STREAM_LEN]
        while len(es_buffer) >= MIN_STREAM_LEN:
            tag = DescriptorTag()
            es_buffer = tag.unpack(es_buffer)
            self.descriptor_tags.append(tag)
        # Return the remainder
        return buffer[es_len + MIN_STREAM_LEN :]

    def pack(self) -> bytes:
        """Convert the PMTSream into bytes

        Returns:
            bytes: _description_
        """
        _payload = bytes()
        for tag in self.descriptor_tags:
            _payload += tag.pack()
        hdr = struct.pack(PMTStream.FMT, self.streamtype, self.elementary_pid + 0xE000, len(_payload) + 0xF000)
        return hdr + _payload

    def __len__(self) -> int:
        r = struct.calcsize(PMTStream.FMT)
        for t in self.descriptor_tags:
            r += len(t)
        return r

    def __eq__(self, value: object) -> bool:
        if not isinstance(value, PMTStream):
            return False
        if (
            self.streamtype != value.streamtype
            or self.elementary_pid != value.elementary_pid
            or self.descriptor_tags != value.descriptor_tags
        ):
            return False
        return True

    def __repr__(self) -> str:
        r = f"Stream Type={self.streamtype:#04X} Elementary PID={self.elementary_pid:#06X}\n"
        for t in self.descriptor_tags:
            r += f" Descriptor: {repr(t)}\n"
        return r


def crc32mpeg2(msg):
    """CRC poly used in the MPEG stream"""
    crc = 0xFFFFFFFF
    for b in msg:
        crc ^= b << 24
        for _ in range(8):
            crc = (crc << 1) ^ 0x04C11DB7 if crc & 0x80000000 else crc << 1
    return crc & 0xFFFFFFFF


# PMT Header = 12
class MPEGPacketPMT(MPEGPacket):
    """Specific version of an MPEG Packet which contains the PMT (program map specific data)
    https://en.wikipedia.org/wiki/Program-specific_information#PMT_(Program_map_specific_data)

    Args:
        MPEGPacket (_type_): _description_

    Returns:
        _type_: _description_
    """

    FMT = ">BHHBBBHH"
    FMT_POINTER = ">B"
    HDR_LEN_NOT_INCL_IN_LEN = 3
    CRC_LEN = 4

    def __init__(self):
        super().__init__()
        self.tableid: int = 0x0
        self.syntax_indicator = 0x0
        self.program_number: int = 0x0
        self.version: int = 0x3
        self.current_next_indicator: int = 0x0
        self.section: int = 0
        self.last_section: int = 0
        self.pcr_pid: int = 0x0
        self.program_info_len: int = 0x0
        self.streams: typing.List[PMTStream] = []
        self._crc = None

    def unpack(self, buf: bytes) -> bool:
        """Unpack the buffer as a PMT packet

        Args:
            buf (bytes): _description_

        Returns:
            bool: CRC as expected
        """
        super().unpack(buf)
        (_pointer,) = struct.unpack_from(MPEGPacketPMT.FMT_POINTER, self.payload)
        logger.debug(f"Pointer={_pointer}")
        (self.tableid, _pmt, self.program_number, _ver, self.section, self.last_section, _pcr, _pil) = (
            struct.unpack_from(MPEGPacketPMT.FMT, self.payload, struct.calcsize(MPEGPacketPMT.FMT_POINTER) + _pointer)
        )
        self.syntax_indicator = _pmt >> 15
        _len = _pmt & 0xFFF
        self.version = (_ver >> 1) & 0x1F
        self.current_next_indicator = _ver & 0x1
        self.pcr_pid = _pcr & 0x1FFF
        self.program_info_len = _pil & 0xFFF

        # Offset to the start of the streams
        _offset = struct.calcsize(MPEGPacketPMT.FMT) + struct.calcsize(MPEGPacketPMT.FMT_POINTER) + _pointer
        # Length of the stream payload
        stream_len = _len - struct.calcsize(MPEGPacketPMT.FMT) + MPEGPacketPMT.HDR_LEN_NOT_INCL_IN_LEN
        stream_buf = self.payload[_offset : (stream_len + _offset)]
        # The buffer over which to calculate the CRC
        crc_buffer = self.payload[
            (_pointer + struct.calcsize(MPEGPacketPMT.FMT_POINTER)) : (_offset + stream_len - MPEGPacketPMT.CRC_LEN)
        ]
        exp_crc = crc32mpeg2(crc_buffer)
        logger.debug(f"crc_len={len(crc_buffer)} :{crc_buffer[0]} : {crc_buffer[-1]}")
        # extract all the streams
        while len(stream_buf) > MPEGPacketPMT.CRC_LEN:
            stream = PMTStream()
            stream_buf = stream.unpack(stream_buf)
            self.streams.append(stream)
        # All that is left is the CRC
        (self._crc,) = struct.unpack(">I", stream_buf)
        # Check it
        if self._crc != exp_crc:
            logger.error(f"CRC Does not match in PMT packet. Act={self._crc:#0X} exp={exp_crc:#0X}")
            return False
        else:
            return True

    def pack(self) -> bytes:
        """Convert MPEGPacketPMT into bytes

        Returns:
            bytes: _description_
        """
        _len = struct.calcsize(MPEGPacketPMT.FMT) - MPEGPacketPMT.HDR_LEN_NOT_INCL_IN_LEN + MPEGPacketPMT.CRC_LEN
        for s in self.streams:
            _len += len(s)
        _buf = struct.pack(MPEGPacketPMT.FMT_POINTER, 0x0)
        _buf += struct.pack(
            MPEGPacketPMT.FMT,
            self.tableid,
            (self.syntax_indicator << 15) + (0x3 << 12) + _len,
            self.program_number,
            (0x3 << 6) + (self.version << 1) + self.current_next_indicator,
            self.section,
            self.last_section,
            (0x7 << 13) + self.pcr_pid,
            (0xF << 12) + self.program_info_len,
        )
        for s in self.streams:
            _buf += s.pack()
        _crc = crc32mpeg2(_buf[struct.calcsize(MPEGPacketPMT.FMT_POINTER) :])
        self.payload = _buf + struct.pack(">L", _crc)

        return super().pack()

    def __repr__(self) -> str:
        r = super().__repr__()
        r += f"PMT: TableID={self.tableid:#04X} ProgramNumer={self.program_number:#06X} SectionNumber={self.section} LastSection={self.last_section} PCR={self.pcr_pid:#06X} PiL={self.program_info_len}\n"
        for s in self.streams:
            r += f"{repr(s)}"
        return r

    def __eq__(self, __value: object) -> bool:
        if not isinstance(__value, MPEGPacketPMT):
            return False
        match_attr = [
            "sync",
            "pid",
            "transport_priority",
            "tei",
            "pusi",
            "continuitycounter",
            "tsc",
            "adaption_ctrl",
            "adaption_field",
            "tableid",
            "syntax_indicator",
            "program_number",
            "section",
            "last_section",
            "pcr_pid",
            "program_info_len",
            "streams",
        ]
        for attr in match_attr:
            if getattr(self, attr) != getattr(__value, attr):
                logger.error(f"Attr={attr}, Self={getattr(self, attr)} Other={getattr(__value, attr)} ")
                return False
            return True
