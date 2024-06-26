import struct
import typing
import logging
from AcraNetwork.MPEGTS import MPEGPacket
from functools import reduce
import datetime

logger = logging.getLogger(__name__)


PES_EXTENSION_W1 = 0x81
PES_EXTENSION_W2 = 0x80


def pts_to_ts(v: int) -> float:
    """Presentation Timestamp to seconds floating"""
    pts = 0
    pts |= (v >> 3) & (0x0007 << 30)  # // top 3 bits, shifted left by 3, other bits zeroed out
    pts |= (v >> 2) & (0x7FFF << 15)  # // middle 15 bits
    pts |= (v >> 1) & (0x7FFF << 0)  # // bottom 15 bits
    return pts / 90e3


def ts_to_pts(ts: float) -> int:
    """Floating point seconds to PTS"""
    pts = int(ts * 90e3)
    v = 0x2100010001  # I have no idea where the 2 comes from at the msb
    v |= (pts & 0x7FFF) << 1  # // bottom 15 bits
    v |= ((pts >> 15) & 0x7FFF) << 17  # // middle 15 bits
    v |= ((pts >> 30) & 0x7) << 31  # // top 3 bits

    return v


def ts_to_buf(ts: float) -> bytes:
    v = ts_to_pts(ts)
    return struct.pack(">BI", (v >> 32), v & 0xFFFF_FFFF)


def buf_to_ts(buffer: bytes) -> float:
    """Convert a buffer (ie PES header) to a timestamp"""
    (msb, lsb) = struct.unpack(">BI", buffer)
    pts_ts = lsb + (msb << 32)
    return pts_to_ts(pts_ts)


class PES(MPEGPacket):

    def __init__(self) -> None:
        super().__init__()
        self.streamid: int = 0
        self.pesdata: bytes = bytes()
        self.extension_w1: typing.Optional[int] = None
        self.extension_w2: typing.Optional[int] = None
        self.header_data: typing.Optional[bytes] = None

    def unpack(self, buffer: bytes):
        super().unpack(buffer)
        (_prefix1, _prefix2, self.streamid, _peslength) = struct.unpack_from(">BHBH", self.payload)
        prefix = (_prefix1 << 16) + _prefix2
        if prefix != 1:
            raise Exception(f"PES Prefix {prefix:#0X} should be 0x1")
        # Peek to see if the data is an extension
        (optional_hdr, _miscbits, _pes_hdr_len) = struct.unpack_from(">BBB", self.payload, 6)
        marker = optional_hdr >> 4
        expected_len_if_extension_present = _peslength + 6
        if marker == 0x8 and len(self.payload) == expected_len_if_extension_present:
            # PES extenion
            (self.extension_w1, self.extension_w2, _hdrlen) = struct.unpack_from(">BBB", self.payload, 6)
            self.header_data = self.payload[9 : (9 + _hdrlen)]
            self.pesdata = self.payload[(9 + _hdrlen) :]
        else:
            logger.debug("No optional PES header")
            self.pesdata = self.payload[6:]

    def pack(self) -> bytes:

        if self.extension_w1 is not None and self.extension_w2 is not None and self.header_data is not None:
            _len = 3 + len(self.pesdata) + len(self.header_data)
            _ext_present = True
        else:
            _ext_present = False
            _len = len(self.header_data)
        self.payload = struct.pack(">BHBH", 0, 1, self.streamid, _len)
        if _ext_present:
            self.payload += struct.pack(">BBB", self.extension_w1, self.extension_w2, len(self.header_data))
            self.payload += self.header_data
        self.payload += self.pesdata

        return super().pack()

    def __repr__(self) -> str:
        r = super().__repr__()
        if self.extension_w1 is None:
            _ext = ""
        else:
            _ext = "Extension"
        return r + "\n" f"   PES {_ext}: Stream ID={self.streamid:#0X}  PESData Len={len(self.pesdata)}"

    def __eq__(self, __value: object) -> bool:
        if self.streamid != __value.streamid or self.pesdata != __value.pesdata:
            return False
        if (
            self.extension_w1 != __value.extension_w1
            or self.extension_w2 != __value.extension_w2
            or self.header_data != __value.header_data
        ):
            return False
        return super().__eq__(__value)


def checksum_stanag(buff: bytes) -> int:
    """Calculate the STANAG checksum as described in 6.8
    https://upload.wikimedia.org/wikipedia/commons/1/19/MISB_Standard_0601.pdf

    """
    bcc = 0

    # Sum each 16-bit chunk within the buffer into a checksum
    for i in range(len(buff)):
        bcc += buff[i] << (8 * ((i + 1) % 2))

    return bcc % 65536


STANAG4609_UNIVERSAL_KEY = struct.pack(">QQ", 0x060E2B34020B0101, 0x0E01030101000000)
STANAG4609_UNKNOWN_OFFSET = 5  # There's some data at the start that I don't understand
STANAG4609_DATA_TAG = 0x2
STANAG4609_TIME_TAG = 0x1
STANAG4609_PID = 0x104
STANAG4609_LEN = 0xE
STANAG4609_DTAG_LEN = 0x8
STANAG4609_TTAG_LEN = 0x2


class STANAG4609(PES):

    def __init__(self) -> None:
        super().__init__()
        self.stanag_counter: int = 0
        self._unknown: int = 0xDF
        self._unknown2: int = 0x1F

        self.time_us: int = 0  # Store the time in us

    # Set the time as a date time option
    @property
    def time(self):
        return datetime.datetime.fromtimestamp(self.time_us / 1e6)

    @time.setter
    def time(self, value: datetime.datetime):
        self.time_us = int(value.timestamp() * 1e6)

    def unpack(self, buffer: bytes):
        """Convert the buffer into a STANAG4609 object"""
        super().unpack(buffer)
        if self.pid != STANAG4609_PID:
            raise Exception(f"PID of STANAG should be 0x104 not {self.pid:#0X}")
        # I can't find documentation for these 3 fields. One looks like a counter
        (self.stanag_counter, self._unknown, self._unknown2) = struct.unpack_from(">HBH", self.pesdata, 0)
        _offset = len(STANAG4609_UNIVERSAL_KEY) + STANAG4609_UNKNOWN_OFFSET
        # Check the universal key
        if self.pesdata[STANAG4609_UNKNOWN_OFFSET:_offset] != STANAG4609_UNIVERSAL_KEY:
            raise Exception("STANAG4609 requires a specific UNIVERSAL KEY")
        # Most of these are static
        (_len, _datatag, _tag_len) = struct.unpack_from(">BBB", self.pesdata, _offset)
        if _datatag != STANAG4609_DATA_TAG:
            raise Exception("Data tag of STANAG should be 0x2")
        if _tag_len != 8:
            raise Exception(f"Tag length should be 8 not {_tag_len}")
        _offset += 3
        # Pull out the time and store as a datetime
        (self.time_us, _timetag, _time_len, actchecksum) = struct.unpack_from(">QBBH", self.pesdata, _offset)
        checksum = checksum_stanag(self.pesdata[STANAG4609_UNKNOWN_OFFSET:-2])
        if checksum != actchecksum:
            raise Exception(f"Extracted checksum={actchecksum:#0X} Calculated={checksum:#0X}")

    def pack(self) -> bytes:
        """Pack the STANAG4609 object into bytes

        Returns:
            bytes: _description_
        """
        self.pid = STANAG4609_PID
        self.pesdata = struct.pack(">HBH", self.stanag_counter, self._unknown, self._unknown2)  # The unknown header
        self.pesdata += STANAG4609_UNIVERSAL_KEY + struct.pack(
            ">BBB", STANAG4609_LEN, STANAG4609_DATA_TAG, STANAG4609_DTAG_LEN
        )
        self.pesdata += struct.pack(">Q", self.time_us) + struct.pack(">BB", STANAG4609_TIME_TAG, STANAG4609_TTAG_LEN)
        checksum = checksum_stanag(self.pesdata[STANAG4609_UNKNOWN_OFFSET:])
        self.pesdata += struct.pack(">H", checksum)
        # _lp = len(self.pesdata)
        return super().pack()

    def __repr__(self) -> str:
        r = super().__repr__()
        time_fmt = datetime.datetime.fromtimestamp(self.time_us / 1e6)
        r += "\n" + f"   Time={repr(time_fmt)}"
        return r

    def __eq__(self, __value: object) -> bool:
        if self.time_us != __value.time_us or self.stanag_counter != __value.stanag_counter:
            return False
        return super().__eq__(__value)
