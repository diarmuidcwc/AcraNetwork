import struct
import typing
import logging
from AcraNetwork.MPEGTS import MPEGPacket
from functools import reduce
import datetime

logger = logging.getLogger(__name__)


PES_EXTENSION_W1 = 0x81
PES_EXTENSION_W2 = 0x80


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
            (self.extension_w1, self.extension_w2) = struct.unpack_from(">HH", self.payload, 6)
            self.header_data = self.payload[9 : (9 + _pes_hdr_len)]
            self.pesdata = self.payload[(9 + _pes_hdr_len) :]
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
            self.payload += struct.pack(">HHB", self.extension_w1, self.extension_w2, len(self.header_data))
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


class STANAG4609(PES):
    UNKNOWN_OFFSET = 5  # There's some data at the start that I don't understand
    UNIVERSAL_KEY = struct.pack(">QQ", 0x060E2B34020B0101, 0x0E01030101000000)
    DATA_TAG = 0x2
    PID = 0x104

    def __init__(self) -> None:
        super().__init__()
        self.time = None

    def unpack(self, buffer: bytes):
        super().unpack(buffer)
        if self.pid != STANAG4609.PID:
            raise Exception(f"PID of STANAG should be 0x104 not {self.pid:#0X}")
        _offset = len(STANAG4609.UNIVERSAL_KEY) + STANAG4609.UNKNOWN_OFFSET
        if self.pesdata[STANAG4609.UNKNOWN_OFFSET : _offset] != STANAG4609.UNIVERSAL_KEY:
            raise Exception("STANAG4609 requires a specific UNIVERSAL KEY")
        (_len, _datatag, _tag_len) = struct.unpack_from(">BBB", self.pesdata, _offset)
        if _datatag != STANAG4609.DATA_TAG:
            raise Exception("Data tag of STANAG should be 0x2")
        if _tag_len != 8:
            raise Exception(f"Tag length should be 8 not {_tag_len}")
        _offset += 3
        (time_us, _timetag, _time_len, actchecksum) = struct.unpack_from(">QBBH", self.pesdata, _offset)
        time_in_s = time_us / 1e6
        self.time = datetime.datetime.fromtimestamp(time_in_s)
        checksum = checksum_stanag(self.pesdata[STANAG4609.UNKNOWN_OFFSET : -2])
        if checksum != actchecksum:
            raise Exception(f"Extracted checksum={actchecksum:#0X} Calculated={checksum:#0X}")

    def __repr__(self) -> str:
        r = super().__repr__()
        r += "\n" + f"Time={repr(self.time)}"
        return r
