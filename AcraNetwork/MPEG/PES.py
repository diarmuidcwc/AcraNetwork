import struct
import datetime
import sys
import typing
import logging

logger = logging.getLogger(__name__)


class PES(object):
    def __init__(self) -> None:
        self.streamid: int = 0
        self.length: int = 0
        self.data: bytes = bytes()

    def unpack(self, buffer: bytes):
        (_prefix1, _prefix2, self.streamid, self.length) = struct.unpack_from(">BHBH", buffer)
        prefix = (_prefix1 << 16) + _prefix2
        if prefix != 1:
            raise Exception(f"PES Prefix {prefix:#0X} should be 0x1")
        (optional_hdr, _miscbits, _pes_hdr_len) = struct.unpack_from(">BBB", buffer, 6)
        marker = optional_hdr >> 4
        if marker != 0x8:
            logger.debug("No optional PES header")
            self.data = buffer[6:]
        else:
            self.data = buffer[(6 + 3 + _pes_hdr_len) :]
        (datafword,) = struct.unpack_from(">H", self.data)
        logger.debug(f"PES First Dataw={datafword:#0X}")

    def __repr__(self) -> str:
        return f"PES: Stream ID={self.streamid:#0X} Len={self.length}"
