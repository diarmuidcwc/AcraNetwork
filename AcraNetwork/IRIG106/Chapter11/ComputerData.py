import struct
from collections import defaultdict
from enum import IntEnum


class _ComputerGeneratedData(object):
    """Base class for the computer generated classes"""

    def __init__(self):
        self._csdw = 0  # type: int
        self.payload = b""

    def pack(self):
        return struct.pack("<I", self._csdw) + self.payload

    def unpack(self, buffer):
        (self._csdw,) = struct.unpack_from("<I", buffer, 0)
        self.payload = buffer[4:]


class ComputerGeneratedFormat0(_ComputerGeneratedData):
    """Class to handled ComputerGeneratedFormat0 payloads"""

    def __init__(self):
        super().__init__()

    def __repr__(self):
        return "Computer Generate Format 0. Data Length={}".format(len(self.payload))


FRMT_ASCII = 0
FRMT_XML = 1
FRMT = defaultdict(lambda: "undefined")
FRMT[FRMT_ASCII] = "ASCII Format"
FRMT[FRMT_XML] = "XML Format"

SRCC = defaultdict(lambda: "undefined")
SRCC_NO_CHANGE = 0
SRCC_CHANGE = 1
SRCC[SRCC_NO_CHANGE] = "No Change to Setup"
SRCC[SRCC_CHANGE] = "Change to Setup"


class RCCVER(IntEnum):
    IRIG_106_07 = 0x7
    IRIG_106_09 = 0x8
    IRIG_106_11 = 0x9
    IRIG_106_13 = 0xA
    IRIG_106_15 = 0xB
    IRIG_106_17 = 0xC
    IRIG_106_19 = 0xD
    IRIG_106_22 = 0xE

    @classmethod
    def _missing_(cls, value):
        return cls.IRIG_106_07


class ComputerGeneratedFormat1(_ComputerGeneratedData):
    """Class to handled ComputerGeneratedFormat1 payloads

    >>> c = ComputerGeneratedFormat1()
    >>> c.payload = bytes(10)
    >>> buffer = c.pack()

    """

    def __init__(self):
        super().__init__()
        self.frmt: int = FRMT_ASCII  # setup record format.
        self.srcc: int = SRCC_NO_CHANGE  # Setup Record Configuration Change (SRCC)
        self.rccver: int = RCCVER.IRIG_106_07  # RCC 106 Version (RCCVER

    def unpack(self, buffer: bytes) -> None:
        super().unpack(buffer)
        self.frmt = (self._csdw >> 9) & 0x1
        self.srcc = (self._csdw >> 8) & 0x1
        self.rccver = RCCVER(self._csdw & 0xFF)
        return True

    def pack(self) -> bytes:
        self._csdw = (self.frmt << 9) + (self.srcc << 8) + self.rccver
        return struct.pack("<I", self._csdw) + self.payload

    def __repr__(self):
        return "Computer Generate Format 1.FRMT={} SRCC={} RCCVER={} Data Length={}".format(
            FRMT[self.frmt], SRCC[self.srcc], self.rccver, len(self.payload)
        )
