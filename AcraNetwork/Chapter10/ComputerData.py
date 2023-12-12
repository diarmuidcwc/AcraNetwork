import struct
from collections import defaultdict


class _ComputerGeneratedData(object):

    def __init__(self):
        self._csdw = 0  # type: int
        self.payload = b''

    def pack(self):
        return struct.pack("<I", self._csdw) + self.payload
    
    def unpack(self, buffer):
        (self._csdw, ) = struct.unpack_from("<I", buffer, 0)
        self.payload = buffer[4:]


class ComputerGeneratedFormat0(_ComputerGeneratedData):
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
SRCC_NO_CHANGE = 1
SRCC_CHANGE = 0
SRCC[SRCC_NO_CHANGE] = "No Change to Setup"
SRCC[SRCC_CHANGE] = "Change to Setup"

RCCVER = defaultdict(lambda: "undefined")
RCCVER_IRIG_106_22 = 0xE
RCCVER[RCCVER_IRIG_106_22] = "IRIG 106-22"


class ComputerGeneratedFormat1(_ComputerGeneratedData):
    def __init__(self):
        super().__init__()
        self.frmt = FRMT_ASCII
        self.srcc = SRCC_NO_CHANGE
        self.rccver = RCCVER_IRIG_106_22

    def unpack(self, buffer):
        super().unpack(buffer)
        self.frmt = (self._csdw >> 8) & 0x1
        self.srcc = (self._csdw >> 7) & 0x1
        self.rccver = self._csdw & 0xFF
        return True

    def pack(self):
        self._csdw = (self.frmt << 8) + (self.srcc << 7) + self.rccver
        return struct.pack("<I", self._csdw) + self.payload

    def __repr__(self):
        return "Computer Generate Format 1.FRMT={} SRCC={} RCCVER={} Data Length={}".format(
            FRMT[self.frmt], SRRC[self.srcc], RCCVER[self.rccver], len(self.payload))