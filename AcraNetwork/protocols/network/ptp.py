import struct
from AcraNetwork.protocols.network.ptpv1 import PTPv1
from AcraNetwork.protocols.network.ptpv2 import PTPv2

class PTP():
    '''Class to build and unpack a PTP packet'''
    def __init__(self, buf):
        fields = struct.unpack_from('>H', buf)
        self.version = fields[0] & 0xf
        if 0x1 == self.version:
            self = PTPv1(buf)
        else:
            self = PTPv2(buf)
