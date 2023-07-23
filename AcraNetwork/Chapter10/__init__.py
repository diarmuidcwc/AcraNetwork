import struct
from functools import reduce
from .Chapter10 import Chapter10
from .ARINC429 import ARINC429DataPacket, ARINC429DataWord
from .Chapter10UDP import Chapter10UDP, DATA_TYPE_TIMEFMT_1, DATA_TYPE_TIMEFMT_2
from .MILSTD1553 import MILSTD1553Message, MILSTD1553DataPacket
from .PCM import PCMDataPacket, PCMMinorFrame
from .TimeDataFormat import TimeDataFormat1, TimeDataFormat2, double_digits_to_bcd, bcd_to_int
from .UART import UARTDataPacket, UARTDataWord


def buf_to_printable(buffer):
    pw = ""
    for idx in range(len(buffer)):
        (v,) = struct.unpack_from(">B", buffer, idx)
        pw += "{:#04X} ".format(v)
        if idx % 8 == 7:
            pw += "\n"
    return pw