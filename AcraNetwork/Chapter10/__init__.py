import struct
from functools import reduce
import logging


DATA_TYPE_TIMEFMT_1 = 0x11
DATA_TYPE_TIMEFMT_2 = 0x12
DATA_TYPE_PCM_DATA_FMT1 = 0x9
DATA_TYPE_MILSTD1553_FMT1 = 0x19
DATA_TYPE_ARINC429_FMT0 = 0x38
DATA_TYPE_UART_FMT0 = 0x50
DATA_TYPE_COMPUTER_GENERATED_FORMAT_0 = 0x0
DATA_TYPE_COMPUTER_GENERATED_FORMAT_1 = 0x1
DATA_TYPE_ANALOG = 0x21


TS_RTC = 0
TS_SECONDARY = 1
TS_CH4 = 0
TS_IEEE1558 = 1
TS_ERTC = 2


def buf_to_printable(buffer):
    pw = ""
    for idx in range(len(buffer)):
        (v,) = struct.unpack_from(">B", buffer, idx)
        pw += "{:#04X} ".format(v)
        if idx % 8 == 7:
            pw += "\n"
    return pw
