import struct
from functools import reduce
import logging



DATA_TYPE_TIMEFMT_1 = 0X11
DATA_TYPE_TIMEFMT_2 = 0X12
DATA_TYPE_PCM_DATA_FMT1 = 0X9
DATA_TYPE_MILSTD1553_FMT1 = 0X19
DATA_TYPE_ARINC429_FMT0 = 0X38
DATA_TYPE_UART_FMT0 = 0X50
DATA_TYPE_COMPUTER_GENERATED_FORMAT_0 = 0x0
DATA_TYPE_COMPUTER_GENERATED_FORMAT_1 = 0x1


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
