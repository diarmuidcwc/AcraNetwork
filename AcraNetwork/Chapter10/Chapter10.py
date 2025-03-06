from AcraNetwork.IRIG106.Chapter11 import (
    buf_to_printable,
    get_checksum_buf,
    get_checksum_byte_buf,
    Chapter11,
    TS_RTC,
    TS_SECONDARY,
    TS_CH4,
    TS_IEEE1558,
    TS_ERTC,
)
import warnings
import struct

warnings.warn(
    "This module has been moved and will be deprecated. The path should be AcraNetwork.IRIG106.Chapter11",
    DeprecationWarning,
)


class Chapter10(Chapter11):
    SYNC_WORD = 0xEB25  # :(Object Constant) Sync word

    CH10_HDR_FORMAT = "<HHIIBBBBIHH"
    CH10_HDR_FORMAT_LEN = struct.calcsize(CH10_HDR_FORMAT)

    CH10_OPT_HDR_FORMAT = "<IIHH"
    CH10_OPT_HDR_FORMAT_LEN = struct.calcsize(CH10_OPT_HDR_FORMAT)

    TS_SOURCES = [TS_RTC, TS_SECONDARY]  # :(Object Constant) Valid timesources, assign to :attr:`Chapter10.ts_source`
    TS_SECONDARY_SOURCES = [TS_CH4, TS_IEEE1558, TS_ERTC]

    PKT_FLAG_SECONDARY = 0x80  # :(Object Constant) add to :attr:`Chapter10.packetflag` to enable
    PKT_FLAG_SEC_HDR_TIME = 0x40  # :(Object Constant) add to :attr:`Chapter10.packetflag` to enable
    PKT_FLAG_RTC_SYNC_ERROR = 0x20  # :(Object Constant) add to :attr:`Chapter10.packetflag` to enable
    PKT_FLAG_DATA_OVERFLOW = 0x10  # :(Object Constant) add to :attr:`Chapter10.packetflag` to enable
    PKT_FLAG_RCC_TIME = 0x0  # :(Object Constant) add to :attr:`Chapter10.packetflag` to enable
    PKT_FLAG_1588_TIME = 0x04  # :(Object Constant) add to :attr:`Chapter10.packetflag` to enable
    PKT_FLAG_8BIT_CHKSUM = 0x1  # :(Object Constant) add to :attr:`Chapter10.packetflag` to enable
    PKT_FLAG_16BIT_CHKSUM = 0x2  # :(Object Constant) add to :attr:`Chapter10.packetflag` to enable
    PKT_FLAG_32BIT_CHKSUM = 0x3  # :(Object Constant) add to :attr:`Chapter10.packetflag` to enable
