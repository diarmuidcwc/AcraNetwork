import struct
from functools import reduce
import logging
from datetime import datetime, timezone
from enum import IntEnum
from decimal import Decimal


DATA_TYPE_TIMEFMT_1 = 0x11
DATA_TYPE_TIMEFMT_2 = 0x12
DATA_TYPE_PCM_DATA_FMT1 = 0x9
DATA_TYPE_MILSTD1553_FMT1 = 0x19
DATA_TYPE_ARINC429_FMT0 = 0x38
DATA_TYPE_UART_FMT0 = 0x50
DATA_TYPE_COMPUTER_GENERATED_FORMAT_0 = 0x0
DATA_TYPE_COMPUTER_GENERATED_FORMAT_1 = 0x1
DATA_TYPE_ANALOG = 0x21


class DataType(IntEnum):
    TIMEFORMAT_1 = DATA_TYPE_TIMEFMT_1
    TIMEFORMAT_2 = DATA_TYPE_TIMEFMT_2
    PCM = DATA_TYPE_PCM_DATA_FMT1
    MILSTD1553 = DATA_TYPE_MILSTD1553_FMT1
    ARINC429 = DATA_TYPE_ARINC429_FMT0
    COMPUTER_FORMAT_0 = DATA_TYPE_COMPUTER_GENERATED_FORMAT_0
    COMPUTER_FORMAT_1 = DATA_TYPE_COMPUTER_GENERATED_FORMAT_1
    ANALOG = DATA_TYPE_ANALOG
    UART = DATA_TYPE_UART_FMT0


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


class PTPTime(object):
    def __init__(self, seconds=0, nanoseconds=0):
        self.seconds = seconds
        self.nanoseconds = nanoseconds

    def pack(self):
        return struct.pack("<II", self.nanoseconds, self.seconds)

    def unpack(self, buffer):
        (self.nanoseconds, self.seconds) = struct.unpack("<II", buffer)
        return True

    def to_rtc(self):
        ptp_as_date = datetime.fromtimestamp(self.seconds, tz=timezone.utc)
        start_of_year = datetime(ptp_as_date.year, 1, 1, 0, 0, 0)
        start_of_year = start_of_year.replace(tzinfo=timezone.utc)
        seconds_since_start_year = int((ptp_as_date - start_of_year).total_seconds())
        rtc_time = int(seconds_since_start_year * 1e7 + self.nanoseconds / 100)
        return rtc_time

    def to_pinksheet_rtc(self):
        ptp_vector = (Decimal(self.seconds) * Decimal(1e9)) + Decimal(self.nanoseconds)
        ptp_vector_100ns = ptp_vector // Decimal(100)
        ptp_vector_truncated = int(ptp_vector_100ns) & (pow(2, 48) - 1)
        return ptp_vector_truncated

    def __repr__(self):
        time_fmt = "%H:%M:%S %d-%b %Y"
        ts = datetime.fromtimestamp(self.seconds, tz=timezone.utc)
        date_str = ts.strftime(time_fmt)
        return "PTP: {} nanosec={}".format(date_str, self.nanoseconds)

    def __eq__(self, __value):
        if not isinstance(__value, PTPTime):
            return False
        if self.nanoseconds != __value.nanoseconds or self.seconds != __value.seconds:
            return False
        return True

    def __add__(self, val):
        if isinstance(val, PTPTime):
            addns = self.nanoseconds + val.nanoseconds
            ns = int(addns % 1e9)
            sec = self.seconds + val.seconds + int(addns // 1e9)
            return PTPTime(sec, ns)
        else:
            raise Exception("Addition of other PTPTime instances")

    def __sub__(self, val):
        if isinstance(val, PTPTime):
            if val.nanoseconds > self.nanoseconds:
                sec = self.seconds - val.seconds - 1
                nsec = int(1e9) - (val.nanoseconds - self.nanoseconds)
            else:
                sec = self.seconds - val.seconds
                nsec = self.nanoseconds - val.nanoseconds
            return PTPTime(sec, nsec)
        else:
            raise Exception("Subtraction of other PTPTime instances")

    def __lt__(self, val):
        if isinstance(val, PTPTime):
            return (self.seconds + self.nanoseconds / 1e9) < (val.seconds + val.nanoseconds / 1e9)

    def __le__(self, val):
        if isinstance(val, PTPTime):
            _d = (self.seconds + self.nanoseconds / 1e9) <= (val.seconds + val.nanoseconds / 1e9)
            return _d


class RTCTime(object):
    def __init__(self, count=0):
        self.count = count

    def pack(self):
        msw = (self.count >> 32) & 0xFFFF
        lsw = self.count & 0xFFFFFFFF
        return struct.pack("<IHH", lsw, msw, 0)

    def unpack(self, buffer):
        (lsw, msw, _zero) = struct.unpack("<IHH", buffer)
        self.count = lsw + (msw << 32)
        return True

    def to_rtc(self):
        return self.count

    def to_pinksheet_rtc(self):
        return self.count

    def __repr__(self):
        return "RTC: count={}".format(self.count)

    def __eq__(self, __value):
        if not isinstance(__value, RTCTime):
            return False
        if self.count != __value.count:
            return False
        return True
