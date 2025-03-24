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
DATA_TYPE_VIDEO_FMT0 = 0x40
DATA_TYPE_VIDEO_FMT1 = 0x41
DATA_TYPE_VIDEO_FMT2 = 0x42
DATA_TYPE_VIDEO_FMT3 = 0x43


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
    VIDEO_FORMAT_0 = DATA_TYPE_VIDEO_FMT0
    VIDEO_FORMAT_1 = DATA_TYPE_VIDEO_FMT1
    VIDEO_FORMAT_2 = DATA_TYPE_VIDEO_FMT2
    VIDEO_FORMAT_3 = DATA_TYPE_VIDEO_FMT3


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


logger = logging.getLogger(__name__)


def get_checksum_buf(buf: bytes) -> int:
    """
    Return the arithmetic checksum of a header. This is the checksum that is used for the chapter 10 header

    :param buf:
    :return:
    """
    if len(buf) % 2 != 0:
        raise Exception("buffer needs to be 16-bit aligned")

    words = struct.unpack("<{}H".format(len(buf) // 2), buf)
    sum = reduce(lambda x, y: x + y, words)

    return sum % 65536


def get_checksum_byte_buf(buf: bytes) -> int:
    """
    Return the arithmetic checksum of a header. This is the checksum used for the secondary header checksu,

    :param buf:
    :return:
    """

    checksumbytes = struct.unpack(f"<{len(buf)}B", buf)
    sum = reduce(lambda x, y: x + y, checksumbytes)

    return sum % 65536


class Chapter11(object):
    """
    Class to pack and unpack Chapter11 packets. These can not be directly transmitted over a network
    but they can be written to .ch10 files

    Create a packet and transmit it via UDP

    >>> from AcraNetwork.IRIG106.Chapter11 import DataType
    >>> from AcraNetwork.IRIG106.Chapter10.FileParser import FileParser
    >>> import AcraNetwork.IRIG106.Chapter11.ComputerData as chcomputer
    >>> fp = FileParser("myfile.ch10", mode="wb")
    >>> c = Chapter11()
    >>> c.channelID = 0
    >>> c.sequence = 0
    >>> c.packetflag = 0
    >>> c.datatype = DataType.COMPUTER_FORMAT_1
    >>> c.relativetimecounter = 0
    >>> ctmats = chcomputer.ComputerGeneratedFormat1()
    >>> ctmats.payload = bytes(3)
    >>> c.payload = ctmats.pack()
    >>> with fp as ch10file:
    ...     ch10file.write(c)


    """

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

    def __init__(self):
        self.syncpattern = (
            Chapter11.SYNC_WORD
        )  # :(2 Bytes) contains a static sync value for the every packet. The Packet Sync Pattern value shall be 0xEB25
        self.channelID = 0  # :(2 Bytes) contains a value representing the Packet Channel ID.
        self.packetlen = 0  # :(4 Bytes) contains a value representing the length of the entire packet. The value shall be in bytes and is always a multiple of four
        self.datalen = 0  # :(4 Bytes) contains a value representing the valid data length within the packet
        self.datatypeversion = 0x5  #: RCC released versions
        self.sequence = 0  # :(1 Byte) contains a value representing the packet sequence number for each Channel ID.
        self._packetflag = (
            0  # :(1 Byte) contains bits representing information on the content and format of the packet(s)
        )
        self.datatype = 0  # :(1 Byte) contains a value representing the type and format of the data
        self.relativetimecounter = 0  # :(6 Bytes) contains a value representing the 10 MHz Relative Time Counter (RTC)
        self.ptptime = PTPTime()  #: PTP Timestamp
        self.ts_source = TS_RTC  # :The timestamp source. Select from :attr:`Chapter10.TS_SOURCES`
        self.payload = b""  # :The payload
        self.data_checksum_size = 0
        self.filler = b""
        self.has_secondary_header = False

    @property
    def packetflag(self):
        """
        (1 Byte) contains bits representing information on the content and format of the packet(s)

        :type val: intx
        """
        return self._packetflag

    @packetflag.setter
    def packetflag(self, val):
        if val > 0xFF:
            raise Exception("Packet flag ={:#0X} to valud".format(val))
        self._packetflag = val

        if self._packetflag >> 7 == 1:
            if ((self._packetflag >> 2) & 0x3) == 0:
                self.ts_source = TS_CH4
            elif ((self._packetflag >> 2) & 0x3) == 1:
                self.ts_source = TS_IEEE1558
            else:
                raise Exception("Time format is illegal")

            self.has_secondary_header = True
        else:
            self.has_secondary_header = False
            self.ts_source = TS_RTC

    def pack(self):
        """
        Pack the Chapter10 object into a binary buffer

        :rtype: bytes
        """

        if self.has_secondary_header:
            if self.ts_source == TS_CH4:
                raise Exception("Ch4 Timestamp in secondary header not supported")

            sec_hdr = self.ptptime.pack() + struct.pack(">HH", 0, 0)
            # Replace the checksum
            cs = get_checksum_byte_buf(sec_hdr)
            sec_hdr = sec_hdr[:-2] + struct.pack("<H", cs)
        else:
            sec_hdr = b""

        total_len_excl_filler = (
            len(sec_hdr) + len(self.payload) + Chapter11.CH10_HDR_FORMAT_LEN + self.data_checksum_size
        )

        # Add the filler
        if total_len_excl_filler % 4 == 0:
            self.filler = b""
        else:
            fill_len = 4 - (total_len_excl_filler % 4)
            fill_val = [0xFF] * fill_len
            self.filler = struct.pack(">{}B".format(fill_len), *fill_val)

        self.packetlen = total_len_excl_filler + len(self.filler)
        self.datalen = len(self.payload)

        checksum = 0
        _rtc_lwr = self.relativetimecounter & 0xFFFFFFFF
        _rtc_upr = self.relativetimecounter >> 32

        hdr = struct.pack(
            Chapter11.CH10_HDR_FORMAT,
            self.syncpattern,
            self.channelID,
            self.packetlen,
            self.datalen,
            self.datatypeversion,
            self.sequence,
            self.packetflag,
            self.datatype,
            _rtc_lwr,
            _rtc_upr,
            checksum,
        )
        hdr = hdr[:-2] + struct.pack("<H", get_checksum_buf(hdr))
        return hdr + sec_hdr + self.payload + self.filler

    def unpack(self, buffer):
        """
        Unpack a string buffer into an Chapter10 object

        :param buffer: A string buffer representing an Chapter10 packet
        :type buffer: bytes
        :rtype: None
        """
        (
            self.syncpattern,
            self.channelID,
            self.packetlen,
            self.datalen,
            self.datatypeversion,
            self.sequence,
            self.packetflag,
            self.datatype,
            _rtc_lwr,
            _rtc_upr,
            checksum,
        ) = struct.unpack_from(Chapter11.CH10_HDR_FORMAT, buffer)

        offset_hdr = struct.calcsize(Chapter11.CH10_HDR_FORMAT) - 2
        exp_checksum = get_checksum_buf(buffer[:offset_hdr])
        if checksum != exp_checksum:
            logger.error("Ch10 Header checksum {:#0X} does not match expected={:#0X}".format(checksum, exp_checksum))

        self.relativetimecounter = _rtc_lwr + (_rtc_upr << 32)

        if (self.packetflag >> 7) == 1:
            self.has_secondary_header = True
            pkt_hdr_time = (self.packetflag >> 2) & 0x3
            (ts_ns, ts_s, _res, _checksum_sec) = struct.unpack_from(
                Chapter11.CH10_OPT_HDR_FORMAT, buffer, Chapter11.CH10_HDR_FORMAT_LEN
            )

            sec_exp_checksum = get_checksum_byte_buf(
                buffer[
                    Chapter11.CH10_HDR_FORMAT_LEN : Chapter11.CH10_HDR_FORMAT_LEN
                    + Chapter11.CH10_OPT_HDR_FORMAT_LEN
                    - 2
                ]
            )

            if _checksum_sec != sec_exp_checksum:
                logger.error(
                    "Ch10 Secondary Header checksum ({:#0X}) does not match expected={:#0X}".format(
                        _checksum_sec, sec_exp_checksum
                    )
                )
                # print("Ch10 Secondary Header checksum does not match expected={:#0X}".format(sec_exp_checksum))

            if pkt_hdr_time == 0:
                raise Exception("Ch4 Timestamp in secondary header not supported")
                # print("Ch4 Timestamp in secondary header not supported")
            elif pkt_hdr_time == 1:
                self.ts_source = TS_IEEE1558
                self.ptptime = PTPTime(ts_s, ts_ns)
            else:
                raise Exception("Secondary Header Time Format not legal")
                # print("Secondary Header Time Format not legal")
            self.payload = buffer[(Chapter11.CH10_HDR_FORMAT_LEN + Chapter11.CH10_OPT_HDR_FORMAT_LEN) :]
        else:
            self.has_secondary_header = False
            self.payload = buffer[Chapter11.CH10_HDR_FORMAT_LEN :]
            self.ts_source = TS_RTC

        return True

    def __eq__(self, other):
        if not isinstance(other, Chapter11):
            return False

        _match_att = (
            "syncpattern",
            "channelID",
            "packetlen",
            "datalen",
            "datatypeversion",
            "datatype",
            "_packetflag",
            "relativetimecounter",
            "ptptime",
            "ts_source",
            "payload",
            "data_checksum_size",
            "filler",
            "has_secondary_header",
        )

        for attr in _match_att:
            if getattr(self, attr) != getattr(other, attr):
                return False

        return True

    def __repr__(self):
        return "Chapter 11: ChannelID={} Sequence={} DataLen={}".format(self.channelID, self.sequence, self.datalen)
