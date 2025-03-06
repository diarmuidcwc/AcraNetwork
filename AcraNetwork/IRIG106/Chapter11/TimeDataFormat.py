from datetime import datetime, timezone
import struct
from AcraNetwork.IRIG106.Chapter11 import PTPTime

ITS_FREEWHEELING = 0x0 << 12
ITS_FREEWHEELING_FROM_TIME = 0x0 << 12
ITS_FREEWHEELING_FROM_RMM = 0x0 << 12
ITS_LOCKED_IRIG = 0x0 << 12
ITS_LOCKED_GPS = 0x0 << 12
ITS_LOCKED_NTP = 0x0 << 12
ITS_LOCKED_PTP = 0x0 << 12
ITS_LOCKED_EMBEDDED = 0x0 << 12

DATE_FMT_YEAR_AVAIL = 0x1 << 9
DATE_FMT_LEAP_YEAR = 0x1 << 8

TIME_FMT_IRIGB = 0x0
TIME_FMT_IRIGA = 0x1 << 4
TIME_FMT_IRIGG = 0x2 << 4
TIME_FMT_RTC = 0x3 << 4
TIME_FMT_UTC = 0x4 << 4
TIME_FMT_GPS = 0x5 << 4
TIME_FMT_NONE = 0xF << 4

SRC_INTERNAL = 0x0
SRC_EXTERNAL = 0x1
SRC_INT_FMM = 0x2
SRC_NONE = 0xF


def double_digits_to_bcd(val: int) -> int:
    """
    Very simplified conversion of time to format used in Ch10 Time packet

    :param val: time field value in integers.
    :return:
    """
    offsets = {1: 0, 10: 4}
    retval = 0
    for dec, offset in offsets.items():
        retval += (int(val / dec) % 10) << offset
    return retval


def bcd_to_int(val: int) -> int:
    """

    :param val:
    :return:
    """
    if val < 0:
        raise ValueError("Cannot be a negative integer")

    if val == 0:
        return 0

    bcdstring = ""
    while val > 0:
        nibble = val % 16
        bcdstring = str(nibble) + bcdstring
        val >>= 4
    return int(bcdstring)


class TimeDataFormat1(object):
    """
    Class to pack and unpack Chapter10 TIME packet payloads.

    Create a packet and transmit it via UDP

    >>> from base64 import b64encode
    >>> t = TimeDataFormat1()
    >>> t.ptptime.seconds = 100
    >>> print(len(t.pack()))
    12

    :type channel_specific_data: int
    :type milliseconds: int
    :type datetime: datetime | None
    :type filler: str
    """

    def __init__(self):
        self.channel_specific_data = ITS_FREEWHEELING + DATE_FMT_YEAR_AVAIL + TIME_FMT_GPS + SRC_EXTERNAL
        self.ptptime = PTPTime(0, 0)

    def pack(self):
        """
        Pack the Chapter10 object into a binary buffer

        :rtype: str
        """

        dt = datetime.fromtimestamp(self.ptptime.seconds, tz=timezone.utc)
        packet_bytes = list()
        packet_bytes.append(double_digits_to_bcd(self.ptptime.nanoseconds / 1e7))
        packet_bytes.append(double_digits_to_bcd(dt.second))
        packet_bytes.append(double_digits_to_bcd(dt.minute))
        packet_bytes.append(double_digits_to_bcd(dt.hour))
        if (self.channel_specific_data & DATE_FMT_YEAR_AVAIL) >> 9 == 0x1:
            packet_bytes.append(double_digits_to_bcd(dt.day))
            packet_bytes.append(double_digits_to_bcd(dt.month))
            packet_bytes.append(double_digits_to_bcd(dt.year % 100))
            packet_bytes.append(double_digits_to_bcd(dt.year / 100))
        else:
            doy = int(dt.strftime("%j"))
            packet_bytes.append(double_digits_to_bcd(doy % 100))
            packet_bytes.append(double_digits_to_bcd(doy / 100))

        mybytes = struct.pack("<I", self.channel_specific_data)
        mybytes += struct.pack("<{}B".format(len(packet_bytes)), *packet_bytes)

        return mybytes

    def unpack(self, buf):
        """
        Unpack a string buffer into a TimeFormat object
        :param buffer:
        :return:
        """
        (self.channel_specific_data, ms, s, mn, h) = struct.unpack_from("<IBBBB", buf)
        milliseconds = bcd_to_int(ms) * 10
        nanoseconds = milliseconds * int(1e6)
        sec = bcd_to_int(s)
        mins = bcd_to_int(mn)
        hrs = bcd_to_int(h)

        if (self.channel_specific_data & DATE_FMT_YEAR_AVAIL) >> 9 == 0x1:
            (d, mo, yr) = struct.unpack_from("<BBH", buf, 8)
            day = bcd_to_int(d)
            mon = bcd_to_int(mo)
            year = bcd_to_int(yr)
            dt = datetime(year, mon, day, hrs, mins, sec)
        else:
            (doy, hdoy) = struct.unpack_from("<BB", buf, 8)
            day_of_year = bcd_to_int(doy) + 100 * bcd_to_int(hdoy)
            date_as_string = "{:02d}:{:02d}:{:02d} {:03d} 1970 GMT".format(hrs, mins, sec, day_of_year)
            dt = datetime.strptime(date_as_string, "%H:%M:%S %j %Y %Z")

        dt = dt.replace(tzinfo=timezone.utc)

        seconds = int(dt.timestamp())
        self.ptptime = PTPTime(seconds, nanoseconds)

        return True

    def __eq__(self, other):
        if not isinstance(other, TimeDataFormat1):
            return False

        _match_att = ("channel_specific_data", "ptptime")

        for attr in _match_att:
            if getattr(self, attr) != getattr(other, attr):
                return False

        return True

    def __repr__(self):
        return "TimeFormat1 ChannelSpecificWord={:#0X} Time={}".format(self.channel_specific_data, self.ptptime)

    def __len__(self):
        if (self.channel_specific_data & DATE_FMT_YEAR_AVAIL) >> 9 == 0x1:
            return 4 * (4 + 1)
        else:
            return 4 * (3 + 1)


TS_STATUS_VALID = 0x1
TS_STATUS_IEEE2002 = 0x1 << 4
TS_STATUS_IEEE2008 = 0x2 << 4


class TimeDataFormat2(object):
    """
    Class to pack and unpack Chapter10 TIME packet payloads.

    Create a packet and transmit it via UDP


    :type channel_specific_data: int
    :type filler: str
    """

    def __init__(self):
        self.channel_specific_data = TS_STATUS_VALID + TS_STATUS_IEEE2002
        self.ptptime = PTPTime()

    def pack(self):
        """
        Pack the Chapter10 time object into a binary buffer

        :rtype: str
        """

        if (self.channel_specific_data >> 4) & 0x1:
            # ptp
            frac_sec = self.ptptime.nanoseconds
        else:
            # ntp
            frac_sec = int(self.ptptime.nanoseconds * (pow(2, 32) / 1e9))

        return struct.pack("<III", self.channel_specific_data, self.ptptime.seconds, frac_sec)

    def unpack(self, buf):
        """
        Unpack a string buffer into a TimeFormat object
        :param buffer: str
        :return:
        """
        (self.channel_specific_data, s, fs) = struct.unpack("<III", buf)
        if (self.channel_specific_data >> 4) & 0xF != 0:  # Make PTP the default
            nanoseconds = fs
        else:
            nanoseconds = int(fs / (pow(2, 32) / 1e9))  # NTP

        self.ptptime = PTPTime(s, nanoseconds)

        return True

    def __eq__(self, other):
        if not isinstance(other, TimeDataFormat2):
            return False

        _match_att = ("channel_specific_data", "ptptime")

        for attr in _match_att:
            if getattr(self, attr) != getattr(other, attr):
                return False

        return True

    def __repr__(self):
        return "TimeFormat2 ChannelSpecificWord={:#0X} Time={} ".format(self.channel_specific_data, self.ptptime)

    def __len__(self):
        return 3 * 4
