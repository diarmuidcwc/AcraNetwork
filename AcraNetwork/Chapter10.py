"""
.. module:: Chapter10
    :platform: Unix, Windows
    :synopsis: Class to construct and de construct Chapter10 Packets

.. moduleauthor:: Diarmuid Collins <dcollins@curtisswright.com>

"""
__author__ = "Diarmuid Collins"
__copyright__ = "Copyright 2018"
__maintainer__ = "Diarmuid Collins"
__email__ = "dcollins@curtisswright.com"
__status__ = "Production"


import struct
from functools import reduce
from datetime import datetime
import time


def get_checksum_buf(buf):
    """
    Return the arithmetic checksum of a header

    :param buf:
    :return:
    """
    if len(buf) % 2 != 0:
        raise Exception("buffer needs to be 16-bit aligned")

    words = struct.unpack("<{}H".format(len(buf)//2), buf)
    sum = reduce(lambda x, y: x + y, words)

    return sum % 65536


def double_digits_to_bcd(val):
    """
    Very simplified conversion of time to format used in Ch10 Time packet

    :param val: time field value in integers.
    :return:
    """
    offsets = {1: 0, 10: 4}
    retval = 0
    for dec, offset in offsets.items():
        retval += ((int(val / dec) % 10) << offset)
    return retval


def bcd_to_int(val):
    """

    :param val:
    :return:
    """
    if val < 0:
        raise ValueError("Cannot be a negative integer")

    if val == 0:
        return 0

    bcdstring = ''
    while val > 0:
        nibble = val % 16
        bcdstring = str(nibble) + bcdstring
        val >>= 4
    return int(bcdstring)


def buf_to_printable(buffer):
    pw = ""
    for idx in range(len(buffer)):
        (v,) = struct.unpack_from(">B", buffer, idx)
        pw += "{:#04X} ".format(v)
        if idx % 8 == 7:
            pw += "\n"
    return pw


class Chapter10UDP(object):
    """ 
    Class to encapsulate Chapter10 payload in UDP packets

    Capture a UDP packet and unpack the payload as an Chapter 10 packet
    
    There are two types of packets, segmented and full. 

    >>> import socket
    >>>> recv_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)  
    >>> data, addr = recv_socket.recvfrom(2048)
    >>> n = Chapter10UDP()
    >>> n.unpack(data)
    >>> print n.type
    0

    :type version: int
    :type type: int
    :type hdrlen: int
    :type channelID: int
    :type channelsequence: int
    :type segmentoffset: int
    :type chapter10: Chapter10
    """

    CH10_UDP_HEADER_FORMAT1 = '<BBH'
    CH10_UDP_HEADER_FORMAT2 = ">HBB"
    CH10_UDP_SEG_HEADER_FORMAT1 = '<HBBI'

    CH10_HDR_LEN = {1: 4, 2: 12, 3: 8}  # fmt1, 2, 3

    CH10_UDP_HEADER_LENGTH = struct.calcsize(CH10_UDP_HEADER_FORMAT1)
    CH10_UDP_SEG_HEADER_LENGTH = struct.calcsize(CH10_UDP_SEG_HEADER_FORMAT1)

    TYPE_FULL = 0  #: Full Chapter 10 packets type field constant. Assign to :attr:`Chapter10UDP.type`
    TYPE_SEG = 1  #: Segmented Chapter 10 packets type field constant. Assign to :attr:`Chapter10UDP.type`

    def __init__(self):
        '''Creator method for a UDP class'''
        self.version = 1  #: Version
        self.type = None  #: Type of message , Full or Segmented
        self.channelID = None  #: Segmented Packets Only. Channel ID of the data in the RCC 106 Chapter 10 packet
        self.channelsequence = None  #: Segmented Packets Only, Channel Sequence Number of the data in the RCC 106 Chapter 10 packet
        self.sequence = None  #: UDP Sequence number
        self.segmentoffset = None  #: Segmented Packets Only. The 32-bit Segmented Packets Only, Position of the data in the RCC 106 Chapter 10 packet.
        self.packetsize = None  #: Format 2 Packet size
        self.sourceid_len = None  #: Format 3 Source ID length
        self.sourceid = 0  #: Format 3 Source ID
        self.offset_pkt_start = None  #: Format 3 Offset to packet start in bytes
        self.payload = b""
        self.chapter10 = Chapter10() #: The encapsulated Chapter10 packet. :class:`Chapter10`

    def unpack(self, buffer):
        """
        Unpack a string buffer into an Chapter10UDP object

        :param buffer: A string buffer representing an Chapter10UDP packet
        :type buffer: bytes
        :rtype: None
        """
        # Format 2 is big endian so check if this packet is format 2 first
        (seg_upr, seg_lwr, _ver_type) = struct.unpack_from(Chapter10UDP.CH10_UDP_HEADER_FORMAT2, buffer)
        # Because of the endianness issue, some format 1 packets can look like format 2 if we naievly look at the
        # format field. Instead also look at the size and if it matches the size of the buffer then assume that
        # we have the correct format
        (_size_upp, _size_lower,) = struct.unpack_from(">BH", buffer, 5)
        size_guess = _size_lower + (_size_upp << 16)
        if _ver_type & 0xF == 2 and size_guess == len(buffer)/4 - 3:
            self.version = _ver_type & 0xF
        else:
            (_ver_type, seg_lwr, seg_upr) = struct.unpack_from(Chapter10UDP.CH10_UDP_HEADER_FORMAT1, buffer)
            self.version = _ver_type & 0xF

        self.type = _ver_type >> 4
        self.sequence = seg_lwr + (seg_upr << 8)

        if self.version == 3:
            self.sourceid_len =_ver_type >> 4
            self.offset_pkt_start = seg_upr

        if self.type == Chapter10UDP.TYPE_SEG and self.format == 1:
            (self.channelID, self.channelsequence, _res, self.segmentoffset) = \
                struct.unpack_from(Chapter10UDP.CH10_UDP_HEADER_FORMAT1, buffer, Chapter10UDP.CH10_UDP_HEADER_LENGTH)
            self.payload = buffer[(Chapter10UDP.CH10_UDP_HEADER_LENGTH + Chapter10UDP.CH10_UDP_SEG_HEADER_LENGTH):]
        elif self.format == 1:
            self.payload = buffer[Chapter10UDP.CH10_UDP_HEADER_LENGTH:]
        elif self.format == 2:

            (_segoffset_upper ,_size_upp, _size_lower , _segoff_lower, self.channelID) = struct.unpack_from(
                ">BBHHH", buffer, 4
            )
            self.packetsize = _size_lower + (_size_upp << 16)
            self.segmentoffset = _segoff_lower + (_segoffset_upper << 16)
            self.payload = buffer[Chapter10UDP.CH10_UDP_HEADER_LENGTH + 8:]
        elif self.format == 3:
            (_srcid_datat, ) = struct.unpack_from("<I", buffer, 4)
            if self.sourceid_len == 0:
                self.sourceid = 0x0
                self.sequence = _srcid_datat
            elif self.sourceid_len == 1:
                self.sourceid = _srcid_datat >> (32 - 4)
                self.sequence = _srcid_datat & 0x0FFFFFFF
            elif self.sourceid_len == 2:
                self.sourceid = _srcid_datat >> (32 - 8)
                self.sequence = _srcid_datat & 0x00FFFFFF
            elif self.sourceid_len == 3:
                self.sourceid = _srcid_datat >> (32 - 12)
                self.sequence = _srcid_datat & 0x000FFFFF
            elif self.sourceid_len == 4:
                self.sourceid = _srcid_datat >> (32 - 16)
                self.sequence = _srcid_datat & 0x0000FFFF
            else:
                raise Exception("Source id length {} is not valid".format(self.sourceid_len))

            self.payload = buffer[Chapter10UDP.CH10_UDP_HEADER_LENGTH + 4:]

        else:
            self.payload = buffer[Chapter10UDP.CH10_UDP_HEADER_LENGTH:]

        return self.chapter10.unpack(self.payload)

    @property
    def format(self):
        return self.version

    @format.setter
    def format(self, val):
        self.version = val

    def pack(self):
        """
        Pack the Chapter10UDP object into a binary buffer

        :rtype: bytes
        """

        if self.format == 3:
            _ver_type = (self.sourceid_len << 4) + self.version
            seg_up = self.offset_pkt_start
            seg_lr = 0
        else:
            _ver_type = (self.type << 4) + self.version
            seg_up = self.sequence >> 8
            seg_lr = self.sequence & 0xFF

        if self.format == 2:
            _payload = struct.pack(Chapter10UDP.CH10_UDP_HEADER_FORMAT2, seg_up, seg_lr, _ver_type)
        else:
            _payload= struct.pack(Chapter10UDP.CH10_UDP_HEADER_FORMAT1, _ver_type, seg_lr, seg_up)

        self.payload = self.chapter10.pack()
        if self.type == Chapter10UDP.TYPE_SEG and self.format == 1:
            _payload += struct.pack(Chapter10UDP.CH10_UDP_SEG_HEADER_FORMAT1, self.channelID, self.channelsequence, 0, self.segmentoffset)

        elif self.format == 2:
            self.packetsize = len(self.payload)//4
            _payload += struct.pack(">BBHHH", self.segmentoffset >> 16, self.packetsize >> 16, self.packetsize & 0xFFFF, self.segmentoffset & 0xFFFF,
                                   self.channelID)

        elif self.format == 3:
            if self.sourceid_len == 0:
                _field = self.sequence
            elif self.sourceid_len == 1:
                _field = (self.sequence & 0x0FFFFFFF) + (self.sourceid << (32 - 4))
            elif self.sourceid_len == 2:
                _field = (self.sequence & 0x00FFFFFF) + (self.sourceid << (32 - 8))
            elif self.sourceid_len == 3:
                _field = (self.sequence & 0x000FFFFF) + (self.sourceid << (32 - 12))
            elif self.sourceid_len == 4:
                _field = (self.sequence & 0x0000FFFF) + (self.sourceid << (32 - 16))
            else:
                _field = 0
                raise Exception("Invalid source id")

            _payload += struct.pack("<I", _field)

        return _payload + self.payload

    def __repr__(self):
        if self.type == Chapter10UDP.TYPE_FULL:
            return "CH10 UDP Full Packet: Format={} Sequence={} Payload={}".format(
                self.format, self.sequence, repr(self.chapter10))
        else:
            return "CH10 UDP Sequence: Format={} Sequence={} ChID={} ChSeqNum={} SegOffset={}".format(
                self.format, self.sequence, self.channelID, self.channelsequence, self.segmentoffset)

    def __eq__(self, other):
        if not isinstance(other, Chapter10UDP):
            return False

        if self.type == Chapter10UDP.TYPE_SEG and self.format == 1:
            _match_att = ("version", "type", "sequence", "channelID", "channelsequence", "segmentoffset", "payload")
        elif self.format == 2:
            _match_att = ("format", "type", "sequence", "channelID", "channelsequence", "segmentoffset", "packetsize",
                          "payload")
        elif self.format == 3:
            _match_att = ("format", "sourceid_len", "sourceid", "sequence", "offset_pkt_start", "payload")
        else:
            _match_att = ("version", "type", "sequence", "payload")

        for attr in _match_att:
            if getattr(self, attr) != getattr(other, attr):
                return False

        return True


DATA_TYPE_TIMEFMT_1 = 0X11
DATA_TYPE_TIMEFMT_2 = 0X12
DATA_TYPE_PCM_DATA_FMT1 = 0X9


class Chapter10(object):
    """
    Class to pack and unpack Chapter10 payloads. 
    
    Create a packet and transmit it via UDP
    
    >>> import socket
    >>> # Open a socket
    >>> tx_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    >>> # Create the Ch10 UDP wrapper
    >>> ch10_udp = Chapter10UDP()
    >>> ch10_udp.type = Chapter10UDP.TYPE_FULL
    >>> ch10_udp.sequence = 1
    >>> # Populate the Chapter 10 packet inthe wrapper
    >>> ch10_udp.chapter10.channelID = 1
    >>> ch10_udp.chapter10.datatypeversion = 2
    >>> ch10_udp.chapter10.sequence = 3
    >>> ch10_udp.chapter10.packetflag = 0 # No secondary
    >>> ch10_udp.chapter10.datatype = 4
    >>> ch10_udp.chapter10.relativetimecounter = 100
    >>> ch10_udp.chapter10.payload = struct.pack(">II", 33, 44)
    >>> # Send the packet
    >>> tx_socket.sendto(ch10_udp.pack(), ("127.0.0.1", 8010))
    36

    :type syncpattern: int
    :type channelID: int
    :type packetlen: int
    :type datalen: int
    :type datatypeversion: int
    :type sequence: int
    :type datatype: int
    :type relativetimecounter: int
    :type timestamp: int
    :type ts_source: str
    :type payload: bytes
    :type data_checksum_size: int
    :type filler: bytes
    """

    SYNC_WORD = 0xEB25  #:(Object Constant) Sync word

    CH10_HDR_FORMAT = "<HHIIBBBBIHH"
    CH10_HDR_FORMAT_LEN = struct.calcsize(CH10_HDR_FORMAT)

    CH10_OPT_HDR_FORMAT = "<IIHH"
    CH10_OPT_HDR_FORMAT_LEN = struct.calcsize(CH10_OPT_HDR_FORMAT)

    TS_SOURCES = ["rtc", "ch4", "ieee1588"] #:(Object Constant) Valid timesources, assign to :attr:`Chapter10.ts_source`

    PKT_FLAG_SECONDARY = 0x80  #:(Object Constant) add to :attr:`Chapter10.packetflag` to enable
    PKT_FLAG_SEC_HDR_TIME = 0x40  #:(Object Constant) add to :attr:`Chapter10.packetflag` to enable
    PKT_FLAG_RTC_SYNC_ERROR = 0x20  #:(Object Constant) add to :attr:`Chapter10.packetflag` to enable
    PKT_FLAG_DATA_OVERFLOW = 0X10  #:(Object Constant) add to :attr:`Chapter10.packetflag` to enable
    PKT_FLAG_RCC_TIME = 0X0  #:(Object Constant) add to :attr:`Chapter10.packetflag` to enable
    PKT_FLAG_1588_TIME = 0X04  #:(Object Constant) add to :attr:`Chapter10.packetflag` to enable
    PKT_FLAG_8BIT_CHKSUM = 0X1  #:(Object Constant) add to :attr:`Chapter10.packetflag` to enable
    PKT_FLAG_16BIT_CHKSUM = 0X2  #:(Object Constant) add to :attr:`Chapter10.packetflag` to enable
    PKT_FLAG_32BIT_CHKSUM = 0X3  #:(Object Constant) add to :attr:`Chapter10.packetflag` to enable

    def __init__(self):

        self.syncpattern = Chapter10.SYNC_WORD  #:(2 Bytes) contains a static sync value for the every packet. The Packet Sync Pattern value shall be 0xEB25
        self.channelID = None  #:(2 Bytes) contains a value representing the Packet Channel ID.
        self.packetlen = None  #:(4 Bytes) contains a value representing the length of the entire packet. The value shall be in bytes and is always a multiple of four
        self.datalen = None  #:(4 Bytes) contains a value representing the valid data length within the packet
        self.datatypeversion = 0x5  #: RCC released versions
        self.sequence= None  #:(1 Byte) contains a value representing the packet sequence number for each Channel ID.
        self._packetflag = None  #:(1 Byte) contains bits representing information on the content and format of the packet(s)
        self.datatype = None  #:(1 Byte) contains a value representing the type and format of the data
        self.relativetimecounter = None  #:(6 Bytes) contains a value representing the 10 MHz Relative Time Counter (RTC)
        self.ptptimeseconds = None  #: PTP Timestamp seconds
        self.ptptimenanoseconds = None  #: PTP Timestamp nanoseconds
        self.ts_source = "ieee1588" #:The timestamp source. Select from :attr:`Chapter10.TS_SOURCES`
        self.payload = b""  #:The payload
        self.data_checksum_size = 0
        self.filler = b""
        self._secondary_header = False

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
            raise Exception("Packet flag ={:#0X} to valuid".format(val))
        self._packetflag = val

        if self._packetflag >> 7 == 1:

            if ((self._packetflag >> 2) & 0x3) == 0:
                self.ts_source = "ch4"
            elif ((self._packetflag >> 2) & 0x3) == 1:
                self.ts_source = "ieee1588"
            else:
                raise Exception("Time format is illegal")

            self._secondary_header = True
        else:
            self._secondary_header = False

    def pack(self):
        """
        Pack the Chapter10 object into a binary buffer

        :rtype: bytes
        """

        if self._secondary_header:
            if self.ts_source == "ch4":
                raise Exception("Ch4 Timestamp in secondary header not supported")

            sec_hdr = struct.pack(Chapter10.CH10_OPT_HDR_FORMAT, self.ptptimenanoseconds, self.ptptimeseconds, 0, 0)
            # Replace the checksum
            cs = get_checksum_buf(sec_hdr)
            sec_hdr = sec_hdr[:-2] + struct.pack("<H", cs)
        else:
            sec_hdr = b""

        total_len_excl_filler = len(sec_hdr) + len(self.payload) + Chapter10.CH10_HDR_FORMAT_LEN + self.data_checksum_size

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

        hdr = struct.pack(Chapter10.CH10_HDR_FORMAT, self.syncpattern, self.channelID, self.packetlen, self.datalen,
                          self.datatypeversion, self.sequence, self.packetflag, self.datatype, _rtc_lwr,_rtc_upr, checksum)
        hdr = hdr[:-2] + struct.pack("<H", get_checksum_buf(hdr))
        return hdr + sec_hdr + self.payload + self.filler

    def unpack(self, buffer):
        """
        Unpack a string buffer into an Chapter10 object

        :param buffer: A string buffer representing an Chapter10 packet
        :type buffer: bytes
        :rtype: None
        """
        (self.syncpattern, self.channelID, self.packetlen, self.datalen, self.datatypeversion, self.sequence,
         self.packetflag, self.datatype, _rtc_lwr,_rtc_upr, checksum) = struct.unpack_from(Chapter10.CH10_HDR_FORMAT, buffer)

        offset_hdr = struct.calcsize(Chapter10.CH10_HDR_FORMAT)-2
        exp_checksum = get_checksum_buf(buffer[:offset_hdr])
        if checksum != exp_checksum:
            raise Exception("Ch10 Header checksum {:#0X} does not match expected={:#0X}".format(checksum, exp_checksum))
            #print("Ch10 Header checksum does not match expected={:#0X}".format(exp_checksum))

        self.relativetimecounter = _rtc_lwr + (_rtc_upr << 32)

        self.ts_source = "ieee1588"
        if (self.packetflag >> 7) == 1:
            self._secondary_header = True
            pkt_hdr_time =  (self.packetflag >> 2) & 0x3
            (ts_ns, ts_s, _res, _checksum_sec) = struct.unpack_from(
                Chapter10.CH10_OPT_HDR_FORMAT, buffer, Chapter10.CH10_HDR_FORMAT_LEN)

            sec_exp_checksum = get_checksum_buf(
                buffer[Chapter10.CH10_HDR_FORMAT_LEN:Chapter10.CH10_HDR_FORMAT_LEN+Chapter10.CH10_OPT_HDR_FORMAT_LEN-2])

            if _checksum_sec != sec_exp_checksum:
                raise Exception("Ch10 Secondary Header checksum ({:#0X}) does not match expected={:#0X}".format(
                    _checksum_sec, sec_exp_checksum))
                #print("Ch10 Secondary Header checksum does not match expected={:#0X}".format(sec_exp_checksum))

            if pkt_hdr_time == 0:
                raise Exception("Ch4 Timestamp in secondary header not supported")
                #print("Ch4 Timestamp in secondary header not supported")
            elif pkt_hdr_time == 1:
                self.ts_source = "ieee1588"
                self.ptptimenanoseconds = ts_ns
                self.ptptimeseconds = ts_s
            else:
                raise Exception("Secondary Header Time Format not legal")
                #print("Secondary Header Time Format not legal")
            self.payload = buffer[(Chapter10.CH10_HDR_FORMAT_LEN + Chapter10.CH10_OPT_HDR_FORMAT_LEN):]
        else:
            self._secondary_header = False
            self.payload = buffer[Chapter10.CH10_HDR_FORMAT_LEN:]


        return True

    def __eq__(self, other):
        if not isinstance(other, Chapter10):
            return False

        _match_att = ("syncpattern", "channelID", "packetlen", "datalen", "datatypeversion", "datatype", "_packetflag",
                      "relativetimecounter", "ptptimeseconds", "ptptimenanoseconds", "ts_source", "payload",
                      "data_checksum_size", "filler", "_secondary_header")

        for attr in _match_att:
            if getattr(self, attr) != getattr(other, attr):
                return False

        return True

    def __repr__(self):
        return "Chapter 10: ChannelID={} Sequence={} DataLen={}".format(self.channelID, self.sequence, self.datalen)


ITS_FREEWHEELING = (0X0 << 12)
ITS_FREEWHEELING_FROM_TIME = (0X0 << 12)
ITS_FREEWHEELING_FROM_RMM = (0X0 << 12)
ITS_LOCKED_IRIG = (0X0 << 12)
ITS_LOCKED_GPS = (0X0 << 12)
ITS_LOCKED_NTP = (0X0 << 12)
ITS_LOCKED_PTP = (0X0 << 12)
ITS_LOCKED_EMBEDDED = (0X0 << 12)

DATE_FMT_YEAR_AVAIL = (0X1 << 9)
DATE_FMT_LEAP_YEAR = (0X1 << 8)

TIME_FMT_IRIGB = 0X0
TIME_FMT_IRIGA = (0X1 << 4)
TIME_FMT_IRIGG = (0X2 << 4)
TIME_FMT_RTC = (0X3 << 4)
TIME_FMT_UTC = (0X4 << 4)
TIME_FMT_GPS = (0X5 << 4)
TIME_FMT_NONE = (0XF << 4)

SRC_INTERNAL = 0X0
SRC_EXTERNAL = 0X1
SRC_INT_FMM = 0X2
SRC_NONE = 0XF


class TimeDataFormat1(object):
    """
    Class to pack and unpack Chapter10 TIME packet payloads. 
    
    Create a packet and transmit it via UDP


    :type channel_specific_data: int
    :type milliseconds: int
    :type datetime: datetime | None
    :type filler: str
    """

    def __init__(self):

        self.channel_specific_data = ITS_FREEWHEELING + DATE_FMT_YEAR_AVAIL + TIME_FMT_GPS + SRC_EXTERNAL
        self.datetime = None
        self.milliseconds = 0

    def pack(self):
        """
        Pack the Chapter10 object into a binary buffer

        :rtype: str
        """
        if not isinstance(self.datetime, datetime):
            raise Exception("datetime attribute should be an instance of the datetime object ")

        packet_bytes = list()
        packet_bytes.append(double_digits_to_bcd(self.milliseconds/10))
        packet_bytes.append(double_digits_to_bcd(self.datetime.second))
        packet_bytes.append(double_digits_to_bcd(self.datetime.minute))
        packet_bytes.append(double_digits_to_bcd(self.datetime.hour))
        if (self.channel_specific_data & DATE_FMT_YEAR_AVAIL) >> 9 == 0x1:
            packet_bytes.append(double_digits_to_bcd(self.datetime.day))
            packet_bytes.append(double_digits_to_bcd(self.datetime.month))
            packet_bytes.append(double_digits_to_bcd(self.datetime.year % 100))
            packet_bytes.append(double_digits_to_bcd(self.datetime.year / 100))
        else:
            doy = int(self.datetime.strftime("%j"))
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
        self.milliseconds = bcd_to_int(ms) * 10
        sec = bcd_to_int(s)
        mins = bcd_to_int(mn)
        hrs = bcd_to_int(h)

        if (self.channel_specific_data & DATE_FMT_YEAR_AVAIL) >> 9 == 0x1:
            (d, mo, yr) = struct.unpack_from("<BBH", buf, 8)
            day = bcd_to_int(d)
            mon = bcd_to_int(mo)
            year = bcd_to_int(yr)
            self.datetime = datetime(year, mon, day, hrs, mins, sec)
        else:
            (doy,hdoy) = struct.unpack_from("<BB", buf, 8)
            day_of_year = bcd_to_int(doy) + 100 * bcd_to_int(hdoy)
            date_as_string = "{:02d}:{:02d}:{:02d} {:03d} 1970".format(hrs, mins, sec, day_of_year)
            self.datetime = datetime.strptime(date_as_string, "%H:%M:%S %j %Y")

        return True

    def __eq__(self, other):
        if not isinstance(other, TimeDataFormat1):
            return False

        _match_att = ("channel_specific_data", "datetime", "milliseconds")

        for attr in _match_att:
            if getattr(self, attr) != getattr(other, attr):
                return False

        return True

    def __repr__(self):
        return "TimeFormat1 ChannelSpecificWord={:#0X} Time={} MilliSeconds={}".format(
            self.channel_specific_data, self.datetime.strftime("%H:%M:%S %x %d-%b %Y"), self.milliseconds
        )

    def __len__(self):
        if (self.channel_specific_data & DATE_FMT_YEAR_AVAIL) >> 9 == 0x1:
            return 4 * (4 + 1)
        else:
            return 4 * (3 + 1)


TS_STATUS_VALID = 0x1
TS_STATUS_IEEE2002 = (0X1 << 4)
TS_STATUS_IEEE2008 = (0X2 << 4)


class TimeDataFormat2(object):
    """
    Class to pack and unpack Chapter10 TIME packet payloads.

    Create a packet and transmit it via UDP


    :type channel_specific_data: int
    :type milliseconds: int
    :type datetime: datetime | None
    :type filler: str
    """

    def __init__(self):

        self.channel_specific_data = TS_STATUS_VALID + TS_STATUS_IEEE2002
        self.datetime = None
        self.nanoseconds = 0

    def pack(self):
        """
        Pack the Chapter10 time object into a binary buffer

        :rtype: str
        """
        if not isinstance(self.datetime, datetime):
            raise Exception("datetime attribute should be an instance of the datetime object ")
        utc_seconds = int(time.mktime(self.datetime.timetuple()))
        if (self.channel_specific_data >> 4) & 0x1:
            # ptp
            frac_sec = self.nanoseconds
        else:
            #ntp
            frac_sec = int(self.nanoseconds * (pow(2, 32)/1e9))

        return struct.pack("<III", self.channel_specific_data, utc_seconds, frac_sec)

    def unpack(self, buf):
        """
        Unpack a string buffer into a TimeFormat object
        :param buffer: str
        :return:
        """
        (self.channel_specific_data, s, fs) = struct.unpack("<III", buf)
        if (self.channel_specific_data >> 4) & 0xF != 0: # Make PTP the default
            self.nanoseconds = fs
        else:
            self.nanoseconds = int(fs / (pow(2, 32)/1e9)) # NTP

        self.datetime = datetime.fromtimestamp(s)

        return True

    def __eq__(self, other):
        if not isinstance(other, TimeDataFormat2):
            return False

        _match_att = ("channel_specific_data", "datetime", "nanoseconds")

        for attr in _match_att:
            if getattr(self, attr) != getattr(other, attr):
                return False

        return True

    def __repr__(self):
        return "TimeFormat2 ChannelSpecificWord={:#0X} Time={} NanoSeconds={}".format(
            self.channel_specific_data, self.datetime.strftime("%H:%M:%S %x %d-%b %Y"), self.nanoseconds
        )

    def __len__(self):
        return 3*4


class ARINC429DataPacket(object):
    """
    Data Packet Format. Contains a list of Arinc Data Words
    
    :type msgcount: int
    :type arincwords: list[ARINC429DataWord]
    
    
    >>> c = Chapter10UDP()
    >>> arinc_p = ARINC429DataPacket()
    >>> arinc_p.unpack(c.chapter10.payload))
    >>> print arinc_p
    ARINCPayload: MessageCount=0
      ARINCData: GapTime=0 FormatError=False ParityError=False BusSpeed=0 Bus=0
    
    """

    def __init__(self):
        self.msgcount = None  #: The number ofARINC-429 words included in the packet.
        self.arincwords = []  #: List of :class:`ARINC429DataWord`

    def pack(self):
        """
        Pack the ARINC-429 data packet object into a binary buffer

        :rtype: str 
        """
        ret_str = struct.pack("<HH", self.msgcount, 0)
        for a in self.arincwords:
            ret_str += a.pack()

        return ret_str

    def unpack(self, buffer):
        """
        Unpack a string buffer into an ARINC-429 data packet object

        :param buffer: A string buffer representing an ARINC-429 data  packet
        :type buffer: str
        :rtype: None
        """
        CH_SPECIFIC_HDR_LEN = 4
        ARINC_WORD_LEN = 8
        (self.msgcount, _res) = struct.unpack_from("<HH", buffer)
        exp_msg = (len(buffer) - CH_SPECIFIC_HDR_LEN) // ARINC_WORD_LEN
        for msg_idx in range(exp_msg):
            offset = (msg_idx * ARINC_WORD_LEN) + CH_SPECIFIC_HDR_LEN
            arinc_data = ARINC429DataWord()
            arinc_msg_word_buffer = buffer[offset:offset+ARINC_WORD_LEN]
            arinc_data.unpack(arinc_msg_word_buffer)
            self.arincwords.append(arinc_data)
            
        if self.msgcount != len(self.arincwords):
            raise Exception("The ARINC Message Count={} does not match number of messages in the packet={}".format(
                self.msgcount, len(self.arincwords)
            ))
        return True

    def __eq__(self, other):
        if not isinstance(other, ARINC429DataPacket):
            return False

        _match_att = ("msgcount", "arincwords")

        for attr in _match_att:
            if getattr(self, attr) != getattr(other, attr):
                return False

        return True

    def __repr__(self):
        ret_str =  "ARINCPayload: MessageCount={}\n".format( self.msgcount)

        for a in self.arincwords:
            ret_str += "  {}\n".format(repr(a))

        return ret_str

    def __iter__(self):
        self._index = 0
        return self

    def next(self):
        if self._index < len(self.arincwords):
            _dw = self.arincwords[self._index]
            self._index += 1
            return _dw
        else:
            raise StopIteration

    __next__ = next

    def __len__(self):
        return len(self.arincwords)

    def __getitem__(self, key):
        return self.arincwords[key]


class ARINC429DataWord(object):
    """
    The Chapter 10 standard defines specific payload formats for different data. This class handles AROINC-429 packets
    
    :type msgcount: int
    :type gaptime: int
    :type format_error: bool
    :type parity_error: bool
    :type bus_speed: int
    :type bus: int
    :type payload: str
    """

    LO_SPEED = 0  #: Bus speed constant
    HI_SPEED = 1  #: Bus speed constant

    HDR_FORMAT = ">HBB"

    def __init__(self):
        self.gaptime = None  #: The gap time from the beginning of the preceding bus word (regardless of bus) to the
        # beginning of the current bus word in 0.1-us increments
        self.format_error = False  #: Format error has occurred
        self.parity_error = False  #: Parity error has occurred
        self.bus_speed = ARINC429DataWord.LO_SPEED  #: Arinc bus speed
        self.bus = None  #: Bus number index from 0
        self.payload = b""  #: ARINC word as a string payload

    def pack(self):
        """
        Pack the ARINC-429 data packet object into a binary buffer

        :rtype: str|bytes
        """
        _flag = (self.format_error << 7) + (self.parity_error << 6) + (self.bus_speed << 5) + (self.gaptime >> 16)
        _gap = self.gaptime & 0xFFFF
        hdr = struct.pack(ARINC429DataWord.HDR_FORMAT, _gap, _flag, self.bus)

        return hdr + self.payload

    def unpack(self, buffer):
        """
        Unpack a string buffer into an ARINC-429 data packet object

        :param buffer: A string buffer representing an ARINC-429 data  packet
        :type buffer: str
        :rtype: None
        """
        ( _gap, _flag, self.bus) = struct.unpack_from(ARINC429DataWord.HDR_FORMAT, buffer)
        self.payload = buffer[struct.calcsize(ARINC429DataWord.HDR_FORMAT):]
        self.format_error = bool((_flag >> 7) & 0x1)
        self.parity_error = bool((_flag >> 6) & 0x1)
        self.bus_speed = (_flag >> 6) & 0x1
        self.gaptime = (_flag << 16) + _gap

        return True

    def __eq__(self, other):
        if not isinstance(other, ARINC429DataWord):
            return False

        _match_att = ( "gaptime", "format_error", "parity_error", "bus_speed", "bus", "payload")

        for attr in _match_att:
            if getattr(self, attr) != getattr(other, attr):
                return False

        return True

    def __repr__(self):
        return "ARINCData: GapTime={} FormatError={} ParityError={} BusSpeed={} Bus={}".format(
             self.gaptime, self.format_error, self.parity_error, self.bus_speed, self.bus)


class UARTDataPacket(object):
    """
    Data Packet Format. Contains a list of UART Data Words

    :type msgcount: int
    :type uartwords: list[UARTDataWord]


    >>> c = Chapter10UDP()
    >>> uart_p = UARTDataPacket()
    >>> uart_p.unpack(c.chapter10.payload))
    >>> print uart_p


    """

    def __init__(self):
        self.uartwords = []  #: List of :class:`UARTDataWord`

    def pack(self):
        """
        Pack the UART data packet object into a binary buffer

        :rtype: str
        """
        # Some checks
        if len(self) == 0:
            raise Exception("No UARTDataWords defined")

        # All words should have the same configuraiton of timestamps
        ts_present = None
        for udw in self:
            if ts_present is None:
                ts_present = (udw.ptptimeseconds is not None)
            elif ts_present != (udw.ptptimeseconds is not None):
                raise Exception("All UARTDataWords should either have or have not a PTPTimestamp header")
        ret_buf = struct.pack("<I", int(ts_present) << 31)
        for udw in self:
            ret_buf += udw.pack()

        return ret_buf

    def unpack(self, mybuffer):
        """
        Unpack a string buffer into an UART data packet object

        :param buffer: A string buffer representing an UART data  packet
        :type buffer: str
        :rtype: None
        """

        (ch_spec_word,) = struct.unpack_from("<I", mybuffer)
        ts_present = bool(ch_spec_word >> 31)
        offset = 4
        while abs(offset - len(mybuffer)) > 4:
            udw = UARTDataWord()
            offset += udw.unpack(mybuffer[offset:], ts_present)
            self.uartwords.append(udw)

        return True

    def append(self, udw):
        """
        Add a UART DW to the DP

        :type udw: UARTDataWord
        :rtype: bool
        """
        if not isinstance(udw, UARTDataWord):
            raise Exception("Can only append UARTDataWords")
        return self.uartwords.append(udw)

    def __eq__(self, other):
        if not isinstance(other, UARTDataPacket):
            return False

        _match_att = ["uartwords"]

        for attr in _match_att:
            if getattr(self, attr) != getattr(other, attr):
                return False

        return True

    def __repr__(self):
        ret_str = "UARTPayload: UARTDataWordCount={}\n".format(len(self))

        for a in self:
            ret_str += "  {}\n".format(repr(a))

        return ret_str

    def __iter__(self):
        self._index = 0
        return self

    def next(self):
        if self._index < len(self.uartwords):
            _dw = self.uartwords[self._index]
            self._index += 1
            return _dw
        else:
            raise StopIteration

    __next__ = next

    def __len__(self):
        return len(self.uartwords)

    def __getitem__(self, key):
        return self.uartwords[key]


class UARTDataWord(object):
    """
    The Chapter 10 standard defines specific payload formats for different data. This class handles UART packets

    :type ptptimeseconds: int
    :type ptptimenanoseconds: int
    :type subchannel: int
    :type parity_error: bool
    :type datalength: int
    :type payload: str
    """

    def __init__(self):
        self.ptptimeseconds = None #: Timestamp of first parameter in the packet. EPOCH time
        self.ptptimenanoseconds = None #: Nanaosecond timestamp
        self.parity_error = False  #: Parity error has occurred
        self.subchannel = None  #: Subchannel
        self.datalength = None  #: Data Length
        self._payload = b""  #: UART payload

    @property
    def payload(self):
        return self._payload

    @payload.setter
    def payload(self, mybuffer):

        self._payload = mybuffer
        self.datalength = len(mybuffer)

    def pack(self):
        """
        Pack the UART data packet object into a binary buffer

        :rtype: str|bytes
        """
        if self.ptptimeseconds is not None and self.ptptimenanoseconds is not None:
            ch_spec_word = struct.pack("<II",self.ptptimenanoseconds, self.ptptimeseconds)
        else:
            ch_spec_word = b""
        data_len = len(self.payload)
        if self.parity_error:
            _subch = self.subchannel + 0x80
        else:
            _subch = self.subchannel
        intra_pkt_header = struct.pack("<HH", data_len, _subch)

        if data_len % 2 == 1:
            padding = struct.pack("B", 0xFF)
        else:
            padding = b""

        return ch_spec_word + intra_pkt_header + self.payload + padding

    def unpack(self, mybuffer, timestamp_present=True):
        """
        Unpack a string buffer into an UART data packet object. Returns the buffer that was consumed

        :param mybuffer: A string buffer representing an UART data  packet
        :type mybuffer: str
        :param timestamp_present: The UART DataPacket Format knows if there is a timestamp or not
        :type timestamp_present: bool
        :rtype: int
        """
        offset = 0
        if timestamp_present:
            #bytes = struct.unpack_from(">8B", mybuffer)
            (self.ptptimenanoseconds, self.ptptimeseconds) = struct.unpack_from("<II", mybuffer, offset)
            offset += 8
        (self.datalength, _pe_sub) = struct.unpack_from("<HH", mybuffer, offset)
        offset += 4

        self.subchannel = _pe_sub & 0x1FFF
        self.parity_error = bool(_pe_sub >> 15)
        self.payload = mybuffer[offset:offset+self.datalength]
        offset += self.datalength

        if self.datalength % 2 == 1:
            return offset + 1
        else:
            return offset

    def __eq__(self, other):
        if not isinstance(other, UARTDataWord):
            return False

        _match_att = ["ptptimeseconds", "ptptimenanoseconds", "parity_error", "subchannel", "datalength", "payload"]

        for attr in _match_att:
            if getattr(self, attr) != getattr(other, attr):
                return False

        return True

    def __repr__(self):
        return "UARTDataWord: PTPSec={} PTPNSec={} ParityError={} DataLen={} SubChannel={}".format(
             self.ptptimeseconds, self.ptptimenanoseconds, self.parity_error, self.datalength, self.subchannel)


class PCMMinorFrame(object):

    HDR_LEN = 10
    """
    Object that represents the PCM minor frame in a PCMPayload.
    """
    def __init__(self):
        self.intra_packet_sec = 0
        self.intra_packet_nsec = 0
        self.intra_packet_data_header = 0x0
        self.minor_frame_data = b''
        self.syncword = None
        self.sfid = None

    def unpack(self, buffer, extract_sync_sfid=False):
        """
        Convert a string buffer into a PCMDataPacket
        :type buffer: str
        :rtype: bool
        """

        (self.intra_packet_nsec, self.intra_packet_sec, self.intra_packet_data_header) = \
            struct.unpack_from("<IIH", buffer)
        if extract_sync_sfid:
            (self.syncword, self.sfid) = struct.unpack_from(">IH", buffer, 10)
        self.minor_frame_data = buffer[10:]
        return True

    def pack(self):
        """
        Convert a PCMFrame object into a string buffer
        :return:
        """
        buf = struct.pack("<IIH", self.intra_packet_nsec, self.intra_packet_sec, self.intra_packet_data_header)
        if self.syncword is not None:
            buf += struct.pack(">I", self.syncword)
        if self.sfid is not None:
            buf += struct.pack(">H", self.sfid)
        buf += self.minor_frame_data

        return buf

    def __repr__(self):
        time_fmt = "%H:%M:%S %d-%b %Y"
        date_str = datetime.fromtimestamp(self.intra_packet_sec).strftime(time_fmt)
        return "Minor Frame. Sec={} ({}) NanoSec={} DataHdr={:#0X} ".format(
            self.intra_packet_sec, date_str, self.intra_packet_nsec, self.intra_packet_data_header
        )

    def __eq__(self, other):
        if not isinstance(other, PCMMinorFrame):
            return False
        for attr in ["intra_packet_sec", "intra_packet_nsec", "intra_packet_data_header", "minor_frame_data",
                     "syncword", "sfid"]:
            if getattr(self, attr) != getattr(other, attr):
                return False

        return True

    def __ne__(self, other):
        return not self.__eq__(other)

PCM_DATA_FRAME_FILL = 0x0


class PCMDataPacket(object):
    """
    This object represents the Payload to a Chapter 10 PCM packet
    The user needs to tell the object how many minor frames in Payload before unpacking a buffer.
    """
    def __init__(self):
        self.channel_specific_word = None
        self.minor_frame_size_bytes = None
        self.minor_frames = []

    def unpack(self, buffer):
        """
        Convert a string buffer into a PCMDataPacket
        :type buffer: bytes
        :rtype: bool
        """

        (self.channel_specific_word,) = struct.unpack_from("<I", buffer, 0)
        offset = 4
        while offset < len(buffer):
            minor_frame = PCMMinorFrame()
            if (self.minor_frame_size_bytes + PCMMinorFrame.HDR_LEN) % 2 != 0:
                padding = 1
            else:
                padding = 0
            minor_frame.unpack(buffer[offset:offset+self.minor_frame_size_bytes+10])
            offset += (self.minor_frame_size_bytes+10+padding)
            self.minor_frames.append(minor_frame)

        return True

    def pack(self):
        buf = struct.pack("<I", self.channel_specific_word)
        for mf in self.minor_frames:
            buf += mf.pack()
            if len(mf.pack()) % 2 == 1:
                buf += struct.pack(">B", PCM_DATA_FRAME_FILL)

        return buf

    def __repr__(self):
        _rstr = "PCM Data Packet Format 1. Channel Specific Word ={:#0X}\n".format(self.channel_specific_word)
        for m in self.minor_frames:
            _rstr += "{}\n".format(repr(m))

        return _rstr

    def __iter__(self):
        self._index = 0
        return self

    def next(self):
        if self._index < len(self.minor_frames):
            _frame = self.minor_frames[self._index]
            self._index += 1
            return _frame
        else:
            raise StopIteration

    __next__ = next

    def __eq__(self, other):
        """

        :type other: PCMDataPacket
        :return:
        """
        if not isinstance(other, PCMDataPacket):
            return False

        if self.channel_specific_word != other.channel_specific_word:
            return False

        if len(self.minor_frames) != len(other.minor_frames):
            return False

        for idx in range(len(self.minor_frames)):
            if self.minor_frames[idx] != other.minor_frames[idx]:
                return False

        return True


class MILSTD1553DataPacket(object):
    """
    Data Packet Format. Contains a list of MIML-STD-1553 Data Words

    :type msgcount: int
    :type uartwords: list[MILSTD1553Message]


    >>> c = Chapter10UDP()
    >>> m = MILSTD1553DataPacket()
    >>> m.unpack(c.chapter10.payload))
    >>> print m


    """

    def __init__(self):
        self.messages = []  #: List of :class:`MILSTD1553Message`
        self.msgcount = 0
        self.ttb = 0

    def pack(self):
        """
        Pack the MIL-STD-1553 data packet object into a binary buffer

        :rtype: str
        """
        # Some checks
        if len(self) == 0:
            raise Exception("No MILSTD1553Messages defined")

        msg_buf = bytes()
        for dw in self:
            msg_buf += dw.pack()

        csw = struct.pack("<I", (self.ttb << 30)+len(self))

        return csw + msg_buf

    def unpack(self, mybuffer):
        """
        Unpack a string buffer into an UART data packet object

        :param buffer: A string buffer representing an UART data  packet
        :type buffer: str
        :rtype: None
        """

        (ch_spec_word,) = struct.unpack_from("<I", mybuffer)
        self.msgcount = ch_spec_word & 0xFFFFFF
        self.ttb = (ch_spec_word >> 30) & 0x3

        offset = 4
        while offset+14 < len(mybuffer):  # Should have at least the timestamp
            m = MILSTD1553Message()
            offset += m.unpack(mybuffer[offset:])
            self.messages.append(m)

        return True

    def append(self, message):
        """
        Add a message to the DP

        :type message: MILSTD1553Message
        :rtype: bool
        """
        if not isinstance(message, MILSTD1553Message):
            raise Exception("Can only append MILSTD1553Message")
        self.msgcount += 1
        return self.messages.append(message)

    def __eq__(self, other):
        if not isinstance(other, MILSTD1553DataPacket):
            return False

        _match_att = ["messages", "msgcount"]

        for attr in _match_att:
            if getattr(self, attr) != getattr(other, attr):
                return False

        return True

    def __repr__(self):
        ret_str = "MILSTD1553DataPacket: MessageCount={}\n".format(self.msgcount, self.messages)

        for a in self:
            ret_str += "  {}\n".format(repr(a))

        return ret_str

    def __iter__(self):
        self._index = 0
        return self

    def next(self):
        if self._index < len(self.messages):
            _dw = self.messages[self._index]
            self._index += 1
            return _dw
        else:
            raise StopIteration

    __next__ = next

    def __len__(self):
        return len(self.messages)

    def __getitem__(self, key):
        return self.messages[key]


class MILSTD1553Message(object):
    """
    The Chapter 10 standard defines specific payload formats for different data. This class handles UART packets

    :type ptptimeseconds: int
    :type ptptimenanoseconds: int
    :type subchannel: int
    :type parity_error: bool
    :type datalength: int
    :type payload: str
    """

    def __init__(self):
        self.ptptimeseconds = None #: Timestamp of first parameter in the packet. EPOCH time
        self.ptptimenanoseconds = None #: Nanaosecond timestamp
        self.blockstatus = 0
        self.gaptimes = 0
        self.length = 0
        self.message = None

    def pack(self):
        """
        Pack the MIL-STD-1553 message object into a binary buffer

        :rtype: str|bytes
        """
        if self.ptptimeseconds is not None and self.ptptimenanoseconds is not None:
            ch_spec_word = struct.pack("<II",self.ptptimenanoseconds, self.ptptimeseconds)
        else:
            raise Exception("No timestamp defined")
        self.length = len(self.message)
        intra_packet_data_header = struct.pack("<HHH", self.blockstatus, self.gaptimes, self.length)

        return ch_spec_word + intra_packet_data_header + self.message

    def unpack(self, mybuffer):
        """
        Unpack a string buffer into an MIL-STD-1553 data packet object. Returns the buffer that was consumed

        :param mybuffer: A string buffer representing an UART data  packet
        :type mybuffer: str
        :rtype: int
        """
        offset = 0
        #bytes = struct.unpack_from(">8B", mybuffer)
        (self.ptptimenanoseconds, self.ptptimeseconds) = struct.unpack_from("<II", mybuffer, offset)
        offset += 8
        (self.blockstatus, self.gaptimes, self.length) = struct.unpack_from("<HHH", mybuffer, offset)
        offset += 6

        self.message = mybuffer[offset:offset+self.length]
        offset += self.length

        return offset

    def __eq__(self, other):
        if not isinstance(other, MILSTD1553Message):
            return False

        _match_att = ["ptptimeseconds", "ptptimenanoseconds", "blockstatus", "gaptimes", "length", "message"]

        for attr in _match_att:
            if getattr(self, attr) != getattr(other, attr):
                return False

        return True

    def __repr__(self):
        return "MILSTD1553Message: PTPSec={} PTPNSec={} BlockStatus={} GapTimes={} Length={}".format(
             self.ptptimeseconds, self.ptptimenanoseconds, self.blockstatus, self.gaptimes, self.length)
