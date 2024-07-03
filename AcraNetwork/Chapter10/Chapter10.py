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
from . import TS_CH4, TS_ERTC, TS_IEEE1558, TS_RTC, TS_SECONDARY, RTCTime, PTPTime
import logging
import typing


logger = logging.getLogger(__name__)


def get_checksum_buf(buf):
    """
    Return the arithmetic checksum of a header

    :param buf:
    :return:
    """
    if len(buf) % 2 != 0:
        raise Exception("buffer needs to be 16-bit aligned")

    words = struct.unpack("<{}H".format(len(buf) // 2), buf)
    sum = reduce(lambda x, y: x + y, words)

    return sum % 65536


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
    :type ts_source: int
    :type payload: bytes
    :type data_checksum_size: int
    :type filler: bytes
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
            Chapter10.SYNC_WORD
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
            raise Exception("Packet flag ={:#0X} to valuid".format(val))
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
            cs = get_checksum_buf(sec_hdr)
            sec_hdr = sec_hdr[:-2] + struct.pack("<H", cs)
        else:
            sec_hdr = b""

        total_len_excl_filler = (
            len(sec_hdr) + len(self.payload) + Chapter10.CH10_HDR_FORMAT_LEN + self.data_checksum_size
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
            Chapter10.CH10_HDR_FORMAT,
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
        ) = struct.unpack_from(Chapter10.CH10_HDR_FORMAT, buffer)

        offset_hdr = struct.calcsize(Chapter10.CH10_HDR_FORMAT) - 2
        exp_checksum = get_checksum_buf(buffer[:offset_hdr])
        if checksum != exp_checksum:
            raise Exception("Ch10 Header checksum {:#0X} does not match expected={:#0X}".format(checksum, exp_checksum))
            # print("Ch10 Header checksum does not match expected={:#0X}".format(exp_checksum))

        self.relativetimecounter = _rtc_lwr + (_rtc_upr << 32)

        if (self.packetflag >> 7) == 1:
            self.has_secondary_header = True
            pkt_hdr_time = (self.packetflag >> 2) & 0x3
            (ts_ns, ts_s, _res, _checksum_sec) = struct.unpack_from(
                Chapter10.CH10_OPT_HDR_FORMAT, buffer, Chapter10.CH10_HDR_FORMAT_LEN
            )

            sec_exp_checksum = get_checksum_buf(
                buffer[
                    Chapter10.CH10_HDR_FORMAT_LEN : Chapter10.CH10_HDR_FORMAT_LEN
                    + Chapter10.CH10_OPT_HDR_FORMAT_LEN
                    - 2
                ]
            )

            if _checksum_sec != sec_exp_checksum:
                raise Exception(
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
            self.payload = buffer[(Chapter10.CH10_HDR_FORMAT_LEN + Chapter10.CH10_OPT_HDR_FORMAT_LEN) :]
        else:
            self.has_secondary_header = False
            self.payload = buffer[Chapter10.CH10_HDR_FORMAT_LEN :]
            self.ts_source = TS_RTC

        if len(self.payload) != self.datalen:
            raise Exception("Data length in primary header {} does not match quantity of bytes in packet after headers {}".format(
                self.datalen, len(self.payload)
                )
            )

        return True

    def __eq__(self, other):
        if not isinstance(other, Chapter10):
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
        return "Chapter 10: ChannelID={} Sequence={} DataLen={}".format(self.channelID, self.sequence, self.datalen)


class FileParser(object):
    """
    Parse a Chapter10 file. Open the file and iterate through it
    """

    def __init__(self, filename, mode="rb"):
        self.filename = filename
        self._mode = mode
        self.insync = False
        self._offset = 0
        self._fd = None

    def write(self, ch10packet):
        # type: (Chapter10) -> None
        """
        Write a chapter10 packet to the file
        """
        if not isinstance(ch10packet, Chapter10):
            raise Exception("Only write Chapter10 instances to the file")
        if self._fd is None or self._mode != "wb":
            raise Exception("File name not defined")
        if not self._fd.writable():
            raise Exception("File {} not open for writing".format(self.filename))
        self._fd.write(ch10packet.pack())

    def __enter__(self):
        self._fd = open(self.filename, self._mode)
        return self

    def __exit__(self, type, value, traceback):
        # Exception handling here
        self._fd.close()

    def close(self):
        if self._fd is not None:
            self._fd.close()

    def __iter__(self):
        return self

    def next(self):
        in_sync = False
        pkt_len = 0
        while not in_sync:
            try:
                self._fd.seek(self._offset)
                _first_few_words = self._fd.read(8)
            except:
                raise StopIteration
            try:
                (sync, chid, pkt_len) = struct.unpack("<HHI", _first_few_words)
            except Exception as e:
                logger.debug("Exiting loop err={}".format(e))
                raise StopIteration

            if sync == Chapter10.SYNC_WORD:
                in_sync = True
            else:
                self._offset += 1

        self._fd.seek(self._offset)
        pkt_payload = self._fd.read(pkt_len)

        ch10 = Chapter10()
        try:
            ch10.unpack(pkt_payload)
        except Exception as e:
            logger.error("Failed to unpack data from {}. err={}".format(self._offset, e))
            raise StopIteration
        else:
            self._offset += pkt_len
            return ch10

    __next__ = next
