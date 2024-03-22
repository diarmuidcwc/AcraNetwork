"""
.. module:: MPEGTS
    :platform: Unix, Windows
    :synopsis: Class to handle MPEG Transport Streams

.. moduleauthor:: Diarmuid Collins <dcollins@curtisswright.com>

"""

__author__ = "Diarmuid Collins"
__copyright__ = "Copyright 2018"
__maintainer__ = "Diarmuid Collins"
__email__ = "dcollins@curtisswright.com"
__status__ = "Production"


import struct
import datetime
import sys
import typing
import logging

logger = logging.getLogger(__name__)


NAL_HEADER = 0x00000001
NAL_HEADER_LEN = 4
NAL_TYPES = {
    "Unspecified": 0,
    "Coded non-IDR": 1,
    "Coded partition A": 2,
    "Coded partition B": 3,
    "Coded partition C": 4,
    "Coded IDR": 5,
    "SEI": 6,
    "SPS": 7,
    "PPS": 8,
    "AUD": 9,
    "EOSeq": 10,
    "EOStream": 11,
    "Filler": 12,
    "SES": 13,
    "Prefix NAL": 14,
    "SSPS": 15,
    "Reserved": 16,
}
# Invert it to go from integer to more useful name
NAL_TYPES_INV = {v: k for k, v in list(NAL_TYPES.items())}
SEI_UNREG_DATA = 5
PY3 = sys.version_info > (3,)


class MPEGAdaptionExtension(object):
    """
    The MPEG Adaptation extension format https://en.wikipedia.org/wiki/MPEG_transport_stream#Packet

    """

    def __init__(self) -> None:
        self.ltw_flag: bool = False
        self.piecewise_rate_flag: bool = False
        self.seamless_splice_flag: bool = False
        self.ltw = bytes()
        self.piecewise = bytes()
        self.seamless_splice = bytes()

    def __eq__(self, __value: object) -> bool:
        if not isinstance(__value, MPEGAdaptionExtension):
            return False
        for attr in self.__dict__.keys():
            if getattr(self, attr) != getattr(__value, attr):
                return False
        return True

    def pack(self) -> bytes:
        if len(self.ltw) == 2:
            self.ltw_flag = True
        elif len(self.ltw) == 0:
            self.ltw_flag = False
        else:
            raise Exception(f"ltw should be 2 bytes")

        if len(self.piecewise) == 3:
            self.piecewise_rate_flag = True
        elif len(self.piecewise) == 0:
            self.piecewise_rate_flag = False
        else:
            raise Exception(f"piecewise should be 3 bytes")

        if len(self.seamless_splice) == 5:
            self.seamless_splice_flag = True
        elif len(self.seamless_splice) == 0:
            self.seamless_splice_flag = False
        else:
            raise Exception(f"seamless should be 5 bytes")

        _len = 4 + len(self.ltw) + len(self.piecewise) + len(self.seamless_splice)
        _flags = (
            0x1F
            + (int(self.ltw_flag) << 7)
            + (int(self.piecewise_rate_flag) << 6)
            + (int(self.seamless_splice_flag << 5))
        )
        return struct.pack(">BB", _len, _flags) + self.ltw + self.piecewise + self.seamless_splice

    def unpack(self, buffer: bytes):
        _len, _flags = struct.unpack_from(">BB", buffer)
        self.ltw_flag = bool((_flags >> 7) & 0x1)
        self.piecewise_rate_flag = bool((_flags >> 6) & 0x1)
        self.seamless_splice_flag = bool((_flags >> 5) & 0x1)
        offset = 4
        if self.ltw_flag:
            self.ltw = buffer[offset : offset + 2]
            offset += 2
        if self.piecewise_rate_flag:
            self.piecewise = buffer[offset : offset + 3]
            offset += 3
        if self.seamless_splice_flag:
            self.seamless_splice = buffer[offset : offset + 5]

    def __repr__(self) -> str:
        return f"ltw_flag={self.ltw_flag}, piecewise_flag={self.piecewise_rate_flag}, seamless_flag={self.seamless_splice_flag}"


class MPEGAdaption(object):
    """
    The MPEG Adaptation field format https://en.wikipedia.org/wiki/MPEG_transport_stream#Packet

    """

    def __init__(self) -> None:
        self.discontinutiy: bool = False
        self.random_access: bool = False
        self.es_priority: bool = False
        self.pcr_flag: bool = False
        self.opcr_flag: bool = False
        self.splicing_flag: bool = False
        self.transpart_flag: bool = False
        self.extension_flag: bool = False
        self.pcr = bytes()
        self.opcr = bytes()
        self.splice_countdown = 0
        self.private_data = bytes()
        self.adaption_extension: typing.Optional[MPEGAdaptionExtension] = None

    def __eq__(self, __value: object) -> bool:
        if not isinstance(__value, MPEGAdaption):
            return False
        for attr in self.__dict__.keys():
            if getattr(self, attr) != getattr(__value, attr):
                return False
        return True

    def __repr__(self) -> str:
        _r = f"Discontunity={self.discontinutiy}, random={self.random_access} Elementary Stream Indicator={self.es_priority} PCR={self.pcr_flag} "
        _r += f"OPCR={self.opcr_flag} Splicing Point Flag={self.splicing_flag} Transport Private Data={self.transpart_flag}, Adaption Extension={self.extension_flag}"
        if self.adaption_extension is not None:
            _r += repr(self.adaption_extension)
        return _r

    def unpack(self, buffer: bytes):
        _len, _flags = struct.unpack_from(">BB", buffer)
        self.discontinutiy = bool((_flags >> 7) & 1)
        self.random_access = bool((_flags >> 6) & 1)
        self.es_priority = bool((_flags >> 5) & 1)
        self.pcr_flag = bool((_flags >> 4) & 1)
        self.opcr_flag = bool((_flags >> 3) & 1)
        self.splicing_flag = bool((_flags >> 2) & 1)
        self.transpart_flag = bool((_flags >> 1) & 1)
        self.extension_flag = bool((_flags >> 0) & 1)

        offset = 2
        if self.pcr_flag:
            self.pcr = buffer[offset : offset + 6]
            offset += 6

        if self.opcr_flag:
            self.opcr = buffer[offset : offset + 6]
            offset += 6

        if self.splicing_flag:
            self.splice_countdown = struct.unpack_from(">B", buffer, offset)
            offset += 1

        if self.transpart_flag:
            _transport_len = struct.unpack_from(">B", buffer, offset)
            offset += 1
            self.private_data = buffer[offset : offset + _transport_len]
            offset += _transport_len
        if self.extension_flag:
            self.adaption_extension = MPEGAdaptionExtension()
            self.adaption_extension.unpack(buffer[offset:])

    def pack(self):

        if len(self.pcr) > 0:
            self.pcr_flag = True
        if len(self.opcr) > 0:
            self.opcr_flag = True
        if self.splice_countdown > 0:
            self.splicing_flag = True
            splice_buf = struct.pack(">B", self.splice_countdown)
        else:
            splice_buf = bytes()
        if len(self.private_data) > 0:
            self.transpart_flag = True
        if self.adaption_extension is not None:
            self.extension_flag = True
            _extension_buffer = self.adaption_extension.pack()
        else:
            _extension_buffer = bytes()
        _len = len(self.pcr) + len(self.opcr) + len(self.private_data) + len(_extension_buffer) + len(splice_buf) + 1
        _flags = (
            (int(self.discontinutiy) << 7)
            + (int(self.random_access) << 6)
            + (int(self.es_priority) << 5)
            + (int(self.pcr_flag) << 4)
            + (int(self.opcr_flag) << 3)
            + (int(self.splicing_flag << 2))
            + (int(self.transpart_flag << 1))
            + int(self.extension_flag)
        )
        return (
            struct.pack(">BB", _len, _flags) + self.pcr + self.opcr + splice_buf + self.private_data + _extension_buffer
        )


class MPEGTS(object):
    """
    This class handles MPEG Transport Streams.
    https://en.wikipedia.org/wiki/MPEG_transport_stream

    Each transport stream contains 188 byte packets.
    These packets contain either video, audio or metadata information

    :type blocks: list[MPEGPacket]

    """

    def __init__(self):
        self.blocks: typing.List[MPEGPacket] = []  #: List of MPEGPacket objects

    def unpack(self, buf: bytes):
        """
        This method will convert a buffer of bytes into an array of MPEG TS packets

        :param buf: The buffer to unpack
        :type buf: str

        :rtype: bool
        """

        remainingbytes = 0
        while remainingbytes < len(buf):
            MpegBlock = MPEGPacket()
            MpegBlock.unpack(buf[remainingbytes : remainingbytes + 188])
            self.blocks.append(MpegBlock)
            remainingbytes += 188

        return True

    def pack(self) -> bytes:
        __bytes = bytes()
        for block in self:
            __bytes += block.pack()

        return __bytes

    def __len__(self):

        return len(self.blocks)

    def __iter__(self):
        self._index = 0
        return self

    def next(self):
        if self._index < len(self.blocks):
            _block = self.blocks[self._index]
            self._index += 1
            return _block
        else:
            raise StopIteration

    __next__ = next

    def __eq__(self, __value: object) -> bool:
        if not isinstance(__value, MPEGTS):
            return False
        if len(self) != len(__value):
            return False
        for idx in range(len(self)):
            if self[idx] != __value[idx]:
                return False

        return True

    def __repr__(self) -> str:
        _r = ""
        for _block in self:
            _r += f"{repr(_block)}\n"
        return _r

    def __getitem__(self, _key):
        if _key >= len(self):
            raise IndexError
        return self.blocks[_key]

    def NumberOfBlocks(self):
        raise DeprecationWarning("This is being deprecated")

    def FirstCount(self):
        raise DeprecationWarning("This is being deprecated")

    def LastCount(self):
        raise DeprecationWarning("This is being deprecated")


class ADTS(object):
    def __init__(self) -> None:
        self.aac: bytes = bytes()
        self.version: int = 0
        self.sampling_freq: int = 0
        self._length: int = 0
        self.no_crc: bool = True

    def unpack(self, buffer):
        words = struct.unpack_from(">7B", buffer)
        sw = ((words[1] >> 4) << 8) + words[0]
        if sw != 0xFFF:
            raise Exception(f"Sync word = {sw:#0X}")
        self.sampling_freq = (words[2] >> 2) & 0xF
        self.no_crc = bool(words[1] & 0x1)
        self._length = (words[5] >> 5) + (words[4] << 3) + ((words[3] & 0x3) << 11)
        if self.no_crc:
            self.aac = buffer[7:]
        else:
            self.aac = buffer[9:]

    def __repr__(self) -> str:
        return f"ADTS: NoCRC={self.no_crc} SamplFreq={self.sampling_freq} len={self._length} lenaac={len(self.aac)}"


TSC = {0: "Not Scrambled", 1: "Reserved", 2: "Scrambled even key", 3: "Scrambled odd key"}
ADAPTION_CTRL = {1: "Payload Only", 2: "Adaption Only", 3: "Adaption and Payload", 0: "Reserved"}


class PES(object):
    def __init__(self) -> None:
        self.streamid: int = 0
        self.length: int = 0
        self.data: bytes = bytes()

    def unpack(self, buffer: bytes):
        (_prefix1, _prefix2, self.streamid, self.length) = struct.unpack_from(">BHBH", buffer)
        prefix = (_prefix1 << 16) + _prefix2
        if prefix != 1:
            raise Exception(f"PES Prefix {prefix:#0X} should be 0x1")
        (optional_hdr, _miscbits, _pes_hdr_len) = struct.unpack_from(">BBB", buffer, 6)
        marker = optional_hdr >> 4
        if marker != 0x8:
            logger.debug("No optional PES header")
            self.data = buffer[6:]
        else:
            self.data = buffer[(6 + 3 + _pes_hdr_len) :]
        (datafword,) = struct.unpack_from(">H", self.data)
        logger.debug(f"PES First Dataw={datafword:#0X}")

    def __repr__(self) -> str:
        return f"PES: Stream ID={self.streamid:#0X} Len={self.length}"


class MPEGPacket(object):
    """
    The MPEGPacket is the elementary unit in an MPEG Transport Stream
    It contains an header, in which there's a sync word, continuity counter, and a _payload
    """

    def __init__(self):
        self.sync: int = 0
        self.pid: int = 0
        self.tei: bool = False
        self.pusi: bool = False
        self.transport_priority = 0
        self.tsc: int = 0
        self.adaption_ctrl: int = 0
        self.continuitycounter: int = 0
        self.payload: bytes = bytes()
        self.adaption_field: typing.Optional[MPEGAdaption] = None

    def unpack(self, buf: bytes):
        """
        Converts a buffer into an MPEGTS packet

        :param buf: The buffer to unpack into an MPEG Packet
        :type buf: str
        :rtype: bool
        """
        (self.sync, pid_full, counter_full) = struct.unpack_from(">BHB", buf)
        if self.sync != 0x47:
            raise Exception(f"Sync word={self.sync:#0X} not 0x47")

        self.pid = pid_full & 0x1FFF
        self.transport_priority = (pid_full >> 15) & 0x1
        self.tei = bool((pid_full >> 16) & 0x1)
        self.pusi = bool((pid_full >> 14) & 0x1)

        self.continuitycounter = counter_full & 0xF
        self.adaption_ctrl = (counter_full >> 4) & 0x3
        self.tsc = (counter_full >> 6) & 0x3

        if self.adaption_ctrl == 0x3:  # payload + adaption
            (adaption_len,) = struct.unpack_from(">B", buf[4:])
            # logger.debug(f"Adaption len ={adaption_len}")
            self.payload = buf[(4 + 1 + adaption_len) :]

            self.adaption_field = MPEGAdaption()
            self.adaption_field.unpack(buf[4 : (adaption_len + 1 + 4)])
        elif self.adaption_ctrl == 0x2:
            self.adaption_field = MPEGAdaption()
            self.adaption_field.unpack(buf[4 : (1 + 4 + adaption_len)])
            self.payload = bytes()
        elif self.adaption_ctrl == 0x1:
            self.payload = buf[4:]
        else:
            raise Exception("Adaption control of 0 is reserved")

    def pack(self) -> bytes:
        pid_full = self.pid + (self.transport_priority << 13) + (int(self.pusi) << 14) + (int(self.tei) << 15)
        continuity = self.continuitycounter + (self.adaption_ctrl << 4) + (self.tsc << 6)
        _payload = struct.pack(">BHB", self.sync, pid_full, continuity)
        if self.adaption_field is not None:
            _adaption_fieldn_paylad = self.adaption_field.pack()
        else:
            _adaption_fieldn_paylad = bytes()
        return _payload + _adaption_fieldn_paylad + self.payload

    def __repr__(self) -> str:
        r = f"PID={self.pid:#0X} PUSI={self.pusi} TSC={TSC[self.tsc]} Adaption={ADAPTION_CTRL[self.adaption_ctrl]}"
        if self.adaption_field is not None:
            r += "\n Adaption=" + repr(self.adaption_field)
        return r

    def __eq__(self, __value: object) -> bool:
        if not isinstance(__value, MPEGPacket):
            return False
        match_attr = [
            "sync",
            "pid",
            "transport_priority",
            "tei",
            "pusi",
            "continuitycounter",
            "tsc",
            "adaption_ctrl",
            "payload",
            "adaption_field",
        ]
        for attr in match_attr:
            if getattr(self, attr) != getattr(__value, attr):
                return False
        return True


class H264(object):
    """
    This class will handle H.264 _payload. It can convert a buffer of bytes into an array
    of NALs(https://en.wikipedia.org/wiki/Network_Abstraction_Layer)
    The NALs contain different data, based on their types.
    """

    def __init__(self):
        self.nals: typing.List[NAL] = []

    def unpack(self, buf: bytes) -> bool:
        """
        Split the buffer into multiple NALs and store as a H264 object

        :param buf: The buffer to unpack into a H264 object
        :type buf: str
        :rtype: bool
        """
        nal_hdr = struct.pack(">L", NAL_HEADER)
        offsets = string_matching_boyer_moore_horspool(buf.decode(), nal_hdr.decode())

        for idx, offset in enumerate(offsets):
            if idx == len(offsets) - 1:
                nal_buf = buf[offset:]
            else:
                nal_buf = buf[offset : (offsets[idx + 1])]
            nal = NAL()
            nal.unpack(nal_buf)
            nal.offset = offset
            self.nals.append(nal)

        return True


class NAL(object):
    """
    The NAL can be split into the various types of NALs.
    """

    def __init__(self):
        self.type: int = 0
        self.size: int = 0
        self.sei: typing.Optional[STANAG4609_SEI] = None
        self.offset = 0

    def unpack(self, buf: bytes):
        """
        Split the buffer into a NAL object

        :param buf: The buffer to unpack into an NAL
        :type buf: str|bytes
        :rtype: bool
        """

        # First 4 bytes are the NAL_HEADER, then forbidden + type
        (self.type,) = struct.unpack_from(">B", buf, NAL_HEADER_LEN)
        self.type = self.type & 0x1F
        self.size = len(buf)
        if self.type == NAL_TYPES["SEI"]:
            sei = STANAG4609_SEI()
            sei.unpack(buf[(NAL_HEADER_LEN + 1) :])
            self.sei = sei

    def __len__(self):
        return self.size


class STANAG4609_SEI(object):
    """
    Handle the SEI NAL and more specifically this will handle SEIs defined in 3.14.3.5 of the STANAG standard
    http://www.gwg.nga.mil/misb/docs/nato_docs/STANAG_4609_Ed3.pdf
    """

    def __init__(self):
        self.payloadtype = None
        self.payloadsize = None
        self.unregdata = False
        self.status = None
        self.seconds = None
        self.microseconds = None
        self.nanoseconds = None
        self.time = None
        self.stanag = False

    def unpack(self, buf):
        """
        Unpack the NAL _payload as an STANAG4609_SEI

        :param buf: The buffer to unpack into an STANAG4609_SEI
        :type buf: str
        :rtype: bool
        """

        (self.payloadtype, self.payloadsize) = struct.unpack(">BB", buf[0:2])
        if self.payloadtype == SEI_UNREG_DATA:
            self.unregdata = True
            (
                sig1,
                sig2,
                self.status,
                ms1,
                _fix1,
                ms2,
                _fix2,
                ms3,
                _fix3,
                ms4,
            ) = struct.unpack_from(">QQBHBHBHBH", buf[2:])
            # combine the time fields (cf  http://www.gwg.nga.mil/misb/docs/nato_docs/STANAG_4609_Ed3.pdf 3.14.3.4 )
            # Verify the signature and if it's good then convert to a time
            if (
                sig1 == 0x4D4953506D696372
                and sig2 == 0x6F73656374696D65
                and _fix1 == 0xFF
                and _fix2 == 0xFF
                and _fix3 == 0xFF
            ):
                useconds = (ms1 << 48) + (ms2 << 32) + (ms3 << 16) + ms4
                self.seconds = float(useconds) / 1.0e6
                self.nanoseconds = (ms3 << 16) + ms4
                self.time = datetime.datetime.fromtimestamp(self.seconds)
                self.stanag = True


def string_matching_boyer_moore_horspool(text="", pattern=""):
    """
    Returns positions where pattern is found in text.
    O(n)
    Performance: ord() is slow so we shouldn't use it here
    Example: text = 'ababbababa', pattern = 'aba'
         string_matching_boyer_moore_horspool(text, pattern) returns [0, 5, 7]
    @param text text to search inside
    @param pattern string to search for
    @return list containing offsets (shifts) where pattern is found inside text
    """
    m = len(pattern)
    n = len(text)
    offsets = []
    if m > n:
        return offsets
    skip = []
    for k in range(256):
        skip.append(m)
    for k in range(m - 1):
        my = pattern[k]
        if PY3:
            skip[pattern[k]] = m - k - 1
        else:
            skip[ord(pattern[k])] = m - k - 1
    skip = tuple(skip)
    k = m - 1
    while k < n:
        j = m - 1
        i = k
        while j >= 0 and text[i] == pattern[j]:
            j -= 1
            i -= 1
        if j == -1:
            offsets.append(i + 1)
        if PY3:
            k += skip[text[k]]
        else:
            k += skip[ord(text[k])]

    return offsets
