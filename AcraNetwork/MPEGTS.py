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


class MPEGTS(object):
    """
    This class handles MPEG Transport Streams.
    https://en.wikipedia.org/wiki/MPEG_transport_stream

    Each transport stream contains 188 byte packets.
    These packets contain either video, audio or metadata information

    :type blocks: list[MPEGPacket]

    """

    def __init__(self):
        self.previouscounter = {}
        self.discontinuity = {}
        self.blocks: typing.List[MPEGPacket] = []  #: List of MPEGPacket objects
        self.contunityerror = False
        self.invalidsync = False
        self.invalidsyncblock = list()

    def unpack(self, buf: bytes):
        """
        This method will convert a buffer of bytes into an array of MPEG TS packets

        :param buf: The buffer to unpack
        :type buf: str

        :rtype: bool
        """

        remainingbytes = 0
        prevcount = self.previouscounter
        block_count = 0
        while remainingbytes < len(buf):
            MpegBlock = MPEGPacket()
            MpegBlock.unpack(buf[remainingbytes : remainingbytes + 188])
            block_count += 1
            self.blocks.append(MpegBlock)
            if MpegBlock.invalidsync:
                self.invalidsync = True
                self.invalidsyncblock.append(block_count)
            remainingbytes += 188
            if MpegBlock.pid not in prevcount:
                prevcount[MpegBlock.pid] = MpegBlock.continuitycounter
            elif ((prevcount[MpegBlock.pid] + 1) % 16) != MpegBlock.continuitycounter:
                self.contunityerror = True
                self.discontinuity[MpegBlock.pid] = (prevcount[MpegBlock.pid], MpegBlock.continuitycounter)
                prevcount[MpegBlock.pid] = MpegBlock.continuitycounter
            else:
                prevcount[MpegBlock.pid] = MpegBlock.continuitycounter

        self.previouscounter = prevcount
        return True

    def NumberOfBlocks(self):
        """
        How many MPEG blocks in the current TS

        :rtype: int
        """

        return len(self.blocks)

    def FirstCount(self):
        """
        Get the value of the first continuity counter

        :rtype: int
        """
        return self.blocks[0].continuitycounter

    def LastCount(self):
        """
        Get the value of the final continuity counter

        :rtype: int
        """
        return self.blocks[self.NumberOfBlocks() - 1].continuitycounter


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
        self._packetstrut = struct.Struct(">BHB")
        self._packetstrutlen = struct.calcsize(">BHB")
        self.sync: int = 0
        self.pid: int = 0
        self.pusi: int = 0
        self.tsc: int = 0
        self.adaption_ctrl: int = 0
        self.continuitycounter: int = 0
        self.invalidsync: bool = False
        self.payload: bytes = bytes()

    def unpack(self, buf: bytes):
        """
        Converts a buffer into an MPEGTS packet

        :param buf: The buffer to unpack into an MPEG Packet
        :type buf: str
        :rtype: bool
        """
        (self.syncbyte, pid_full, counter_full) = self._packetstrut.unpack_from(buf)
        if self.syncbyte != 0x47:
            self.invalidsync = True

        self.pid = pid_full % 8192
        self.pusi = (pid_full >> 14) & 0x1
        self.continuitycounter = counter_full % 16
        self.tsc = (counter_full >> 6) & 0x3
        self.adaption_ctrl = (counter_full >> 4) & 0x3

        if self.adaption_ctrl == 0x3:  # payload + adaption
            (adaption_len,) = struct.unpack_from(">B", buf[self._packetstrutlen :])
            # logger.debug(f"Adaption len ={adaption_len}")
            self.payload = buf[(self._packetstrutlen + 1 + adaption_len) :]
        elif self.adaption_ctrl == 0x2:
            self.payload = bytes()
        elif self.adaption_ctrl == 0x1:
            self.payload = buf[self._packetstrutlen :]
        else:
            raise Exception("Adaption control of 0 is reserved")

    def __repr__(self) -> str:
        return f"PID={self.pid:#0X} PUSI={self.pusi} TSC={TSC[self.tsc]} Adaption={ADAPTION_CTRL[self.adaption_ctrl]}"


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
