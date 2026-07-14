from __future__ import annotations

"""
.. module:: Chapter7
    :platform: Unix, Windows
    :synopsis: Class to construct and de construct Chapter7 Packets
    http://www.irig106.org/docs/106-17/chapter7.pdf

.. moduleauthor:: Diarmuid Collins <dcollins@curtisswright.com>

"""

__author__ = "Diarmuid Collins"
__copyright__ = "Copyright 2024"
__maintainer__ = "Diarmuid Collins"
__email__ = "dcollins@curtisswright.com"
__status__ = "Production"

import re
import struct
import logging
from AcraNetwork.IRIG106.Chapter7 import Golay
import math
import typing
from enum import IntEnum
from collections import namedtuple

ch7_logger = logging.getLogger(__name__)
try:
    from AcraNetwork.IRIG106.Chapter7 import golay_c as _golay_c

    _c_chapter7_available = hasattr(_golay_c, "ptdp_unpack") and hasattr(_golay_c, "ptfr_unpack")
except ImportError:
    _golay_c = None
    _c_chapter7_available = False

if _c_chapter7_available:
    ch7_logger.info("Chapter7 unpack in C")
else:
    ch7_logger.info("Chapter7 unpack in Python")


class PTDPContent(IntEnum):
    FILL = 0x0
    ASP = 0x1
    TEST_COUNTER = 0x2
    CHAPTER_10 = 0x3
    ETHERNET_MAC = 0x4
    IP = 0x5
    CHAPTER_24 = 0x6
    ILLEGAL = 0xF

    @classmethod
    def _missing_(cls, value):
        return PTDPContent.ILLEGAL


class PTDPFragment(IntEnum):
    COMPLETE = 0x0
    FIRST = 0x1
    MIDDLE = 0x2
    LAST = 0x3
    ILLEGAL = 0x4

    @classmethod
    def _missing_(cls, value):
        return PTDPFragment.ILLEGAL


# perf: precomputed lookup tables so PTDP.unpack() doesn't pay the IntEnum
# metaclass cost (Enum.__call__ / __new__) on every header it decodes.
# Indices are the raw bit-masked values pulled out of the Golay-decoded
# header word, so these must stay in sync with the bit widths used there.
_FRAGMENT_BY_BITS = (
    PTDPFragment.COMPLETE,  # 0
    PTDPFragment.FIRST,  # 1
    PTDPFragment.MIDDLE,  # 2
    PTDPFragment.LAST,  # 3
)

_CONTENT_BY_BITS = (
    PTDPContent.FILL,  # 0
    PTDPContent.ASP,  # 1
    PTDPContent.TEST_COUNTER,  # 2
    PTDPContent.CHAPTER_10,  # 3
    PTDPContent.ETHERNET_MAC,  # 4
    PTDPContent.IP,  # 5
    PTDPContent.CHAPTER_24,  # 6
    PTDPContent.ILLEGAL,  # 7
    PTDPContent.ILLEGAL,  # 8
    PTDPContent.ILLEGAL,  # 9
    PTDPContent.ILLEGAL,  # 10
    PTDPContent.ILLEGAL,  # 11
    PTDPContent.ILLEGAL,  # 12
    PTDPContent.ILLEGAL,  # 13
    PTDPContent.ILLEGAL,  # 14
    PTDPContent.ILLEGAL,  # 15
)

FILL_LEN2_PATTERN = b"\x00\x00\x00\x00)>\xaa\xaa"

# perf: cache of (pattern, compiled run-regex, pattern length) keyed by
# (id(golay), fill_word). re.compile() is not free (~1-2us), and PTFR
# instances are typically constructed once per frame with an unchanged
# fill_word (see _new_ptfr/datapkts_to_ptfr), so caching avoids recompiling
# an identical regex on every PTFR construction. Keyed by id(golay) rather
# than the golay object itself so this works regardless of whether the
# Golay class is hashable.
_fill_pattern_cache: dict[tuple[int, int], tuple[bytes, "re.Pattern[bytes]", int]] = {}


def _build_fill_pattern(golay, fill_word: int) -> tuple[bytes, "re.Pattern[bytes]", int]:
    if not (0 <= fill_word <= 0xFFFF):
        raise ValueError(f"fill_word must be in range 0x0-0xFFFF, got {fill_word:#x}")
    key = (id(golay), fill_word)
    cached = _fill_pattern_cache.get(key)
    if cached is not None:
        return cached
    pattern = golay.encode(0, as_string=True) + golay.encode(2, as_string=True) + struct.pack(">H", fill_word)
    run_re = re.compile(b"(?:" + re.escape(pattern) + b")+")
    result = (pattern, run_re, len(pattern))
    _fill_pattern_cache[key] = result
    return result


PTDP_HDR_LEN = 0x6  # 24bits x2
PTFR_HDR_LEN = 0x4  # 1 byte unprotected and 3 bytes protected

PTDT_LLP_TRAILER_LEN = 1
PTDP_MAX_LEN = 0x800

PTDPDetails = namedtuple("PTDPDetails", ["is_llp", "content"])


class PTDPLengthError(Exception):
    pass


def _new_ptfr(ptfr_len: int, streamid: int = 0x1, golay=Golay.Golay()) -> PTFR:
    """Return a new PTFR object initialised with some useful values"""
    ptfr = PTFR(golay)
    ptfr.length = ptfr_len
    ptfr.streamid = streamid
    return ptfr


def datapkts_to_ptfr(
    eth_ch10_packets: typing.Iterable[tuple[bytes, PTDPDetails]],
    ptfr_len: int = 500,
    streamid: int = 0x1,
    golay=Golay.Golay(),
) -> typing.Generator[PTFR, None, None]:
    """
    Generator that will take a generator for ethernet packet aligned payloads
    and return the PTFRs encapsulating the payload

    """
    # Create a new frame
    ptfr = _new_ptfr(ptfr_len, streamid, golay)
    for ptdp in datapkts_to_ptdp(eth_ch10_packets):

        remaining_space = ptfr.remaining_space()
        # logging.debug(f"Adding ptdp {ptdp} with remaining space {remaining_space}")
        # If we have a low latency packet but not enough space to insert it full then
        # insert a fill packet
        if ptdp.low_latency and remaining_space <= (len(ptdp) + PTDT_LLP_TRAILER_LEN):
            # logging.warning(f"Need to add fill packet to fill remaining space={remaining_space}")
            fill = ptdp_fill(remaining_space)
            remainder = ptfr.add_payload(fill.pack(), False)
            yield ptfr
            ptfr = _new_ptfr(ptfr_len, streamid, golay)
            if len(remainder) > 0:
                ptfr.add_payload(remainder)
                # logging.debug(f"Added remainder of len {len(remainder)}. Remainder={ptfr.remaining_space()}")

        # Add the packet and if there is remainder push out the ptfr packet and start a new one
        remainder = ptfr.add_payload(ptdp.pack(), ptdp.low_latency)
        ch7_logger.debug(f"PTDP ({ptdp}) to be added to PTRF leaving remainder of len={len(remainder)}")
        while not ptfr.has_space():
            # Spit out the full frame
            yield ptfr
            # Create anew frame
            ptfr = _new_ptfr(ptfr_len, streamid, golay)
            # Maybe the  PTFP is bigger than one frame, then split it across PTFRs.
            while len(remainder) > ptfr_len:
                ptfr.ptdp_offset = 0x3FF  # Signifies that we have all PTDP payload
                ptfr.add_payload(remainder[:ptfr_len])
                yield ptfr  # Frame is full
                remainder = remainder[ptfr_len:]  # If we have more data then save it for the next frame
                ptfr = _new_ptfr(ptfr_len, streamid, golay)

            if len(remainder) > 0:
                # Point to the first offset of the frame.
                ptfr.ptdp_offset = len(remainder)
                # Add the PTDS to the frame
                remainder = ptfr.add_payload(remainder)


def datapkts_to_ptdp(
    eth_ch10_packets: typing.Iterable[tuple[bytes, PTDPDetails]],
) -> typing.Generator[PTDP, None, None]:
    """
    Generator that will take a generator for ethernet packet aligned payloads
    and return the PTDPs encapsulating the payload

    :param eth_ch10_packets:
    :type eth_ch10_packets: collections.Iterable[bytes, PTDPContent]
    :rtype: collections.Iterable[PTDP]
    """
    for buffer, details in eth_ch10_packets:
        if details.content == PTDPContent.FILL:
            if len(buffer) > PTDP_MAX_LEN:
                raise Exception(f"No support for fill packets greater than PTDP_MAX_LEN{PTDP_MAX_LEN}")
            yield ptdp_fill(len(buffer))
            continue

        # The packet fits in one PTDP
        if len(buffer) <= PTDP_MAX_LEN:
            ptdp_pkt = PTDP()
            ptdp_pkt.low_latency = details.is_llp
            ptdp_pkt.fragment = PTDPFragment.COMPLETE
            ptdp_pkt.content = details.content
            ptdp_pkt.payload = bytearray(buffer)
            ptdp_pkt.length = len(buffer)
            yield ptdp_pkt
        else:
            # NEED to split the packet into multiple PTDP packets. How many?
            number_of_packets = int(math.ceil(float(len(buffer)) / PTDP_MAX_LEN))
            for i in range(number_of_packets):
                ptdp_pkt = PTDP()
                ptdp_pkt.low_latency = details.is_llp
                ptdp_pkt.content = details.content
                # Label the fragments
                if i == 0:
                    ptdp_pkt.fragment = PTDPFragment.FIRST
                    ptdp_pkt.payload = bytearray(buffer[:PTDP_MAX_LEN])
                elif i == number_of_packets - 1:
                    ptdp_pkt.fragment = PTDPFragment.LAST
                    ptdp_pkt.payload = bytearray(buffer[i * PTDP_MAX_LEN :])
                else:
                    ptdp_pkt.fragment = PTDPFragment.MIDDLE
                    ptdp_pkt.payload = bytearray(buffer[PTDP_MAX_LEN * i : PTDP_MAX_LEN * (i + 1)])

                ptdp_pkt.length = len(ptdp_pkt.payload)
                yield ptdp_pkt


class PTDP(object):
    def __init__(self, golay=Golay.Golay()) -> None:
        self.low_latency: bool = False
        self.length: int = 0
        self.content: PTDPContent = PTDPContent.FILL
        self.fragment: int = PTDPFragment.COMPLETE
        self._payload: bytearray = bytearray()
        # perf: lazy payload - unpack() stores a reference + offset into the
        # source buffer instead of copying immediately. The bytearray copy
        # only happens if/when .payload is actually accessed. _payload_buf
        # is the source of truth whenever it's not None; _payload_cache
        # memoizes the materialized copy so repeated .payload access doesn't
        # re-copy. _payload stays the source of truth for the "set directly"
        # path (payload.setter / ptdp_fill / datapkts_to_ptdp etc).
        self._payload_buf: bytes | bytearray | None = None
        self._payload_off: int = 0
        self._payload_cache: bytearray | None = None
        self._golay: Golay.Golay = golay
        # perf: fast-path fill pattern. Defaults to the module-level 0xFFFF
        # pattern so standalone PTDP() use (not owned by a configured PTFR)
        # keeps working as before. A PTFR overrides this on its owned
        # _ptdp instance via its fill_word property, so the run-length
        # detector and this single-packet fast path always agree.
        self._fill_pattern: bytes = FILL_LEN2_PATTERN
        if _c_chapter7_available:
            self.unpack = self._unpack_c
        else:
            self.unpack = self._unpack_python

    @property
    def payload(self) -> bytearray:
        if self._payload_buf is not None:
            if self._payload_cache is None:
                self._payload_cache = bytearray(self._payload_buf[self._payload_off : self._payload_off + self.length])
            return self._payload_cache
        return self._payload

    @payload.setter
    def payload(self, val: bytes | bytearray):
        if len(val) > PTDP_MAX_LEN:
            raise Exception(
                "One PTDP packet can only be of max length {}. Split your data into multiple PTDP packets".format(
                    PTDP_MAX_LEN
                )
            )

        self._payload = bytearray(val)
        self._payload_buf = None
        self._payload_cache = None
        self.length = len(val)

    def pack(self) -> bytes:
        """
        Convert a PTDP object into a string buffer

        :rtype: bytes
        """
        self.length = len(self.payload)
        msw = self.length & 0xFFF
        lsw = (self.length >> 12) + (self.fragment << 4) + (self.content << 6)

        return self._golay.encode(lsw, as_string=True) + self._golay.encode(msw, as_string=True) + self.payload

    def _unpack_c(self, buffer: bytes | bytearray) -> "bytes | None":
        """
        Fast path — uses C extension for Golay decodes and header parsing.
        Bound directly at construction time; no availability check per call.
        """
        if buffer.startswith(self._fill_pattern):
            self.length = 2
            self.fragment = PTDPFragment.COMPLETE
            self.content = PTDPContent.FILL
            self._payload_buf = buffer
            self._payload_off = 6
            self._payload_cache = None
            return buffer[8:]
        # ch7_logger.debug("PTDP unpack in C")
        result = _golay_c.ptdp_unpack(buffer)

        if result is None:  # buffer too short
            return None

        if result == -1:  # corrupt Golay length field
            raise PTDPLengthError("GolayHdr=len corrupt. Must be corrupted")

        length, fragment, content, remainder_start = result

        self.length = length
        self.fragment = _FRAGMENT_BY_BITS[fragment]
        self.content = _CONTENT_BY_BITS[content]
        self._payload_buf = buffer
        self._payload_off = 6
        self._payload_cache = None

        if remainder_start > len(buffer):
            return None

        return buffer[remainder_start:]

    def _unpack_python(self, buffer: bytes | bytearray) -> bytes | None:
        """
        Convert a buffer into a PTDP object returning the remaining buffer

        :type buffer: bytes
        :rtype: bytes
        """
        if buffer.startswith(self._fill_pattern):
            self.length = 2
            self.fragment = PTDPFragment.COMPLETE
            self.content = PTDPContent.FILL
            self._payload_buf = buffer
            self._payload_off = 6
            self._payload_cache = None
            return buffer[8:]
        # ch7_logger.info("PTDP unpack in Python")
        _buf_len = len(buffer)
        if _buf_len < 6:
            return None
        mv = memoryview(buffer)
        lsw = self._golay.decode(mv[:3])
        msw = self._golay.decode(mv[3:6])

        self.length = msw + ((lsw & 0xF) << 12)
        self.fragment = _FRAGMENT_BY_BITS[(lsw >> 4) & 0x3]
        self.content = _CONTENT_BY_BITS[(lsw >> 6) & 0xF]
        if self.length > PTDP_MAX_LEN:
            raise PTDPLengthError("GolayHdr=len={}. Must be corrupted".format(self.length))
        _end = self.length + 6
        if _buf_len < _end:
            return None
        self._payload_buf = buffer
        self._payload_off = 6
        self._payload_cache = None

        return buffer[_end:]

    def __len__(self):
        return self.length + PTDP_HDR_LEN

    def __eq__(self, other: object):
        if not isinstance(other, PTDP):
            return False
        for attr in ["payload", "length", "fragment", "content"]:
            if getattr(self, attr) != getattr(other, attr):
                return False

        return True

    def __ne__(self, other: object):
        return not self.__eq__(other)

    def __repr__(self):
        return f"PTDP: Len={self.length} Content={repr(self.content)} Fragment={repr(self.fragment)} LowLatency={self.low_latency}"


def ptdp_fill(total_len_min: int) -> PTDP:
    _p = PTDP()
    _p.content = PTDPContent.FILL
    if total_len_min < (PTDP_HDR_LEN + 1):
        payload_len = 1
    else:
        payload_len = total_len_min - PTDP_HDR_LEN
    _p.payload = bytearray(b"\xff" * payload_len)
    return _p


class PTFR(object):
    """
    Object to represent the PTFR frame
    Pass in a Golay object as creation of one is expensive so sharing and caching speeds things up a lot
    """

    def __init__(self, golay=Golay.Golay()) -> None:
        self.version: int = 0x0
        self.streamid: int = 0x0
        self.llp: bool = False
        self.ptdp_offset: int = 0x0
        self.length: int = 0
        self._payload: bytes = bytearray()
        self._golay: Golay.Golay = golay
        self._ptdp = PTDP(self._golay)
        # perf: when True, get_aligned_payload() still performs every bit of
        # offset-tracking bookkeeping for FILL packets (later real packets
        # depend on it being correct), but skips building/yielding the FILL
        # PTDP objects themselves. Off by default so existing callers see no
        # behavior change; opt in if you don't need to see FILL packets.
        self.discard_fill: bool = False
        # perf: configurable 2-byte fill payload (0x0-0xFFFF, always big
        # endian). Setting this via the property below (including here at
        # construction) derives and caches the matching Golay-encoded
        # pattern/regex, and pushes the pattern onto self._ptdp so its own
        # single-packet fast path stays consistent with the run-length
        # detector in get_aligned_payload.
        self.fill_word = 0xAAAA
        if _c_chapter7_available:
            self.unpack = self._unpack_c
        else:
            self.unpack = self._unpack_python

    @property
    def fill_word(self) -> int:
        return self._fill_word

    @fill_word.setter
    def fill_word(self, value: int) -> None:
        pattern, run_re, total = _build_fill_pattern(self._golay, value)
        self._fill_word = value
        self._fill_pattern = pattern
        self._fill_run_re = run_re
        self._fill_len2_total = total
        self._ptdp._fill_pattern = pattern

    @property
    def payload(self):
        return self._payload

    @payload.setter
    def payload(self, val: bytes):
        if len(val) + len(self._payload) > self.length:
            raise Exception("Length of payload ({}) is larger than length field ({})".format(len(val), self.length))
        self._payload += val

    def add_payload(self, buffer: bytes, is_llp: bool = False) -> bytes:
        """
        Add the buffer to the payload ensuring not to go over the length field
        Return the remainder
        """
        if len(buffer) == 0:
            raise Exception("Can't add payload of len = 0")
        if is_llp and len(buffer) + len(self._payload) > self.length:
            raise Exception(
                f"LLP packet ({len(buffer)}) cannot be added (ptfrlen={self.length}) as it will push the payload ({len(self.payload)}) into the next frame. Add a fill word"
            )
        if is_llp and len(self._payload) > 0 and self.llp:
            ch7_logger.debug(
                f"Adding an LLP buffer({len(buffer)}) to some existing llp payload ({len(self._payload)}). Shifting original data and adding llp at "
                "start. len={}".format(len(buffer) + 1)
            )
            self.ptdp_offset += len(buffer) + 1
            self._payload = buffer + struct.pack(">B", 0xFF) + self._payload
            self.llp = True
        elif is_llp and len(self._payload) > 0 and not self.llp:
            ch7_logger.debug(
                "Adding an LLP buffer to a payload with high latency data. Shifting the data and adding the "
                "offset. len={}".format(len(buffer) + 1)
            )
            self.ptdp_offset = len(buffer) + 1
            self._payload = buffer + struct.pack(">B", 0x0) + self._payload
            self.llp = True
        elif is_llp and len(self.payload) == 0:
            ch7_logger.debug("Adding first LLP buffer len={}".format(len(buffer) + 1))
            self.llp = True
            self._payload = buffer + struct.pack(">B", 0x00)  # Further LLPs will be added in front of this one
            self.ptdp_offset += len(buffer) + 1
        else:
            self._payload += buffer
            ch7_logger.debug(f"Adding a normal PTDP buffer of len={len(buffer)} to a total len={len(self._payload)}")

        if len(self._payload) > self.length:
            len_to_take = self.length - len(self._payload)
            remainder = self.payload[len_to_take:]
            self._payload = self.payload[:len_to_take]
            return remainder
        else:
            return bytes()

    def has_space(self, expected_addition: int = 0) -> bool:
        return (len(self.payload) + expected_addition) < self.length

    def remaining_space(self) -> int:
        return self.length - len(self.payload)

    def pack(self) -> bytes:
        """
        Convert a PTFR object into a string for transmission. This will return the packed string and the remainder string
        for any partial ptdp packet

        :param previous_partial: If we have some partial data from the previous PTFR packet, add it here
        :rtype: (bytes, bytes)
        """
        if len(self.payload) != self.length:
            raise Exception("Payload length does not match the length field")

        buffer = struct.pack(">B", self.version + (self.streamid << 4))
        buffer += self._golay.encode(self.ptdp_offset + (self.llp << 11), as_string=True)
        buffer += self.payload

        return buffer

    def _unpack_c(self, buffer: bytes) -> bool:
        """
        Fast path — uses C extension for Golay decode and header parsing.
        Bound directly at construction time; no availability check per call.
        """
        result = _golay_c.ptfr_unpack(buffer)

        if result is None:  # buffer too short
            return False

        version, streamid, llp, ptdp_offset = result

        self.version = version
        self.streamid = streamid
        self.llp = bool(llp)
        self.ptdp_offset = ptdp_offset
        self.payload = buffer[4:]

        return True

    def _unpack_python(self, buffer: bytes) -> bool:
        """
        Convert the PTFR data from one minor frame into a PTFR object
        :param buffer:
        :return:
        """
        mv = memoryview(buffer)
        byte_ = mv[0]
        self.version = byte_ & 0x3
        self.streamid = (byte_ >> 4) & 0xF
        # Protected field
        protected_field = self._golay.decode(buffer[1:4])
        self.llp = bool((protected_field >> 11) & 0x1)
        self.ptdp_offset = protected_field & 0x7FF
        self.payload = buffer[4:]

        return True

    def check_offsets(self, act_offset: int) -> bool:
        if (act_offset != self.ptdp_offset) and (self.ptdp_offset != 2047):
            ch7_logger.debug(
                f"Offset of unpacked PTDP packet ({act_offset}) does not match the declared offset ({self.ptdp_offset})"
            )
            return False
        elif self.ptdp_offset != 2047:
            ch7_logger.debug(
                "Offset of unpacked PTDP packet ({}) matches the declared offset ({})".format(
                    act_offset, self.ptdp_offset
                )
            )
        return True

    def get_aligned_payload(self, first_PTFR: bool, remainder: typing.Optional[bytes] = None) -> typing.Generator[
        typing.Tuple[typing.Optional[PTDP], typing.Optional[bytes], typing.Union[PTDPLengthError, str]],
        None,
        None,
    ]:
        """
        Return the payload as PTDP packets with the final partial payload
        The remainder is the bytes from the end of the previous PTFR. IF this is the middle of a
        capture set it to None so that false positive messages about offsets is triggered

        :type remainder: bytes
        :param remainder: Optional partial payload from previous frame
        :rtype: Tuple[PTDP, bytes, str]
        """
        aligned = True
        # The PTFR decides what is low latency initially
        is_llp = self.llp

        if is_llp:
            # ch7_logger.debug("LLP flag set. First packet should be LLP")
            buf = self.payload
        elif remainder is None and self.ptdp_offset > 0 and self.ptdp_offset < 0x7FF:
            buf = self.payload[self.ptdp_offset :]
            # ch7_logger.debug(
            #    "Start of analysis. Could be in the middle of a packet offset={} buffer length={}".format(
            #        self.ptdp_offset, len(buf)
            #    )
            # )
        elif remainder == bytes() and self.ptdp_offset > 0 and self.ptdp_offset < 0x7FF:
            buf = self.payload[self.ptdp_offset :]
            # ch7_logger.debug(
            #    "No remainder from previous packet, offset={} buffer length={}".format(self.ptdp_offset, len(buf))
            # )
        elif remainder is None:
            buf = self.payload
            # ch7_logger.debug(
            #    "Buffer length={}. Ignoring offset={} Remainder undefined".format(len(buf), self.ptdp_offset)
            # )
        else:
            buf = remainder + self.payload
            # ch7_logger.debug(
            #    "Buffer length={}. Ignoring offset={} Remainder length={}".format(
            #        len(buf), self.ptdp_offset, len(remainder)
            #    )
            # )

        do_offset_check = True
        if is_llp:
            byte_offset = 0
        elif remainder is None:  # Fake the offset if we have jumped into the middle of a data stream
            byte_offset = self.ptdp_offset
        else:
            byte_offset = -1 * len(remainder)
            if len(remainder) == 0:
                do_offset_check = False

        offset_check_count = 0

        while aligned:
            # perf: detect a whole run of consecutive fixed-length fill
            # packets in a single regex call instead of paying a full
            # unpack() call (Golay decode or even just the pattern check)
            # per packet. Only valid outside an LLP sequence, since LLP
            # packets interleave with other data and change is_llp/buf
            # mid-stream in ways this loop doesn't need to special-case.
            if not is_llp:
                run_match = self._fill_run_re.match(buf)
                # ch7_logger.info(f"rematch={run_match}")
                if run_match is not None:
                    run_bytes = run_match.end()
                    fill_len_total = self._fill_len2_total
                    run_count = run_bytes // fill_len_total

                    if self.discard_fill:
                        # perf: caller doesn't want these packets at all.
                        # Replay every bit of the offset-bookkeeping state
                        # machine below (later real packets depend on it
                        # being correct) but skip building a PTDP and
                        # yielding entirely - no attribute writes, no
                        # generator suspend/resume, per discarded packet.
                        for _fill_i in range(run_count):
                            if do_offset_check and byte_offset >= 0:
                                do_offset_check = False
                                offset_check_count += 1
                            elif not do_offset_check and offset_check_count < 1:
                                do_offset_check = True
                                byte_offset += fill_len_total
                            else:
                                byte_offset += fill_len_total
                    else:
                        for _fill_i in range(run_count):
                            # Same offset-bookkeeping state machine as below,
                            # inlined so the run doesn't pay for a function call
                            # per packet. Only the first packet of a run can
                            # change do_offset_check/offset_check_count; after
                            # that it's a flat byte_offset accumulation.
                            if do_offset_check and byte_offset >= 0:
                                do_offset_check = False
                                offset_check_count += 1
                            elif not do_offset_check and offset_check_count < 1:
                                do_offset_check = True
                                byte_offset += fill_len_total
                            else:
                                byte_offset += fill_len_total

                            self._ptdp.length = 2
                            self._ptdp.fragment = PTDPFragment.COMPLETE
                            self._ptdp.content = PTDPContent.FILL
                            self._ptdp.low_latency = False
                            self._ptdp._payload_buf = buf
                            self._ptdp._payload_off = _fill_i * fill_len_total + 6
                            self._ptdp._payload_cache = None
                            yield (self._ptdp, bytes(), "")

                    buf = buf[run_bytes:]
                    continue

            # ch7_logger.debug(f"Starting to check buf of lenght={len(buf)}")
            prev_buf = buf
            try:
                buf = self._ptdp.unpack(buf)
            except PTDPLengthError as e:
                aligned = False
                ch7_logger.warning(
                    "Looks like we got an illegal PTDP length. Resetting. {}bytes. Message={} Offset={}".format(
                        len(buf), e, self.ptdp_offset
                    )
                )

                yield (None, None, e)

            else:
                len_p = self._ptdp.length + PTDP_HDR_LEN
                if buf is None:
                    aligned = False
                    yield (None, prev_buf, "")
                    break

                if not is_llp and do_offset_check and byte_offset >= 0:
                    # ch7_logger.debug(f"do_offset_check={do_offset_check} byte_offset={byte_offset}")
                    # self.check_offsets(byte_offset)
                    do_offset_check = False
                    offset_check_count += 1
                elif not is_llp and not do_offset_check and offset_check_count < 1:
                    do_offset_check = True
                    byte_offset += len_p
                    # ch7_logger.debug(
                    #    f"Enable do_offset_check because {offset_check_count} < 1 byte_offset={byte_offset} len_p={len(p)}"
                    # )
                elif not is_llp:
                    byte_offset += len_p

                # set the low latency flag on the current packet now we know if we are at the end of the LLP sequence.
                self._ptdp.low_latency = is_llp

                if is_llp:  # If this is a low latency packet
                    # Remove the last byte
                    next_llp = buf[0]
                    # Check if the next PTDP is low latency before yielding
                    if next_llp == 0xFF:
                        # ch7_logger.debug("Next packet is LLP")
                        is_llp = True
                        buf = buf[1:]
                        byte_offset += len_p + 1
                    else:
                        is_llp = False
                        # if ((remainder == bytes()) or first_PTFR)  and self.ptdp_offset > 0:
                        if ((remainder == bytes()) and self.ptdp_offset > 0) or first_PTFR:
                            # ch7_logger.debug("LLP Packets extracted, jumping to offset")
                            buf = self.payload[self.ptdp_offset :]
                            do_offset_check = False
                            byte_offset = self.ptdp_offset
                            offset_check_count = 1
                        elif remainder is None:
                            buf = buf[1:]
                            byte_offset += len_p + 1
                        else:
                            buf = (
                                remainder + buf[1:]
                            )  # The remainder is only added after all the llp packets are removed
                            byte_offset += len_p + 1 - len(remainder)
                            if len(remainder) > 0:
                                do_offset_check = False

                # ch7_logger.debug(f"Returning p={repr(p)} and no remainder")
                if not (self.discard_fill and self._ptdp.content == PTDPContent.FILL):
                    yield (self._ptdp, bytes(), "")

        # ch7_logger.debug("------PTFR expired-----")

    def __eq__(self, other: object):
        if not isinstance(other, PTFR):
            return False

        for attr in ["version", "streamid", "llp", "ptdp_offset", "payload"]:
            if getattr(self, attr) != getattr(other, attr):
                return False

        return True

    def __ne__(self, other):
        return not self.__eq__(other)

    def __repr__(self):
        return (
            f"PTFR: Length={self.length} StreamID={self.streamid:#0X} Offset={self.ptdp_offset} LowLatency={self.llp}\n"
        )
