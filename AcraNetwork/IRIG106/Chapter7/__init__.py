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

import struct

from AcraNetwork.IRIG106.Chapter7 import Golay
import math
import logging
import typing
from enum import IntEnum


ch7_logger = logging.getLogger(__name__)


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


PTDP_HDR_LEN = 0x6  # 24bits x2
PTFR_HDR_LEN = 0x4  # 1 byte unprotected and 3 bytes protected

PTDT_LLP_TRAILER_LEN = 1
PTDP_MAX_LEN = 0x800


class PTDPLengthError(Exception):
    pass


class PTDPRemainingData(Exception):
    pass


def _new_ptfr(ptfr_len: int, streamid: int = 0x1, golay=Golay.Golay()) -> PTFR:
    """Return a new PTFR object initialised with some useful values"""
    ptfr = PTFR(golay)
    ptfr.length = ptfr_len
    ptfr.streamid = streamid
    return ptfr


def datapkts_to_ptfr(
    eth_ch10_packets: typing.Iterable[bytes, bool], ptfr_len: int = 500, streamid: int = 0x1, golay=Golay.Golay()
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


def datapkts_to_ptdp(eth_ch10_packets: typing.Iterable[bytes, bool]) -> typing.Generator[PTDP, None, None]:
    """
    Generator that will take a generator for ethernet packet aligned payloads
    and return the PTDPs encapsulating the payload

    :param eth_ch10_packets:
    :type eth_ch10_packets: collections.Iterable[bytes, bool]
    :rtype: collections.Iterable[PTDP]
    """
    for buffer, llp in eth_ch10_packets:
        # The packet fits in one PTDP
        if len(buffer) <= PTDP_MAX_LEN:
            ptdp_pkt = PTDP()
            ptdp_pkt.low_latency = llp
            ptdp_pkt.fragment = PTDPFragment.COMPLETE
            ptdp_pkt.content = PTDPContent.ETHERNET_MAC
            ptdp_pkt.payload = buffer
            ptdp_pkt.length = len(buffer)
            yield ptdp_pkt
        else:
            # NEED to split the packet into multiple PTDP packets. How many?
            number_of_packets = int(math.ceil(float(len(buffer)) / PTDP_MAX_LEN))
            for i in range(number_of_packets):
                ptdp_pkt = PTDP()
                ptdp_pkt.low_latency = llp
                ptdp_pkt.content = PTDPContent.ETHERNET_MAC  # Assume it's Ethernet for the moment
                # Label the fragments
                if i == 0:
                    ptdp_pkt.fragment = PTDPFragment.FIRST
                    ptdp_pkt.payload = buffer[:PTDP_MAX_LEN]
                elif i == number_of_packets - 1:
                    ptdp_pkt.fragment = PTDPFragment.LAST
                    ptdp_pkt.payload = buffer[i * PTDP_MAX_LEN :]
                else:
                    ptdp_pkt.fragment = PTDPFragment.MIDDLE
                    ptdp_pkt.payload = buffer[PTDP_MAX_LEN * i : PTDP_MAX_LEN * (i + 1)]

                ptdp_pkt.length = len(ptdp_pkt.payload)
                yield ptdp_pkt


class PTDP(object):
    def __init__(self, golay=Golay.Golay()):
        self.payload: bytes = bytes()
        self.low_latency: bool = False
        self.length: int = 0
        self.content: PTDPContent = PTDPContent.FILL
        self.fragment: int = PTDPFragment.COMPLETE
        self._payload: bytes = bytes()
        self._golay: Golay.Golay = golay

    @property
    def payload(self):
        return self._payload

    @payload.setter
    def payload(self, val: bytes):
        if len(val) > PTDP_MAX_LEN:
            raise Exception(
                "One PTDP packet can only be of max length {}. Split your data into multiple PTDP packets".format(
                    PTDP_MAX_LEN
                )
            )

        self._payload = val
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

    def unpack(self, buffer: bytes) -> bytes:
        """
        Convert a buffer into a PTDP object returning the remaining buffer

        :type buffer: bytes
        :rtype: bytes
        """

        if len(buffer) < 6:
            raise PTDPRemainingData("Can't unpack less than the header length")

        lsw = self._golay.decode(buffer[:3])
        msw = self._golay.decode(buffer[3:6])

        self.length = msw + ((lsw & 0xF) << 12)
        self.fragment = PTDPFragment((lsw >> 4) & 0x3)
        self.content = PTDPContent((lsw >> 6) & 0xF)
        if self.length > PTDP_MAX_LEN:
            raise PTDPLengthError("GolayHdr=len={}. Must be corrupted".format(self.length))
        elif len(buffer[6:]) < self.length:
            raise PTDPRemainingData(
                "Not a full PTDP packet. Rest likely in next packet . Buffer length={} GolayHdr=len={} fragment={} content={}".format(
                    len(buffer[6:]), self.length, self.fragment, self.content
                )
            )
        self.payload = buffer[6 : self.length + 6]

        return buffer[self.length + 6 :]

    def __len__(self):
        return len(self.payload) + PTDP_HDR_LEN

    def __eq__(self, other: PTDP):
        if not isinstance(other, PTDP):
            return False
        for attr in ["payload", "length", "fragment", "content"]:
            if getattr(self, attr) != getattr(other, attr):
                return False

        return True

    def __ne__(self, other: PTDP):
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
    _p.payload = struct.pack(f">{payload_len}B", *([0xFF] * payload_len))
    return _p


class PTFR(object):
    """
    Object to represent the PTFR frame
    Pass in a Golay object as creation of one is expensive so sharing and caching speeds things up a lot
    """

    def __init__(self, golay=Golay.Golay()):
        self.version: int = 0x0
        self.streamid: int = 0x0
        self.llp: bool = False
        self.ptdp_offset: int = 0x0
        self.length: int = 0
        self._payload: bytes = bytes()
        self._golay: Golay.Golay = golay

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

    def unpack(self, buffer: bytes) -> bool:
        """
        Convert the PTFR data from one minor frame into a PTFR object
        :param buffer:
        :return:
        """
        (byte_,) = struct.unpack_from(">B", buffer)
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

    def get_aligned_payload(
        self, first_PTFR: bool, remainder: typing.Optional[bytes] = None
    ) -> typing.Generator[typing.Tuple[PTDP, bytes, str], None, None]:
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
            # ch7_logger.debug(f"Starting to check buf of lenght={len(buf)}")
            p = PTDP(self._golay)
            try:
                buf = p.unpack(buf)
            except PTDPLengthError as e:
                aligned = False
                ch7_logger.warning(
                    "Looks like we got an illegal PTDP length. Resetting. {}bytes. Message={} Offset={}".format(
                        len(buf), e, self.ptdp_offset
                    )
                )

                yield (None, None, e)
            except PTDPRemainingData as e:
                aligned = False
                # ch7_logger.debug(
                #    "Failed to unpack buffer of length {}bytes. Message={} Offset={}".format(
                #        len(buf), e, self.ptdp_offset
                #    )
                # )
                # if not is_llp and byte_offset > 0 and do_offset_check:
                #    self.check_offsets(byte_offset)

                yield (None, buf, e)
            else:
                if not is_llp and do_offset_check and byte_offset >= 0:
                    # ch7_logger.debug(f"do_offset_check={do_offset_check} byte_offset={byte_offset}")
                    # self.check_offsets(byte_offset)
                    do_offset_check = False
                    offset_check_count += 1
                elif not is_llp and not do_offset_check and offset_check_count < 1:
                    do_offset_check = True
                    byte_offset += len(p)
                    # ch7_logger.debug(
                    #    f"Enable do_offset_check because {offset_check_count} < 1 byte_offset={byte_offset} len_p={len(p)}"
                    # )
                elif not is_llp:
                    byte_offset += len(p)

                # set the low latency flag on the current packet now we know if we are at the end of the LLP sequence.
                p.low_latency = is_llp

                if is_llp:  # If this is a low latency packet
                    # Remove the last byte
                    (next_llp,) = struct.unpack_from(">B", buf)
                    # Check if the next PTDP is low latency before yielding
                    if next_llp == 0xFF:
                        # ch7_logger.debug("Next packet is LLP")
                        is_llp = True
                        buf = buf[1:]
                        byte_offset += len(p) + 1
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
                            byte_offset += len(p) + 1
                        else:
                            buf = (
                                remainder + buf[1:]
                            )  # The remainder is only added after all the llp packets are removed
                            byte_offset += len(p) + 1 - len(remainder)
                            if len(remainder) > 0:
                                do_offset_check = False

                # ch7_logger.debug(f"Returning p={repr(p)} and no remainder")
                yield (p, bytes(), "")

        # ch7_logger.debug("------PTFR expired-----")

    def __eq__(self, other: PTFR):
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
