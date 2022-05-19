"""
.. module:: Chapter7
    :platform: Unix, Windows
    :synopsis: Class to construct and de construct Chapter7 Packets
    http://www.irig106.org/docs/106-17/chapter7.pdf

.. moduleauthor:: Diarmuid Collins <dcollins@curtisswright.com>

"""
__author__ = "Diarmuid Collins"
__copyright__ = "Copyright 2018"
__maintainer__ = "Diarmuid Collins"
__email__ = "dcollins@curtisswright.com"
__status__ = "Production"


import struct
from AcraNetwork import Golay
import math
import logging


ch7_logger = logging.getLogger(__name__)

PTDP_CONTENT_FILL = 0X0
PTDP_CONTENT_ASP = 0X1
PTDP_CONTENT_TEST_CNT = 0X2
PTDP_CONTENT_CH10 = 0X3
PTDP_CONTENT_MAC = 0X4
PTDP_CONTENT_IP = 0X5
PTDP_CONTENT_CH24 = 0X6

PTDP_CONTENT_TEXT = ["Fill", "ASP", "Test Counter", "Chapter 10", "Ethernet MAC", "IP", "Chapter 24"]

PTDP_FRAGMENT_COMPLETE = 0X0
PTDP_FRAGMENT_FIRST = 0X1
PTDP_FRAGMENT_MIDDLE = 0X2
PTDP_FRAGMENT_LAST = 0X3

PTDP_FRAGMENT_TEXT = ["Complete", "First", "Middle", "Last"]

PTDP_HDR_LEN = 0x6  # 24bits x2
PTFR_HDR_LEN = 0x4  # 1 byte unprotected and 3 bytes protected


PTDP_MAX_LEN = 0x800


class PTDPLengthError(Exception):
    pass


class PTDPRemainingData(Exception):
    pass


def _new_ptfr(ptfr_len, streamid=0x1, golay=Golay.Golay()):
    """Return a new PTFR object initialised with some useful values"""
    ptfr = PTFR(golay)
    ptfr.length = ptfr_len
    ptfr.streamid = streamid
    return ptfr


def datapkts_to_ptfr(eth_ch10_packets, ptfr_len=500, streamid=0x1, golay=Golay.Golay()):
    """
    Generator that will take a generator for ethernet packet aligned payloads
    and return the PTFRs encapsulating the payload

    :type eth_ch10_packets: collections.Iterable[bytes, bool]
    :param ptfr_len: Length of the PTFR frame
    :type ptfr_len: int
    :rtype: collections.Iterable[PTFR]
    """
    # Create a new frame
    ptfr = _new_ptfr(ptfr_len, streamid, golay)
    for ptdp in datapkts_to_ptdp(eth_ch10_packets):
        # Encapsulate the data in PTDP packets
        # Add the payload to the PTFR frame. IF we get a remainder then this from is full
        remainder = ptfr.add_payload(ptdp.pack(), ptdp.low_latency)
        while remainder != bytes():
            # Spit out the full frame
            yield ptfr
            # Create anew frame
            ptfr = _new_ptfr(ptfr_len, streamid, golay)
            # Maybe the  PTFP is bigger than one frame, then split it across PTFRs.
            while len(remainder) > ptfr_len:
                ptfr.ptdp_offset = 0x3ff  # Signifies that we have all PTDP payload
                ptfr.add_payload(remainder[:ptfr_len])
                yield ptfr  # Frame is full
                remainder = remainder[ptfr_len:]  # If we have more data then save it for the next frame
                ptfr = _new_ptfr(ptfr_len, streamid, golay)

            # Point to the first offset of the frame.
            ptfr.ptdp_offset = len(remainder)
            #Add the PTDS to the frame
            remainder = ptfr.add_payload(remainder)


def datapkts_to_ptdp(eth_ch10_packets):
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
            ptdp_pkt.fragment = PTDP_FRAGMENT_COMPLETE
            ptdp_pkt.content = PTDP_CONTENT_MAC
            ptdp_pkt.payload = buffer
            ptdp_pkt.length = len(buffer)
            yield ptdp_pkt
        else:
            # NEED to split the packet into multiple PTDP packets. How many?
            number_of_packets = int(math.ceil(float(len(buffer)) / PTDP_MAX_LEN))
            for i in range(number_of_packets):
                ptdp_pkt = PTDP()
                ptdp_pkt.low_latency = llp
                ptdp_pkt.content = PTDP_CONTENT_MAC  # Assume it's Ethernet for the moment
                # Label the fragments
                if i == 0:
                    ptdp_pkt.fragment = PTDP_FRAGMENT_FIRST
                    ptdp_pkt.payload = buffer[:PTDP_MAX_LEN]
                elif i == number_of_packets - 1:
                    ptdp_pkt.fragment = PTDP_FRAGMENT_LAST
                    ptdp_pkt.payload = buffer[i*PTDP_MAX_LEN:]
                else:
                    ptdp_pkt.fragment = PTDP_FRAGMENT_MIDDLE
                    ptdp_pkt.payload = buffer[PTDP_MAX_LEN*i:PTDP_MAX_LEN*(i+1)]

                ptdp_pkt.length = len(ptdp_pkt.payload)
                yield ptdp_pkt


class PTDP(object):
    def __init__(self, golay=Golay.Golay()):
        self.payload = ""
        self.low_latency = False
        self.length = 0
        self.content = PTDP_CONTENT_FILL
        self.fragment = PTDP_FRAGMENT_COMPLETE
        self._payload = ""
        self._golay = golay

    @property
    def payload(self):
        return self._payload

    @payload.setter
    def payload(self, val):
        if len(val) > PTDP_MAX_LEN:
            raise Exception("One PTDP packet can only be of max length {}. Split your data into multiple PTDP packets".format(PTDP_MAX_LEN))

        self._payload = val

    def pack(self):
        """
        Convert a PTDP object into a string buffer

        :rtype: bytes
        """
        self.length = len(self.payload)
        msw = self.length & 0xFFF
        lsw = (self.length >> 12) + (self.fragment << 4) + (self.content << 6)

        return self._golay.encode(lsw, as_string=True) + self._golay.encode(msw, as_string=True) + self.payload

    def unpack(self, buffer):
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
        self.fragment = (lsw >> 4) & 0x3
        self.content = (lsw >> 6) & 0xF
        if self.length > PTDP_MAX_LEN:
            raise PTDPLengthError("GolayHdr=len={}. Must be corrupted".format(self.length))
        elif len(buffer[6:]) < self.length:
            raise PTDPRemainingData("Buffer length={} GolayHdr=len={} fragment={} content={}".format(
                len(buffer[6:]), self.length, self.fragment, self.content))
        self.payload = buffer[6:self.length+6]

        return buffer[self.length+6:]

    def __len__(self):
        return len(self.payload) + PTDP_HDR_LEN

    def __eq__(self, other):
        if not isinstance(other , PTDP):
            return False
        for attr in ["payload", "length", "fragment", "content"]:
            if getattr(self, attr) != getattr(other, attr):
                return False

        return True

    def __ne__(self, other):
        return not self.__eq__(other)

    def __repr__(self):
        return "PTDP: Len={} Content={} Fragment={} LowLatency={}".format(
            self.length, PTDP_CONTENT_TEXT[self.content], PTDP_FRAGMENT_TEXT[self.fragment], self.low_latency)


class PTFR(object):
    """
    Object to represent the PTFR frame
    Pass in a Golay object as creation of one is expensive so sharing and caching speeds things up a lot
    """
    def __init__(self, golay=Golay.Golay()):
        self.version = 0x0
        self.streamid = 0x0
        self.llp = False
        self.ptdp_offset = 0x0
        self.length = 0
        self._payload = bytes()
        self._golay = golay

    @property
    def payload(self):
        return self._payload

    @payload.setter
    def payload(self, val):
        if len(val) + len(self._payload) > self.length:
            raise Exception("Length of payload ({}) is larger than length field ({})".format(len(val), self.length))
        self._payload += val

    def add_payload(self, buffer, is_llp=False):
        """
        Add the buffer to the payload ensuring not to go over the length field
        :param buffer:
        :return:
        """
        if is_llp and len(self._payload) > 0 and self.llp:
            ch7_logger.debug("Adding an LLP buffer to some existing llp payload. Shifting original data and adding llp at "
                          "start. len={}".format(len(buffer) + 1))
            self.ptdp_offset += (len(buffer) + 1)
            self._payload = buffer + struct.pack(">B", 0xFF) + self._payload
            self.llp = True
        elif is_llp and len(self._payload) > 0 and not self.llp:
            ch7_logger.debug("Adding an LLP buffer to a payload with high latency data. Shifting the data and adding the "
                          "offset. len={}".format(len(buffer) + 1))
            self.ptdp_offset = (len(buffer) + 1)
            self._payload = buffer + struct.pack(">B", 0x0) + self._payload
            self.llp = True
        elif is_llp and len(self.payload) == 0:
            ch7_logger.debug("Adding first LLP buffer len={}".format(len(buffer)+1))
            self.llp = True
            self._payload = buffer + struct.pack(">B", 0xFF)
        else:
            ch7_logger.debug("Adding a normal PTDP buffer len={}".format(len(buffer)))
            self._payload += buffer

        if len(self._payload) > self.length:
            len_to_take = self.length-len(self._payload)
            remainder = self.payload[len_to_take:]
            self._payload = self.payload[:len_to_take]
            return remainder
        else:
            return bytes()

    def pack(self):
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

    def unpack(self, buffer):
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

    def check_offsets(self, act_offset):
        if (act_offset != self.ptdp_offset) and (self.ptdp_offset != 2047):
            ch7_logger.error(
                "Offset of unpacked PTDP packet ({}) does not match the declared offset ({})".format(
                    act_offset, self.ptdp_offset))
        elif (self.ptdp_offset != 2047):
            ch7_logger.debug(
                "Offset of unpacked PTDP packet ({}) matches the declared offset ({})".format(
                    act_offset, self.ptdp_offset))

    def get_aligned_payload(self, first_PTFR, remainder=None):
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
            ch7_logger.debug("LLP flag set. First packet should be LLP")
            buf = self.payload
        elif remainder is None and self.ptdp_offset > 0 and self.ptdp_offset < 0x7ff:
            buf = self.payload[self.ptdp_offset:]
            ch7_logger.debug("Start of analysis. Could be in the middle of a packet offset={} buffer length={}".format(self.ptdp_offset, len(buf)))
        elif remainder == bytes() and self.ptdp_offset > 0 and self.ptdp_offset < 0x7ff:
            buf = self.payload[self.ptdp_offset:]
            ch7_logger.debug("No remainder from previous packet, offset={} buffer length={}".format(self.ptdp_offset, len(buf)))
        elif remainder is None:
            buf =  self.payload
            ch7_logger.debug("Buffer length={}. Ignoring offset={} Remainder undefined".format(
                len(buf), self.ptdp_offset))
        else:
            buf = remainder + self.payload
            ch7_logger.debug("Buffer length={}. Ignoring offset={} Remainder length={}".format(
                len(buf), self.ptdp_offset, len(remainder)))

        if is_llp:
            byte_offset = 0
        elif remainder is None:  # Fake the offset if we have jumped into the middle of a data stream
            byte_offset = self.ptdp_offset
        else:
            byte_offset = -1 * len(remainder)
        do_offset_check = True
        offset_check_count = 0
        while aligned:
            p = PTDP(self._golay)
            try:
                buf = p.unpack(buf)
            except PTDPLengthError as e:
                aligned = False
                ch7_logger.warning("Looks like we got an illegal PTDP length. Resetting. {}bytes. Message={} Offset={}".format(len(buf), e,
                                                                                                       self.ptdp_offset))
                yield (None, None, e)
            except PTDPRemainingData as e:
                aligned = False
                ch7_logger.debug("Failed to unpack buffer of length {}bytes. Message={} Offset={}".format(len(buf), e,
                                                                                                       self.ptdp_offset))
                if not is_llp and byte_offset > 0 and do_offset_check:
                    self.check_offsets(byte_offset)

                yield (None, buf, e)
            else:
                if not is_llp and do_offset_check and byte_offset >= 0:
                    self.check_offsets(byte_offset)
                    do_offset_check = False
                    offset_check_count += 1
                elif not is_llp and not do_offset_check and offset_check_count < 1:
                    do_offset_check = True
                    byte_offset += len(p)
                elif not is_llp:
                    byte_offset += len(p)


                # set the low latency flag on the current packet now we know if we are at the end of the LLP sequence.
                p.low_latency = is_llp


                if is_llp:  # If this is a low latency packet
                    # Remove the last byte
                    (next_llp, ) = struct.unpack_from(">B", buf)
                    # Check if the next PTDP is low latency before yielding
                    if next_llp == 0xFF:
                        is_llp = True
                        buf = buf[1:]
                        byte_offset += (len(p) + 1)
                    else:
                        is_llp = False
                        #if ((remainder == bytes()) or first_PTFR)  and self.ptdp_offset > 0:
                        if ( ((remainder == bytes()) and self.ptdp_offset > 0) or first_PTFR):
                            ch7_logger.debug( "LLP Packets extracted, jumping to offset")
                            buf = self.payload[self.ptdp_offset:]
                            do_offset_check = False
                            byte_offset = self.ptdp_offset
                            offset_check_count = 1
                        elif remainder is None:
                            buf =  buf[1:]
                            byte_offset += (len(p) + 1)
                        else:
                            buf = remainder + buf[1:]  # The remainder is only added after all the llp packets are removed
                            byte_offset += (len(p) + 1 - len(remainder))
                            if len(remainder) > 0:
                                do_offset_check = False

                yield (p, bytes(), "")

    def __eq__(self, other):
        if not isinstance(other, PTFR):
            return False

        for attr in ["version", "streamid", "llp", "ptdp_offset", "payload"]:
            if getattr(self, attr) != getattr(other, attr):
                return False

        return True

    def __ne__(self, other):
        return not self.__eq__(other)

    def __repr__(self):
        return "PTFR: Length={} StreamID={:#0X} Offset={} LowLatency={}\n".format(
            self.length, self.streamid, self.ptdp_offset, self.llp)
