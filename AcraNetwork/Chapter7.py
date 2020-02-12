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


def _new_pdfr(pdfr_len, streamid=0x1):
    """Return a new PDFR object initialised with some useful values"""
    pdfr = PDFR()
    pdfr.length = pdfr_len
    pdfr.streamid = streamid
    return pdfr


def datapkts_to_pdfr(eth_ch10_packets, pdfr_len=500, streamid=0x1):
    """
    Generator that will take a generator for ethernet packet aligned payloads
    and return the PTFRs encapsulating the payload

    :type eth_ch10_packets: collections.Iterable[bytes]
    :param pdfr_len: Length of the PDFR frame
    :type pdfr_len: int
    :rtype: collections.Iterable[PDFR]
    """
    # Create a new frame
    pdfr = _new_pdfr(pdfr_len, streamid)
    for ptdp in datapkts_to_ptdp(eth_ch10_packets):
        # Encapsulate the data in PTDP packets
        # Add the payload to the PDFR frame. IF we get a remainder then this from is full
        remainder = pdfr.add_payload(ptdp.pack())
        while remainder != bytes():
            # Spit out the full frame
            yield pdfr
            # Create anew frame
            pdfr = _new_pdfr(pdfr_len, streamid)
            # Maybe the  PTFP is bigger than one frame, then split it across PDFRs.
            while len(remainder) > pdfr_len:
                pdfr.ptdp_offset = 0x3ff  # Signifies that we have all PTDP payload
                pdfr.add_payload(remainder[:pdfr_len])
                yield pdfr  # Frame is full
                remainder = remainder[pdfr_len:]  # If we have more data then save it for the next frame
                pdfr = _new_pdfr(pdfr_len, streamid)

            # Point to the first offset of the frame.
            pdfr.ptdp_offset = len(remainder)
            #Add the PTDS to the frame
            remainder = pdfr.add_payload(remainder)


def datapkts_to_ptdp(eth_ch10_packets):
    """
    Generator that will take a generator for ethernet packet aligned payloads
    and return the PTDPs encapsulating the payload

    :param eth_ch10_packets:
    :rtype: collections.Iterable[PTDP]
    """
    for buffer in eth_ch10_packets:
        # The packet fits in one PTDP
        if len(buffer) <= PTDP_MAX_LEN:
            ptdp_pkt = PTDP()
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
    def __init__(self):
        self.payload = ""
        self.length = 0
        self.content = PTDP_CONTENT_FILL
        self.fragment = PTDP_FRAGMENT_COMPLETE
        self._payload = ""

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
        g = Golay.Golay()
        self.length = len(self.payload)
        msw = self.length & 0xFFF
        lsw = (self.length >> 12) + (self.fragment << 4) + (self.content << 6)

        return g.encode(lsw, as_string=True) + g.encode(msw, as_string=True) + self.payload

    def unpack(self, buffer):
        """
        Convert a buffer into a PTDP object returning the remaining buffer

        :type buffer: bytes
        :rtype: bytes
        """

        if len(buffer) < 6:
            raise Exception("Can't unpack less than the header length")

        g = Golay.Golay()
        lsw = g.decode(buffer[:3])
        msw = g.decode(buffer[3:6])

        self.length = msw + ((lsw & 0xF) << 12)
        self.fragment = (lsw >> 4) & 0x3
        self.content = (lsw >> 6) & 0xF
        if len(buffer[6:]) < self.length:
            raise Exception("Buffer length={} GolayHdr=len={} fragment={} content={}".format(
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
        return "PTDP: Len={} Content={} Fragment={}".format(self.length, PTDP_CONTENT_TEXT[self.content], PTDP_FRAGMENT_TEXT[self.fragment])


class PDFR(object):
    def __init__(self):
        self.version = 0x0
        self.streamid = 0x0
        self.llp = False
        self.ptdp_offset = 0x0
        self.length = 0
        self._payload = bytes()

    @property
    def payload(self):
        return self._payload

    @payload.setter
    def payload(self, val):
        if len(val) + len(self._payload) > self.length:
            raise Exception("Length of payload ({}) is larger than length field ({})".format(len(val), self.length))
        self._payload += val

    def add_payload(self, buffer):
        """
        Add the buffer to the payload ensureing not to go over the length field
        :param buffer:
        :return:
        """
        if len(buffer) + len(self._payload) > self.length:
            len_to_take = self.length-len(self._payload)
            self._payload += buffer[:len_to_take]
            return buffer[len_to_take:]
        else:
            self._payload += buffer
            return bytes()

    def pack(self):
        """
        Convert a PDFR object into a string for transmission. This will return the packed string and the remainder string
        for any partial ptdp packet

        :param previous_partial: If we have some partial data from the previous PDFR packet, add it here
        :rtype: (bytes, bytes)
        """
        if len(self.payload) != self.length:
            raise Exception("Payload length does not match the length field")

        buffer = struct.pack(">B", self.version + (self.streamid << 4))
        g = Golay.Golay()
        buffer += g.encode(self.ptdp_offset + (self.llp << 11), as_string=True)
        buffer += self.payload

        return buffer

    def unpack(self, buffer):
        """
        Convert the PTFR data from one minor frame into a PDFR object
        :param buffer:
        :return:
        """
        (byte_,) = struct.unpack_from(">B", buffer)
        self.version = byte_ & 0x3
        self.streamid = (byte_ >> 4) & 0xF
        # Protected field
        g = Golay.Golay()
        protected_field = g.decode(buffer[1:4])
        self.llp = (protected_field >> 11) & 0x1
        self.ptdp_offset = protected_field & 0x7FF
        self.payload = buffer[4:]

        return True

    def get_aligned_payload(self, remainder=bytes()):
        """
        Return the payload as PTDP packets with the final partial payload
        :type remainder: bytes
        :param remainder: Optional partial payload from previous frame
        :rtype: Tuple[PTDP, bytes, str]
        """
        aligned = True

        if remainder == bytes() and self.ptdp_offset > 0 and self.ptdp_offset < 0x3ff:
            buf = self.payload[self.ptdp_offset:]
            logging.debug("No remainder from previous packet, offset={} buffer length={}".format(self.ptdp_offset, len(buf)))
        else:
            buf = remainder + self.payload
            logging.debug("Buffer length={}. Ignoring offset={}".format(len(buf), self.ptdp_offset))
        while aligned:
            p = PTDP()
            try:
                buf = p.unpack(buf)
            except Exception as e:
                aligned = False
                yield (None, buf, e)
                logging.debug("Failed to unpack buffer of length {}bytes. Error={}".format(len(buf), e))
            else:
                yield (p, bytes(), "")

    def __eq__(self, other):
        if not isinstance(other, PDFR):
            return False

        for attr in ["version", "streamid", "llp", "ptdp_offset", "payload"]:
            if getattr(self, attr) != getattr(other, attr):
                return False

        return True

    def __ne__(self, other):
        return not self.__eq__(other)

    def __repr__(self):
        return "PTFR: Length={} StreamID={:#0X} Offset={}\n".format(self.length, self.streamid, self.ptdp_offset)
