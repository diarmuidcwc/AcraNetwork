
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

NAL_HEADER = 0x00000001
NAL_HEADER_LEN = 4
NAL_TYPES = { "Unspecified" : 0, "Coded non-IDR": 1, "Coded partition A": 2, "Coded partition B": 3,
              "Coded partition C": 4,
              "Coded IDR": 5, "SEI": 6, "SPS": 7, "PPS": 8, "AUD": 9, "EOSeq": 10, "EOStream": 11,
              "Filler": 12, "SES": 13, "Prefix NAL": 14, "SSPS": 15, "Reserved": 16
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
        self.blocks = [] #: List of MPEGPacket objects
        self.contunityerror = False
        self.invalidsync = False
        self.invalidsyncblock = list()

    def unpack(self,buf):
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
            MpegBlock.unpack(buf[remainingbytes:remainingbytes+188])
            block_count += 1
            self.blocks.append(MpegBlock)
            if MpegBlock.invalidsync == True:
                self.invalidsync = True
                self.invalidsyncblock.append(block_count)
            remainingbytes += 188
            if  not MpegBlock.pid in prevcount:
                prevcount[MpegBlock.pid] = MpegBlock.continuitycounter
            elif ((prevcount[MpegBlock.pid]+1) % 16) != MpegBlock.continuitycounter:
                self.contunityerror = True
                self.discontinuity[MpegBlock.pid] = (prevcount[MpegBlock.pid],MpegBlock.continuitycounter)
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
        return self.blocks[self.NumberOfBlocks()-1].continuitycounter


class MPEGPacket(object):
    """
    The MPEGPacket is the elementary unit in an MPEG Transport Stream
    It contains an header, in which there's a sync word, continuity counter, and a _payload
    """

    def __init__(self):
        self.packetstrut = struct.Struct('>BHB')
        self.sync = None
        self.pid = None
        self.continuitycounter = None
        self.invalidsync = False
        self.payload = ""

    def unpack(self, buf):
        """
        Converts a buffer into an MPEGTS packet
        
        :param buf: The buffer to unpack into an MPEG Packet
        :type buf: str
        :rtype: bool
        """
        (self.syncbyte, pid_full, counter_full)  = self.packetstrut.unpack_from(buf)
        if self.syncbyte != 0x47:
            self.invalidsync = True

        self.pid = pid_full % 8192
        self.continuitycounter = counter_full % 16
        self.payload = buf[struct.calcsize(">BHB"):]


class H264(object):
    """
    This class will handle H.264 _payload. It can convert a buffer of bytes into an array
    of NALs(https://en.wikipedia.org/wiki/Network_Abstraction_Layer)
    The NALs contain different data, based on their types.
    """

    def __init__(self):
        self.nals = []

    def unpack(self, buf):
        """
        Split the buffer into multiple NALs and store as a H264 object

        :param buf: The buffer to unpack into a H264 object
        :type buf: str
        :rtype: bool
        """
        nal_hdr = struct.pack(">L",NAL_HEADER)
        offsets = string_matching_boyer_moore_horspool(buf,nal_hdr)

        for idx,offset in enumerate(offsets):
            if idx == len(offsets)-1:
                nal_buf = buf[offset:]
            else:
                nal_buf = buf[offset:(offsets[idx+1])]
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
        self.type = None
        self.size = None
        self.sei = None
        self.offset = None

    def unpack(self, buf):
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
            sei.unpack(buf[(NAL_HEADER_LEN+1):])
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

        (self.payloadtype,self.payloadsize) = struct.unpack(">BB",buf[0:2])
        if self.payloadtype == SEI_UNREG_DATA:
            self.unregdata = True
            (sig1,sig2,self.status,ms1,_fix1,ms2,_fix2,ms3,_fix3,ms4,) = struct.unpack_from(">QQBHBHBHBH",buf[2:])
            # combine the time fields (cf  http://www.gwg.nga.mil/misb/docs/nato_docs/STANAG_4609_Ed3.pdf 3.14.3.4 )
            # Verify the signature and if it's good then convert to a time
            if sig1 == 0x4d4953506d696372 and sig2 == 0x6f73656374696d65 and \
                            _fix1 == 0xff and _fix2 == 0xff and _fix3 == 0xff:
                useconds = (ms1<<48)+(ms2<<32)+(ms3<<16)+ms4
                self.seconds = float(useconds)/1.0e6
                self.nanoseconds = (ms3<<16)+ms4
                self.time = datetime.datetime.fromtimestamp(self.seconds)
                self.stanag = True


def string_matching_boyer_moore_horspool(text='', pattern=''):
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
    for k in range(m-1):
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
