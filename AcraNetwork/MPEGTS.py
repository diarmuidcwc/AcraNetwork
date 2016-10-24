#-------------------------------------------------------------------------------
# Name:        iNetX
# Purpose:     Class to construct and de construct iNetx Packets
#
# Author:      DCollins
#
# Created:     19/12/2013
#
# Copyright 2014 Diarmuid Collins
#
#    This program is free software; you can redistribute it and/or
#    modify it under the terms of the GNU General Public License
#    as published by the Free Software Foundation; either version 2
#    of the License, or (at your option) any later version.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with this program; if not, write to the Free Software
#    Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.


import struct
import datetime

NAL_HEADER = 0x00000001
NAL_HEADER_LEN = 4
NAL_TYPES = { "SEI":6, "Unspecified" : 0, "Coded IDR" : 5, "SPS" : 7, "PPS" : 8, "AUD" : 9,
              "EOS" : 10, "DPS" : 16}
# Invert it to go from integer to more useful name
NAL_TYPES_INV = dict((v, k) for k, v in NAL_TYPES.iteritems())
SEI_UNREG_DATA = 5


class MPEGTS():
    '''
    This class handles MPEG Transport Streams.
    https://en.wikipedia.org/wiki/MPEG_transport_stream

    Each transport stream contains 188 byte packets.
    These packets contain either video, audio or metadata information

    '''

    def __init__(self):
        '''
        Each MPEGTS contains an array of MPEGTS Packets
        '''
        self.previouscounter = {}
        self.discontinuity ={}
        self.blocks = []
        self.contunityerror = False
        self.invalidsync = False
        self.invalidsyncblock = list()

    def unpack(self,buf):
        '''
        This method will convert a buffer of bytes into an array of MPEG TS packets
        :param buf:
        :return:
        '''
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

    def NumberOfBlocks(self):
        return len(self.blocks)

    def FirstCount(self):
        return self.blocks[0].continuitycounter

    def LastCount(self):
        return self.blocks[self.NumberOfBlocks()-1].continuitycounter


class MPEGPacket():
    '''
    The MPEGPacket is the elementary unit in an MPEG Transport Stream
    It contains an header, in which there's a sync word, continuity counter, and a payload
    '''
    def __init__(self):
        self.packetstrut = struct.Struct('>BHB')
        self.sync = None
        self.pid = None
        self.continuitycounter = None
        self.invalidsync = False
        self.payload = ""


    def unpack(self,buf):
        '''
        Converts a buffer into an MPEGTS packet
        :param buf:
        :return:
        '''
        (self.syncbyte,pid_full,counter_full)  = self.packetstrut.unpack_from(buf)
        if self.syncbyte != 0x47:
            self.invalidsync = True

        self.pid = pid_full % 8192
        self.continuitycounter = counter_full % 16
        self.payload = buf[struct.calcsize(">BHB"):]


class H264(object):
    '''
    This class will handle H.264 payload. It can convert a buffer of bytes into an array
    of NALs(https://en.wikipedia.org/wiki/Network_Abstraction_Layer)
    The NALs contain different data, based on their types.
    '''

    def __init__(self):
        self.nals = []

    def unpack(self,buf):
        """
        Unpack a buffer into the NALs
        :param buf:
        :return:
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
    '''
    The NAL can be split into the various types of NALs.
    '''
    def __init__(self):
        self.type = None
        self.size = None
        self.sei = None
        self.offset = None

    def unpack(self,buf):
        # First 4 bytes are the NAL_HEADER, then forbidden + type
        (self.type,) = struct.unpack(">B",buf[NAL_HEADER_LEN])
        self.type = self.type & 0x1F
        if self.type == NAL_TYPES["SEI"]:
            sei = STANAG4609_SEI()
            sei.unpack(buf[(NAL_HEADER_LEN+1):])
            self.sei = sei


class STANAG4609_SEI(object):
    '''
    Handle the SEI NAL and more specifically this will handle SEIs defined in 3.14.3.5 of the STANAG standard
    http://www.gwg.nga.mil/misb/docs/nato_docs/STANAG_4609_Ed3.pdf
    '''
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

    def unpack(self,buf):
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
    """Returns positions where pattern is found in text.
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
        k += skip[ord(text[k])]

    return offsets
