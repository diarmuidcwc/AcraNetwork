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


class iNetX ():
    '''Class to pack and unpack iNetX payloads. iNet-X is an open payload format for use
    in FTI networks. It is usually transmitted in a UDP packet containing parameter data
    acquired from sensors and buses'''
    DEF_CONTROL_WORD = 0x11000000
    INETX_HEADER_FORMAT = '>LLLLLLL'
    INETX_HEADER_LENGTH = struct.calcsize(INETX_HEADER_FORMAT)


    def __init__(self):
        '''Creator method for an iNetX class'''
        self.inetxcontrol = iNetX.DEF_CONTROL_WORD
        """:type : int"""
        self.streamid = None
        """:type : int"""
        self.sequence = None
        """:type : int"""
        self.packetlen = None
        """:type : int"""
        self.ptptimeseconds = None
        """:type : int"""
        self.ptptimenanoseconds = None
        """:type : int"""
        self.pif = None
        """:type : int"""
        self.payload = None
        """:type : str"""

        self._packetStrut = struct.Struct(iNetX.INETX_HEADER_FORMAT)



    def pack(self):
        '''Pack the packet into a binary format and return as a string
        :rtype: str
        '''
        for required_field in (self.inetxcontrol,self.streamid,self.sequence,self.ptptimeseconds,self.ptptimenanoseconds,self.pif,self.payload):
            if required_field == None:
                raise ValueError("A required field in the iNet-X packet is not defined")

        self.packetlen =  len(self.payload)  + iNetX.INETX_HEADER_LENGTH
        packetvalues = (self.inetxcontrol,self.streamid,self.sequence,self.packetlen,self.ptptimeseconds,self.ptptimenanoseconds,self.pif )
        packet = self._packetStrut.pack(*packetvalues) + self.payload
        return packet


    def unpack(self,buf):
        '''
        Unpack a raw byte stream to an iNetX object.
        Accepts a buffer to unpack as the required argument
        :type buf: str
        :type checkcontrol: bool
        '''
        if len(buf) < iNetX.INETX_HEADER_LENGTH:
            raise ValueError ("Buffer is too short to be an iNetX packet")

        self.inetxcontrol,self.streamid,self.sequence,self.packetlen,self.ptptimeseconds,self.ptptimenanoseconds,self.pif  = self._packetStrut.unpack_from(buf)

        if self.packetlen != len(buf):
            raise ValueError("Length of buffer 0x{:X} does not match length field 0x{:X}".format(len(buf),self.packetlen))

        self.payload = buf[iNetX.INETX_HEADER_LENGTH:]


    def setPacketTime(self,utctimestamp,nanoseconds=0):
        ''''Set the packet timestamp
        :type timestamp: int
        :type nanoseconds: int
        '''
        self.ptptimeseconds = utctimestamp
        self.ptptimenanoseconds = nanoseconds








