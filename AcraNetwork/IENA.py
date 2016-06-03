#-------------------------------------------------------------------------------
# Name:        IENA
# Purpose:     Class to pack and unpack IENA packets
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
import datetime,time

def unpack48(x):
    x2, x3 = struct.unpack('>HI', x)
    return x3 | (x2 << 32)


class IENA ():
    '''Class to pack and unpack IENA(tm) payloads. IENA(tm) is an proprietary payload format
    developed by Airbus for use in FTI networks. It is usually transmitted in a UDP packet
     containing parameter data acquired from sensors and buses'''
    IENA_HEADER_FORMAT = '>HHHIBBH'
    IENA_HEADER_LENGTH = struct.calcsize(IENA_HEADER_FORMAT)
    TRAILER_LENGTH = 2


    def __init__(self):
        '''Constructor class for an IENA payload'''


        self.key = None # know as ienaky
        """:type : int"""
        self.size = None
        """:type : int"""
        self.timeusec = None
        """:type : int"""
        self.keystatus = None
        """:type : int"""
        self.status = None
        """:type : int"""
        self.sequence = None
        """:type : int"""
        self.endfield = 0xdead
        """:type : int"""
        self.payload = None #string containing payload
        """:type : str"""

        self._packetStrut = struct.Struct(IENA.IENA_HEADER_FORMAT)
        # only calculate this once
        self._startOfYear = datetime.datetime(datetime.datetime.today().year, 1, 1, 0, 0, 0,0)
        self.lengthError = False # Flag to verify the buffer length





    def unpack(self,buf,ExceptionOnLengthError=False):
        '''Unpack a raw byte stream to an IENA object
        Accepts a buffer to unpack as the required argument
        :type buf: str
        :type ExceptionOnLengthError: bool
        '''
        # Some checking
        if len(buf) < IENA.IENA_HEADER_LENGTH:
            raise ValueError("Buffer passed to unpack is too small to be an IENA packet")

        (self.key, self.size, timehi, timelo, self.keystatus, self.status, self.sequence)  = self._packetStrut.unpack_from(buf)
        self.timeusec = timelo + timehi * 2**32

        if self.size*2 != len(buf):
            self.lengthError = True
            if ExceptionOnLengthError:
                raise ValueError

        self.payload = buf[IENA.IENA_HEADER_LENGTH:-2]
        (self.endfield,) = struct.unpack(">H",buf[-2:]) # last two bytes are the trailer


    def pack(self):
        '''Pack the IENA payload into a binary format
        :rtype: str
        '''
        timehi = self.timeusec >> 32
        timelo = self.timeusec % 0x100000000
        for required_field in [self.key,timehi,timelo,self.keystatus,self.status,self.sequence,self.endfield,self.payload]:
            if required_field == None:
                raise ValueError("A required field in the IENA packet is not defined")

        self.size =  (len(self.payload)  + IENA.IENA_HEADER_LENGTH + IENA.TRAILER_LENGTH) /2 # size is in words

        packetvalues = (self.key,self.size,timehi,timelo,self.keystatus,self.status,self.sequence)
        packet = self._packetStrut.pack(*packetvalues) + self.payload + struct.pack('>H',self.endfield)
        return packet


    def _getPacketTime(self):
        '''Return the Packet time in standard UNIX time
        :rtype: int
        '''
        return int(self.timeusec/1e6 + time.mktime(self._startOfYear.timetuple()))

    def setPacketTime(self,utctimestamp,microseconds=0):
        ''''Set the packet timestamp
        :type timestamp: int
        :type microseconds: int
        '''
        seconds_this_year = utctimestamp - int(time.mktime(self._startOfYear.timetuple()))
        packettime = microseconds + int(seconds_this_year)*1000000
        self.timeusec = packettime







