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
import time
import datetime
from AcraNetwork.protocols.network.BasePacket import BasePacket

class IENA(BasePacket):
    '''Create or unpack an IENA packet'''
    TRAILER_LENGTH = 2
    HEADER = [
        {'n': 'key', 'w': 'H', 'd': None},
        {'n': 'size', 'w': 'H', 'd': None},
        {'n': 'timeusec', 'w': ['H', 'I']},
        {'n': 'keystatus', 'w': 'B', 'd': None},
        {'n': 'status', 'w': 'B', 'd': None},
        {'n': 'sequence', 'w': 'H', 'd': None},
        ]

    def __init__(self, buf=None, payload_length=None):
        super(self.__class__, self).__init__(buf)
        self.endfield = 0xdead
        # only calculate this once
        self._startOfYear = datetime.datetime(datetime.datetime.today().year, 1, 1, 0, 0, 0,0)
        self.lengthError = False # Flag to verify the buffer length

    def pack(self):
        self.size = int((len(self.payload) + self.HEADER_SIZE + self.TRAILER_LENGTH)/2) # size is in words
        extra = struct.pack('>H',self.endfield)
        #return super(self.__class__, self, self).pack()
        return super(IENA, self).pack(extra)
 
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
