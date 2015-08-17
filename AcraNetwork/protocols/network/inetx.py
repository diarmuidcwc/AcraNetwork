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
from AcraNetwork.protocols.network.BasePacket import BasePacket

class iNetX(BasePacket):
    '''
    Class to pack and unpack iNetX payloads. iNet-X is an open payload format for use
    in FTI networks. It is usually transmitted in a UDP packet containing parameter data
    acquired from sensors and buses
    '''
    
    CALC_HEADER = '>LLLLLLL'
    DEF_CONTROL_WORD = 0x11000000

    HEADER = [
        {'n': 'inetxcontrol', 'w': 'L', 'd': DEF_CONTROL_WORD},
        {'n': 'streamid', 'w': 'L', 'd': None},
        {'n': 'sequence', 'w': 'L', 'd': None},
        {'n': 'packetlen', 'w': 'L', 'd': 0},
        {'n': 'ptptimeseconds', 'w': 'L', 'd': None},
        {'n': 'ptptimenanoseconds', 'w': 'L', 'd': None},
        {'n': 'pif', 'w': 'L', 'd': None},
        ]

    def __init__(self, buf=None, payload_length=None):
        super(self.__class__, self).__init__(buf)
        self.packetlen = None

    def pack(self):
        self.packetlen = len(self.payload) + self.HEADER_SIZE
        #return super(self.__class__, self, self).pack()
        return super(iNetX, self).pack()

    def setPacketTime(self,utctimestamp,nanoseconds=0):
        ''''Set the packet timestamp
        :type timestamp: int
        :type nanoseconds: int
        '''
        self.ptptimeseconds = utctimestamp
        self.ptptimenanoseconds = nanoseconds
