#-------------------------------------------------------------------------------
# Name:        Ethernet
# Purpose:     
#
# Author:      DKeeshan
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
from AcraNetwork.protocols.network.MacAddress import MacAddress

class Ethernet(BasePacket):
    '''This is a class to build or deconstruct an Ethernet packet'''
    TYPE_IP = 0x0800
    CALC_HEADER = '>HIHIH'
    BASETYPE_MAPPING = 'type'

    TYPE = {
        0x0800: {'from': 'AcraNetwork.protocols.network.ip', 'import': 'IP'},
        0x0806: {'from': None, 'import': 'ARP'},
        0x86dd: {'from': 'AcraNetwork.protocols.network.ipv6', 'import': 'IPv6'},
        0x891d: {'from': 'AcraNetwork.protocols.network.tte', 'import': 'TTE'},
        0xfffe: {'from': None, 'import': None}, # for testing only
        }

    HEADER = [
        {'n': 'dstmac', 'w': ['H', 'I'], 'd': None, 'c': MacAddress()},
        {'n': 'srcmac', 'w': ['H', 'I'], 'd': None, 'c': MacAddress()},
        {'n': 'type', 'w': 'H', 'd': None},
        ]

#     def unpack_local(self, buf):
#         self.assign_packet()
#     def __init__(self, buf=None, payload_length=None, parent=None):
#         super(self.__class__, self).__init__(buf, parent=parent)
    
    def unpack_local(self, buf):
        super(self.__class__, self).unpack_local(buf)
#         self.dstmac = MacAddress(self.dstmac)
#         self.srcmac = MacAddress(self.srcmac)
