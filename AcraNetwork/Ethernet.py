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

def mactoreadable(macaddress):
    '''Convert a macaddress into the readable form'''
    mac_string = ""
    for i in range(5,0,-1):
        eachbyte = 0xff & int(macaddress >> (i*8))
        mac_string += ":{:02x}".format(eachbyte)
    return mac_string

# 
# def calc_checksum(pkt):
#     '''Calculate the checksum of a packet'''
#     if len(pkt) % 2 == 1:
#         pkt += "\0"
#     s = sum(array.array("H", pkt))
#     s = (s >> 16) + (s & 0xffff)
#     s += s >> 16
#     s = ~s
#     return s & 0xffff


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
        {'n': 'dstmac', 'w': ['H', 'I'], 'd': None},
        {'n': 'srcmac', 'w': ['H', 'I'], 'd': None},
        {'n': 'type', 'w': 'H', 'd': None},
        ]

#     def unpack_local(self, buf):
#         self.assign_packet()

#     def pack(self):
#         #self.size = int((len(self.payload) + self.HEADER_SIZE + self.TRAILER_LENGTH)/2) # size is in words
#         #extra = struct.pack('>H',self.endfield)
#         #return super(self.__class__, self, self).pack()
#         return super(Ethernet, self).pack()

#     def pack(self):
#         '''Pack the Ethernet object into a bufferr
#         :rtype : str
#         '''
#         if self.dstmac == None or self.srcmac == None or self.type == None or self.payload == None:
#             raise ValueError("All thre required Ethernet fields are not complete")
#         header = struct.pack('>HIHIH',(self.dstmac>>32),(self.dstmac&0xffffffff),(self.srcmac>>32),(self.srcmac&0xffffffff),0x0800)
#         return header + self.payload
