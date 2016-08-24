#-------------------------------------------------------------------------------
# Name:        SimpleEthernet
# Purpose:     A very trimmed down set of classes to unpack the common network packet formats
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
import socket
import array

def unpack48(x):
    '''Convert a 48 bit buffer into an integer'''
    x2, x3 = struct.unpack('>HI', x)
    return x3 | (x2 << 32)



def mactoreadable(macaddress):
    '''Convert a macaddress into the readable form'''
    mac_string = ""
    for i in range(5,0,-1):
        eachbyte = 0xff & int(macaddress >> (i*8))
        mac_string += ":{:02x}".format(eachbyte)
    return mac_string


def calc_checksum(pkt):
    '''Calculate the checksum of a packet'''
    if len(pkt) % 2 == 1:
        pkt += "\0"
    s = sum(array.array("H", pkt))
    s = (s >> 16) + (s & 0xffff)
    s += s >> 16
    s = ~s
    return s & 0xffff


class Ethernet(object):
    '''This is simple class to build or deconstruct an Ethernet packet'''
    HEADERLEN = 14
    TYPE_IP = 0x800

    def __init__(self,buf=None):
        '''Constructor for and Ethernet packet'''
        self.type = None
        """:type : int"""
        self.srcmac = None
        """:type : int"""
        self.dstmac = None
        """:type : int"""
        self.payload = None
        """:type : str"""

        if buf != None:
            self.unpack(buf)

    def unpack(self,buf):
        '''Unpack a buffer into an Ethernet object
        :type buf: str
        '''
        self.dstmac = unpack48(buf[:6])
        self.srcmac = unpack48(buf[6:12])
        (self.type,) = struct.unpack_from('>H',buf,12)
        self.payload = buf[Ethernet.HEADERLEN:]


    def pack(self):
        '''Pack the Ethernet object into a bufferr
        :rtype : str
        '''
        if self.dstmac == None or self.srcmac == None or self.type == None or self.payload == None:
            raise ValueError("All thre required Ethernet fields are not complete")
        header = struct.pack('>HIHIH',(self.dstmac>>32),(self.dstmac&0xffffffff),(self.srcmac>>32),(self.srcmac&0xffffffff),0x0800)
        return header + self.payload



class IP():
    '''Create or unpack an IP packet'''
    PROTOCOLS = {"ICMP":0x01,"IGMP" : 0X02, "TCP":0x6,"UDP":0x11}
    IP_HEADER_FORMAT = '>BBHHBBBBHII'
    IP_HEADER_SIZE = struct.calcsize(IP_HEADER_FORMAT)

    def __init__(self,buf=None):
        self.srcip = None
        """:type str"""
        self.dstip = None
        """:type str"""
        self.len = None
        """:type int"""
        self.flags = 0x0
        """:type int"""
        self.protocol = IP.PROTOCOLS['UDP'] # default to udp
        """:type int"""
        self.payload = None
        """:type str"""
        self.version = 4 # IPV4
        """:type int"""
        self.ihl = 5 # Header len in 32 bit words
        """:type int"""
        self.dscp = 0
        """:type int"""
        self.id = 0
        """:type int"""
        self.ttl = 20
        """:type int"""
        if buf != None:
            self.unpack(buf)

    def unpack(self,buf):
        '''Unpack a buffer into an ethernet object'''

        if len(buf) < IP.IP_HEADER_SIZE:
            raise ValueError("Buffer too short for to be an IP packet")
        (na1,self.dscp, self.len,self.id,self.flags,na3, self.ttl, self.protocol, checksum, self.srcip,self.dstip) = struct.unpack_from(IP.IP_HEADER_FORMAT,buf)
        self.flags = self.flags >> 5
        #self.version = na1 >>4
        #self.ihl = na1 & 0xf
        self.srcip = socket.inet_ntoa(struct.pack('!I',self.srcip))
        self.dstip = socket.inet_ntoa(struct.pack('!I',self.dstip))
        self.payload = buf[IP.IP_HEADER_SIZE:self.len]

    def pack(self):
        '''Pack the IP object into a string buffer
        :rtype :str
        '''
        for word in [self.dscp,self.id,self.flags,self.ttl,self.protocol,self.srcip,self.dstip]:
            if word == None:
                raise ValueError("All required IP payloads not defined")

        (srcip_as_int,) = struct.unpack('!I',socket.inet_aton(self.srcip))
        (dstip_as_int,) = struct.unpack('!I',socket.inet_aton(self.dstip))
        self.len = IP.IP_HEADER_SIZE+len(self.payload)
        header = struct.pack(IP.IP_HEADER_FORMAT,0x45,self.dscp,self.len,self.id,self.flags,0,self.ttl,self.protocol,0,srcip_as_int,dstip_as_int)
        checksum = calc_checksum(header)
        header = header[:10] + struct.pack('H',checksum) + header[12:]
        return header + self.payload


class UDP():
    '''Class to build and unpack a UDP packet'''
    UDP_HEADER_FORMAT = '>HHHH'
    UDP_HEADER_SIZE = struct.calcsize(UDP_HEADER_FORMAT)
    def __init__(self,buf=None):

        self.srcport = None
        self.dstport = None
        self.len = None
        self.payload = None

        if buf != None:
            self.unpack(buf)

    def unpack(self,buf):
        '''Unpack a buffer into a UDP object'''

        if len(buf) < UDP.UDP_HEADER_SIZE:
            raise ValueError("Buffer too short to be a UDP packet")
        (self.srcport,self.dstport,self.len,checksum) = struct.unpack_from(UDP.UDP_HEADER_FORMAT,buf)
        self.payload = buf[UDP.UDP_HEADER_SIZE:]

    def pack(self):
        '''Pack a UDP object into a buffer
        :rtype :str
        '''
        if self.srcport == None or self.dstport == None or self.payload == None:
            raise ValueError("All UDP fields need to be defined to pack the payload")

        self.len = len(self.payload) + UDP.UDP_HEADER_SIZE
        return struct.pack(UDP.UDP_HEADER_FORMAT,self.srcport,self.dstport,self.len,0) + self.payload


class AFDX():
    '''This class will  unpack an AFDX packet'''
    HEADERLEN = 14
    DSTMAC_CONST = 0x3000000
    SRCMAC_CONST = 0x20000
    MIN_PAYLOAD_LEN = 42
    def __init__(self,buf=None):
        self.type =None
        self.networkID = None
        self.equipmentID = None
        self.interfaceID = None
        self.vlink = None

        self.payload = None
        self.sequencenum = None
        if buf != None:
            self.unpack(buf)

    def unpack(self,buf):
        self.set_dstmac(buf[:6])
        self.unpacksrcmac(unpack48(buf[6:12]))

        (self.type,) = struct.unpack_from('>H',buf,12)
        self.payload = buf[AFDX.HEADERLEN:-1]
        self.sequencenum = struct.unpack('B',buf[-1])

    def unpacksrcmac(self,mac):
        srcconstantf = mac >> 24
        #if srcconstantf != AFDX.SRCMAC_CONST:
        #    raise ValueError('Expected constant field of {:#x} in SrcMac Address'.format(AFDX.SRCMAC_CONST))
        #(self.networkID,self.equipmentID,self.interfaceID) = struct.unpack_from('BBB',mac[:3])
        #self.interfaceID = self.interfaceID >> 5

    def set_dstmac(self,mac):
        (dstconstantf,vlink) = struct.unpack_from('>IH',mac)
        #if dstconstantf != AFDX.DSTMAC_CONST:
        #    raise ValueError('Expected constant field of {:#x} in DestMac Address'.format(AFDX.DSTMAC_CONST))
        self.vlink = vlink

    def pack(self):

        if (len(self.payload) < AFDX.MIN_PAYLOAD_LEN):
            raise ValueError('Minimum Payload of {} bytes'.format(AFDX.MIN_PAYLOAD_LEN))

        afdx_header = struct.pack('>IHHBBBBH',AFDX.DSTMAC_CONST,self.vlink,(AFDX.SRCMAC_CONST>>8),0,self.networkID,self.equipmentID,(self.interfaceID<<5),self.type)
        packet = afdx_header + self.payload + struct.pack('>B',self.sequencenum)

        return packet


