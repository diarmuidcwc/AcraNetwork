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
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#-------------------------------------------------------------------------------


import struct
import socket
import array

def unpack48(x):
    x2, x3 = struct.unpack('>HI', x)
    return x3 | (x2 << 32)

def pack24(x):
    x1 = x >> 16
    x2 = x & 0xffff
    return struct.pack('BH',x1,x2)


def mactoreadable(macaddress):
    mac_string = ""
    for i in range(5,0,-1):
        eachbyte = 0xff & int(macaddress >> (i*8))
        mac_string += ":{:02x}".format(eachbyte)
    return mac_string


def calc_checksum(pkt):
    if len(pkt) % 2 == 1:
        pkt += "\0"
    s = sum(array.array("H", pkt))
    s = (s >> 16) + (s & 0xffff)
    s += s >> 16
    s = ~s
    return s & 0xffff


class Ethernet():
    '''This class will  unpack an Ethernet packet'''
    HEADERLEN = 14
    def __init__(self,buf):
        self.type =None
        self.srcmac = None
        self.dstmac = None
        self.payload = None
        self.unpack(buf)

    def unpack(self,buf):
        self.dstmac = unpack48(buf[:6])
        self.srcmac = unpack48(buf[6:12])
        (self.type,) = struct.unpack_from('>H',buf,12)
        self.payload = buf[Ethernet.HEADERLEN:]





class IP():
    '''This class will  unpack an IP packet '''
    HEADERLEN = 20
    PROTOCOLS = {"ICMP":0x01,"TCP":0x6,"UDP":0x11}
    def __init__(self,buf=None):
        self.format = '>BBHHBBBBHII'
        self.srcip = None
        self.dstip = None
        self.len = None
        self.flags = 0x0
        self.protocol = IP.PROTOCOLS['UDP'] # default to udp
        self.payload = None
        self.version = 4 # IPV4
        self.ihl = 5 # Header len in 32 bit words
        self.dscp = 0
        self.id = 0
        self.ttl = 0
        if buf != None:
            self.unpack(buf)

    def unpack(self,buf):
        (na1,self.dscp, self.len,self.id,self.flags,na3, self.ttl, self.protocol, checksum, self.srcip,self.dstip) = struct.unpack_from(self.format,buf)
        #self.version = na1 >>4
        #self.ihl = na1 & 0xf
        self.srcip = socket.inet_ntoa(struct.pack('!I',self.srcip))
        self.dstip = socket.inet_ntoa(struct.pack('!I',self.dstip))
        self.payload = buf[IP.HEADERLEN:]

    def pack(self):
        (srcip_as_int,) = struct.unpack('!I',socket.inet_aton(self.srcip))
        (dstip_as_int,) = struct.unpack('!I',socket.inet_aton(self.dstip))
        self.len = 20+len(self.payload)
        header = struct.pack(self.format,0x45,self.dscp,self.len,self.id,self.flags,0,self.ttl,self.protocol,0,srcip_as_int,dstip_as_int)
        checksum = calc_checksum(header)
        header = header[:10] + struct.pack('H',checksum) + header[12:]
        return header + self.payload


class UDP():
    '''This class will  unpack a UDP packet just pulling out the ports'''
    HEADERLEN = 8
    def __init__(self,buf=None):

        self.srcport = None
        self.dstport = None
        self.len = None
        self.payload = None

        self.isinetx = False

        self.format = '>HHHH'
        if buf != None:
            self.unpack(buf)
            self.testisinetx()

    def unpack(self,buf):
        (self.srcport,self.dstport,self.len,checksum) = struct.unpack_from(self.format,buf)
        self.payload = buf[UDP.HEADERLEN:]

    def testisinetx(self,controlword=0x11000000):
        """Just a simple test to see if the first 4 bytes of the payload are the control word"""
        if len(self.payload) < 4:
            return
        (control_word,) = struct.unpack_from('>I',self.payload)
        if control_word == controlword:
            self.isinetx = True

    def pack(self):
        self.len = len(self.payload) + 8
        return struct.pack(self.format,self.srcport,self.dstport,self.len,0) + self.payload

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
        if srcconstantf != AFDX.SRCMAC_CONST:
            raise ValueError('Expected constant field of {:#x} in SrcMac Address'.format(AFDX.SRCMAC_CONST))
        (self.networkID,self.equipmentID,self.interfaceID) = struct.unpack_from('BBB',mac[:3])
        self.interfaceID = self.interfaceID >> 5

    def set_dstmac(self,mac):
        (dstconstantf,vlink) = struct.unpack_from('>IH',mac)
        if dstconstantf != AFDX.DSTMAC_CONST:
            raise ValueError('Expected constant field of {:#x} in DestMac Address'.format(AFDX.DSTMAC_CONST))
        self.vlink = vlink

    def pack(self):

        if (len(self.payload) < AFDX.MIN_PAYLOAD_LEN):
            raise ValueError('Minimum Payload of {} bytes'.format(AFDX.MIN_PAYLOAD_LEN))

        afdx_header = struct.pack('>IHHBBBBH',AFDX.DSTMAC_CONST,self.vlink,(AFDX.SRCMAC_CONST>>8),0,self.networkID,self.equipmentID,(self.interfaceID<<5),self.type)
        packet = afdx_header + self.payload + struct.pack('>B',self.sequencenum)

        return packet


