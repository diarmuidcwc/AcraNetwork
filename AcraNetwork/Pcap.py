#-------------------------------------------------------------------------------
# Name:        pcap
# Purpose:     Class to pack and unpack pcap files
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
import iNetX
import os
import SimpleEthernet
import time

class PcapRecord(object):
    '''Class that can be used to store one pcap record'''
    def __init__(self):
        self.sec = None
        """:type : int"""
        self.usec = None
        """:type : int"""
        self.incl_len = None
        """:type : int"""
        self.orig_len = None
        """:type : int"""
        self._packet = None
        """:type : str"""

    # Use a property on packet so that the length is triggered on it changing
    @property
    def packet(self):
        return self._packet

    @packet.setter
    def packet(self,p):
        self._packet = p
        self.incl_len = len(p)
        self.orig_len = self.incl_len

    def unpack(self,buf):
        '''Unpack the pcap header. Pass in a buffer containing the header
        :type buf: str
        '''
        if struct.calcsize(Pcap.RECORD_HEADER_FORMAT) > len(buf):
            raise ValueError("Header buffer too big to be a Pcap record header")
        (self.sec,self.usec,self.incl_len,self.orig_len) = struct.unpack(Pcap.RECORD_HEADER_FORMAT,buf)


    def pack(self):
        '''Pack a PcapRecord into a buffer'''
        if self.sec == None or self.usec == None or self.incl_len == None or self.orig_len == None or self.packet == None:
            raise ValueError("Cannot build record with undefined fields in the payload")
        return struct.pack(Pcap.RECORD_HEADER_FORMAT,self.sec,self.usec,self.incl_len,self.orig_len) + self.packet


    def setCurrentTime(self):
        currenttime = time.time()
        self.usec = int((currenttime%1)*1e6)
        self.sec = int(currenttime)


class Pcap(object):

    '''Pcap handling class. Supports basic handling of pcap files. Read and write.
    Assumption: Ethernet packets only supported'''

    GLOBAL_HEADER_FORMAT = '<IhhiIII'
    RECORD_HEADER_FORMAT = '<IIII'
    RECORD_HEADER_SIZE =  struct.calcsize(RECORD_HEADER_FORMAT)
    GLOBAL_HEADER_SIZE = struct.calcsize(GLOBAL_HEADER_FORMAT)

    def __init__(self,filename,**kwargs):
        '''Class for parsing pcap file.
        Create a new pcap object passing in the pcapfilename.
        Then call the other methods to parse the file

        :type filename: str
        :type forreading: bool
        '''

        self.filename = filename
        self.bytesread=0
        self.mode = kwargs.get('mode','r')

        if 'forreading' in kwargs:
            if kwargs['forreading']  == False:
                self.mode = 'w'
            raise DeprecationWarning("forreading is being deprecated and replaced with the mode argument")

        if self.mode == 'a':
            try:
                self.fopen = file(filename,'ab')
            except:
                raise IOError("Failed to open {} for appending".format(filename))

        elif self.mode == 'r':
            try:
                self.fopen = file(filename,'rb')
                self.filesize = os.path.getsize(filename)
            except Exception as e:
                raise IOError("Failed to open {} for reading {}".format(filename,e))
        else:
            self.fopen = file(filename,'wb')

        # Global header fields
        self.magic = 0xa1b2c3d4
        self.versionmaj = 2
        self.versionmin = 4
        self.zone = 0
        self.sigfigs = 0
        self.snaplen = 65535
        self.network  = 1 # Ethernet


    def readGlobalHeader(self):
        '''This method will read the pcap global header and unpack it.
        This should be the first method to call on reading a PCAP file
        '''

        header = self.fopen.read(Pcap.GLOBAL_HEADER_SIZE)
        self.bytesread += Pcap.GLOBAL_HEADER_SIZE
        (self.magic,self.versionmaj,self.versionmin,self.zone,self.sigfigs,self.snaplen,self.network) = struct.unpack(Pcap.GLOBAL_HEADER_FORMAT,header)

    def writeGlobalHeader(self):
        '''Write the global header to a new pcap file'''

        header = struct.pack(Pcap.GLOBAL_HEADER_FORMAT,self.magic,self.versionmaj,self.versionmin,self.zone,self.sigfigs,self.snaplen,self.network)
        self.fopen.write(header)

    def writeARecord(self,pcaprecord):
        '''Write the supplied pcaprecord to the pcap file
        :type pcaprecord: PcapRecord
        '''

        self.fopen.write(pcaprecord.pack())

    def close(self):
        '''Close the current pcap file'''
        self.fopen.close()

    def readAPacket(self):
        '''Method to read the next Packet in the pcap file
        :rtype: PcapRecord
        '''
        if self.bytesread >= self.filesize:
            raise IOError("Reached the end of the packet")

        # read the pcap header to a new object
        pcaprecord = PcapRecord()
        pcaprecord.unpack(self.fopen.read(Pcap.RECORD_HEADER_SIZE))
        try:
            pcaprecord.packet = self.fopen.read(pcaprecord.incl_len)
        except:
            raise IOError("Failed to read {} bytes from pcap file".format(pcaprecord.incl_len))
        self.bytesread += pcaprecord.incl_len+Pcap.RECORD_HEADER_SIZE

        return pcaprecord





    #-------------------------------------------------
    # Old, deprecated methods that should not be used
    # and I'm not going to test for them
    #-------------------------------------------------
    def _readNextiNetXPacket(self):
        """This method will read the next iNetX packet one by one. It will raise an IOError when it hits
        the end of the file and n NoImplementedError when it hits packets that are not iNetx. It returns
        the ip, udp and inetx packets"""
        # already at the end of the file
        if self.bytesread >= self.filesize:
            raise IOError

        # otherwise pull our the PCAP header size. Should really push headersize to the object self
        pcapheader = self.fopen.read(Pcap.RECORD_HEADER_SIZE)
        (sec,usec,incl_len,orig_len) = struct.unpack(Pcap.RECORD_HEADER_FORMAT,pcapheader)

        # now we have a packet then lets deconstruct it. first read in the ethernet header and unpack it
        eth_header = SimpleEthernet.Ethernet(self.fopen.read(SimpleEthernet.Ethernet.HEADERLEN))

        # This is the most portable but as a quick hack I'm going
        # to ignore smoe packets. All non-IP packets for starter
        if eth_header.type != 2048:
            throwaway=self.fopen.read(orig_len-SimpleEthernet.Ethernet.HEADERLEN)
            self.bytesread += (orig_len+Pcap.RECORD_HEADER_SIZE)
            raise NotImplementedError

        # pull apart the other headers. Again I'm assuming all the IP packets
        # are udp packets
        ip_header = SimpleEthernet.IP(self.fopen.read(SimpleEthernet.IP.HEADERLEN))
        udp_header = SimpleEthernet.UDP(self.fopen.read(SimpleEthernet.UDP.HEADERLEN))

        # Lets create an iNetx packet then test if we are really dealing with an
        # inetx packet. Do this by testing the first 4 bytes which should be the control word
        CONTROLWORD_LEN=4
        CONTROLWORD_STRING = struct.pack('>I',0x11000000)
        inetx_packet = iNetX.iNetX()
        inetx_packet.packet = self.fopen.read(CONTROLWORD_LEN)

        # So are the first 4 bytes the control word
        if inetx_packet.packet != CONTROLWORD_STRING:
            # throw away the rest of the packet and bail out with an exception
            throwaway=self.fopen.read(orig_len-SimpleEthernet.Ethernet.HEADERLEN-SimpleEthernet.IP.HEADERLEN-SimpleEthernet.UDP.HEADERLEN-CONTROLWORD_LEN)
            self.bytesread += (orig_len+headersize)
            raise NotImplementedError

        # So we have an inetx packet, read in the rest of the pcap packet and unpack it as an inetX packet
        inetx_packet.packet += self.fopen.read(orig_len-SimpleEthernet.Ethernet.HEADERLEN-SimpleEthernet.IP.HEADERLEN-SimpleEthernet.UDP.HEADERLEN-CONTROLWORD_LEN)
        inetx_packet.unpack(inetx_packet.packet)

        self.bytesread += (headersize + orig_len)
        # return the interesting packet headers, the packet time and the temperature if it exists
        return (inetx_packet,ip_header,udp_header,sec,bcu_temperature)


    def _readNextUDPPacket(self):
        """This method will read the next UDP packet in the pcap file one by one and returns the udp,eth and ip packets"""
        # already at the end of the file
        if self.bytesread >= self.filesize:
            raise IOError

        # otherwise pull our the PCAP header size. Should really push headersize to the object self
        headersize=struct.calcsize(Pcap.RECORD_HEADER_FORMAT)
        pcapheader = self.fopen.read(headersize)
        self.bytesread +=headersize
        (sec,usec,incl_len,orig_len) = struct.unpack(Pcap.RECORD_HEADER_FORMAT,pcapheader)

        # now we have a packet then lets deconstruct it. first read in the packet
        eth_pkt = SimpleEthernet.Ethernet(self.fopen.read(orig_len))
        self.bytesread +=orig_len

        # This is the most portable but as a quick hack I'm going
        # to ignore smoe packets. All non-IP packets for starter
        if eth_pkt.type != 2048:
            raise NotImplementedError

        # pull apart the other headers. Again I'm assuming all the IP packets
        # are udp packets
        ip_pkt = SimpleEthernet.IP(eth_pkt.payload)
        # Only parse udp
        if ip_pkt.protocol != SimpleEthernet.IP.PROTOCOLS['UDP']:
            raise NotImplementedError

        udp_pkt = SimpleEthernet.UDP(ip_pkt.payload)

        # return the interesting packet headers, the packet time and the temperature if it exists
        return (eth_pkt,ip_pkt,udp_pkt)