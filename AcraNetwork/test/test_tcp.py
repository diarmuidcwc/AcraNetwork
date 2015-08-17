#-------------------------------------------------------------------------------
# Name:        
# Purpose:     
#
# Author:      
#
# Created:     
#
# Copyright 2015 Dave Keeshan
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
__author__ = '$USER'

import os

import unittest
import struct

import AcraNetwork.Ethernet as Ethernet
import AcraNetwork.protocols.network.tcp as tcp
import AcraNetwork.protocols.network.ip as ip
import AcraNetwork.protocols.network.udp as udp
import AcraNetwork.Pcap as pcap

class TCPTest(unittest.TestCase):

    def test_defaultTCP(self):
        '''Check the defaults for the TCP packet'''
        i = tcp.TCP()
        self.assertEqual(i.src, 0)
        self.assertEqual(i.dst, 0)
        self.assertEqual(i.sequence, 0)
        self.assertEqual(i.acknowledge, 0)
        self.assertEqual(i.flags, 0)
        self.assertEqual(i.window,0)
        self.assertEqual(i.checksum,0)
        self.assertEqual(i.urgentptr,0)

    def test_basicTCP(self):
        '''Build a very basic packet and check the packed result'''
        i = tcp.TCP()
        i.src = 1
        i.dst = 2
        i.sequence = 10
        i.acknowledge = 3
        i.flags = 4
        i.window = 5
        i.checksum = 6
        i.urgentptr = 7
        expected_payload = struct.pack(tcp.TCP().HEADER_FORMAT,1,2,10,3,4,5,6,7)
        self.assertEqual(i.pack(), expected_payload)

    def test_unpackTCPFromPcap(self):
        '''
        Read all the TCP packets in a pcap file and check each field
        '''
        filename = 'pcap/tcp_test.pcap'
        TESTDATA_FILENAME = os.path.join(os.path.dirname(__file__), filename)
        p = pcap.Pcap(TESTDATA_FILENAME)
        p.readGlobalHeader()
        sequencenum = 195
        exptime = 0x1d102f800
        mypcaprecord = p.readAPacket()
        e = Ethernet.Ethernet()
        e.unpack(mypcaprecord.packet)
        i = ip.IP()
        i.unpack(e.payload)
        # Now I have a payload that will be an tcp packet
        t = tcp.TCP()
        t.unpack(i.payload)
        self.assertEqual(t.src, 55431)
        self.assertEqual(t.dst, 389)
        self.assertEqual(t.sequence, 2170942011)
        self.assertEqual(t.acknowledge, 0)
        self.assertEqual(t.flags, 32770)
        self.assertEqual(t.window, 8192)
        self.assertEqual(t.checksum, 57928)
        self.assertEqual(t.urgentptr, 0)
        
        self.assertEqual(e.ip.tcp.src, 55431)
        self.assertEqual(e.ip.tcp.dst, 389)
        self.assertEqual(e.ip.tcp.sequence, 2170942011)
        self.assertEqual(e.ip.tcp.acknowledge, 0)
        self.assertEqual(e.ip.tcp.flags, 32770)
        self.assertEqual(e.ip.tcp.window, 8192)
        self.assertEqual(e.ip.tcp.checksum, 57928)
        self.assertEqual(e.ip.tcp.urgentptr, 0)
        
        mypcaprecord = p.readAPacket()
        e = Ethernet.Ethernet()
        e.unpack(mypcaprecord.packet)
        self.assertEqual(e.ip.tcp.src, 55432)
        self.assertEqual(e.ip.tcp.dst, 389)
        self.assertEqual(e.ip.tcp.sequence, 1946064890)
        self.assertEqual(e.ip.tcp.acknowledge, 0)
        self.assertEqual(e.ip.tcp.flags, 32770)
        self.assertEqual(e.ip.tcp.window, 8192)
        self.assertEqual(e.ip.tcp.checksum, 18928)
        self.assertEqual(e.ip.tcp.urgentptr, 0)
        
        self.assertEqual(e.isPacket('ip'), True)
        self.assertEqual(e.isPacket('tcp'), True)
        self.assertEqual(e.isPacket('udp'), False)
        self.assertEqual(e.isPacket('IP'), True)
        self.assertEqual(e.isPacket('TCP'), True)
        self.assertEqual(e.isPacket('UDP'), False)
        self.assertEqual(e.packetpath, ['Ethernet', 'ip', 'tcp'])
        self.assertEqual(e.ip.packetpath, ['ip', 'tcp'])
        
        p.close()

if __name__ == '__main__':
    unittest.main()
