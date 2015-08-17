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

import AcraNetwork.protocols.network.tte as tte
import AcraNetwork.Pcap as pcap

class TTETest(unittest.TestCase):

    def test_defaultTTE(self):
        '''Check the defaults for the TTE packet'''
        i = tte.TTE()
        self.assertEqual(i.integration_cycle, 0)
        self.assertEqual(i.membership_new, 0)
        self.assertEqual(i.sync_priority, 0)
        self.assertEqual(i.sync_domain, 0)
        self.assertEqual(i.type, 0)
        self.assertEqual(i.transparent_clock, 0)
        self.assertEqual(i.type_text, 'Unknown')
        self.assertEqual(i.macdest, 0)
        self.assertEqual(i.ctid, 0)


    def test_basicTTE(self):
        '''Build a very basic packet and check the packed result'''
        i = tte.TTE()
        i.integration_cycle = 1
        i.membership_new = 2
        i.sync_priority = 3
        i.sync_domain = 4
        i.type = 5
        i.transparent_clock = 6
        x = bytearray(0)
        i.reserved0 = x
        i.reserved1 = x
        i.reserved2 = x
        expected_payload = struct.pack(tte.TTE().HEADER_FORMAT,1,2,x,3,4,5,x,6,x)
        self.assertEqual(i.pack(), expected_payload)

    def test_unpackTTEFromPcap(self):
        '''
        Read all the TCP packets in a pcap file and check each field
        '''
        filename = 'pcap/tte_test.pcap'
        TESTDATA_FILENAME = os.path.join(os.path.dirname(__file__), filename)
        p = pcap.Pcap(TESTDATA_FILENAME)
        p.silent = True
        packets = p.parse()
        
        self.assertEqual(len(packets), 4)
        self.assertEqual(packets[0].eth.isPacket('TTE'), True)
        self.assertEqual(packets[0].eth.isPacket('TCP'), False)
        
        t = packets[0].eth.tte
        self.assertEqual(t.integration_cycle, 0)
        self.assertEqual(t.membership_new, 1)
        self.assertEqual(t.sync_priority, 128)
        self.assertEqual(t.sync_domain, 0)
        self.assertEqual(t.type, 0)
        self.assertEqual(t.transparent_clock, 110100480)
        self.assertEqual(t.type_text, 'Unknown')
        self.assertEqual(t.macdest, 0x3000101)
        self.assertEqual(t.ctid, 0xffff)
        
        t = packets[1].eth.tte
        self.assertEqual(t.integration_cycle, 0)
        self.assertEqual(t.membership_new, 1)
        self.assertEqual(t.sync_priority, 128)
        self.assertEqual(t.sync_domain, 0)
        self.assertEqual(t.type, 0)
        self.assertEqual(t.transparent_clock, 110100480)
        self.assertEqual(t.type_text, 'Unknown')
        self.assertEqual(t.macdest, 0x11223344)
        self.assertEqual(t.ctid, 0x5566)

        p.close()

if __name__ == '__main__':
    unittest.main()
