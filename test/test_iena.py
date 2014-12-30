#-------------------------------------------------------------------------------
# Name:        
# Purpose:     
#
# Author:      
#
# Created:     
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
__author__ = '$USER'

import sys
sys.path.append("..")

import unittest
import datetime
import time
import AcraNetwork.IENA as iena
import AcraNetwork.SimpleEthernet as SimpleEthernet
import AcraNetwork.Pcap as pcap

import struct

class IENATest(unittest.TestCase):

    def test_defaultIENA(self):
        '''Check the defaults for the IENA packet'''
        i = iena.IENA()
        self.assertEqual(i.key,None)
        self.assertEqual(i.size,None)
        self.assertEqual(i.keystatus,None)
        self.assertEqual(i.status,None)
        self.assertEqual(i.sequence,None)
        self.assertEqual(i.endfield,0xdead)
        self.assertEqual(i.payload,None)

    def test_basicIENA(self):
        '''Build a very basic packet and check the packed result'''
        i = iena.IENA()
        i.key = 1
        i.keystatus = 2
        i.status = 3
        i.sequence = 10
        i.setPacketTime(time.mktime(datetime.datetime(datetime.datetime.today().year, 1, 2, 0, 0, 0,0).timetuple()),0)
        i.payload = struct.pack('H',0x5)
        # size = 9. Time = midnight Jan 02 = 86400s 0us = 0x14dd760000
        expected_payload = struct.pack(iena.IENA.IENA_HEADER_FORMAT,1,9,0x14,0x1dd76000,2,3,10) + struct.pack('H',0x5) + struct.pack('>H',0xdead)
        self.assertEqual(i.pack(),expected_payload)

    def test_unpackIENA(self):
        pass

    def test_unpackIEANFromPcap(self):
        '''Read all the IENA packets in a pcap file and check each field'''
        p = pcap.Pcap("iena_test.pcap")
        p.readGlobalHeader()
        sequencenum = 195
        exptime = 0x1d102f800
        while True:
            # Loop through the pcap file reading one packet at a time
            try:
                mypcaprecord = p.readAPacket()
            except IOError:
                # End of file reached
                break
            e = SimpleEthernet.Ethernet()
            e.unpack(mypcaprecord.packet)
            ip =  SimpleEthernet.IP()
            ip.unpack(e.payload)
            u = SimpleEthernet.UDP()
            u.unpack(ip.payload)
            # Now I have a payload that will be an iena packet
            i = iena.IENA()
            i.unpack(u.payload)
            self.assertEquals(i.key,0x1a)
            self.assertEquals(i.size,24)
            self.assertEquals(i.status,0)
            self.assertEquals(i.keystatus,0)
            self.assertEquals(i.sequence,sequencenum)
            sequencenum += 1
            self.assertEqual(i.timeusec,exptime)
            exptime += 0x186a0 # The timestamp increments by a fixed number of microseconds
            self.assertEquals(i.endfield,0xdead)



if __name__ == '__main__':
    unittest.main()
