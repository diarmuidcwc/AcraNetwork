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
import sys
sys.path.append("..")

import unittest
import datetime
import time
import struct

import AcraNetwork.protocols.network.iena as iena
import AcraNetwork.protocols.network.ip as ip
import AcraNetwork.protocols.network.udp as udp
#import AcraNetwork.SimpleEthernet as SimpleEthernet
import AcraNetwork.Ethernet as Ethernet
import AcraNetwork.Pcap as pcap

class IENATest(unittest.TestCase):

    def test_defaultIENA(self):
        '''Check the defaults for the IENA packet'''
        i = iena.IENA()
        self.assertEqual(i.key,None)
        self.assertEqual(i.size,None)
        self.assertEqual(i.keystatus,None)
        self.assertEqual(i.timeusec,0)
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
        expected_payload = struct.pack(iena.IENA().HEADER_FORMAT,1,9,0x14,0x1dd76000,2,3,10) + struct.pack('H',0x5) + struct.pack('>H',0xdead)
        self.assertEqual(i.pack(), expected_payload)

    def test_unpackIENA(self):
        pass

    def test_unpackIEANFromPcap(self):
        '''Read all the IENA packets in a pcap file and check each field'''
        TESTDATA_FILENAME = os.path.join(os.path.dirname(__file__), 'iena_test.pcap')
        p = pcap.Pcap(TESTDATA_FILENAME)
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
            e = Ethernet.Ethernet()
            e.unpack(mypcaprecord.packet)
            i = ip.IP()
            i.unpack(e.payload)
            u = udp.UDP()
            u.unpack(i.payload)
            # Now I have a payload that will be an iena packet
            ie = iena.IENA()
            ie.unpack(u.payload)
            self.assertEqual(ie.key,0x1a)
            self.assertEqual(ie.size,24)
            self.assertEqual(ie.status,0)
            self.assertEqual(ie.keystatus,0)
            self.assertEqual(ie.sequence,sequencenum)
            sequencenum += 1
            self.assertEqual(ie.timeusec,exptime)
            exptime += 0x186a0 # The timestamp increments by a fixed number of microseconds
            self.assertEqual(ie.endfield,0xdead)
        p.close()

if __name__ == '__main__':
    unittest.main()
