#-------------------------------------------------------------------------------
# Name:        IENA
# Purpose:     Class to pack and unpack IENA packets
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
import datetime,time

def unpack48(x):
    x2, x3 = struct.unpack('>HI', x)
    return x3 | (x2 << 32)


class IENA ():
    def __init__(self):
        '''Class for generating an IENA packet. '''
        self.key = None # know as ienaky
        self.size = None
        self.timeusec = None
        self.keystatus = None
        self.status = None
        self.sequence = None
        self.endfield = 0xdead
        self.payload = None #string containing payload
        self.timestamp = None

        self.format = '>HHHIBBH'
        self.packetstrut = struct.Struct(self.format)
        self.headerlen = struct.calcsize(self.format)
        self.packet = ""
        # only calculate this once
        self.start_of_year = datetime.datetime(datetime.datetime.today().year, 1, 1, 0, 0, 0,0)
        self.lenerror = False # Flag to verify the buffer length





    def unpack(self,buf,ExceptionOnLengthError=False):
        '''Unpack a raw byte stream to an IENA object'''
        self.key,self.size,timehi,timelo,self.keystatus,self.status,self.sequence  = self.packetstrut.unpack_from(buf)
        self.timeusec = timelo | (timehi << 32)

        if self.size*2 != len(buf):
            self.lenerror = True
            if ExceptionOnLengthError:
                raise ValueError

        self.payload = buf[self.headerlen:-2]
        self.endfield = buf[-2:]
        #self.CalcTimeStamp()

    def CalcTimeStamp(self):
        """Get the time of the packet in seconds"""
        self.timestamp = int(self.timeusec/1e6 + time.mktime(self.start_of_year.timetuple()))
        return




