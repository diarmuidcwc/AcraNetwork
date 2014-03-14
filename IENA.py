#-------------------------------------------------------------------------------
# Name:        module1
# Purpose:
#
# Author:      DCollins
#
# Created:     19/12/2013
# Copyright:   (c) DCollins 2013
# Licence:     <your licence>
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




