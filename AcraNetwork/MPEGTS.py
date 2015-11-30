#-------------------------------------------------------------------------------
# Name:        module1
# Purpose:
#
# Author:      DCollins
#
# Created:     22/08/2014
# Copyright:   (c) DCollins 2014
# Licence:     <your licence>
#-------------------------------------------------------------------------------

import struct

class MPEGTS():
    def __init__(self):
        self.previouscounter = {}
        self.discontinuity ={}
        self.blocks = []
        self.contunityerror = False
        self.invalidsync = False
        self.invalidsyncblock = list()

    def unpack(self,buf):
        remainingbytes = 0
        prevcount = self.previouscounter
        block_count = 0
        while remainingbytes < len(buf):
            MpegBlock = MPEGPacket()
            MpegBlock.unpack(buf[remainingbytes:remainingbytes+188])
            block_count += 1
            self.blocks.append(MpegBlock)
            if MpegBlock.invalidsync == True:
                self.invalidsync = True
                self.invalidsyncblock.append(block_count)
            remainingbytes += 188
            if  not MpegBlock.pid in prevcount:
                prevcount[MpegBlock.pid] = MpegBlock.continuitycounter
            elif ((prevcount[MpegBlock.pid]+1) % 16) != MpegBlock.continuitycounter:
                self.contunityerror = True
                self.discontinuity[MpegBlock.pid] = (prevcount[MpegBlock.pid],MpegBlock.continuitycounter)
                prevcount[MpegBlock.pid] = MpegBlock.continuitycounter
            else:
                prevcount[MpegBlock.pid] = MpegBlock.continuitycounter

        self.previouscounter = prevcount

    def NumberOfBlocks(self):
        return len(self.blocks)

    def FirstCount(self):
        return self.blocks[0].continuitycounter

    def LastCount(self):
        return self.blocks[self.NumberOfBlocks()-1].continuitycounter



class MPEGPacket():
    def __init__(self):
        self.packetstrut = struct.Struct('>BHB')
        self.sync = None
        self.pid = None
        self.continuitycounter = None
        self.invalidsync = False


    def unpack(self,buf):
        (self.syncbyte,pid_full,counter_full)  = self.packetstrut.unpack_from(buf)
        if self.syncbyte != 0x47:
            self.invalidsync = True

        self.pid = pid_full % 8192
        self.continuitycounter = counter_full % 16
        #print "PID={:x} Counterfull={:x} count={:x}".format(pid_full,counter_full,self.continuitycounter)
