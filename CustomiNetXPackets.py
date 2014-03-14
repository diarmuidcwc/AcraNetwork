#-------------------------------------------------------------------------------
# Name:        CustomiNetXPackets
# Purpose:     This is a catch all file for various custom iNetX Packets.
#
# Author:      DCollins
#
# Created:     19/12/2013
# Copyright:   (c) DCollins 2013
# Licence:     <your licence>
#-------------------------------------------------------------------------------
import struct

class BCUTemperature():
    """Unpacks an iNetx packet and pulls out the temperature
    This is a very custom Class"""
    PAYLOADLEN= 4
    def __init__(self, buf):
        if len(buf) != BCUTemperature.PAYLOADLEN:
            raise BufferError
        self.unpack(buf)

    def unpack(self,buf):
        (self.temperature,) = struct.unpack('>i',buf)
