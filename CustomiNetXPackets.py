
#-------------------------------------------------------------------------------
# Name:        CustomiNetXPackets
# Purpose:     This is a catch all file for various custom iNetX Packets.
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
