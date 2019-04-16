#-------------------------------------------------------------------------------
# Name:        module1
# Purpose:
#
# Author:      DCollins
#
# Created:     19/12/2013
# Copyright:   (c) DCollins 2013
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

import colorama
from colorama import Fore, Back, Style
import os

def pos(y,x):
    return '\x1b[%d;%dH' % (y, x)

#pos = lambda y, x: '\x1b[%d;%dH' % (y, x)
def clear():
    if os.name == "nt":
        os.system('cls')
    else:
        os.system('reset')
    return
#clear = lambda: os.system('cls')


class ColouredOutput():
    """This class makes it easy to print out static tables on the console
    It's quite custom to iNetx packets"""
    # The starting locations on the screen
    MINY = 3
    MINX = 5
    # How long do we want the bar to be
    BAR_LEN = 14



    def __init__(self):
        """"""
        #----------------------------------
        # Setup the coloured output
        #----------------------------------
        colorama.init(autoreset=True)

        clear()

        self.y_location = ColouredOutput.MINY
        self.x_location = ColouredOutput.MINX
        # How the output will look
        self.output_format = "{:#10x} {:>15s} {:15d} {:>15s}"


        # This dict will contain a line number per streamid.
        self.YPosition = dict()
        self.lastyposition = self.y_location # Increment this on every streamid we find
        # We keep a count of the previous sequence number per streamid so that we can
        # identify dropped packets
        self.PreviousSeqNum = dict()

        # Print a nice vertical line with the temperature. the taller the line, the hotter it gets so chance
        # the colour of the line accordingly
        # Temperature colour gradient
        self.TempGradient = {1:colorama.Back.BLUE,2:colorama.Back.BLUE,3:colorama.Back.BLUE,4:colorama.Back.CYAN,5:colorama.Back.CYAN,
                            6:colorama.Back.CYAN,7:colorama.Back.YELLOW,8:colorama.Back.YELLOW,9:colorama.Back.MAGENTA,10:colorama.Back.MAGENTA,
                            11:colorama.Back.MAGENTA,12:colorama.Back.RED,13:colorama.Back.RED,14:colorama.Back.RED,15:colorama.Back.RED}

    def PrintHeader(self):
        """Print a header describing the columns"""
        outstring="{:>10s} {:>15s} {:>15s} {:>15s}".format("StreamID","Source IP","Sequence Num","TimeStamp")
        print(( pos(self.y_location, self.x_location) + colorama.Fore.BLACK+colorama.Back.RED + outstring))


    def PrintALine(self,string,sequencenum,streamid):
        """Print a line on the output one per streamid. The sequence number is incremented on each one"""
        # Figure out which line on the screen we should print at
        if streamid not in self.YPosition:
            self.lastyposition += 1
            self.YPosition[streamid] = self.lastyposition

        # Alternate the line colours to make it more readable
        if (sequencenum <= 100):
            # if we have recently reset keep this in red so it's obvious
            outputcolour = colorama.Fore.RED+colorama.Back.BLACK
        elif self.YPosition[streamid] % 2  == 0:
            outputcolour = colorama.Fore.CYAN+colorama.Back.BLACK
        else:
            outputcolour = colorama.Fore.GREEN+colorama.Back.BLACK


        # Print it to the correct position on the scree
        print(( pos(self.YPosition[streamid], self.x_location) + outputcolour + string))


    def PrintDroppedPacket(self,sequencenum,streamid,packet_count,pcapfilename):
        """Print out a warning if we have missed some sequence numbers"""
        # Check if we have dropped packets
        if streamid not in self.PreviousSeqNum:
            self.PreviousSeqNum[streamid] = sequencenum
        else:
            if self.PreviousSeqNum[streamid]+1 != sequencenum:
                # Dropped packet!
                print(( pos(self.YPosition[streamid], self.x_location+72) + colorama.Fore.MAGENTA+colorama.Back.CYAN+ "Dropped packet at count={} in {}".format(packet_count,pcapfilename)))

            self.PreviousSeqNum[streamid] = sequencenum

    def PrintTemperatureBar(self,temperature,offset):
        """This prints a verticl column with the temperature. Quite custom to one application"""
        bar_max_y = ColouredOutput.MINY + ColouredOutput.BAR_LEN - offset
        # So loop through the column and print accordingly
        for yposn in range(ColouredOutput.MINY, ColouredOutput.MINY + ColouredOutput.BAR_LEN):
            if yposn >= bar_max_y:
                print(( pos(yposn, 70) + self.TempGradient[offset] + "{: 3.1f}".format(temperature)))
            else:
                print(( pos(yposn, 70) + colorama.Back.BLACK + "     "))


    def PrintFileName(self,pcapfilename):
        """Print a header with the filename"""
        print(( pos(self.y_location-1, self.x_location) + colorama.Fore.BLACK+colorama.Back.RED + pcapfilename))

    def PrintExitInfo(self,string):
        print(( pos(self.y_location-1, self.x_location+30) + colorama.Fore.WHITE+colorama.Back.BLACK + string))


    def PrintMissingContinuity(self,streamid,mpegts):
        """Print out a warning if we have missed some sequence numbers"""
        # Check if we have dropped packets
        print(( pos(self.YPosition[streamid], self.x_location+72) + colorama.Fore.MAGENTA+colorama.Back.CYAN+ "Missed Continutiy"))

