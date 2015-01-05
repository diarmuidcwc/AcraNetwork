#-------------------------------------------------------------------------------
# Name:        McastSocket
# Purpose:
#
# Author:      LionKimbro
#
# Created:     19/12/2013
#
# Copyright 2014 LionKimbro
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
# This is based on https://wiki.python.org/moin/UdpCommunication
#-------------------------------------------------------------------------------

import socket

class McastSocket(socket.socket):
    '''Create a multicast udp socket'''
    def __init__(self, local_port=0, reuse=False):
        socket.socket.__init__(self, socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        if(reuse):
            self.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            if hasattr(socket, "SO_REUSEPORT"):
                self.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        self.bind(('', local_port))

    def mcast_add(self, addr, iface="192.168.28.110"):
        '''Add a multicast address to an interface
        :type addr: str
        :type iface: str
        '''
        self.setsockopt(
            socket.IPPROTO_IP,
            socket.IP_ADD_MEMBERSHIP,
            socket.inet_aton(addr) + socket.inet_aton(iface))
