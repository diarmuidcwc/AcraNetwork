# -------------------------------------------------------------------------------
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
# -------------------------------------------------------------------------------

import socket
import struct


class McastSocket(socket.socket):
    """
    Class to make Multicast UDP handling easier.

    >>> recv_socket = McastSocket(local_port=5555, reuse=1)
    >>> recv_socket.mcast_add("235.0.0.1")
    >>> recv_socket.settimeout(0.5)
    >>> recv_socket.sendto(bytes(3), ("235.0.0.2", 8010))
    3

    """

    def __init__(self, local_port=0, reuse=False):
        socket.socket.__init__(self, socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        if reuse:
            self.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        self.bind(("", local_port))

    def mcast_add(self, addr, iface=socket.INADDR_ANY):
        """
        Add a multicast address to an interface

        :param addr: The multicast address to subscribe to
        :type addr: str
        :param iface: IP address of network interface on which to use this multicast address. Generally not required.
        :type iface: str
        """

        mreq = struct.pack("=4sl", socket.inet_aton(addr), socket.INADDR_ANY)
        self.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
