__author__ = 'diarmuid'

import sys
sys.path.append("../")

import AcraNetwork.iNetX as inetx
import socket
import struct
from matplotlib import pyplot as plt
from matplotlib import animation
import thread
from collections import deque


# some configuration
MULTICAST_PORT = 8010
MULTICAST_IP = "235.0.0.1"
PARAMETERS_PER_PACKET = 64

# the udp socket
udp_socket = socket.socket(socket.AF_INET,socket.SOCK_DGRAM,socket.IPPROTO_UDP)
udp_socket.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP,socket.inet_aton(MULTICAST_IP) + socket.inet_aton("192.168.1.153"))
udp_socket.bind(('', MULTICAST_PORT))

# the stack containing the samples
datastack = deque([0,0,0])
xaxis = deque([0])
yaxis = deque([0])

# create the plot
fig = plt.figure()
ax = plt.axes(xlim=(0, 200), ylim=(0, 100000))
line, = ax.plot([], [], lw=2)

def UDPClient(arg):
    while True:
        data, addr = udp_socket.recvfrom(2048)
        packet = inetx.iNetX()
        packet.unpack(data)
        samples = struct.unpack("{}H".format(PARAMETERS_PER_PACKET),packet.payload)
        datastack.extend(samples)

def init():
    line.set_data([], [])
    return line,

def animate(i):
    global xaxis
    global yaxis
    #for value in datastack:
    #    print value

    newxpoint = xaxis[-1] + 0.125
    xaxis.append(newxpoint)
    if len(xaxis) > 1000:
        xaxis.popleft()

    yaxis.append(datastack.popleft())
    if len(yaxis) > 1000:
        yaxis.popleft()

    line.set_data(xaxis, yaxis)
    return line,

thread.start_new_thread(UDPClient, (0,))

anim = animation.FuncAnimation(fig, animate, init_func=init,
                               frames=100, interval=10, blit=True)
plt.show()


