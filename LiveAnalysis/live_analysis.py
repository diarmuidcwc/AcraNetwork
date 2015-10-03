__author__ = 'diarmuid'

import sys
sys.path.append("../")

import AcraNetwork.iNetX as inetx
import socket
import struct
from matplotlib import pyplot as plt
from matplotlib import animation


# some configuration
MULTICAST_PORT = 8010
MULTICAST_IP = "235.0.0.1"
PARAMETERS_PER_PACKET = 64

# the udp socket
udp_socket = socket.socket(socket.AF_INET,socket.SOCK_DGRAM,socket.IPPROTO_UDP)
udp_socket.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP,socket.inet_aton(MULTICAST_IP) + socket.inet_aton("192.168.1.153"))
udp_socket.bind(('', MULTICAST_PORT))

# the stack containing the samples
datastack = [0,0,0]
timeaxis = 0.0
# create the plot
fig = plt.figure()
ax = plt.axes(xlim=(0, 2), ylim=(-2, 2))
line, = ax.plot([], [], lw=2)

def init():
    line.set_data([], [])
    return line,

def animate(i):
    global timeaxis
    print datastack[0]

    line.set_data(timeaxis, datastack.pop())
    timeaxis = (timeaxis + 0.125) % 1
    return line,

anim = animation.FuncAnimation(fig, animate, init_func=init,
                               frames=100, interval=1000, blit=False)
plt.show()


while True:
    data, addr = udp_socket.recvfrom(2048)
    packet = inetx.iNetX()
    packet.unpack(data)
    samples = struct.unpack("{}H".format(PARAMETERS_PER_PACKET),packet.payload)
    datastack.extend(samples)