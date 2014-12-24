
import time
import struct
import AcraNetwork.IENA as iena
import AcraNetwork.iNetX as inetx
import AcraNetwork.McastSocket as mcast


# simple application that tests building and sending of iena and inetx packets

UDP_IP = "235.0.0.2"
UDP_PORT = 5005

print "UDP target IP:", UDP_IP
print "UDP target port:", UDP_PORT


sock = mcast.McastSocket()
sock.mcast_add(UDP_IP)

# Fixed payload for both
payload = struct.pack(">L",5)


# Create an inetx packet
myinetx = inetx.iNetX()
myinetx.inetxcontrol = inetx.iNetX.DEF_CONTROL_WORD
myinetx.pif = 0
myinetx.streamid = 0xdc
myinetx.sequence = 0
myinetx.payload = payload

# Create an iena packet
myiena = iena.IENA()
myiena.key = 0xdc
myiena.keystatus = 0
myiena.endfield = 0xbeef
myiena.sequence = 0
myiena.payload = payload
myiena.status = 0



while True:

    currenttime = int(time.time())

    myiena.sequence += 1
    myiena.setPacketTime(currenttime)
    sock.sendto(myiena.pack(), (UDP_IP, UDP_PORT))
    print "iena sent"

    myinetx.sequence += 1
    myinetx.setPacketTime(currenttime)
    sock.sendto(myinetx.pack(), (UDP_IP, UDP_PORT+1))
    print "inetx sent"

    time.sleep(1)
