#-------------------------------------------------------------------------------
# Name:        iNetXStream
# Purpose:
#
# Author:      DCollins
#
# Created:     19/12/2013
# Copyright:   (c) DCollins 2013
# Licence:     <your licence>
#-------------------------------------------------------------------------------



#******************************************************
#
# DO NOT USE THIS CLASS. I WILL REMOVE IT BUT NOT AT THE MOMENT
#
#*****************************************************





import inetx

def getaccuratetiming():
    if sys.platform.startswith('linux'):
        return time.time()
    else:
        return time.clock()


# Install the following:

#pypcap : http://code.google.com/p/pypcap/issues/detail?id=11#c10
#dpkt : http://code.google.com/p/dpkt/downloads/list
#numpy: http://sourceforge.net/projects/numpy/files/NumPy/1.6.1/

# If you want to capture from the network
#Zope: Download the egg file http://pypi.python.org/pypi/zope.interface/3.8.0#downloads and then install it using easy_install
#      eg: python ./site-packages/easy_install.py zope.interface-3.8.0-py2.7-win32.egg
#Twisted: http://twistedmatrix.com/trac/wiki/Downloads

class iNetXStream(socket.socket):
    '''Class describing a stream if iNetX packets. When you init this it creates a load of defaults
    You can then modify it to your hearts content'''
    def __init__(self,length=10,payloadsize=1000,parserblocks=0,proto="UDP"):

        self.protocol = proto
        if self.protocol =="UDP":
            self._sock = socket.socket(
                socket.AF_INET,
                socket.SOCK_DGRAM,
                socket.IPPROTO_UDP)

        else:
            self._sock = socket.socket(
                socket.AF_INET,
                socket.SOCK_STREAM)

        self.length = length # the length of the stream in packets
        self.parserblocks = parserblocks # The number of parser blocks
        self.payloadsize = payloadsize # if we set the parserblocks to zero then random data is generated
        self.packets = [] # list of packets
        self.mbitrate=0
        self._delayloop=5000
        self._delayloopres=0


        # The udp/ip info
        self.dstip = "192.168.28.1"
        self.dstport = 8181
        self.srcport = 1616
        self.hostip = "192.168.28.100"

        # validation stuff
        self.missedseqences = defaultdict(list)
        self.missedcount = 0
        self.missedtimes = []
        self.missedpacket = defaultdict(list)
        self.streamsize = 0
        self.packetschecked = 0
        self.firsttimestamp = sys.float_info.max
        self.lasttimestamp = 0.0

        self._loadmbitdly()





    def buildstream(self):
        '''This builds a stream of xnet packets. It's done in memory and then dumped down the
        ethernet socket'''
        # Open the socket then fire down the packets in chunks

        for i in range(self.length):

            packet = iNetX() # create a iNetX packet
            packet.sequence = i

            # fill the payload
            if self.parserblocks > 0:
                # we want to create a parser aligned payload
                packet.parserPayload(self.parserblocks,quadbytes=3,count=i*self.parserblocks)
            else:
                packet.randomPayload(self.payloadsize)

            # build it
            packet.buildpacket()
            self.packets.append(packet)



    def sendstream(self):
        '''Generates a stream of iNetX packets'''
        # Open the socket then fire down the packets in chunks

        self.buildstream()

        self._sock.bind((self.hostip,self.srcport))
#        prev_time = time.clock()
#        if self.mbitrate > 70:
#            sleeptime = 0
#        elif self.mbitrate > 40:
#            sleeptime = 0.0002
#        else:
#            sleeptime = 0.0004

        i=0
        for packet in self.packets:
            # adjust the bandwidth if we defined the mbitrate
#            if ( i%30 == 29 and self.mbitrate > 0):
#                now_time = time.clock()
#                delta = now_time-prev_time
#                mbitrate = int(packet.bytes * 8 * 29/(1000000*delta)) # we have had 100 packets
#                if (mbitrate > self.mbitrate):
#                    sleeptime += 0.0002
#                else:
#                    sleeptime = 0
#                prev_time = time.clock()
#            i += 1
#            if sleeptime > 0:
#                time.sleep(sleeptime)


            self._sock.sendto(packet.packet,(self.dstip,self.dstport))


    def buildandsend(self,pkttype="inetx",bench=False):
        '''This combines the other two methods. It generates the packets at the same time
        as it dumps it onto the interface. This ensures that you can generate a constants stream
        of data. I get about 65Mbit/s at a max rate'''
        self._sock.bind((self.hostip,self.srcport))
        start_time_of_100_packets = time.clock()
        current_time = time.time()
        ptpsec  = int(current_time)
        ptpnsec = int(math.modf(current_time)[0] * 1e9)
        mbitrate = 0


        loopdelay = 1000
        if mbitrate < 1:
            loopdelay = self.mbitrate
        elif mbitrate < 10:
            loopdelay = 10*self.mbitrate
        elif mbitrate < 100:
            loopdelay = 100

        for i in range(self.length):

            if pkttype == "inetx":
                packet = iNetX()
                packet.streamid = self.mbitrate
                packet.sequence = i % pow(2,32)
                packet.ptptimeseconds = ptpsec
                packet.ptptimenanoseconds = ptpnsec
            else:
                packet = IENA()
                packet.sequence = i % pow(2,16)


            # fill the payload
            if self.parserblocks > 0:
                # we want to create a parser aligned payload
                packet.parserPayload(self.parserblocks,quadbytes=3,count=i*self.parserblocks)
            else:
                packet.randomPayload(self.payloadsize)

            # build it
            packet.pack()
            self.streamsize += packet.bytes
            for j in range(self._delayloop):
                self._delayloopres += math.sqrt(j+self._delayloopres)
            self._delayloopres = 0
            if self.protocol == "UDP":
                self._sock.sendto(packet.packet,(self.dstip,self.dstport))
            else:
                self._sock.connect((self.dstip,self.dstport))
                self._sock.sendall(packet.packet)


            if bench == False:
                prev_mbitrate =  0
                # keep an eye on the data rate
                if i % loopdelay == (loopdelay-1):
                    end_time_of_100_packets = getaccuratetiming()
                    time_since_start_of_100_packets = end_time_of_100_packets - start_time_of_100_packets
                    bytes_sent = packet.bytes * (loopdelay-1)
                    prev_mbitrate = mbitrate
                    mbitrate =  int((8*bytes_sent)/(time_since_start_of_100_packets*1000*1000))

                    # Trying to figure out a wway to get to the target rate fast
                    if mbitrate < 5 :
                        scaling = 100
                    elif mbitrate < 10:
                        scaling = 50
                    elif mbitrate < 30:
                        scaling = 1
                    else:
                        scaling = 1

                    if abs(mbitrate - self.mbitrate ) < 5:
                        dlyloop_change = 1*scaling
                    elif abs(mbitrate - self.mbitrate) < 10:
                        dlyloop_change = 5*scaling
                    elif abs(mbitrate - self.mbitrate) < 15:
                        dlyloop_change = 10*scaling
                    else:
                        dlyloop_change = 20*scaling
                    if dlyloop_change > 5000:
                        dlyloop_change = 5000

                    if mbitrate > self.mbitrate:
                        self._delayloop = self._delayloop + dlyloop_change;
                    elif mbitrate < self.mbitrate:
                        self._delayloop = self._delayloop - dlyloop_change;
                    start_time_of_100_packets = getaccuratetiming()
                    # update the ptptimestamp
                    current_time = time.time()
                    ptpsec  = int(current_time)
                    ptpnsec = int(math.modf(current_time)[0] * 1e9)

                if i % (loopdelay*10) == loopdelay*10-1:
                    print ("INFO Current bit rate = {} Mbit/s. Delay loop = {} Data sent = {} MB Delay loop change = {} ".format(mbitrate,self._delayloop,self.streamsize/1000000,dlyloop_change))

    def sendudp(self,bench=False):
        '''This proc just sends a stream of upd packets. Need to move this out of this class as it's not a inetx stream'''
        self._sock.bind(('',self.srcport))
        start_time_of_100_packets = time.clock()
        for i in range(self.length):

            #payload = ''.join(['\x05' for num in xrange(self.payloadsize)])
            payload = '\x05' * self.payloadsize
            payloadsize = self.payloadsize + 32
            self.streamsize += payloadsize
            for j in range(self._delayloop):
                self._delayloopres += math.sqrt(j+self._delayloopres)
            self._delayloopres = 0
            self._sock.sendto(payload,(self.dstip,self.dstport))

            if bench == False:
                # keep an eye on the data rate
                if i % 1000 == 999:
                    end_time_of_100_packets = time.clock()
                    time_since_start_of_100_packets = end_time_of_100_packets - start_time_of_100_packets
                    bytes_sent = payloadsize * 999
                    mbitrate =  int((8*bytes_sent)/(time_since_start_of_100_packets*1000*1000))
                    if mbitrate > self.mbitrate:
                        self._delayloop = self._delayloop + 1;
                    elif mbitrate < self.mbitrate and self._delayloop > 2:
                        self._delayloop = self._delayloop - 1;
                    start_time_of_100_packets = time.clock()

                    if i % 10000 == 9999:
                        print ("INFO Current bit rate = {} Mbit/s. Delay loop = {} Data sent = {} MB".format(mbitrate,self._delayloop,self.streamsize/1000000))


    def pcapstreamread(self,filename,dport=0,pkttype="inetx",dietpacket=True):
        '''This method will read a pcap file (argument). It will pick out the UDP packets and will
        validate all teh sequence numbers. It will also pull out the dropped packet event packets'''
        try:
            open(filename)
        except IOError:
            print 'Cannot read pcap file '

        pcapfile = pcap.pcap(filename)
        count = 0
        for ts, pkt in pcapfile:
            self.streamsize += len(pkt)
            count += 1
            # Is it an Ethernet packet?
            try:
                packet = dpkt.ethernet.Ethernet(pkt)

            except:
                continue
            # An IP packet. If not bail
            try:
                if packet.type == dpkt.ethernet.ETH_TYPE_IP:
                    # The data is an IP packet
                    ip = packet.data
                else:
                    continue
            except:
                continue

            # A UDP
            try:
                if ip.p == dpkt.ip.IP_PROTO_UDP:
                    # We have the udp packet!
                    udp = ip.data
                    srcip = socket.inet_ntoa(ip.src)
                    dstip = socket.inet_ntoa(ip.dst)
                else:
                    continue
            except:
                continue

            #print("Dst port =  {}".format(udp.dport))
            if pkttype == "inetx":
                pkt = iNetX()
            else:
                pkt = IENA()

            try:
                if (dport > 0 and udp.dport == dport) or (dport == 0):
                    pkt.packet = udp.data
                    pkt.unpack()
                    pkt.timestamp = ts
                    pkt.packetnumber = count
                    if dietpacket == True:
                        pkt.dietpkt()
                    pkt.srcip = srcip
                    pkt.dstip = dstip
                    pkt.dstport = udp.dport
                    self.packets.append(pkt)
            except:
                continue#
#
        self.length = len(self.packets)


    def extractcvsd(self,cvsdfile,srcip,ports=list()):
        for packet in self.packets:
            if packet.srcip != srcip:
                continue
            if len(ports) > 0:
                if not packet.dstport in ports:
                    continue

            packet.unpackpayload()
            cvsdf = open(cvsdfile,'ab')
            cvsdf.write(packet.payload)
            cvsdf.close()

    def validatestream(self,srcip,ports=list(),reporttime=0):
        '''Method to valudate the sequence numbers in a stream. It will record all missing sequence numbers
        for each stream and the first and last timestamp for the stream'''
        previous_sequence = dict()
        previous_gpslock = 2
        pktcount = 0
        previouspackettime = 0
        for packet in self.packets:
            pktcount = pktcount + 1
            if packet.srcip != srcip:
                continue
            if len(ports) > 0:
                if not packet.dstport in ports:
                    continue

            self.packetschecked += 1
            if self.firsttimestamp > packet.timestamp:
                self.firsttimestamp = packet.timestamp
            if self.lasttimestamp < packet.timestamp:
                self.lasttimestamp = packet.timestamp

            if packet.dstport == 9194:
                packet.unpackpayload()
                gpspacketstruct = struct.Struct('>HHHHHHHHHHH')
                packet_data = gpspacketstruct.unpack_from(packet.payload)
                gpslockint = int(math.floor(packet_data[10]/(2**15)))
                if gpslockint != previous_gpslock:
                    print "Packet Count = {} GPS Lock = {}".format(pktcount,gpslockint)
                    previous_gpslock = gpslockint


            if packet.dstport  == reporttime:
                packet.unpackpayload()

                pkttime = time.gmtime(packet.ptptimeseconds)
                if packet.ptptimeseconds != previouspackettime:
                    print "Packet PTP Time = {} sequence={} on streamid={} packet count={}".format(time.strftime("%H:%M:%S %d %b %Y",pkttime),packet.sequence,packet.streamid,pktcount)
                    if packet.ptptimeseconds - previouspackettime > 1:
                        print " -- ERROR -- Time jump of over 1 second"

                previouspackettime = packet.ptptimeseconds


            if packet.streamid not in previous_sequence :
                previous_sequence[packet.streamid] = packet.sequence
            elif((previous_sequence[packet.streamid] + 1) != packet.sequence):
                if (previous_sequence[packet.streamid] + 1) == pow(2,packet.sequencewidth) and packet.sequence == 0:
                    previous_sequence[packet.streamid] = packet.sequence
                else:
                    self.missedseqences[packet.streamid].append(previous_sequence[packet.streamid]+1)
                    self.missedcount += 1
                    self.missedtimes.append(packet.timestamp)
                    self.missedpacket[packet.packetnumber]=[previous_sequence[packet.streamid]+1,packet.sequence]
                    previous_sequence[packet.streamid] = packet.sequence
            else:
                previous_sequence[packet.streamid] = packet.sequence

    def streamdatarate(self):
        '''Return the data rate of the stream in Mbit/sec. To match reported values from wireshark'''
        return (self.streamsize * 8) / ((self.lasttimestamp - self.firsttimestamp)*1000*1000) # Mbit/se is 1000 not 1024 based on Wireshark

    def benchmark(self):
        '''Benchmark th computers performance. The data race of packet generation is  computer specific. This method
        will send a number of short streams and record the datarate achieved. Internally a delay loop is used to vary the rate
        and this method will calibrate that delay loop to a polynomial '''
        xlist = list()
        ylist = list()


        for i in range(22):
            # create a few streams and see what the data rates is
            mystream = iNetXStream(length=1000,payloadsize=self.payloadsize,parserblocks=self.parserblocks)
            mystream.dstip = self.dstip
            mystream.dstport = self.dstport
            mystream.srcport = self.srcport
            mystream.mbitrate = self.mbitrate
            mystream._delayloop = i*i*3
            t = timeit.Timer(mystream.buildandsend())
            tottime = t.timeit(1)
            ylist.append(mystream._delayloop) # the delay loop value used
            xlist.append(mystream.streamsize*8/(tottime*1000*1000)) # the data rate achieved
        # fit the data to a poly
        p = numpy.polyfit(xlist, ylist, deg=3)
        # store the coeff in the mbittodly list
        self._storembitdly(p.tolist())
        self._updatedlyloop()

    def _updatedlyloop(self):
        if self.mbitrate > 0:
            self._delayloop = int(self.mbitrate**3*self._mbittodly[0] + self.mbitrate**2*self._mbittodly[1] + self.mbitrate*self._mbittodly[2] + self._mbittodly[3])
        if self._delayloop < 0 :
            self._delayloop = 0

    def _storembitdly(self,mbitlist):
        self._mbittodly = mbitlist
        jsonencodedlist = json.dumps(mbitlist)
        f = open('.mbit.json', 'w')
        f.write(jsonencodedlist)
        f.close

    def _loadmbitdly(self):
        if os.path.exists('.mbit.json'):
            f = open('.mbit.json', 'r')
            self._mbittodly = json.load(f)
            f.close
        else:
            self._mbittodly = list()
