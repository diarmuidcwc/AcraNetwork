import struct
import importlib

STRUCT_ARRAY = {
#     'Z' : 1,
#     'V' : 2,
#     'N' : 4,
    'B' : 8,
    'H' : 16,
    'I' : 32,
    'Q' : 64,
    }

class BasePacket(object):
    '''
    Class to build and unpack a Base packet
    '''
    
    CALC_HEADER = None
    BASETYPE_MAPPING = None
    TRAILER_LENGTH = 0
    TYPE   = []
    HEADER = []
    PAYLOAD_REQUIRED = True
   
    def isPacket(self, packettype):
        for p in self.packetpath:
            if p.upper().startswith(packettype.upper()):
                return True
        return False
    
    def calcHeaderFormat(self, header=None):
        if not None == header:
            self.HEADER = header
        
        s = []
        for i in self.HEADER:
            # This is required for non-power of 2 chunks
            # of data, e.g. MAC address = 6 bytes
            for j in i['w']:
                s.append(j)
        self.HEADER_FORMAT = ">" + "".join(s)
        self.HEADER_SIZE = struct.calcsize(self.HEADER_FORMAT)
        if not None == self.CALC_HEADER:
            if not self.CALC_HEADER == self.HEADER_FORMAT:
                raise ValueError("Incorrect format generated {}".format(HEADER_FORMAT))
    
    def __init__(self, buf=None, debug=False, parent=None):
           
        self.offset = 0
        self.basetype = None
        self.debug = debug
        self.regress = True
        self.packettype = str(type(self)).split('.')[-2]
        self.packetpath = [self.packettype]
        self.calcHeaderFormat()
        self._packetStrut = struct.Struct(self.HEADER_FORMAT)

        if None == parent:
            self.parent = None
        else:
            self.parent = parent
            self.parent.packetpath.extend(self.packetpath)

        for i in self.HEADER:
            if not hasattr(self, i['n']):
                # If a default value is present populate
                # it other wise set to 0.
                if 'd' in i.keys():
                    r = i['d']
                else:
                    r = 0
#                 if 'c' in i.keys():
#                     setattr(i['c'], 'int', r)
#                     r = i['c']
                setattr(self, i['n'], r)
            else:
                raise ValueError("Attribute {} already exists!".format(i['n']))

        if not hasattr(self, 'payload'):
            self.payload = None
        if buf != None:
            self.unpack(buf)
           
    def unpack(self, buf=None, header=None):
        '''Unpack a buffer into a object'''
        self.calcHeaderFormat(header)
        self._packetStrut = struct.Struct(self.HEADER_FORMAT)
        if len(buf[self.offset:]) < self.HEADER_SIZE:
            raise ValueError("Buffer too short to fill remaining packet")
        
        fields = struct.unpack_from(self.HEADER_FORMAT, buf[self.offset:])
        #print(fields)
        j = 0
        for i in self.HEADER:
            if not isinstance(i['w'], list):
                r = fields[j]
                j += 1
            else:
                # Here is where we reconstruct the non power of
                # 2 chunks of data
                r = 0
                for k in i['w']:
                    if k.upper() in STRUCT_ARRAY:
                        s = STRUCT_ARRAY[k.upper()]
                    else:
                        raise ValueError("Unknown field, {:s}".format(k))
                    r = (r << s) + fields[j]
                    j += 1
            
            if 'c' in i.keys():
                i['c'].set(r)
                r = i['c']
            
            setattr(self, i['n'], r)
        
        if not None == self.BASETYPE_MAPPING:
            self.basetype = getattr(self, self.BASETYPE_MAPPING)
        
        if self.debug:
            for i in self.HEADER:
                print('b', i['n'], getattr(self, i['n']))
        self.offset += self.HEADER_SIZE
        self.payload = buf[self.HEADER_SIZE:]
        
        if None == header:
            self.unpack_local(buf)
    
    def unpack_local(self, buf=None):
        if self.regress:
            self.assign_packet()

    def assign_packet(self):
        if 0 == len(self.TYPE):
            return
        if self.basetype in self.TYPE:
            e = self.TYPE[self.basetype]
            if not None == e['from'] and not None == e['import']:
                i = importlib.import_module(e['from'])
                p = e['from'].split('.')[-1]
                m = getattr(i, e['import'])(self.payload, parent=self)
                setattr(self, p, m)
            else:
                a = ''
                if not None == e['import']:
                    a = '{:s}, '.format(e['import'])
                print("{:s}Unsupported Type, 0x{:04x}, skipping".format(a, self.basetype))
        else:
            raise ValueError("Unsupported Type, 0x{0:04x}".format(self.basetype))

    def pack(self, extra=None):
        '''Pack the payload into a binary format
        :rtype: str
        '''
        packetvalues = []
        for i in self.HEADER:
            try:
                x = getattr(self, i['n'])
                #  If attribute has been cast back to a string
                #  When it should be a class, we fetch the class and 
                #  update the string value
                if 'c' in i.keys():
                    if not isinstance(x, type(i['c'])):
                        i['c'].set(x)
                        x = i['c']
                    
                if hasattr(x, 'int'):
                   r = x.int
                else:
                   r = x
                if None == r:
                    raise ValueError("Unpopulated values")
            except:
                raise ValueError("A required field, {:s}, in the packet is not defined".format(i['n']))
            
            if not isinstance(i['w'], list):
               packetvalues.append(r)
            else:
                # Here is where we reconstruct the non power of
                # 2 chunks of data
                a = []
                for k in reversed(i['w']):
                    if k.upper() in STRUCT_ARRAY:
                        s = STRUCT_ARRAY[k.upper()]
                    else:
                        raise ValueError("Unknown field, {:s}".format(k))
                    o = r & ((2**s)-1)
                    r >>= s
                    a.append(o)
                packetvalues.extend(a[::-1])

        # Construct payload here, sometimes there will
        # be no payload required
        payload = bytearray()
        if self.PAYLOAD_REQUIRED:
            if None == self.payload:
                raise ValueError("Unpopulated payload")
            payload = self.payload
        
        if not None == extra:
            payload = payload + extra
        
        packet = self._packetStrut.pack(*packetvalues) + payload
        return packet
