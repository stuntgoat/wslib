
## RFC 6455
"""
    0                   1                   2                   3
      0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
     +-+-+-+-+-------+-+-------------+-------------------------------+
     |F|R|R|R| opcode|M| Payload len |    Extended payload length    |
     |I|S|S|S|  (4)  |A|     (7)     |             (16/64)           |
     |N|V|V|V|       |S|             |   (if payload len==126/127)   |
     | |1|2|3|       |K|             |                               |
     +-+-+-+-+-------+-+-------------+ - - - - - - - - - - - - - - - +
     |     Extended payload length continued, if payload len == 127  |
     + - - - - - - - - - - - - - - - +-------------------------------+
     |                               |Masking-key, if MASK set to 1  |
     +-------------------------------+-------------------------------+
     | Masking-key (continued)       |          Payload Data         |
     +-------------------------------- - - - - - - - - - - - - - - - +
     :                     Payload Data continued ...                :
     + - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - +
     |                     Payload Data continued ...                |
     +---------------------------------------------------------------+
"""

import binascii
import struct

class Frame(object):

    def __init__(self, _bytes):
        self.bytes = _bytes
        
    def parse_char_byte(self, byte):
        """Accepts a byte; returns a Python struct.Struct 
        object which `unpack`s a Big Endian C char byte."""
        byte_struct = struct.Struct(">B")
        value = byte_struct.unpack(byte)
        return value[0]
    
    def parse_uint_2bytes(self, _bytes):
        """Accepts 2 bytes; returns a Python struct.Struct 
        object which `unpack`s a Big Endian 16 bit Unsigned Short."""
        byte_struct = struct.Struct(">H")
        value = byte_struct.unpack(_bytes)
        return value[0]
    
    def parse_ulonglong_8bytes(self, _bytes):
        """Accepts 8 bytes; returns a Python struct.Struct 
        object which `unpack`s a Big Endian 64 bit Unsigned Long Long."""
        byte_struct = struct.Struct(">q")
        value = byte_struct.unpack(_bytes)
        return value[0]

    def parse_uint_4bytes(self, _bytes):
        """Accepts 4 bytes; returns a Python struct.Struct 
        object which `unpack`s a Big Endian Unsigned Integer."""
        byte_struct = struct.Struct(">I")
        value = byte_struct.unpack(_bytes)
        return value[0]
        

class Frame6455(Frame):
    def __init__(self, _bytes):
        super(Frame6455, self).__init__(_bytes)
        self.fin = None
        self.rsv1 = None
        self.rsv2 = None
        self.rsv3 = None
        self.opcode = None
        self.mask_flag = None
        self.payload_len = None
        self.begin_mask_index = None
        self.payload = ''
        self.translated_payload = ''

    def first_two_bytes(self):
        first = self.parse_char_byte(self.bytes[0:1])
        self.fin = (first >> 7) & 1
        self.rsv1 = (first >> 6) & 1
        self.rsv2 = (first >> 5) & 1
        self.rsv3 = (first >> 4) & 1
        self.opcode = ~(0b1111 << 4) & first
        second = self.parse_char_byte(self.bytes[1:2])
        self.mask_flag = (second >> 7) & 1
        length = ~(1 << 7) & second
        if length < 126:
            self.payload_len = length
            self.begin_mask_index = 2
        elif length == 126:
            self.payload_len = self.parse_uint_2bytes(self.bytes[2:4])
            self.begin_mask_index = 4
        elif length == 127:
            self.payload_len = self.parse_ulonglong_8bytes(self.bytes[2:10])
            self.begin_mask_index = 11

    def get_mask(self):
        if self.mask_flag:
            begin = self.begin_mask_index
            end = begin + 4
            self.mask = [byte for byte in self.bytes[begin:end]]

    def read_payload(self):
        begin = self.begin_mask_index + 4
        end = begin + self.payload_len
        for byte in self.bytes[begin:end]:
            self.payload += byte
        # may simply return the raw bytestring; depending on the protocol negitiated
        # in the handshake, the server may use the bytes as binary or text. For now,
        # treat the data as a string using chr
        print self.payload_len
        print len(self.payload)
        for index in xrange(self.payload_len):
            mask_byte = self.parse_char_byte(self.mask[index % 4])
            payload_byte = self.parse_char_byte(self.payload[index])
            self.translated_payload += chr(mask_byte ^ payload_byte)

    def unpack(self):
        self.first_two_bytes()
        self.get_mask()
        self.read_payload()


    def printsofar(self):
        print self.fin, "fin"
        print self.rsv1
        print self.rsv2
        print self.rsv3
        print self.opcode, "opcode"
        print self.mask_flag, "mask flag"
        print self.payload_len, "payload len"
        print bin(self.payload_len), "payload len binary"
        print self.begin_mask_index, "begin mask index"
        print self.mask, "mask"
        print self.payload, "payload"        
        print self.translated_payload

## RFC 6455                        
"""
*  %x0 denotes a continuation frame

*  %x1 denotes a text frame

*  %x2 denotes a binary frame

*  %x3-7 are reserved for further non-control frames

*  %x8 denotes a connection close

*  %x9 denotes a ping

*  %xA denotes a pong

*  %xB-F are reserved for further control frames
"""



