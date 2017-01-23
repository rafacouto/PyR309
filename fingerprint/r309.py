
"""
r039

@author: Rafa Couto <caligari@treboada.net>
"""

import struct
import serial
import time

BAUD_RATE_9600 = 1
BAUD_RATE_19200 = 2
BAUD_RATE_38400 = 4
BAUD_RATE_57600 = 6
BAUD_RATE_76800 = 8
BAUD_RATE_115200 = 12

SECURITY_LEVEL_1 = 1
SECURITY_LEVEL_2 = 2
SECURITY_LEVEL_3 = 3
SECURITY_LEVEL_4 = 4
SECURITY_LEVEL_5 = 5

PACKET_SIZE_32 = 0
PACKET_SIZE_64 = 1
PACKET_SIZE_128 = 2
PACKET_SIZE_256 = 3

class R309(object):

    SYSPARAM_BAUD_RATE = 0x04
    SYSPARAM_SECURITY_LEVEL = 0x05
    SYSPARAM_PACKET_SIZE = 0x06

    PACKET_TYPE_CMD = 0X01
    PACKET_TYPE_DAT = 0X02
    PACKET_TYPE_ACK = 0X07
    PACKET_TYPE_END = 0X08

    COMMAND_VFYPWD = 0x13
    COMMAND_READSYSPARAMS = 0x0F
    COMMAND_SETSYSPARAM = 0x0E
    COMMAND_TEMPLATENUM = 0x1D
    COMMAND_GETIMG = 0x01
    COMMAND_IMG2TZ = 0x02
    COMMAND_SEARCH = 0x04

    CODE_OK = 0x00
    CODE_PACKAGE_ERROR = 0x01
    CODE_NO_FINGER= 0x02
    CODE_INVALID_TEMPLATE = 0x03
    CODE_WRONG_PASSWORD = 0X13
    CODE_IMG_DISORDER = 0x06
    CODE_IMG_SMALL = 0x07
    CODE_IMG_INVALID = 0x15
    CODE_NO_MATCH = 0x09

    __address = None

    __password = None

    __serial = None

    __sys_params = None

    def __init__(self, address = 0xffffffff, password = 0x00000000):

        self.__address = address
        self.__password = password

    def connect(self, port, bps = 57600, timeout = 2):

        self.__serial = serial.Serial(port = port, baudrate = bps, write_timeout = 2)

        if not self.__serial.isOpen(): 
            self.__serial.open()
            
        self.__serial.timeout = timeout

        result = self.__verifyPassword()
        if (result['type'] != R309.PACKET_TYPE_ACK) or (result['code'] != R309.CODE_OK):
            raise Exception("Something was wrong when verifying device password.")

        self.__getSysParams()

        return True

    def getSecurityLevel(self):

        return self.__sys_params['security_level']

    def getPacketSize(self):

        return self.__sys_params['data_size']

    def getStorageCapacity(self):

        return self.__sys_params['lib_size']

    def setBaudrate(self, baudrate):

        self.__setSysParam(SYSPARAM_BAUD_RATE, baudrate)

    def setSecurityLevel(self, level):

        self.__setSysParam(SYSPARAM_SECURITY_LEVEL, level)
        
    def setPacketSize(self, size):

        self.__setSysParam(SYSPARAM_PACKET_SIZE, size)
        
    def getNextTemplateNumber(self):

        result = self.__templateNum()
        if (result['type'] != R309.PACKET_TYPE_ACK) or (result['code'] != R309.CODE_OK):
            raise Exception("Something was wrong when getting the valid template number.")

        payload = result['payload']
        return (payload[1] << 8) | payload[2]

    def scanFinger(self):

        result = self.__getImg()

        if (result['type'] == R309.PACKET_TYPE_ACK):

            code = result['code']
            if  code == R309.CODE_OK:
                return { 'success': True, 'code': code, 'message': "Finger detected." }
            elif code == R309.CODE_NO_FINGER:
                return { 'success': False, 'code': code, 'message': "Finger was not detected." }
            elif code == R309.CODE_INVALID_TEMPLATE:
                return { 'success': False, 'code': code, 'message': "Template was not read." }

        raise Exception("Something was wrong when scanning finger.")

    def identify(self, buffer = 1):

        result = self.__find(buffer)
        if (result['type'] == R309.PACKET_TYPE_ACK):

            code = result['code']
            if  code == R309.CODE_OK:
                # match OK
                result['message'] = "Matched with register #%i" % result['match']
            else:
                # no match or errors
                result['match'] = None
                if code == R309.CODE_NO_MATCH:
                    result['message'] = "No match."
                elif code == R309.CODE_IMG_DISORDER:
                    result['message'] = "Over-disorderly fingerprint image."
                elif code == R309.CODE_IMG_SMALL:
                    result['message'] = "Lackness of character point or over-smallness of fingerprint image."
                elif code == R309.CODE_IMG_INVALID:
                    result['message'] = "Lackness of valid primary image."
                else:
                    raise Exception("Unknown error when identifying template.")

            return result

        raise Exception("Something was wrong when identifying template.")

    def enroll(self):

        pass

    def __getSysParams(self):

        result = self.__readSysParams()

        if (result['type'] != R309.PACKET_TYPE_ACK) or (result['code'] != R309.CODE_OK):
            raise Exception("Something was wrong when reading system parameters.")

        regs = result['payload'][1:17]
        self.__sys_params = { 
            'status': (regs[0] << 8) | regs[1],
            'sys_id': (regs[2] << 8) | regs[3],
            'lib_size': (regs[4] << 8) | regs[5],
            'security_level': (regs[6] << 8) | regs[7],
            'device_addr': (regs[8] << 24) | (regs[9] << 16) | (regs[10] << 8) | regs[11],
            'packet_max_size': (regs[12] << 8) | regs[13],
            'bauds': (regs[14] << 8) | regs[15],
            }

    def __setSysParam(self, param, value):

        data = self.__buildCommand(R309.COMMAND_SETSYSPARAM)
        data += struct.pack(">B", param)
        data += struct.pack(">B", value)

        self.__sendPacket(R309.PACKET_TYPE_CMD, data)
        result = self.__receivePacket()

        if (result['type'] != R309.PACKET_TYPE_ACK) or (result['code'] != R309.CODE_OK):
            raise Exception("Something was wrong when setting system param %i." % param)

        self.__getSysParams()

    def __verifyPassword(self):

        data = self.__buildCommand(R309.COMMAND_VFYPWD)
        self.__sendPacket(R309.PACKET_TYPE_CMD, data)
        return self.__receivePacket()

    def __readSysParams(self):

        data = self.__buildCommand(R309.COMMAND_READSYSPARAMS)
        self.__sendPacket(R309.PACKET_TYPE_CMD, data)
        return self.__receivePacket()

    def __templateNum(self):

        data = self.__buildCommand(R309.COMMAND_TEMPLATENUM)
        self.__sendPacket(R309.PACKET_TYPE_CMD, data)
        return self.__receivePacket()

    def __getImg(self):

        data = self.__buildCommand(R309.COMMAND_GETIMG)
        self.__sendPacket(R309.PACKET_TYPE_CMD, data)
        return self.__receivePacket()

    def __img2tz(self, buffer = 1):

        data = self.__buildCommand(R309.COMMAND_IMG2TZ)
        data += struct.pack(">B", buffer) 
        self.__sendPacket(R309.PACKET_TYPE_CMD, data)
        return self.__receivePacket()

    def __search(self, page_offset, page_count, buffer = 1):

        data = self.__buildCommand(R309.COMMAND_SEARCH)
        data += struct.pack(">B", buffer) 
        data += struct.pack(">I", page_offset) 
        data += struct.pack(">I", page_count) 
        self.__sendPacket(R309.PACKET_TYPE_CMD, data)
        return self.__receivePacket()

    def __find(self, buffer = 1):

        result = self.__img2tz(buffer)
        if (result['type'] == R309.PACKET_TYPE_ACK) and (result['code'] == R309.CODE_OK):

            count = self.__sys_params['lib_size']
            result = self.__search(0, count, buffer)
            if result['type'] == R309.PACKET_TYPE_ACK:

                if result['code'] == R309.CODE_OK:
                    payload = result['payload']
                    result['match'] = (payload[1] << 8) | payload[2]
                    result['score'] = (payload[3] << 8) | payload[4]

        return result

    def __sendPacket(self, type, data):

        packet = ""
        length = len(data) + 2
        sum = type + (length >> 8) + (length & 0xff)

        packet += struct.pack(">H", 0xEF01)
        packet += struct.pack(">I", self.__address)
        packet += struct.pack(">B", type)
        packet += struct.pack(">H", length)

        for b in data:
            packet += b
            sum += ord(b)

        packet += struct.pack(">H", sum & 0xFFFF)

        self.__serial.write(packet)

    def __receivePacket(self):

        packet = []

        while True:

            pending = self.__serial.in_waiting
            if pending == 0:
                # timeout
                break
            else:
                # read pending bytes
                for c in self.__serial.read(pending):
                    packet.append(ord(c))

            if len(packet) >= 9:

                if packet[0] != 0xEF or packet[1] != 0x01:
                    raise Exception("Unknown packet header: %02X%02X" % packet[0], packet[1])

                length = (packet[7] << 8) + packet[8]
                if len(packet) >= length + 9:
                    return self.__processPacket(packet, length)

        raise Exception("Timed out while receiving the packet (%i bytes received)." % len(packet))

    def __processPacket(self, packet, payload_length):

        # test integrity
        expected = packet[-1] + (packet[-2] << 8)
        sum = 0
        for b in xrange(6, 7 + payload_length):
            sum += packet[b]
        sum &= 0xFFFF
        if sum != expected:
            raise Exception("Checksum error (%04X != %04X)." % (sum, expected))

        # common exception
        if packet[9] == 0x01:
            raise exception("Error when receiving the packet.")

        return { 'type': packet[6], 'payload': packet[9:-2], 'code': packet[9] }

    def __buildCommand(self, cmd):

        data = ""
        data += struct.pack(">B", cmd) 
        data += struct.pack(">I", self.__password)

        return data

    def __packetStr(self, packet, separator = ":"):

        bytes = []
        for b in packet:
            bytes.append("%02X" % b)

        return separator.join(bytes)

