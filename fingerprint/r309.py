
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

    CODE_OK = 0x00
    CODE_PACKAGE_ERROR = 0x01
    CODE_WRONG_PASSWORD = 0X13

    __address = None

    __password = None

    __serial = None

    def __init__(self, address = 0xffffffff, password = 0x00000000):

        self.__address = address
        self.__password = password

    def connect(self, port, bps = 57600):

        self.__serial = serial.Serial(port = port, baudrate = bps, write_timeout = 2)

        if not self.__serial.isOpen(): 
            self.__serial.open()

        answer = self.__verifyPassword()
        if (answer['type'] != R309.PACKET_TYPE_ACK) or (answer['payload'][0] != R309.CODE_OK):
            raise Exception("Something was wrong when verifying device password.")

        return True

    def getSecurityLevel(self):

        sys_params = self.__getSysParams()
        return sys_params['security_level']

    def getPacketSize(self):

        sys_params = self.__getSysParams()
        return sys_params['data_size']

    def setBaudrate(self, baudrate):

        self.__setSysParam(SYSPARAM_BAUD_RATE, baudrate)

    def setSecurityLevel(self, level):

        self.__setSysParam(SYSPARAM_SECURITY_LEVEL, level)
        

    def setPacketSize(self, size):

        self.__setSysParam(SYSPARAM_PACKET_SIZE, size)
        
    def getStorageCapacity(self):

        sys_params = self.__getSysParams()
        return sys_params['lib_size']

    def getNextTemplateNumber(self):

        answer = self.__templateNum()
        payload = answer['payload']

        if (answer['type'] != R309.PACKET_TYPE_ACK) or (payload[0] != R309.CODE_OK):
            raise Exception("Something was wrong when getting the valid template number.")

        return (payload[1] << 8) | payload[2]

    def scanFinger(self):

        answer = self.__getImg()
        if (answer['type'] == R309.PACKET_TYPE_ACK):

            code = answer['payload'][0]
            if code == 0:
                return { 'success': True, 'code': code, 'message': "" }
            elif code == 2:
                return { 'success': False, 'code': code, 'message': "Finger was not detected." }
            elif code == 3:
                return { 'success': False, 'code': code, 'message': "Template was not read." }

        raise Exception("Something was wrong when scanning finger.")

    def __getSysParams(self):

        answer = self.__readSysParams()

        if (answer['type'] != R309.PACKET_TYPE_ACK) or (answer['payload'][0] != R309.CODE_OK):
            raise Exception("Something was wrong when reading system parameters.")

        regs = answer['payload'][1:17]
        return { 
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
        answer = self.__receivePacket()

        if (answer['type'] != R309.PACKET_TYPE_ACK) or (payload[0] != R309.CODE_OK):
            raise Exception("Something was wrong when setting system param %i." % param)

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

    def __receivePacket(self, timeout = 1):

        packet = []

        seconds = 0
        while seconds <= timeout:

            waiting = self.__serial.in_waiting
            if waiting > 0:
                for c in self.__serial.read(waiting):
                    packet.append(ord(c))
                timeout = 0

            if len(packet) >= 9:

                if packet[0] != 0xEF or packet[1] != 0x01:
                    raise Exception("Unknown packet header: %02X%02X" % packet[0], packet[1])

                length = (packet[7] << 8) + packet[8]
                if len(packet) >= length + 9:
                    return self.__processPacket(packet, length)

            time.sleep(0.10)
            seconds += 0.10

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

        return { 'type': packet[6], 'payload': packet[9:-2] }

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

