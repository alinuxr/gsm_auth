#! /usr/bin/python3
class _A5(object):
    """A5/1 encryption class"""
    def __init__(self):
        # registers masks
        self.R1MASK = 0x07FFFF
        self.R2MASK = 0x3FFFFF
        self.R3MASK = 0x7FFFFF
        # control bits masks
        self.R1CTRLBIT = 0x000100
        self.R2CTRLBIT = 0x000400
        self.R3CTRLBIT = 0x000400
        # feedback bits masks
        self.R1FEEDBACK = 0x072000
        self.R2FEEDBACK = 0x300000
        self.R3FEEDBACK = 0x700080
        # output bits masks
        self.R1OUT = 0x040000
        self.R2OUT = 0x200000
        self.R3OUT = 0x400000
        # registers themselfs
        self.R1 = 0
        self.R2 = 0
        self.R3 = 0
    def parity(self, x):
        x ^= x >> 16
        x ^= x >> 8
        x ^= x >> 4
        x ^= x >> 2
        x ^= x >> 1
        return x & 1
    def majority(self):
        sum = self.parity(self.R1 & self.R1CTRLBIT) + self.parity(self.R2 & self.R2CTRLBIT) + self.parity(self.R3 & self.R3CTRLBIT)
        if sum >= 2:
            return 1
        else:
            return 0
    def getbit(self):
        return self.parity(self.R1 & self.R1OUT) ^ self.parity(self.R2 & self.R2OUT) ^ self.parity(self.R3 & self.R3OUT)
    def clockone(self, reg, mask, fb):
        tmp = reg & fb
        reg = (reg << 1) & mask
        reg |= self.parity(tmp)
        return reg
    def clock(self):#xor регистров с контрольными битами
        maj = self.majority()
        if self.parity(self.R1 & self.R1CTRLBIT) == maj:
            self.R1 = self.clockone(self.R1, self.R1MASK, self.R1FEEDBACK)
        if self.parity(self.R2 & self.R2CTRLBIT) == maj:
            self.R2 = self.clockone(self.R2, self.R2MASK, self.R2FEEDBACK)
        if self.parity(self.R3 & self.R3CTRLBIT) == maj:
            self.R3 = self.clockone(self.R3, self.R3MASK, self.R3FEEDBACK)
    def clockall(self):
        self.R1 = self.clockone(self.R1, self.R1MASK, self.R1FEEDBACK)
        self.R2 = self.clockone(self.R2, self.R2MASK, self.R2FEEDBACK)
        self.R3 = self.clockone(self.R3, self.R3MASK, self.R3FEEDBACK)
    def keysetup(self, key, frame):#xor регистров с ключами
        for i in range(64):
            self.clockall()
            keybit = (key >> i) & 1
            self.R1 ^= keybit
            self.R2 ^= keybit
            self.R3 ^= keybit
        for i in range(22):
            self.clockall()
            framebit = (frame >> i) & 1
            self.R1 ^= framebit
            self.R2 ^= framebit
            self.R3 ^= framebit
        for i in range(100):
            self.clock()
    def run(self):
        downlink = 0
        uplink = 0
        for i in range(114):
            self.clock()#вызов функции clock
            downlink |= self.getbit() << (113 - i)
        for i in range(114):
            self.clock()
            uplink |= self.getbit() << (113 - i)
        return downlink, uplink
def encrypt(msg, key, direction): #msg-наше сообщение key -ключ direction-выбор типа трафика
    _114mask = (2 << 113) - 1
    a5 = _A5()
    msgbitlen = len(msg) * 8 #находим длину переданного сообщения
    msgint = int.from_bytes(msg, byteorder='big')
    result = 0
    frame_count = msgbitlen // 114 #определяем количество фреймов
    if msgbitlen % 114 != 0:
        frame_count += 1 #если не делится нацело,то добавляем один 
    for i in range(frame_count):
        frame = i
        a5.keysetup(key, frame) #обозначаем регистры,ксорим их
        downlink, uplink = a5.run() #начало алгоритма
        if direction == 0: #выбор- исходящий или входящий трафик нужно шифровать
            xor_key = downlink
        else:
            xor_key = uplink
        result |= ((msgint ^ xor_key) & _114mask) << (114 * i)
        msgint >>= 114

    result &= (2 << (msgbitlen - 1)) - 1
    result = result.to_bytes(len(msg), byteorder='big')
    return result

