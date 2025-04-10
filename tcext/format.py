from .instruction import Instruction
from .utils import bits


class ABSForm(Instruction):

    @staticmethod
    def decode(data: bytes) -> tuple[int]:
        off18_0_5 = bits(data, 32, 16, 22)
        off18_6_9 = bits(data, 32, 28, 32)
        off18_10_13 = bits(data, 32, 22, 26)
        off18_14_17 = bits(data, 32, 12, 16)
        a = bits(data, 32, 8, 12)
        o = bits(data, 32, 0, 8)
        x = bits(data, 32, 26, 28)
        return o, x, a, ((off18_0_5) | (off18_6_9 << 6) | (off18_10_13 << 10) | (off18_14_17 << 28)) & 0xffffffff


class BForm(Instruction):
    @staticmethod
    def decode(data: bytes):
        opcode = bits(data, 4, 0, 8)
        disp24_16_23 = bits(data, 4, 8, 16)
        disp24_0_15 = bits(data, 4, 16, 32)
        disp24 = disp24_16_23 << 16 | disp24_0_15
        pc_1_21 = bits(disp24, 4, 0, 20)
        pc_28_32 = bits(disp24, 4, 20, 24)
        pc = pc_1_21 << 1 | pc_28_32 << 28
        return opcode, pc


class SRCForm(Instruction):
    @staticmethod
    def decode(data: bytes) -> tuple[int]:
        op = bits(data, 16, 0, 8)
        s1 = bits(data, 16, 8, 12)
        const4 = bits(data, 16, 12, 16)
        return op, s1, const4


class SRRForm(Instruction):
    @staticmethod
    def decode(data: bytes) -> tuple[int]:
        op = bits(data, 16, 0, 8)
        s1 = bits(data, 16, 8, 12)
        s2 = bits(data, 16, 12, 16)
        return op, s1, s2


class SCForm(Instruction):
    @staticmethod
    def decode(data: bytes) -> tuple[int]:
        op = bits(data, 16, 0, 8)
        const8 = bits(data, 16, 8, 16)
        return op, const8
