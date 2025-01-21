from abc import ABC

from binaryninja.architecture import InstructionTextToken
from binaryninja.enums import InstructionTextTokenType
from binaryninja.lowlevelil import LowLevelILFunction, LLIL_TEMP

from .instruction import Instruction


def bits(_data: bytes, length: int, start: int, end: int) -> int:
    data = _data[:length]
    inst = int.from_bytes(data, 'little')
    return (inst >> start) & ((1 << (end - start)) - 1)


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


class LEA(ABSForm):

    @staticmethod
    def get_instruction_text(data, addr):
        o, x, a, ea = LEA.decode(data)
        if o == 0xc5 and x == 0x00:
            return [
                InstructionTextToken(InstructionTextTokenType.InstructionToken, "lea"),
                InstructionTextToken(InstructionTextTokenType.TextToken, "     "),
                InstructionTextToken(InstructionTextTokenType.RegisterToken, f"a{a}"),
                InstructionTextToken(InstructionTextTokenType.OperandSeparatorToken, ", "),
                InstructionTextToken(InstructionTextTokenType.IntegerToken, hex(ea), ea)
            ], 4
    
    @staticmethod
    def get_instruction_low_level_il(data, addr, il: LowLevelILFunction):
        o, x, a, ea = LEA.decode(data)
        if o == 0xc5 and x == 0x00:
            il.append(il.set_reg(il.arch.address_size, f"a{a}", il.const(il.arch.address_size, ea)))
            return 4


class LD(ABSForm):

    @staticmethod
    def decode(data):

        o, x, a, ea = ABSForm.decode(data)
        b = a >> 1 << 1

        mnemonic = "ld."
        register = None
        length = None
        signed = False
        upper = False

        if o == 0x05:
            register = (f"d{a}", )
            signed = not bool(x & 1)
            length = 1 if x < 2 else 2
            mnemonic += "b" if length == 1 else "h"
            mnemonic += "" if signed else "u"
        elif o == 0x45:
            register = (f"d{a}", )
            length = 2
            upper = True
            mnemonic += "q"
        elif o == 0x85:
            if x == 0:
                register = (f"d{a}", )
                length = 4
                mnemonic += "w"
            elif x == 1:
                register = (f"d{b}", f"d{b+1}")
                length = 8
                mnemonic += "e"
            elif x == 2:
                register = (f"a{a}", )
                length = 4
                mnemonic += "a"
            elif x == 3:
                register = (f"a{b}", f"a{b+1}")
                length = 8
                mnemonic += "p"

        return mnemonic, register, length, signed, upper, ea
    
    @staticmethod
    def get_instruction_text(data, addr):

        mnemonic, register, length, signed, upper, ea = LD.decode(data)
        if None in (mnemonic, register, length):
            return None

        return [
            InstructionTextToken(InstructionTextTokenType.InstructionToken, mnemonic),
            InstructionTextToken(InstructionTextTokenType.TextToken, " " * (8 - len(mnemonic))),
            InstructionTextToken(InstructionTextTokenType.RegisterToken, "".join(register)),
            InstructionTextToken(InstructionTextTokenType.OperandSeparatorToken, ", "),
            InstructionTextToken(InstructionTextTokenType.IntegerToken, hex(ea), ea)
        ], 4
    
    @staticmethod
    def get_instruction_low_level_il(data, addr, il):

        mnemonic, register, length, signed, upper, ea = LD.decode(data)
        if None in (mnemonic, register, length):
            return None

        right = il.const_pointer(il.arch.address_size, ea)

        if upper == 1:
            right = il.load(2, right) # l = 2
            right = il.shift_left(4, right, 0x10)
            right = il.and_expr(4, right, il.const(4, 0xffff0000))
            il.append(il.set_reg(4, register[0], right))
            return 4

        elif length in (1, 2, 4):
            right = il.load(length, right)
            if length <= 2:
                if signed:
                    right = il.sign_extend(il.arch.address_size, right)
                else:
                    right = il.zero_extend(il.arch.address_size, right)
            il.append(il.set_reg(4, register[0], right))
            return 4

        elif length == 8:
            right = il.load(8, right)
            il.append(il.set_reg_split(4, register[1], register[0], right))
            return 4


class ST(ABSForm):

    @staticmethod
    def decode(data: bytes):

        o, x, a, ea = ABSForm.decode(data)
        b = a >> 1 << 1

        mnemonic = None
        register = None
        length = None
        upper = False

        if o == 0x25:
            if x == 0:
                mnemonic = "st.b"
                register = (f"d{a}", )
                length = 1
            elif x == 2:
                mnemonic = "st.h"
                register = (f"d{a}", )
                length = 2
        elif o == 0x65:
            if x == 0:
                mnemonic = "st.q"
                register = (f"d{a}", )
                length = 2
                upper = True
        elif o == 0xa5:
            if x == 0:
                mnemonic = "st.w"
                register = (f"d{a}", )
                length = 4
            elif x == 1:
                mnemonic = "st.d"
                register = (f"d{b}", f"d{b+1}")
                length = 8
            elif x == 2:
                mnemonic = "st.a"
                register = (f"a{a}", )
                length = 4
            elif x == 3:
                mnemonic = "st.da"
                register = (f"a{b}", f"a{b+1}")
                length = 8

        return mnemonic, register, length, upper, ea

    @staticmethod
    def get_instruction_text(data, addr):

        mnemonic, register, length, upper, ea = ST.decode(data)
        if None in (mnemonic, register, length):
            return None
        
        return [
            InstructionTextToken(InstructionTextTokenType.InstructionToken, mnemonic),
            InstructionTextToken(InstructionTextTokenType.TextToken, " " * (8 - len(mnemonic))),
            InstructionTextToken(InstructionTextTokenType.RegisterToken, "".join(register)),
            InstructionTextToken(InstructionTextTokenType.OperandSeparatorToken, ", "),
            InstructionTextToken(InstructionTextTokenType.IntegerToken, hex(ea), ea),
        ], 4
    
    @staticmethod
    def get_instruction_low_level_il(data, addr, il):

        mnemonic, register, length, upper, ea = ST.decode(data)
        if None in (mnemonic, register, length):
            return None
        
        if upper:
            right = il.logical_shift_right(4, il.reg(4, register[0]), 0x10)
            il.append(il.store(2, il.const_pointer(4, ea), right))
        elif len(register) == 1:
            il.append(il.store(length, il.const_pointer(4, ea), il.reg(length, register[0])))
        elif len(register) == 2:
            il.append(il.store(4, il.const_pointer(4, ea+0), il.reg(4, register[1])))
            il.append(il.store(4, il.const_pointer(4, ea+4), il.reg(4, register[0])))
        else:
            raise ValueError
        
        return 4


class SWAP(ABSForm):

    @staticmethod
    def get_instruction_text(data, addr):
        o, x, a, ea = SWAP.decode(data)
        if o == 0xE5 and x == 0x00:
            return [
                InstructionTextToken(InstructionTextTokenType.InstructionToken, "swap.w"),
                InstructionTextToken(InstructionTextTokenType.TextToken, "  "),
                InstructionTextToken(InstructionTextTokenType.RegisterToken, f"r{a}"),
                InstructionTextToken(InstructionTextTokenType.OperandSeparatorToken, ", "),
                InstructionTextToken(InstructionTextTokenType.IntegerToken, hex(ea), ea)
            ], 4

    @staticmethod
    def get_instruction_low_level_il(data, addr, il):
        o, x, a, ea = SWAP.decode(data)
        if o == 0xE5 and x == 0x00:
            right = il.const_pointer(4, ea)
            right = il.load(4, right)
            il.append(il.set_reg(4, LLIL_TEMP(0), right))
            il.append(il.store(4, il.const_pointer(4, ea), il.reg(4, a)))
            il.append(il.set_reg(4, il.reg(4, a), il.reg(4, LLIL_TEMP(0))))
            return 4


class STLDCX(ABSForm):
    pass