from abc import ABC

from binaryninja.architecture import ArchitectureHook, InstructionInfo, InstructionTextToken
from binaryninja.enums import InstructionTextTokenType
from binaryninja.lowlevelil import LowLevelILFunction
from binaryninja.log import log_warn


def bits(_data: bytes, length: int, start: int, end: int) -> int:
    data = _data[:length]
    inst = int.from_bytes(data, 'little')
    return (inst >> start) & ((1 << (end - start)) - 1)


class Pass(ABC):

    @staticmethod
    def get_instruction_info(data: bytes, addr: int) -> tuple[list[InstructionTextToken], int]:
        pass

    @staticmethod
    def get_instruction_text(data: bytes, addr: int) -> tuple[list[InstructionTextToken], int]:
        pass

    @staticmethod
    def get_instruction_low_level_il(data: bytes, addr: int, il: LowLevelILFunction) -> int:
        pass


class ABSFormPass(Pass):

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


class LEA(ABSFormPass):

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
            il.append(
                il.set_reg(
                    il.arch.address_size,
                    f"a{a}",
                    il.const(il.arch.address_size, ea)
                )
            )
            return 4


class LD(ABSFormPass):

    @staticmethod
    def decode(data):

        o, x, a, ea = ABSFormPass.decode(data)

        if o == 0x05:
            r = 'd'
            u = x & 1
            l = 1 if x < 2 else 2
            q = 0
        elif o == 0x45:
            r = 'd'
            u = 0
            l = 2
            q = 1
        elif o == 0x85:
            u = 0
            l = 8 if x & 1 else 4
            q = 0
            if x == 0:
                r = 'd'
            elif x == 1:
                r = 'e'
            elif x == 2:
                r = 'a'
            elif x == 3:
                r = 'p'
        else:
            raise ValueError(f"Unknown opcode {o} with x-bit {x}")

        return o, x, a, ea, r, u, l, q
    
    @staticmethod
    def get_instruction_text(data, addr):

        try:
            _, _, a, ea, r, u, l, q = LD.decode(data)
        except ValueError as exc:
            log_warn(f"Detected LD instruction but failed to decode: 0x{addr:x}")
            return None

        if a < 0 or a >= 16:
            log_warn(f"Detected LD instruction but invalid register selection: 0x{addr:x}, {a}")
            return None

        mnemonic = "ld"
        if l == 1:
            mnemonic += ".b" if u == 0 else ".bu"
        elif l == 2:
            if q == 0:
                mnemonic += ".h" if u == 0 else ".hu"
            else:
                mnemonic += ".q"
        elif l == 4:
            mnemonic += ".w" if r == 'd' else ".a"
        elif l == 8:
            mnemonic += ".e" if r == 'e' else ".dap"
        else:
            return None

        if r == 'd':
            reg = f"d{a}"
        elif r == 'a':
            reg = f"a{a}"
        elif r == 'e':
            b = a >> 1 << 1
            reg = f"d{b}d{b+1}"
        elif r == 'p':
            reg = f"a{b}a{a+1}"
        else:
            return None

        return [
            InstructionTextToken(InstructionTextTokenType.InstructionToken, mnemonic),
            InstructionTextToken(InstructionTextTokenType.TextToken, " " * (8 - len(mnemonic))),
            InstructionTextToken(InstructionTextTokenType.RegisterToken, reg),
            InstructionTextToken(InstructionTextTokenType.OperandSeparatorToken, ", "),
            InstructionTextToken(InstructionTextTokenType.IntegerToken, hex(ea), ea)
        ], 4
    
    @staticmethod
    def get_instruction_low_level_il(data, addr, il):

        try:
            _, _, a, ea, r, u, l, q = LD.decode(data)
        except ValueError as exc:
            log_warn(f"Detected LD instruction but failed to decode: 0x{addr:x}")
            return None
        
        if a < 0 or a >= 16:
            log_warn(f"Detected LD instruction but invalid register selection: 0x{addr:x}, {a}")
            return None

        if r == 'd':
            left = f"d{a}"
        elif r == 'a':
            left = f"a{a}"
        elif r == 'e':
            b = a >> 1 << 1
            left = f"d{b}d{b+1}"
        elif r == 'p':
            left = f"a{b}a{a+1}"
        else:
            return None

        right = il.const_pointer(il.arch.address_size, ea)
        if q == 1:
            right = il.load(2, right) # l = 2
            right = il.shift_left(4, right, 0x10)
            right = il.and_expr(4, right, il.const(4, 0xffff0000))
            il.append(il.set_reg(4, left, right))
            return 4
        elif l in (1, 2, 4):
            right = il.load(l, right)
            if l <= 2:
                if u == 0:
                    right = il.sign_extend(il.arch.address_size, right)
                else:
                    right = il.zero_extend(il.arch.address_size, right)
            il.append(il.set_reg(4, left, right))
            return 4
        elif l == 8:
            b = a >> 1 << 1
            n = "d" if r == 'e' else "a"
            right = il.load(8, right)
            il.append(il.set_reg_split(4, f"{n}{b+1}", f"{n}{b}", right))
            return 4
        else:
            return None


class ST(ABSFormPass):
    pass


class STLDCX(ABSFormPass):
    pass


class SWAP(ABSFormPass):
    pass


class AbsoluteAddressingHook(ArchitectureHook):

    table = {
        0x05: LD, #(LD_BD, LD_BUD, LD_HD, LD_HUD),
        0x15: STLDCX, #(STLCX, STUCX, LDLCX, LDUCX),
        0x25: ST, #(ST_B, None, ST_H, None),
        0x45: LD, #(LD_QD, None, None, None),
        0x65: ST, #(ST_Q, None, None, None),
        0x85: LD, #(LD_WD, LD_DE, LD_A, LD_DAP),
        0xA5: ST, #(ST_W, ST_D, ST_A, ST_DA),
        0xC5: LEA,
        0xE5: SWAP, #(SWAP_W, LDMST, None, None),
    }

    def dispatch(self, data: bytes) -> Pass | None:
        inst = int.from_bytes(data, 'little')
        special_opcode = inst & 0b111111
        if special_opcode not in [0x10, 0x6F]:
            opcode = inst & 0b11111111
            if opcode in self.table:
                return self.table[opcode]

    def get_instruction_info(self, data: bytes, addr: int) -> InstructionInfo | None:
        return super().get_instruction_info(data, addr)

    def get_instruction_text(self, data: bytes, addr: int) -> tuple[list[InstructionTextToken], int] | None:
        passed = None
        original = super().get_instruction_text(data, addr)
        if (ps := self.dispatch(data)):
            passed = ps.get_instruction_text(data, addr)
            if passed and original:
                if passed[0][0].text != original[0][0].text:
                    log_warn(f"mnemonic changed during disassembly: 0x{addr:x}, '{original[0][0].text}' != '{passed[0][0].text}'")
                    passed = None
        return passed if passed else original

        # ret = None
        # if (ps := self.dispatch(data)):
        #     ret = ps.get_instruction_text(data, addr)
        # return ret if ret else super().get_instruction_text(data, addr)

    def get_instruction_low_level_il(self, data: bytes, addr: int, il: LowLevelILFunction) -> int:
        ret = None
        if (ps := self.dispatch(data)):
            ret = ps.get_instruction_low_level_il(data, addr, il)
        return ret if ret else super().get_instruction_low_level_il(data, addr, il)

