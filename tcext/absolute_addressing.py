from abc import ABC, abstractmethod

from binaryninja.architecture import ArchitectureHook, InstructionInfo, InstructionTextToken
from binaryninja.enums import InstructionTextTokenType
from binaryninja.lowlevelil import LowLevelILFunction


def bits(_data: bytes, length: int, start: int, end: int) -> int:
    data = _data[:length]
    inst = int.from_bytes(data, 'little')
    return (inst >> start) & ((1 << (end - start)) - 1)


class Pass(ABC):

    @staticmethod
    @abstractmethod
    def get_instruction_text(data: bytes, addr: int) -> tuple[list[InstructionTextToken], int]:
        ...

    @staticmethod
    @abstractmethod
    def get_instruction_low_level_il(data: bytes, addr: int, il: LowLevelILFunction) -> int:
        ...


class LEA(Pass):

    @staticmethod
    def decode(data: bytes) -> tuple[int]:
        off18_0_5 = bits(data, 32, 16, 22)
        off18_6_9 = bits(data, 32, 28, 32)
        off18_10_13 = bits(data, 32, 22, 26)
        off18_14_17 = bits(data, 32, 12, 16)
        a = bits(data, 32, 8, 12)
        return a, ((off18_0_5) | (off18_6_9 << 6) | (off18_10_13 << 10) | (off18_14_17 << 28)) & 0xffffffff

    @staticmethod
    def get_instruction_text(data, addr):
        a, ea = LEA.decode(data)
        return [
            InstructionTextToken(InstructionTextTokenType.InstructionToken, "lea"),
            InstructionTextToken(InstructionTextTokenType.TextToken, "     "),
            InstructionTextToken(InstructionTextTokenType.RegisterToken, f"a{a}"),
            InstructionTextToken(InstructionTextTokenType.OperandSeparatorToken, ", "),
            InstructionTextToken(InstructionTextTokenType.IntegerToken, hex(ea), ea)
        ], 4
    
    @staticmethod
    def get_instruction_low_level_il(data, addr, il: LowLevelILFunction):
        a, ea = LEA.decode(data)
        il.append(il.set_reg(4, f"a{a}", il.const(4, ea)))
        return 4


class AbsoluteAddressingHook(ArchitectureHook):

    table = {
        0xC5: LEA,
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
        if (ps := self.dispatch(data)):
            return ps.get_instruction_text(data, addr)
        else:
            return super().get_instruction_text(data, addr)

    def get_instruction_low_level_il(self, data: bytes, addr: int, il: LowLevelILFunction) -> int:
        if (ps := self.dispatch(data)):
            return ps.get_instruction_low_level_il(data, addr, il)
        else:
            return super().get_instruction_low_level_il(data, addr, il)

