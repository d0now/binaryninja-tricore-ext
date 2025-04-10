from binaryninja.architecture import InstructionInfo, InstructionTextToken
from binaryninja.lowlevelil import LowLevelILFunction, LLIL_TEMP
from binaryninja.enums import InstructionTextTokenType, BranchType

from .instruction import Instruction
from .format import BForm


def bits(_data: int | bytes, length: int, start: int, end: int) -> int:
    if type(_data) == bytes:
        inst = int.from_bytes(_data[:length], 'little')
    else:
        inst = _data & ((1 << (length * 8)) - 1)
    return (inst >> start) & ((1 << (end - start)) - 1)


class CALLA(BForm):

    @staticmethod
    def get_instruction_info(data: bytes, addr: int) -> InstructionInfo | None:
        opcode, pc = CALLA.decode(data)
        if opcode == 0xED:
            info = InstructionInfo()
            info.length = 4
            info.add_branch(BranchType.CallDestination, pc)
            return info

    @staticmethod
    def get_instruction_text(data: bytes, addr: int) -> tuple[list[InstructionTextToken], int] | None:
        opcode, pc = CALLA.decode(data)
        if opcode == 0xED:
            return [
                InstructionTextToken(InstructionTextTokenType.InstructionToken, "calla"),
                InstructionTextToken(InstructionTextTokenType.TextToken, "   "),
                InstructionTextToken(InstructionTextTokenType.IntegerToken, hex(pc), pc)
            ], 4

    @staticmethod
    def get_instruction_low_level_il(data: bytes, addr: int, il: LowLevelILFunction) -> int | None:
        opcode, pc = CALLA.decode(data)
        if opcode == 0xED:
            temp_start = il.temp_reg_count
            ctx = ["a10", "a11", "a12", "a13", "a14", "a15", "d8", "d9", "d10", "d11", "d12", "d13", "d14", "d15"]
            for i, r in enumerate(ctx): il.append(il.set_reg(4, LLIL_TEMP(temp_start + i), il.reg(4, r)))
            il.append(il.call(il.const_pointer(4, pc)))
            for i, r in enumerate(ctx): il.append(il.set_reg(4, r, il.reg(4, LLIL_TEMP(temp_start + i))))
            return 4


class FCALLA(BForm):

    @staticmethod
    def get_instruction_info(data: bytes, addr: int) -> InstructionInfo | None:
        opcode, pc = FCALLA.decode(data)
        if opcode == 0xE1:
            info = InstructionInfo()
            info.length = 4
            info.add_branch(BranchType.CallDestination, pc)
            return info

    @staticmethod
    def get_instruction_text(data: bytes, addr: int) -> tuple[list[InstructionTextToken], int] | None:
        opcode, pc = FCALLA.decode(data)
        if opcode == 0xE1:
            return [
                InstructionTextToken(InstructionTextTokenType.InstructionToken, "fcalla"),
                InstructionTextToken(InstructionTextTokenType.TextToken, "  "),
                InstructionTextToken(InstructionTextTokenType.IntegerToken, hex(pc), pc)
            ], 4

    @staticmethod
    def get_instruction_low_level_il(data: bytes, addr: int, il: LowLevelILFunction) -> int | None:
        opcode, pc = FCALLA.decode(data)
        if opcode == 0xE1:
            il.append(il.call(il.const_pointer(4, pc)))
            return 4


class JA(BForm):

    @staticmethod
    def get_instruction_info(data: bytes, addr: int) -> InstructionInfo | None:
        opcode, pc = JA.decode(data)
        if opcode == 0x9D:
            info = InstructionInfo()
            info.length = 4
            info.add_branch(BranchType.UnconditionalBranch, pc)
            return info

    @staticmethod
    def get_instruction_text(data: bytes, addr: int) -> InstructionInfo | None:
        opcode, pc = JA.decode(data)
        if opcode == 0x9D:
            return [
                InstructionTextToken(InstructionTextTokenType.InstructionToken, "ja"),
                InstructionTextToken(InstructionTextTokenType.TextToken, "      "),
                InstructionTextToken(InstructionTextTokenType.IntegerToken, hex(pc), pc),
            ], 4

    @staticmethod
    def get_instruction_low_level_il(data: bytes, addr: int, il: LowLevelILFunction) -> int:
        opcode, pc = JA.decode(data)
        if opcode == 0x9D:
            il.append(il.jump(il.const_pointer(4, pc)))
            return 4
