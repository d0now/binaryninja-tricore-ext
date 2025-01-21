from binaryninja.architecture import InstructionInfo, InstructionTextToken
from binaryninja.lowlevelil import LowLevelILFunction, LLIL_TEMP
from binaryninja.enums import InstructionTextTokenType, BranchType

from .instruction import Instruction


def bits(_data: int | bytes, length: int, start: int, end: int) -> int:
    if type(_data) == bytes:
        inst = int.from_bytes(_data[:length], 'little')
    else:
        inst = _data & ((1 << (length * 8)) - 1)
    return (inst >> start) & ((1 << (end - start)) - 1)


class CALLA(Instruction):

    @staticmethod
    def decode_calla(data: bytes) -> int:
        opcode = bits(data, 4, 0, 8)
        disp24_16_23 = bits(data, 4, 8, 16)
        disp24_0_15 = bits(data, 4, 16, 32)
        disp24 = disp24_16_23 << 16 | disp24_0_15
        pc_1_21 = bits(disp24, 4, 0, 20)
        pc_28_32 = bits(disp24, 4, 20, 24)
        pc = pc_1_21 << 1 | pc_28_32 << 28
        return opcode, pc

    @classmethod
    def get_instruction_info(cls, data: bytes, addr: int) -> InstructionInfo | None:
        opcode, pc = CALLA.decode_calla(data)
        if opcode == 0xED:
            info = InstructionInfo()
            info.length = 4
            info.add_branch(BranchType.CallDestination, pc)
            return info

    @classmethod
    def get_instruction_text(cls, data: bytes, addr: int) -> tuple[list[InstructionTextToken], int] | None:

        opcode, pc = CALLA.decode_calla(data)
        if opcode == 0xED:
            return [
                InstructionTextToken(InstructionTextTokenType.InstructionToken, "calla"),
                InstructionTextToken(InstructionTextTokenType.TextToken, "   "),
                InstructionTextToken(InstructionTextTokenType.IntegerToken, hex(pc), pc)
            ], 4

    @classmethod
    def get_instruction_low_level_il(cls, data: bytes, addr: int, il: LowLevelILFunction) -> int | None:
        opcode, pc = CALLA.decode_calla(data)
        if opcode == 0xED:
            temp_start = il.temp_reg_count
            ctx = ["a10", "a11", "a12", "a13", "a14", "a15", "d8", "d9", "d10", "d11", "d12", "d13", "d14", "d15"]
            for i, r in enumerate(ctx): il.append(il.set_reg(4, LLIL_TEMP(temp_start + i), il.reg(4, r)))
            il.append(il.call(il.const(4, pc)))
            for i, r in enumerate(ctx): il.append(il.set_reg(4, r, il.reg(4, LLIL_TEMP(temp_start + i))))
            return 4
