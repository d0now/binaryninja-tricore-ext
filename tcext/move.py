from .instruction import Instruction
from .format import SCForm
from .utils import bits, sign_extend

from binaryninja.architecture import InstructionTextToken
from binaryninja.enums import InstructionTextTokenType
from binaryninja.lowlevelil import LowLevelILFunction, LowLevelILLabel


class MOV_C8(SCForm):

    @staticmethod
    def get_instruction_text(data: bytes, addr: int):
        op, const8 = MOV_C8.decode(data)
        # mov       d15, -0x1b
        return ([
            InstructionTextToken(InstructionTextTokenType.InstructionToken, "mov"),
            InstructionTextToken(InstructionTextTokenType.TextToken, " " * 7),
            InstructionTextToken(InstructionTextTokenType.RegisterToken, "d15"),
            InstructionTextToken(InstructionTextTokenType.TextToken, ", "),
            InstructionTextToken(InstructionTextTokenType.IntegerToken, hex(const8), const8),
        ], 2)

    @staticmethod
    def get_instruction_low_level_il(data: bytes, addr: int, il: LowLevelILFunction):
        op, const8 = MOV_C8.decode(data)
        il.append(il.set_reg(4, "d15", il.const(4, const8)))
        return 2
