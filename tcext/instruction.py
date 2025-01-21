from abc import ABC

from binaryninja.architecture import InstructionInfo, InstructionTextToken
from binaryninja.lowlevelil import LowLevelILFunction


class Instruction(ABC):

    @staticmethod
    def get_instruction_info(data: bytes, addr: int) -> InstructionInfo | None:
        pass

    @staticmethod
    def get_instruction_text(data: bytes, addr: int) -> tuple[list[InstructionTextToken], int] | None:
        pass

    @staticmethod
    def get_instruction_low_level_il(data: bytes, addr: int, il: LowLevelILFunction) -> int | None:
        pass
