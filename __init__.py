from binaryninja.architecture import Architecture
from binaryninja.architecture import Architecture, ArchitectureHook, InstructionInfo, InstructionTextToken
from binaryninja.lowlevelil import LowLevelILFunction
from binaryninja.plugin import PluginCommand
from binaryninja.log import log_warn, log_error

from .tcext.instruction import Instruction
from .tcext.conditonal_move import CMOV_C, CMOV_R, CMOVN_C, CMOVN_R
from .tcext.move import MOV_C8


class TriCoreExtHook(ArchitectureHook):

    table: dict[int, type[Instruction]] = {
        0xAA: CMOV_C,
        0x2A: CMOV_R,
        0xEA: CMOVN_C,
        0x6A: CMOVN_R,
        0xDA: MOV_C8,
    }

    def dispatch(self, data: bytes) -> type[Instruction] | None:
        inst = int.from_bytes(data, 'little')
        special_opcode = inst & 0b111111
        if special_opcode not in [0x10, 0x6F]:
            opcode = inst & 0b11111111
            if opcode in self.table:
                return self.table[opcode]

    def get_instruction_info(self, data: bytes, addr: int) -> InstructionInfo | None:
        result = None
        if (inst := self.dispatch(data)) != None:
            result = inst.get_instruction_info(data, addr)
        return super().get_instruction_info(data, addr) if result == None else result

    def get_instruction_text(self, data: bytes, addr: int) -> str | None:
        orig = super().get_instruction_text(data, addr)
        result = None
        if (inst := self.dispatch(data)) != None:
            result = inst.get_instruction_text(data, addr)
            if orig and result:
                if orig[0][0].text != result[0][0].text:
                    log_warn(f"Instruction mnemonic different from original: 0x{addr:x} {orig[0][0].text} != {result[0][0].text}")
        return orig if result == None else result
    
    def get_instruction_low_level_il(self, data: bytes, addr: int, il: LowLevelILFunction) -> int:
        result = None
        if (inst := self.dispatch(data)) != None:
            result = inst.get_instruction_low_level_il(data, addr, il)
        return super().get_instruction_low_level_il(data, addr, il) if result == None else result


try:
    TriCoreExtHook.register(Architecture['tricore'])
except KeyError:
    log_error("Failed to register TriCore Architecture Hook. try plugin command.")
    # workaround for TriCore architecture not being recognized by Binary Ninja at plugin loading time
    # (maybe not a core architecture?)
    PluginCommand.register(
        "TriCore Extension Architecture Hook",
        "",
        lambda _: TriCoreExtHook(Architecture['tricore']).register()
    )
