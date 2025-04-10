from .instruction import Instruction
from .format import SRCForm, SRRForm
from .utils import bits, sign_extend

from binaryninja.lowlevelil import LowLevelILFunction, LowLevelILLabel


class CMOV_C(SRCForm):
    @staticmethod
    def get_instruction_low_level_il(data: bytes, addr: int, il: LowLevelILFunction):
        op, s1, const4 = CMOV_C.decode(data)
        const4_sext = sign_extend(const4, 8)

        cond = il.compare_equal(4, il.reg(4, "d15"), il.const(4, 0))

        true_label = LowLevelILLabel()
        false_label = LowLevelILLabel()
        il.append(il.if_expr(cond, true_label, false_label))

        il.mark_label(true_label)
        il.append(il.set_reg(4, s1, il.const(4, const4_sext)))

        il.mark_label(false_label)

        return 2


class CMOV_R(SRRForm):
    @staticmethod
    def get_instruction_low_level_il(data: bytes, addr: int, il: LowLevelILFunction):
        op, s1, s2 = CMOV_R.decode(data)

        cond = il.compare_equal(4, il.reg(4, "d15"), il.const(4, 0))

        true_label = LowLevelILLabel()
        false_label = LowLevelILLabel()
        il.append(il.if_expr(cond, true_label, false_label))

        il.mark_label(true_label)
        il.append(il.set_reg(4, s1, s2))

        il.mark_label(false_label)

        return 2


class CMOVN_C(SRCForm):
    @staticmethod
    def get_instruction_low_level_il(data: bytes, addr: int, il: LowLevelILFunction):
        op, s1, const4 = CMOVN_C.decode(data)
        print(op, s1, const4)
        const4_sext = sign_extend(const4, 8)

        cond = il.compare_not_equal(4, il.reg(4, "d15"), il.const(4, 0))

        true_label = LowLevelILLabel()
        false_label = LowLevelILLabel()
        il.append(il.if_expr(cond, true_label, false_label))

        il.mark_label(true_label)
        il.append(il.set_reg(4, s1, il.const(4, const4_sext)))

        il.mark_label(false_label)

        return 2


class CMOVN_R(SRRForm):
    @staticmethod
    def get_instruction_low_level_il(data: bytes, addr: int, il: LowLevelILFunction):
        op, s1, s2 = CMOVN_R.decode(data)

        cond = il.compare_not_equal(4, il.reg(4, "d15"), il.const(4, 0))

        true_label = LowLevelILLabel()
        false_label = LowLevelILLabel()
        il.append(il.if_expr(cond, true_label, false_label))

        il.mark_label(true_label)
        il.append(il.set_reg(4, s1, s2))

        il.mark_label(false_label)

        return 2