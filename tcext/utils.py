def bits(_data: bytes, length: int, start: int, end: int) -> int:
    data = _data[:length]
    inst = int.from_bytes(data, 'little')
    return (inst >> start) & ((1 << (end - start)) - 1)

def sign_extend(value: int, width: int) -> int:
    value &= (1 << width) - 1
    if value & (1 << (width - 1)):
        value -= 1 << width
    return value