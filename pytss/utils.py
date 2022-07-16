import binascii

def chunks(lst, n):
    for i in range(0, len(lst), n):
        yield lst[i:i + n]

class Converters:
    def string_to_int(message: str) -> int:
        return int(binascii.hexlify(message.encode("utf-8")), 16)

    def int_to_string(value: str) -> str:
        return binascii.unhexlify(format(value, "x").encode("utf-8")).decode("utf-8")

    def bytes_to_int(data: bytes) -> int:
        return int.from_bytes(data, byteorder='big')

    def int_to_bytes(data: int, size: int) -> bytes:
        return data.to_bytes(size, byteorder='big')

def int_to_hex_str(value: int, num_bits: int=256) -> str:
    return hex(value).zfill(num_bits)