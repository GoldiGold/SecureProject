from Crypto.Cipher import AES

block_size = 16


def xor_bytes(byte_seq_1, byte_seq_2):
    return bytes([x ^ y for x, y in zip(byte_seq_1, byte_seq_2)])


def print_bytes(b: bytes):
    print([bin(byte) for byte in b])
