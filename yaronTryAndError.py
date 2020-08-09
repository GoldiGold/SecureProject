import Cryptodome.Cipher.AES as AES

KEY_SIZE = BLOCK_SIZE = 16


def xor_bytes(a: bytes, b: bytes) -> bytes:
    if len(a) != len(b):
        raise ValueError("Two byte strings do not have the same length")

    xor = bytearray()
    for b1, b2 in zip(a, b):
        xor.append(b1 ^ b2)
    return bytes(xor)


def aes_ecb_decrypt(key):
    ebc = AES.new(key, AES.MODE_ECB)

    def decrypt(block):
        return ebc.decrypt(block)

    return decrypt


def aes_cbc_decrypt(key: bytes, IV: bytes):
    if len(key) != KEY_SIZE:
        raise ValueError(f"Key has an invalid size: "
                         f"expected {KEY_SIZE} bytes, got {len(key)} bytes")
    if len(IV) != BLOCK_SIZE:
        raise ValueError(f"Initialization vector has an invalid length: "
                         f"expected {BLOCK_SIZE} bytes, got {len(key)}bytes")

    decrypt_block = aes_ecb_decrypt(key)
    c_i = IV

    def decryptor(cipher_block: bytes):
        nonlocal c_i

        if len(cipher_block) != BLOCK_SIZE:
            raise ValueError(f"Block has an invalid length: "
                             f"expected {BLOCK_SIZE} bytes, got {len(cipher_block)}bytes")

        # Perform decryption according to formula:
        # Where aes⁻¹(k, block) = decrypt_block(block)
        #       Cᵢ˖₁ = current cipher_block
        #       Pᵢ˖₁ is the plaintext of Cᵢ˖₁
        #       key is k
        # Formula:
        #       Pᵢ˖₁ = aes⁻¹(k, Cᵢ˖₁) ⊕ Cᵢ
        plaintext_block = xor_bytes(decrypt_block(cipher_block), c_i)
        c_i = cipher_block

        return plaintext_block

    return decryptor


def cbc_custom_decrypt(key, n, cipher):
    if len(key) != KEY_SIZE:
        raise ValueError(f"Key has an invalid size: "
                         f"expected {KEY_SIZE} bytes, got {len(key)} bytes")
    if len(cipher) != (n + 1) * BLOCK_SIZE:
        raise ValueError("Invalid cipher length")

    IV = cipher[:BLOCK_SIZE]
    cipher = cipher[BLOCK_SIZE:]

    cbc_decrypt = aes_cbc_decrypt(key, IV)

    plaintext = bytearray()
    while len(cipher) > 0:
        encrypted_block = cipher[:BLOCK_SIZE]
        decrypted_block = cbc_decrypt(encrypted_block)
        plaintext.extend(decrypted_block)
        cipher = cipher[BLOCK_SIZE:]

    return bytes(plaintext)


if __name__ == '__main__':
    k = b'\x81\x0ff\t\x04\xb6\xcf\x1f.\x10\x8frd\xb4E\x19'
    n = 1
    cipher = b'e|\x92\xd0\x8b\xd9\x00\xc8X\xf2Noi\xa1\x155\x8b\xa5\xb7\xdcka\xaa\x94=a_!x\x1a\xcf\xf4'
    output = cbc_custom_decrypt(k, n, cipher)
    print(output, output == b'1111111111111111')

    k = b'\xfcV\xc8\x7f\xcf\x8f\x9ff\x8c\xadX\xaf\xa1\x0fs\x1e'
    IV = b'\xf51\xf7\xe4\xb1m\xda\xed\xddz\xb4\xff.\x8dN\xe6'
    cipher = b'\xf51\xf7\xe4\xb1m\xda\xed\xddz\xb4\xff.\x8dN' \
             b'\xe6|8\xa1x\x18@\xb1\x82\x98\x01\xb3"\xdc\x95\xc2' \
             b'\\d{\xe8(\xb6\x93G\x8a#\x04q\xb6\x89\xbfN\x9a'

    decrypted = AES.new(k, AES.MODE_CBC, cipher[:BLOCK_SIZE]).decrypt(cipher[BLOCK_SIZE:])
    output = cbc_custom_decrypt(k, len(cipher) // BLOCK_SIZE - 1, cipher)
    print(decrypted, output, decrypted == output)
