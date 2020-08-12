import Crypto.Cipher.AES as AES

# Sizes of key and block are 16 bytes
KEY_SIZE = BLOCK_SIZE = 16


def xor_bytes(a: bytes, b: bytes) -> bytes:
    """
    Preforms byte-wise xor between a and b.
    :raises: ValueError if a and b do not have an equal length
    :return: a ⊕ b
    """
    if len(a) != len(b):
        raise ValueError("Two byte strings do not have the same length")

    # Create a byte sequence that stores the result
    xor = bytearray()

    # Iterate over pairs of bytes b1 from a and b2 from b
    # In each iteration b1 and b2 share the same index in their origin
    # Such behaviour is achieved by using zip(,) which combines two iterators
    for b1, b2 in zip(a, b):
        # Store b₁⊕ b₂ in the result array
        xor.append(b1 ^ b2)
    # Return the result as a bytes object
    return bytes(xor)


def aes_ecb_decrypt(key):
    """
    This function creates an (ECB) AES block cipher.
    This function returns a function that decrypts a 16 byte
    block using AES in ECB mode, i.e. the block is fed into the
    AES PRF without any other context (decrypted "as-is").
    :param key: the 256 bit key
    :return: The decryption function as described
    """
    # Create EBC object
    ebc = AES.new(key, AES.MODE_ECB)

    # EBC object is used in a function closure
    def decrypt(block):
        return ebc.decrypt(block)

    return decrypt


def aes_cbc_decrypt(key: bytes, IV: bytes):
    """
    This function creates a CBC AES block cipher, for a
    16 byte block stream.
    This function returns a function that decrypts one block
    at a time, chaining the results as the CBC mode of operation defines.
    :param key: The 256 bit key
    :param IV: The initialization vector
    :return: The decryption function as described
    :raises: ValueError if either key or IV aren't 16 bytes in length
    """
    # Ensure that the key and IV have a valid length
    if len(key) != KEY_SIZE:
        raise ValueError(f"Key has an invalid size: "
                         f"expected {KEY_SIZE} bytes, got {len(key)} bytes")
    if len(IV) != BLOCK_SIZE:
        raise ValueError(f"Initialization vector has an invalid length: "
                         f"expected {BLOCK_SIZE} bytes, got {len(key)}bytes")

    # Crete an AES block decryptor (ECB Mode)
    # and init C_0 to be the IV
    decrypt_block = aes_ecb_decrypt(key)
    c_i = IV

    def decryptor(cipher_block: bytes):
        nonlocal c_i
        # Ensure that that the given block has a valid length
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

        # Update the last block seen
        c_i = cipher_block

        return plaintext_block

    return decryptor


def cbc_custom_decrypt(key, n, cipher):
    """
    This function decrypts some given cipher text that is n blocks long,
    in CBC mode of operation using AES.
    :param key: The key
    :param n: The number of blocks
    :param cipher: n+1 blocks chained when the first one is the IV and
    the rest are the blocks of the cipher text in sequential order.
    :return: The decrypted plain text
    """
    if len(key) != KEY_SIZE:
        raise ValueError(f"Key has an invalid size: "
                         f"expected {KEY_SIZE} bytes, got {len(key)} bytes")
    if len(cipher) != (n + 1) * BLOCK_SIZE:
        raise ValueError("Invalid cipher length")

    # Extract the IV
    IV = cipher[:BLOCK_SIZE]

    # Remove the IV from the cipher text
    cipher = cipher[BLOCK_SIZE:]

    # Init a cbc decryption function
    cbc_decrypt = aes_cbc_decrypt(key, IV)

    # Store the results in a bytearray
    plaintext = bytearray()

    # Perform until no blocks are left
    while len(cipher) > 0:
        # Extract the first block and remove it
        encrypted_block = cipher[:BLOCK_SIZE]
        cipher = cipher[BLOCK_SIZE:]

        # Decrypt the current block
        decrypted_block = cbc_decrypt(encrypted_block)

        # Add the decrypted block bytes to the byte array
        plaintext.extend(decrypted_block)

    # Cast the bytearray into a bytes object
    return bytes(plaintext)


def test_cbc_1():
    k = b'\x81\x0ff\t\x04\xb6\xcf\x1f.\x10\x8frd\xb4E\x19'
    n = 1
    cipher = b'e|\x92\xd0\x8b\xd9\x00\xc8X\xf2Noi\xa1\x155\x8b\xa5\xb7\xdcka\xaa\x94=a_!x\x1a\xcf\xf4'
    output = cbc_custom_decrypt(k, n, cipher)
    assert output == b'1111111111111111'


def test_cbc_2():
    k = b'\xfcV\xc8\x7f\xcf\x8f\x9ff\x8c\xadX\xaf\xa1\x0fs\x1e'
    IV = b'\xf51\xf7\xe4\xb1m\xda\xed\xddz\xb4\xff.\x8dN\xe6'
    cipher = b'\xf51\xf7\xe4\xb1m\xda\xed\xddz\xb4\xff.\x8dN' \
             b'\xe6|8\xa1x\x18@\xb1\x82\x98\x01\xb3"\xdc\x95\xc2' \
             b'\\d{\xe8(\xb6\x93G\x8a#\x04q\xb6\x89\xbfN\x9a'

    decrypted = AES.new(k, AES.MODE_CBC, cipher[:BLOCK_SIZE]).decrypt(cipher[BLOCK_SIZE:])
    output = cbc_custom_decrypt(k, len(cipher) // BLOCK_SIZE - 1, cipher)
    assert decrypted == output


if __name__ == '__main__':
    test_cbc_1()
    test_cbc_2()
