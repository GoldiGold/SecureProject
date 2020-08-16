# Yaron ,Hay ,318879103
# Python 3.7
import Crypto.Cipher.AES as AES

# # # # # # # # # # # # # # # # #
# Question 1
# # # # # # # # # # # # # # # # #

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
        """

        :param cipher_block:
        :return:
        """
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


# # # # # # # # # # # # # # # # #
# Question 2
# # # # # # # # # # # # # # # # #

def xor_all_bytes(s: bytes):
    """
    This function is applying the xor method on all the bytes it got (byte byte).
    :param s: the bytes to xor on.
    :return: the result of the xor on all the bytes.
    """
    # Start with neutral to XOR
    res = 0
    # xoring byte byte in the string of bytes.
    for b in s:
        res ^= b
    return res


def what_bit_lit(b: int):
    """
    This function gets a number and finds its single lit bit in the first 8 bits - 1st byte, if has more than 1 bit,
    returns false, None. if doesn't have a single bit lit in the first 8 bits raise a ValueError.
    :param b: a number
    :return: the single bit that is lit
    """
    # Use only the first 8 bits
    b &= 0xFF

    for i in range(8):
        if b & (1 << i):
            if not (b & (0xFF << (i + 1))):
                return True, i
            else:
                return False, None
    raise ValueError("No bit was lit")


def is_only_one_byte_diff(block):
    """
    The function gets a block and checks if there is a single different byte or all similar
    (the block is supposed to be built from repeating bytes. it counts the amount of similar blocks with a dictionary.
    If the block is fine there will be only one key, if not then there will be a key with value of: length_of_block - 1
    if the block is not "fine" we iterate over the bytes and find the different byte and its index.
    :param block: a block of bytes.
    :return: true - if there is a different byte and its index. false + None - if the bytes are fine.
    """
    n = len(block) - 1
    counts = dict()
    # iterating over each byte in the block and counting the appearances of them.
    for b in block:
        if b not in counts:
            counts[b] = 0
        counts[b] += 1

    for b in counts:
        # check if a byte repeats itself n times (len(block) - 1): there is a different (wrong) byte
        if counts[b] == n:
            # if a wrong byte exists we will find it and return its index
            for i in range(n + 1):
                if block[i] != b:
                    return True, i
    return False, None


def cbc_flip_fix(key, n, cipher):
    """
    The function receives a cipher text that was supposed to be created in this way:
    Each of the n plaintext blocks, was generated by choosing a random byte and repeating it 16 times.
    The plaintext message m1 , . . . , mn was encrypted using the key k in CBC mode. The result is c0,...,cn.
    A random bit in one of the blocks c1,...,cn−1 was flipped.
    The resulting n + 1 blocks are the input given to the function.
    The function outputs the original value of the block whose encryption was completely corrupted.
    :param key: a key
    :param n: an integer
    :param cipher: A string of n + 1 blocks of 16 bytes.
    :return:
    """
    if len(key) != KEY_SIZE:
        raise ValueError(f"Key has an invalid size: "
                         f"expected {KEY_SIZE} bytes, got {len(key)} bytes")
    if len(cipher) != (n + 1) * BLOCK_SIZE:
        raise ValueError("Invalid cipher length")
    copy = cipher

    # Extract the IV
    IV = cipher[:BLOCK_SIZE]

    # Remove the IV from the cipher text
    cipher = cipher[BLOCK_SIZE:]

    # Init a cbc decryption function
    cbc_decrypt = aes_cbc_decrypt(key, IV)

    i = 0
    idx = None
    j = None
    # Perform until no blocks are left
    while len(cipher) > 0:
        # Extract the first block and remove it
        encrypted_block = cipher[:BLOCK_SIZE]
        cipher = cipher[BLOCK_SIZE:]
        i += 1

        # Decrypt the block
        decrypted_block = cbc_decrypt(encrypted_block)

        # find if there is bad byte (ok = True) and its index (idx)
        ok, idx = is_only_one_byte_diff(decrypted_block)
        if ok:
            # find the decrypted value of the bad byte.
            b = decrypted_block[idx]
            # find the index of the wrong bit in the byte, by xoring the bad byte to its previous byte
            ok, j = what_bit_lit(b ^ decrypted_block[idx - 1])
            if ok:
                # we found the bit. finishing the loop
                break
    i = i - 1
    c_i = bytearray(copy[BLOCK_SIZE * i: BLOCK_SIZE * (i + 1)])
    c_prev = copy[BLOCK_SIZE * (i - 1): BLOCK_SIZE * i]

    if idx is not None and j is not None:
        # Flip bit j in idx byte
        c_i[idx] ^= (1 << j)

    return aes_cbc_decrypt(key, c_prev)(c_i)


# # # # # # # # # # # # # # # # #
# Tests
# # # # # # # # # # # # # # # # #

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
