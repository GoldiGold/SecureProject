#Yaron , Hay ,318879103
#Python 3.7

# File Encoding: UTF-8

import Crypto.Cipher.AES as AES

# Sizes of key and block are 16 bytes
KEY_SIZE = BLOCK_SIZE = 16


# # # # # # # # # # # # # # # # #
# Utils
# # # # # # # # # # # # # # # # #

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


# # # # # # # # # # # # # # # # #
# Question 1
# # # # # # # # # # # # # # # # #

# Algorithm:
# Extract (remove it from cipher) the IV and Init c₀ = IV
# In each iteration remove the first block in cipher:
#  Apply the following formula:
#       aes⁻¹(k, Cᵢ˖₁) ⊕ Cᵢ
#   Applying the formula is done by using the aes_cbc_decrypt function
#   that stores the last block each time a decryption is preformed
#  And append (bytearray::extend) the result to the plaintext bytearray
# Cast the bytearray into a bytes object and return it
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
        nonlocal c_i  # Use the c_i defined aes_cbc_decrypt and not a local one
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


# # # # # # # # # # # # # # # # #
# Question 2
# # # # # # # # # # # # # # # # #

# Algorithm:
# By recalling that
#
# each one of the blocks except the corrupted one and the following one
# will decrypted correctly and,
# each one of the blocks is 16 repetitions of the same byte and,
# know that only the bit in the decryption of the block after the corrupted block will be
# flipped and the rest will remain unchanged
#
# we can identify the block after the the corrupted block and the location of the flipped bit by:
#
# Decrypting the blocks one by one and testing if the all of decrypted block bytes except one
# are the same and that only one bit in that byte is different from the others (a "flip").
#
# When such a block is found, we now that the index of the corrupted block is one before the
# current one and we also know the location of the flipped bit.
# Finally we can flip the bit at that same location in the previous block, and decrypt it as usual.
def cbc_flip_fix(key, n, cipher):
    """
    The function receives a cipher text that was supposed to be created in this way:
    Each of the n plaintext blocks, is generated by choosing a random byte and repeating it 16 times.
    The plaintext message m1 , . . . , mn is encrypted using the key k in CBC mode. The result is c0,...,cn.
    A random bit in one of the blocks c1,...,cn−1 is flipped.
    The resulting n + 1 blocks are the input given to the function.
    The function outputs the original value of the block whose encryption was completely corrupted.
    :param key: a key
    :param n: an integer
    :param cipher: A string of n + 1 blocks of 16 bytes.
    :return: the result of the function aes_cbc_decrypt(key, c_prev)(block_flipped). aes_cbc_decrypt(key, c_prev) - returns a decryptor according to a
    key and IV, that return the decryption of the corrupted block - block_flipped.
    """
    if len(key) != KEY_SIZE:
        raise ValueError(f"Key has an invalid size: "
                         f"expected {KEY_SIZE} bytes, got {len(key)} bytes")
    if len(cipher) != (n + 1) * BLOCK_SIZE:
        raise ValueError("Invalid cipher length")

    # Make a copy of the cipher
    cipher_copy = bytes(cipher)

    # Extract the IV
    IV = cipher[:BLOCK_SIZE]

    # Remove the IV from the cipher text
    cipher = cipher[BLOCK_SIZE:]

    # Init a cbc decryption function
    cbc_decrypt = aes_cbc_decrypt(key, IV)

    block_after_flipped_idx = 0

    # Perform until no blocks are left
    while len(cipher) > 0:
        flipped_byte_idx = None  # Stores the byte no where the flipped bit was
        flipped_bit_idx = None

        # Extract the first block and remove it
        encrypted_block = cipher[:BLOCK_SIZE]
        cipher = cipher[BLOCK_SIZE:]

        # Decrypt the block
        decrypted_block = cbc_decrypt(encrypted_block)

        # Increment the current block index
        block_after_flipped_idx += 1

        # Test if there only one different byte than all other bytes in the decrypted block (ok = True)
        # Also store its index in flipped_byte_idx variable
        ok, flipped_byte_idx = is_only_one_byte_diff(decrypted_block)
        if ok:
            # The value of the different bytes
            b = decrypted_block[flipped_byte_idx]

            # Test if only one bit is different than all other bits (at the same index) in the repeating byte
            #
            # Recall that decrypted_block[flipped_byte_idx - 1] is the repeating byte's value
            #  because all bytes except flipped_byte_idx are equal
            #
            # Let v := b ⊕ decrypted_block[flipped_byte_idx - 1]
            # Note that only one bit was flipped in b iff v has only ONE bit lit
            # Then passing v to what_bit_lit tests that one only bit in v is lit (by definition of what_bit_lit)
            #   Note that v must have at least one bit that is lit since b ≠ decrypted_block[flipped_byte_idx - 1]
            #
            # When the condition above is holds ok = True, and the index is stored in flipped_bit_idx
            ok, flipped_bit_idx = what_bit_lit(b ^ decrypted_block[flipped_byte_idx - 1])
            if ok:
                # We have identified the block that is after the corrupted block, thus we may stop the loop
                break
    assert flipped_byte_idx is not None and flipped_bit_idx is not None

    # The index of the corrupted block
    block_flipped_idx = block_after_flipped_idx - 1

    # Extract the corrupted block from the cipher copy and cast it to an editable bytearray
    block_flipped = bytearray(cipher_copy[BLOCK_SIZE * block_flipped_idx: BLOCK_SIZE * (block_flipped_idx + 1)])

    # Extract the block before from the cipher copy for decryption purposes
    c_prev = cipher_copy[BLOCK_SIZE * (block_flipped_idx - 1): BLOCK_SIZE * block_flipped_idx]

    # Flip the jth bit in byte no. flipped_byte_idx
    block_flipped[flipped_byte_idx] ^= (1 << flipped_bit_idx)

    # Return the decryption of the corrupted block
    # Setting the IV to c_prev makes sure that the correct block is used as the previous
    return aes_cbc_decrypt(key, c_prev)(block_flipped)


def what_bit_lit(b: int):
    """
    This function gets a number and finds the SINGLE lit bit in the first 8 bits (ok=True).
    If more than one bit is lit the function will return (ok=False, None)
    :param b: a byte
    :return: (ok, the single bit's that is lit location)
    :raises: ValueError if none of the first 8 bits lit
    """
    # Use only the first 8 bits
    b &= 0xFF

    for i in range(8):
        # Test if the i'th bit is lit
        if b & (1 << i):
            # Test that any other bits aren't lit
            # 0xFF << (i + 1) is a mask that turns off all bit from 0 to i
            if not (b & (0xFF << (i + 1))):
                return True, i
            else:
                return False, None
    raise ValueError("No bit was lit")


def is_only_one_byte_diff(block):
    """
    The function receives a block and checks if there is a single byte that is different from the others.
    :param block: a block of bytes.
    :return: boolean answer, the different byte's index (or None if is answer is False)
    """
    n = len(block) - 1
    counts = dict()
    # iterating over each byte in the block and counting the appearances of them.
    for b in block:
        if b not in counts:
            counts[b] = 0
        counts[b] += 1

    for b in counts:
        # check if a byte repeats itself n times (n = len(block) - 1):
        # if so, there must be only one different ("wrong") byte
        if counts[b] == n:
            # if a "wrong" byte exists we will find it and return its index
            for i in range(n + 1):
                if block[i] != b:
                    return True, i
    return False, None


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

    # Also possible: decrypted = AES.new(k, AES.MODE_CBC, cipher[:BLOCK_SIZE]).decrypt(cipher[BLOCK_SIZE:])
    decrypted = b'aaaaaaaaaaaaaaaabbbbbbbbbbbbbbbb'
    output = cbc_custom_decrypt(k, len(cipher) // BLOCK_SIZE - 1, cipher)
    assert decrypted == output


def test_cbc_flip():
    blocks = [b * BLOCK_SIZE for b in [b'1', b'a', b'2', b'b', b'3', b'c']]

    key = b'1122334455667788'
    iv = b'8877665544332211'

    list_of_flip_indexes = [1, 12, 157, 223, 334, 315, 458, 511, 550]
    corrupted_ciphers = [
        b"\xef\xd5&O9\xc3{`\xde<\xae'$?\xd2\xcf;\xadlN\x8a^-\x1e\xb4J\x96\n@\x0c>\xc0i\x15&\xe6r\xd1\x06\x97\xfe\x9e"
        b"\x89\xb7$\xe3Z@Y\x1a\xf2\x109\xb4\xee>yP\x9e\x87\xed\x94Y\xa3\xa9\xa9Y\xa0\xb5N\xd3\x05\xe8:\xa5\x08jeFK"
        b"\x11zB\x92r\x0bvC\x117\xcb\x02\xf4\xcd\x06b",

        b"o\xc5&O9\xc3{`\xde<\xae'$?\xd2\xcf;\xadlN\x8a^-\x1e\xb4J\x96\n@\x0c>\xc0i\x15&\xe6r\xd1\x06\x97\xfe\x9e\x89"
        b"\xb7$\xe3Z@Y\x1a\xf2\x109\xb4\xee>yP\x9e\x87\xed\x94Y\xa3\xa9\xa9Y\xa0\xb5N\xd3\x05\xe8:\xa5\x08jeFK\x11zB"
        b"\x92r\x0bvC\x117\xcb\x02\xf4\xcd\x06b",

        b"o\xd5&O9\xc3{`\xde<\xae'$?\xd2\xcf;\xadlF\x8a^-\x1e\xb4J\x96\n@\x0c>\xc0i\x15&\xe6r\xd1\x06\x97\xfe\x9e\x89"
        b"\xb7$\xe3Z@Y\x1a\xf2\x109\xb4\xee>yP\x9e\x87\xed\x94Y\xa3\xa9\xa9Y\xa0\xb5N\xd3\x05\xe8:\xa5\x08jeFK\x11zB"
        b"\x92r\x0bvC\x117\xcb\x02\xf4\xcd\x06b",

        b"o\xd5&O9\xc3{`\xde<\xae'$?\xd2\xcf;\xadlN\x8a^-\x1e\xb4J\x96\x08@\x0c>\xc0i\x15&\xe6r\xd1\x06\x97\xfe\x9e"
        b"\x89\xb7$\xe3Z@Y\x1a\xf2\x109\xb4\xee>yP\x9e\x87\xed\x94Y\xa3\xa9\xa9Y\xa0\xb5N\xd3\x05\xe8:\xa5\x08jeFK"
        b"\x11zB\x92r\x0bvC\x117\xcb\x02\xf4\xcd\x06b",

        b"o\xd5&O9\xc3{`\xde<\xae'$?\xd2\xcf;\xadlN\x8a^-\x1e\xb4J\x96\n@\x0c>\xc0i\x15&\xe6r\xd1\x06\x97\xfe\x9a\x89"
        b"\xb7$\xe3Z@Y\x1a\xf2\x109\xb4\xee>yP\x9e\x87\xed\x94Y\xa3\xa9\xa9Y\xa0\xb5N\xd3\x05\xe8:\xa5\x08jeFK\x11zB"
        b"\x92r\x0bvC\x117\xcb\x02\xf4\xcd\x06b",

        b"o\xd5&O9\xc3{`\xde<\xae'$?\xd2\xcf;\xadlN\x8a^-\x1e\xb4J\x96\n@\x0c>\xc0i\x15&\xe6r\xd1\x06\xb7\xfe\x9e\x89"
        b"\xb7$\xe3Z@Y\x1a\xf2\x109\xb4\xee>yP\x9e\x87\xed\x94Y\xa3\xa9\xa9Y\xa0\xb5N\xd3\x05\xe8:\xa5\x08jeFK\x11zB"
        b"\x92r\x0bvC\x117\xcb\x02\xf4\xcd\x06b",

        b"o\xd5&O9\xc3{`\xde<\xae'$?\xd2\xcf;\xadlN\x8a^-\x1e\xb4J\x96\n@\x0c>\xc0i\x15&\xe6r\xd1\x06\x97\xfe\x9e\x89"
        b"\xb7$\xe3Z@Y\x1a\xf2\x109\xb4\xee>y\x10\x9e\x87\xed\x94Y\xa3\xa9\xa9Y\xa0\xb5N\xd3\x05\xe8:\xa5\x08jeFK"
        b"\x11zB\x92r\x0bvC\x117\xcb\x02\xf4\xcd\x06b",

        b"o\xd5&O9\xc3{`\xde<\xae'$?\xd2\xcf;\xadlN\x8a^-\x1e\xb4J\x96\n@\x0c>\xc0i\x15&\xe6r\xd1\x06\x97\xfe\x9e\x89"
        b"\xb7$\xe3Z@Y\x1a\xf2\x109\xb4\xee>yP\x9e\x87\xed\x94Y\xa1\xa9\xa9Y\xa0\xb5N\xd3\x05\xe8:\xa5\x08jeFK\x11zB"
        b"\x92r\x0bvC\x117\xcb\x02\xf4\xcd\x06b",

        b"o\xd5&O9\xc3{`\xde<\xae'$?\xd2\xcf;\xadlN\x8a^-\x1e\xb4J\x96\n@\x0c>\xc0i\x15&\xe6r\xd1\x06\x97\xfe\x9e\x89"
        b"\xb7$\xe3Z@Y\x1a\xf2\x109\xb4\xee>yP\x9e\x87\xed\x94Y\xa3\xa9\xa9Y\xa0\xb1N\xd3\x05\xe8:\xa5\x08jeFK\x11zB"
        b"\x92r\x0bvC\x117\xcb\x02\xf4\xcd\x06b"
    ]
    for i, corrupted_cipher in enumerate(corrupted_ciphers):
        assert cbc_flip_fix(key, 6, iv + corrupted_cipher) == blocks[list_of_flip_indexes[i] // (BLOCK_SIZE * 8)]


if __name__ == '__main__':
    test_cbc_1()
    test_cbc_2()
    test_cbc_flip()
