# By Evyatar Itzhaki
# from Crypto.Cipher import AES

from glob import *
from project import cbc_custom_decrypt
from project import cbc_flip_fix


def test_cbc_custom_decrypt(num_tests=1000):
    from Crypto.Random import get_random_bytes

    # we'll use AES CBC
    key = get_random_bytes(block_size)
    aes = AES.new(key, AES.MODE_CBC, iv=get_random_bytes(block_size))

    total_cipher = aes.iv
    total_message = bytes([])

    for i in range(num_tests):
        # create a random message
        message = get_random_bytes(block_size)

        # concatenate the new ciphertext and mdessage to the whole strings
        total_cipher += aes.encrypt(message)
        total_message += message

        decryption = cbc_custom_decrypt(key, i + 1, total_cipher)

        if decryption != total_message:
            # raise Exception("Failed a test")
            print("Failed a test")
            break
    else:
        print(f"Passed all cbc_custom_decrypt tests ({num_tests} random tests)")


# not used
def output_example_test():
    # key = b'\x81\x0ff\t\x04\xb6\xcf\x1f.\x10\x8frd\xb4E\x19'
    # key_hex = '810f660904b6cf1f2e108f7264b44519'
    # iv = b'e|\x92\xd0\x8b\xd9\x00\xc8X\xf2Noi\xa1\x155'
    # cipher = b'e|\x92\xd0\x8b\xd9\x00\xc8X\xf2Noi\xa1\x155\xb5b\xe7r\xb1\xec\xb5\xed\xca\xca\x1f$\xf8\xe33%'
    # output = b'\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01'

    key = b'\x81\x0ff\t\x04\xb6\xcf\x1f.\x10\x8frd\xb4E\x19'
    cipher = b'e|\x92\xd0\x8b\xd9\x00\xc8X\xf2Noi\xa1\x155\xb5b\xe7r\xb1\xec\xb5\xed\xca\xca\x1f$\xf8\xe33%'
    message = b'1111111111111111'

    dec = cbc_custom_decrypt(key, 1, cipher)
    if message == dec:
        print("Passed example test")
    else:
        print("Failed example test")


def test_cbc_flip_fix(num_tests=100, message_length=8):
    from Crypto.Random import get_random_bytes
    import random
    from functools import reduce

    def repeat_byte():
        return get_random_bytes(1) * block_size

    for _ in range(num_tests):
        # we'll use AES CBC
        key = get_random_bytes(block_size)
        aes = AES.new(key, AES.MODE_CBC, iv=get_random_bytes(block_size))

        # create message and encryption
        message = reduce(lambda x, y: x + y,
                         [repeat_byte() for _ in range(message_length)])
        cipher = aes.iv + aes.encrypt(message)

        # choose flip bit index and flip that bit
        # (from the first n blocks, we cannot flip a bit at the last block)
        flip_message_block = random.randrange(message_length - 1) * block_size
        flip_cipher_block_byte = flip_message_block + block_size
        flip_byte = flip_cipher_block_byte + random.randrange(block_size)

        flipped_cipher = list(cipher)
        flipped_cipher[flip_byte] = flipped_cipher[flip_byte] ^ (1 << random.randrange(8))
        flipped_cipher = bytes(flipped_cipher)

        # save on the side the original message
        original_message = message[flip_message_block:flip_message_block + block_size]

        result = cbc_flip_fix(key, message_length, flipped_cipher)

        if result != original_message:
            print("-----Failed a test")
            print(f"Expected Result: {list(original_message)}")
            print(f"Got: {list(result)}")
            break

    else:
        print("Passed all cbc_flip_fix tests successfully"
              f"({num_tests} random tests with message of length {message_length})")


test_cbc_custom_decrypt(num_tests=100)

for message_size in range(2, 16):
    test_cbc_flip_fix(message_length=message_size)
