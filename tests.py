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


def test_part2():
    key = b'1122334455667788'
    iv = b'8877665544332211'
    message = b'1' * 16 + b'a' * 16 + b'2' * 16 + b'b' * 16 + b'3' * 16 + b'c' * 16
    aes = AES.new(key, AES.MODE_CBC, iv)
    cipher = aes.encrypt(message)
    print(f'\033[92m[ORIGINAL MESSAGE]: {message}\n[KEY]: {key}\n[IV]: {iv}\n[ORIGINAL CIPHER]: {cipher}\033[0m')
    list_of_flip_indexes = [1, 12, 157, 223, 334, 315, 458, 511, 550]
    corrupted_ciphers = [
        b"\xef\xd5&O9\xc3{`\xde<\xae'$?\xd2\xcf;\xadlN\x8a^-\x1e\xb4J\x96\n@\x0c>\xc0i\x15&\xe6r\xd1\x06\x97\xfe\x9e\x89\xb7$\xe3Z@Y\x1a\xf2\x109\xb4\xee>yP\x9e\x87\xed\x94Y\xa3\xa9\xa9Y\xa0\xb5N\xd3\x05\xe8:\xa5\x08jeFK\x11zB\x92r\x0bvC\x117\xcb\x02\xf4\xcd\x06b",
        b"o\xc5&O9\xc3{`\xde<\xae'$?\xd2\xcf;\xadlN\x8a^-\x1e\xb4J\x96\n@\x0c>\xc0i\x15&\xe6r\xd1\x06\x97\xfe\x9e\x89\xb7$\xe3Z@Y\x1a\xf2\x109\xb4\xee>yP\x9e\x87\xed\x94Y\xa3\xa9\xa9Y\xa0\xb5N\xd3\x05\xe8:\xa5\x08jeFK\x11zB\x92r\x0bvC\x117\xcb\x02\xf4\xcd\x06b",
        b"o\xd5&O9\xc3{`\xde<\xae'$?\xd2\xcf;\xadlF\x8a^-\x1e\xb4J\x96\n@\x0c>\xc0i\x15&\xe6r\xd1\x06\x97\xfe\x9e\x89\xb7$\xe3Z@Y\x1a\xf2\x109\xb4\xee>yP\x9e\x87\xed\x94Y\xa3\xa9\xa9Y\xa0\xb5N\xd3\x05\xe8:\xa5\x08jeFK\x11zB\x92r\x0bvC\x117\xcb\x02\xf4\xcd\x06b",
        b"o\xd5&O9\xc3{`\xde<\xae'$?\xd2\xcf;\xadlN\x8a^-\x1e\xb4J\x96\x08@\x0c>\xc0i\x15&\xe6r\xd1\x06\x97\xfe\x9e\x89\xb7$\xe3Z@Y\x1a\xf2\x109\xb4\xee>yP\x9e\x87\xed\x94Y\xa3\xa9\xa9Y\xa0\xb5N\xd3\x05\xe8:\xa5\x08jeFK\x11zB\x92r\x0bvC\x117\xcb\x02\xf4\xcd\x06b",
        b"o\xd5&O9\xc3{`\xde<\xae'$?\xd2\xcf;\xadlN\x8a^-\x1e\xb4J\x96\n@\x0c>\xc0i\x15&\xe6r\xd1\x06\x97\xfe\x9a\x89\xb7$\xe3Z@Y\x1a\xf2\x109\xb4\xee>yP\x9e\x87\xed\x94Y\xa3\xa9\xa9Y\xa0\xb5N\xd3\x05\xe8:\xa5\x08jeFK\x11zB\x92r\x0bvC\x117\xcb\x02\xf4\xcd\x06b",
        b"o\xd5&O9\xc3{`\xde<\xae'$?\xd2\xcf;\xadlN\x8a^-\x1e\xb4J\x96\n@\x0c>\xc0i\x15&\xe6r\xd1\x06\xb7\xfe\x9e\x89\xb7$\xe3Z@Y\x1a\xf2\x109\xb4\xee>yP\x9e\x87\xed\x94Y\xa3\xa9\xa9Y\xa0\xb5N\xd3\x05\xe8:\xa5\x08jeFK\x11zB\x92r\x0bvC\x117\xcb\x02\xf4\xcd\x06b",
        b"o\xd5&O9\xc3{`\xde<\xae'$?\xd2\xcf;\xadlN\x8a^-\x1e\xb4J\x96\n@\x0c>\xc0i\x15&\xe6r\xd1\x06\x97\xfe\x9e\x89\xb7$\xe3Z@Y\x1a\xf2\x109\xb4\xee>y\x10\x9e\x87\xed\x94Y\xa3\xa9\xa9Y\xa0\xb5N\xd3\x05\xe8:\xa5\x08jeFK\x11zB\x92r\x0bvC\x117\xcb\x02\xf4\xcd\x06b",
        b"o\xd5&O9\xc3{`\xde<\xae'$?\xd2\xcf;\xadlN\x8a^-\x1e\xb4J\x96\n@\x0c>\xc0i\x15&\xe6r\xd1\x06\x97\xfe\x9e\x89\xb7$\xe3Z@Y\x1a\xf2\x109\xb4\xee>yP\x9e\x87\xed\x94Y\xa1\xa9\xa9Y\xa0\xb5N\xd3\x05\xe8:\xa5\x08jeFK\x11zB\x92r\x0bvC\x117\xcb\x02\xf4\xcd\x06b",
        b"o\xd5&O9\xc3{`\xde<\xae'$?\xd2\xcf;\xadlN\x8a^-\x1e\xb4J\x96\n@\x0c>\xc0i\x15&\xe6r\xd1\x06\x97\xfe\x9e\x89\xb7$\xe3Z@Y\x1a\xf2\x109\xb4\xee>yP\x9e\x87\xed\x94Y\xa3\xa9\xa9Y\xa0\xb1N\xd3\x05\xe8:\xa5\x08jeFK\x11zB\x92r\x0bvC\x117\xcb\x02\xf4\xcd\x06b"]
    try:
        for i, corrupted_cipher in enumerate(corrupted_ciphers):
            print(f"\033[1m\033[4mFor flipped bit {list_of_flip_indexes[i]}:\033[0m")
            print(f"\033[91m[CORRUPTED CIPHER] {corrupted_cipher}\033[0m")
            print(
                f"\033[93m[CORRUPTED MESSAGE] For flipped bit in index {list_of_flip_indexes[i]}: {cbc_custom_decrypt(key, 6, iv + corrupted_cipher)}\033[0m")
            print(
                f"\033[94m[FIXED] For flipped bit in index {list_of_flip_indexes[i]}: {cbc_flip_fix(key, 6, iv + corrupted_cipher)}\033[0m")
    except Exception as err:
        print(f"ERROR: {err}")
        pass


#     output:
# [ORIGINAL MESSAGE]: b'1111111111111111aaaaaaaaaaaaaaaa2222222222222222bbbbbbbbbbbbbbbb3333333333333333cccccccccccccccc'
# [KEY]: b'1122334455667788'
# [IV]: b'8877665544332211'
# [ORIGINAL CIPHER]: b"o\xd5&O9\xc3{`\xde<\xae'$?\xd2\xcf;\xadlN\x8a^-\x1e\xb4J\x96\n@\x0c>\xc0i\x15&\xe6r\xd1\x06\x97\xfe\x9e\x89\xb7$\xe3Z@Y\x1a\xf2\x109\xb4\xee>yP\x9e\x87\xed\x94Y\xa3\xa9\xa9Y\xa0\xb5N\xd3\x05\xe8:\xa5\x08jeFK\x11zB\x92r\x0bvC\x117\xcb\x02\xf4\xcd\x06b"
# For flipped bit 1:
# [CORRUPTED CIPHER] b"\xef\xd5&O9\xc3{`\xde<\xae'$?\xd2\xcf;\xadlN\x8a^-\x1e\xb4J\x96\n@\x0c>\xc0i\x15&\xe6r\xd1\x06\x97\xfe\x9e\x89\xb7$\xe3Z@Y\x1a\xf2\x109\xb4\xee>yP\x9e\x87\xed\x94Y\xa3\xa9\xa9Y\xa0\xb5N\xd3\x05\xe8:\xa5\x08jeFK\x11zB\x92r\x0bvC\x117\xcb\x02\xf4\xcd\x06b"
# [CORRUPTED MESSAGE] For flipped bit in index 1: b'\xd4\xb3`\xa2\xbd \xc8\xfb\x06\x10\xc3L\x15\x0b\x8f \xe1aaaaaaaaaaaaaaa2222222222222222bbbbbbbbbbbbbbbb3333333333333333cccccccccccccccc'
# [FIXED] For flipped bit in index 1: b'1111111111111111'
# For flipped bit 12:
# [CORRUPTED CIPHER] b"o\xc5&O9\xc3{`\xde<\xae'$?\xd2\xcf;\xadlN\x8a^-\x1e\xb4J\x96\n@\x0c>\xc0i\x15&\xe6r\xd1\x06\x97\xfe\x9e\x89\xb7$\xe3Z@Y\x1a\xf2\x109\xb4\xee>yP\x9e\x87\xed\x94Y\xa3\xa9\xa9Y\xa0\xb5N\xd3\x05\xe8:\xa5\x08jeFK\x11zB\x92r\x0bvC\x117\xcb\x02\xf4\xcd\x06b"
# [CORRUPTED MESSAGE] For flipped bit in index 12: b'\x96#c\x13\x85;yN\xc4\x91\x8a\x82\xcdk\xd9vaqaaaaaaaaaaaaaa2222222222222222bbbbbbbbbbbbbbbb3333333333333333cccccccccccccccc'
# [FIXED] For flipped bit in index 12: b'1111111111111111'
# For flipped bit 157:
# [CORRUPTED CIPHER] b"o\xd5&O9\xc3{`\xde<\xae'$?\xd2\xcf;\xadlF\x8a^-\x1e\xb4J\x96\n@\x0c>\xc0i\x15&\xe6r\xd1\x06\x97\xfe\x9e\x89\xb7$\xe3Z@Y\x1a\xf2\x109\xb4\xee>yP\x9e\x87\xed\x94Y\xa3\xa9\xa9Y\xa0\xb5N\xd3\x05\xe8:\xa5\x08jeFK\x11zB\x92r\x0bvC\x117\xcb\x02\xf4\xcd\x06b"
# [CORRUPTED MESSAGE] For flipped bit in index 157: b'1111111111111111\x82\x84\xc0\x1e\x91\xc5\xcd\xc7\x17^rf0\xd1\n\x9d222:222222222222bbbbbbbbbbbbbbbb3333333333333333cccccccccccccccc'
# [FIXED] For flipped bit in index 157: b'aaaaaaaaaaaaaaaa'
# For flipped bit 223:
# [CORRUPTED CIPHER] b"o\xd5&O9\xc3{`\xde<\xae'$?\xd2\xcf;\xadlN\x8a^-\x1e\xb4J\x96\x08@\x0c>\xc0i\x15&\xe6r\xd1\x06\x97\xfe\x9e\x89\xb7$\xe3Z@Y\x1a\xf2\x109\xb4\xee>yP\x9e\x87\xed\x94Y\xa3\xa9\xa9Y\xa0\xb5N\xd3\x05\xe8:\xa5\x08jeFK\x11zB\x92r\x0bvC\x117\xcb\x02\xf4\xcd\x06b"
# [CORRUPTED MESSAGE] For flipped bit in index 223: b'1111111111111111@\xef\x9e\xdd.xmO\x19\t\xcf\xfc\x18\xfd\xeb\x912222222222202222bbbbbbbbbbbbbbbb3333333333333333cccccccccccccccc'
# [FIXED] For flipped bit in index 223: b'aaaaaaaaaaaaaaaa'
# For flipped bit 334:
# [CORRUPTED CIPHER] b"o\xd5&O9\xc3{`\xde<\xae'$?\xd2\xcf;\xadlN\x8a^-\x1e\xb4J\x96\n@\x0c>\xc0i\x15&\xe6r\xd1\x06\x97\xfe\x9a\x89\xb7$\xe3Z@Y\x1a\xf2\x109\xb4\xee>yP\x9e\x87\xed\x94Y\xa3\xa9\xa9Y\xa0\xb5N\xd3\x05\xe8:\xa5\x08jeFK\x11zB\x92r\x0bvC\x117\xcb\x02\xf4\xcd\x06b"
# [CORRUPTED MESSAGE] For flipped bit in index 334: b'1111111111111111aaaaaaaaaaaaaaaaf\xd6\xb1\x85\x01%\x05\x9d\x1c\xae\xef,\x88/\xe6>bbbbbbbbbfbbbbbb3333333333333333cccccccccccccccc'
# [FIXED] For flipped bit in index 334: b'2222222222222222'
# For flipped bit 315:
# [CORRUPTED CIPHER] b"o\xd5&O9\xc3{`\xde<\xae'$?\xd2\xcf;\xadlN\x8a^-\x1e\xb4J\x96\n@\x0c>\xc0i\x15&\xe6r\xd1\x06\xb7\xfe\x9e\x89\xb7$\xe3Z@Y\x1a\xf2\x109\xb4\xee>yP\x9e\x87\xed\x94Y\xa3\xa9\xa9Y\xa0\xb5N\xd3\x05\xe8:\xa5\x08jeFK\x11zB\x92r\x0bvC\x117\xcb\x02\xf4\xcd\x06b"
# [CORRUPTED MESSAGE] For flipped bit in index 315: b'1111111111111111aaaaaaaaaaaaaaaa[h\x06\xf1\xd4\xae\x182\x86\xb9%\xa2\x9c{r\xbfbbbbbbbBbbbbbbbb3333333333333333cccccccccccccccc'
# [FIXED] For flipped bit in index 315: b'2222222222222222'
# For flipped bit 458:
# [CORRUPTED CIPHER] b"o\xd5&O9\xc3{`\xde<\xae'$?\xd2\xcf;\xadlN\x8a^-\x1e\xb4J\x96\n@\x0c>\xc0i\x15&\xe6r\xd1\x06\x97\xfe\x9e\x89\xb7$\xe3Z@Y\x1a\xf2\x109\xb4\xee>y\x10\x9e\x87\xed\x94Y\xa3\xa9\xa9Y\xa0\xb5N\xd3\x05\xe8:\xa5\x08jeFK\x11zB\x92r\x0bvC\x117\xcb\x02\xf4\xcd\x06b"
# [CORRUPTED MESSAGE] For flipped bit in index 458: b'1111111111111111aaaaaaaaaaaaaaaa2222222222222222\x12\xbb\xd8\xe2\x88\xb5\x85\x1f0\xfc\x08\x8b\x06\x92\x11H333333333s333333cccccccccccccccc'
# [FIXED] For flipped bit in index 458: b'bbbbbbbbbbbbbbbb'
# For flipped bit 511:
# [CORRUPTED CIPHER] b"o\xd5&O9\xc3{`\xde<\xae'$?\xd2\xcf;\xadlN\x8a^-\x1e\xb4J\x96\n@\x0c>\xc0i\x15&\xe6r\xd1\x06\x97\xfe\x9e\x89\xb7$\xe3Z@Y\x1a\xf2\x109\xb4\xee>yP\x9e\x87\xed\x94Y\xa1\xa9\xa9Y\xa0\xb5N\xd3\x05\xe8:\xa5\x08jeFK\x11zB\x92r\x0bvC\x117\xcb\x02\xf4\xcd\x06b"
# [CORRUPTED MESSAGE] For flipped bit in index 511: b'1111111111111111aaaaaaaaaaaaaaaa2222222222222222"\xe1(\xbc\xc4G\xefRE5\xa3o\xe3-G\xb83333333333333331cccccccccccccccc'
# [FIXED] For flipped bit in index 511: b'bbbbbbbbbbbbbbbb'
# For flipped bit 550:
# [CORRUPTED CIPHER] b"o\xd5&O9\xc3{`\xde<\xae'$?\xd2\xcf;\xadlN\x8a^-\x1e\xb4J\x96\n@\x0c>\xc0i\x15&\xe6r\xd1\x06\x97\xfe\x9e\x89\xb7$\xe3Z@Y\x1a\xf2\x109\xb4\xee>yP\x9e\x87\xed\x94Y\xa3\xa9\xa9Y\xa0\xb1N\xd3\x05\xe8:\xa5\x08jeFK\x11zB\x92r\x0bvC\x117\xcb\x02\xf4\xcd\x06b"
# [CORRUPTED MESSAGE] For flipped bit in index 550: b'1111111111111111aaaaaaaaaaaaaaaa2222222222222222bbbbbbbbbbbbbbbb\xdd\xc2\x9f\xe6$\x89\xaa\xff\x11\xda\xd4\xf4\xe6Q\xe5/ccccgccccccccccc'
# [FIXED] For flipped bit in index 550: b'3333333333333333'

test_cbc_custom_decrypt(num_tests=100)

for message_size in range(2, 16):
    test_cbc_flip_fix(message_length=message_size)
