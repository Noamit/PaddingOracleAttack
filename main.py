# for encoding with DES block encoders
from Crypto.Cipher import DES
# for padding
from Crypto.Util.Padding import pad, unpad
import sys


def xor(a, b, c):
    result = a ^ b ^ c
    return bytes([result])


def oracle(ciphertext, key, iv):
    oracle_cipher = DES.new(key, DES.MODE_CBC, iv)
    try:
        unpad(oracle_cipher.decrypt(ciphertext), DES.block_size)
        return True
    except:
        return False


ciphertext = sys.argv[1]
key = bytes.fromhex(sys.argv[2])
iv = bytes.fromhex(sys.argv[3])

c1_options = [b'\x00\x00\x00\x00\x00\x00\x00'.hex(),
              b'\x00\x00\x00\x00\x00\x00'.hex(),
              b'\x00\x00\x00\x00\x00'.hex(),
              b'\x00\x00\x00\x00'.hex(),
              b'\x00\x00\x00'.hex(),
              b'\x00\x00'.hex(),
              b'\x00'.hex(),
              b''.hex()]

c1 = c1_options[0]
c1_2 = bytes([0]).hex()
c2_2 = ''
c2 = ciphertext[0:16]

num_of_blocks = int(len(ciphertext) / 16)
plaintext_dicts = {}
ciphertext_arrays = {}
iv_as_first_block = {}
c_hex = {}

# init params
# create plaintext_dicts - at first nothing is known
for i in range(1, num_of_blocks+1):
    plaintext_dicts[i] = {}
# for every block in the ciphertext
for i in range(0, num_of_blocks):
    c_hex[i] = ciphertext[16*i:(16*i)+16]
for i in range(0, num_of_blocks-1):
    ciphertext_arrays[i] = {}
    for j in range(0, 8):
        ciphertext_arrays[i][j] = int(c_hex[i][(j*2):((j*2) + 2)], base=16)
for i in range(0, 8):
    iv_as_first_block[i] = int(iv.hex()[(i*2):((i*2) + 2)], base=16)

# i is the current cipher text
for i in range(0, num_of_blocks):
    # the current ciphertext to decode
    c_i = c_hex[i]

    c1 = c1_options[0]
    c1_2 = bytes([0]).hex()
    c2_2 = ''

    # for key 0<=i<=7 the value is the plaintext in byte 1
    p_i_dict = {}
    # the prev ciphertext that is using for decoding the index i in the next plaintext
    prev_c_block_dict = []
    if i != 0:
        prev_c_block_dict = ciphertext_arrays[i-1]
    else:
        prev_c_block_dict = iv_as_first_block

    for k in range(0, 8):
        c1 = c1_options[k]
        # the byte we want to find with the oracle
        c1_2 = bytes([0]).hex()
        # find the byte using the oracle
        for i_1 in range(0, 256):
            c1_2 = bytes([i_1]).hex()
            new_ciphertext = c1 + c1_2 + c2_2 + c_i
            if oracle(bytes.fromhex(new_ciphertext), key, iv) is True:
                break
        # after we know the 8 bytes that return true, we can calculate the 7-k index
        # (k + 1) - the padding we know . first iteration(i=0) the padding is 1, second is 2.... -> i+1
        # prev_c_block_dict[7 - k] - the same index in the prev cipher text
        p_i_dict[7 - k] = xor((k + 1), prev_c_block_dict[7 - k], int(c1_2, base=16)).hex()
        if k == 7:
            break
        else:
            # Fixing the values that we will chain to c_i in the next iteration and then using the oracle,
            # we will find the relevant byte
            c2_2 = ''
            # after we know the k right bytes, we can set the k right bytes of what we will chain to c_i
            # to be k+1 so that the plaintext of the channing we create, will end with the padding we want
            # so if we are here in the k-th iteration, we find the k+1 right bytes of what we will chain to c_i
            # example : when k=3 we know the 4 right bytes of the plain text so 8-k-1 = 4, t = 4,5,6,7
            # we need to create padding of 5 (3+2 = 5), so we want to find the t byte in what we will chain to c_i
            for t in range(8 - k - 1, 8):
                c2_2 = c2_2 + xor((k + 2), prev_c_block_dict[t], int(p_i_dict[t], base=16)).hex()
    # after finding the i block, we will add it to the plaintext_dicts which will eventually contain all the plaintext
    plaintext_dicts[i] = p_i_dict

result = ''
for l_outter in range(0, num_of_blocks):
    for l_inner in range(0, 8):
        result += plaintext_dicts[l_outter][l_inner]
print(unpad(bytes.fromhex(result), DES.block_size).decode('utf-8'))
