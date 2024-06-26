from AdvancedEncryptionStandard.Cipher.AESstatic import *



__all__ = [
    'xor_bytes', 
    'rot_word', 
    'sub_word', 
    'add_round_key',
    'sub_bytes',
    'shift_rows',
    'mix_columns',
    'inv_sub_bytes',
    'inv_shift_rows',
    'inv_mix_columns',
]



def xor_bytes(data1: bytes, data2: bytes) -> bytes:
    if len(data1) != len(data2):
        raise ValueError("Input bytes must have the same length")
    
    return bytes(a ^ b for a, b in zip(data1, data2))


def rot_word(data: bytes) -> bytes:
    return data[1:] + data[:1]


def sub_word(data: bytes) -> bytes:
    result = b''
    for j in data:  # sbox
        result += SBOX[j]
    return result


def add_round_key(word_list: list[bytes], round_key: list[bytes]) -> None:
    for i in range(4):
        word = xor_bytes(word_list[i], round_key[i])
        word_list[i] = word


# -----Encrypt-----
def sub_bytes(word_list: list[bytes]) -> None:
    for i in range(4):
        word = b''
        for j in range(4):
            word += SBOX[word_list[i][j]]
        word_list[i] = word


def shift_rows(word_list: list[bytes]) -> None:
    result = []
    for i in range(4):
        word = b''
        for j in range(4):
            word += word_list[(i+j)%4][j].to_bytes(length=1, byteorder='big')
        result.append(word)
    
    for i in range(4):
        word_list[i] = result[i]


def mix_columns(word_list: list[bytes]) -> None:
    # 真的看不懂，透過ghatGPT生成的,反正結果有檢查是對的
    def gmul(a, b):
        """Galois Field (256) Multiplication of two Bytes"""
        p = 0
        for counter in range(8):
            if b & 1:
                p ^= a
            carry = a & 0x80
            a <<= 1
            if carry:
                a ^= 0x1b
            b >>= 1
        return p & 0xFF

    def mix_single_column(column):
        """Mix one column of the state matrix"""
        temp = column.copy()
        column[0] = gmul(temp[0], 2) ^ gmul(temp[3], 1) ^ gmul(temp[2], 1) ^ gmul(temp[1], 3)
        column[1] = gmul(temp[1], 2) ^ gmul(temp[0], 1) ^ gmul(temp[3], 1) ^ gmul(temp[2], 3)
        column[2] = gmul(temp[2], 2) ^ gmul(temp[1], 1) ^ gmul(temp[0], 1) ^ gmul(temp[3], 3)
        column[3] = gmul(temp[3], 2) ^ gmul(temp[2], 1) ^ gmul(temp[1], 1) ^ gmul(temp[0], 3)

    def mix_column(state):
        """Perform MixColumns on the state matrix"""
        for i in range(4):
            mix_single_column(state[i])

    state_matrix = [[word[i] for word in word_list] for i in range(4)]
    state_matrix = [list(x) for x in zip(*state_matrix)]

    mix_column(state_matrix)

    word_list_mixed = [bytes([state_matrix[col][row] for row in range(4)]) for col in range(4)]

    for i, word in enumerate(word_list_mixed):
        word_list[i] = word


# -----Decrypt-----
def inv_sub_bytes(word_list: list[bytes]) -> None:
    for i in range(4):
        word = b''
        for j in range(4):
            word += INVERSE_SBOX[word_list[i][j]]
        word_list[i] = word


def inv_shift_rows(word_list: list[bytes]) -> None:
    result = []
    for i in range(4):
        word = b''
        for j in range(4):
            word += word_list[(i-j)%4][j].to_bytes(length=1, byteorder='big')
        result.append(word)
    
    for i in range(4):
        word_list[i] = result[i]


def inv_mix_columns(word_list: list[bytes]) -> None:
    # 真的看不懂，透過ghatGPT生成的,反正結果有檢查是對的
    def gmul(a, b):
        """Galois Field (256) Multiplication of two Bytes"""
        p = 0
        for counter in range(8):
            if b & 1:
                p ^= a
            carry = a & 0x80
            a <<= 1
            if carry:
                a ^= 0x1b
            b >>= 1
        return p & 0xFF

    def mix_single_column(column):
        """Mix one column of the state matrix using the inverse mix columns transformation"""
        temp = column.copy()
        column[0] = gmul(temp[0], 0x0e) ^ gmul(temp[1], 0x0b) ^ gmul(temp[2], 0x0d) ^ gmul(temp[3], 0x09)
        column[1] = gmul(temp[0], 0x09) ^ gmul(temp[1], 0x0e) ^ gmul(temp[2], 0x0b) ^ gmul(temp[3], 0x0d)
        column[2] = gmul(temp[0], 0x0d) ^ gmul(temp[1], 0x09) ^ gmul(temp[2], 0x0e) ^ gmul(temp[3], 0x0b)
        column[3] = gmul(temp[0], 0x0b) ^ gmul(temp[1], 0x0d) ^ gmul(temp[2], 0x09) ^ gmul(temp[3], 0x0e)

    def mix_column(state):
        """Perform Inverse MixColumns on the state matrix"""
        for i in range(4):
            mix_single_column(state[i])

    state_matrix = [[word[i] for word in word_list] for i in range(4)]
    state_matrix = [list(x) for x in zip(*state_matrix)]

    mix_column(state_matrix)

    word_list_mixed = [bytes([state_matrix[col][row] for row in range(4)]) for col in range(4)]

    for i, word in enumerate(word_list_mixed):
        word_list[i] = word