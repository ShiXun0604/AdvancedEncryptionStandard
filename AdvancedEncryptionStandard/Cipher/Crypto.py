# External
import random
# internal
from AdvancedEncryptionStandard.Cipher.AESstatic import *
from AdvancedEncryptionStandard.IO import Converter



def xor_bytes(data1: bytes, data2: bytes) -> bytes:
    if len(data1) != len(data2):
        raise ValueError("Input bytes must have the same length")
    
    return bytes(a ^ b for a, b in zip(data1, data2))


class AESkey():
    def __init__(self) -> None:
        self.key = None

    
    @property
    def keylen(self) -> int:
        if not self.key:
            return None
        else:
            return len(self.key)
    

    @staticmethod 
    def generate_key(keylen: int = 256) -> str:
        if keylen not in [128, 192, 256]:
            error_message = 'not support'
        data = ''.join(str(random.randint(0, 1)) for _ in range(keylen))
        return hex(int(data, 2))
    

    @staticmethod
    def gen_round_key(curr_key: bytes, j: int) -> bytes:
        # 組成word
        word = []
        for i in range(0, len(curr_key), 4):
            word.append(curr_key[i:i+4])

        # 開始function g
        iter_time = 4
        if j == 0:
            iter_time = len(word)
        
        for i in range(len(word), len(word)+iter_time, 1):
            # 256 bits
            if len(curr_key) == 32:
                
                if i % 8 == 0:
                    # 第一項
                    w_1 = word[i-1]
                    
                    # 第二項
                    rot_w_1 = w_1[1:] + w_1[:1]
                    result_word_i = b''
                    for i in rot_w_1:
                        result_word_i += SBOX[i]

                    # 第三項
                    print(result_word_i)


                pass
            # 192 bits
            elif len(curr_key) == 24:
                pass
            # 128 bits
            elif len(curr_key) == 16:
                pass

        


