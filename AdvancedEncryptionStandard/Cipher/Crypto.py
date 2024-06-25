# External
from __future__ import annotations
import random, base64
# internal
from AdvancedEncryptionStandard.Cipher.AESoperations import *
from AdvancedEncryptionStandard.Cipher.AESstatic import *
from AdvancedEncryptionStandard.IO import Converter



__all__ = ['AESKey', 'AESCrypto']



class AESKey():
    def __init__(self, key: bytes = None) -> None:
        self.key = key
        self.round_key = self.gen_round_key() if key else None


    @property
    def keylen(self) -> int:
        if not self.key:
            return None
        else:
            return len(self.key) * 8
    

    @staticmethod
    def generate_key(keylen: int = 256) -> str:
        if keylen not in VALID_KEYLEN:
            error_message = 'Not support key length.'
            raise ValueError(error_message)
        
        bin_key = ''.join(str(random.randint(0, 1)) for _ in range(keylen))
        bytes_key = Converter.binary_to_bytes(bin_key)
        return AESKey(bytes_key)
    

    # 符號參考維基百科 https://en.wikipedia.org/wiki/AES_key_schedule
    def gen_round_key(self) -> bytes:
        # 拆分key
        K = []
        for i in range(0, int(self.keylen/8), 4):
            K.append(self.key[i:i+4])
        N = len(K)

        # R為round key數 + 1
        R_list = {128: 11, 192: 13, 256: 15}
        R = R_list[self.keylen]
        
        # 計算round key
        W = []
        for i in range(4*R):
            if i < N:
                word = K[i]
            elif i % N == 0:
                a = W[i-N]
                b = sub_word(rot_word(W[i-1]))
                c = RCON[int(i/N)]
                word = xor_bytes(xor_bytes(a, b), c)
            elif N > 6 and i % N == 4:
                a = W[i-N]
                b = sub_word(W[i-1])
                word = xor_bytes(a, b)
            else:
                word = xor_bytes(W[i-N], W[i-1])

            W.append(word)

        self.round_key = W
        return W
        

    def extract_key(self) -> bytes:
        key = self.key
        hex_key = Converter.bytes_to_hex(key)

        ext_str = b'-----BEGIN AES KEY-----' + b'\n'
        ext_str += hex_key.encode() + b'\n-----END AES KEY-----'

        return ext_str
    
    def import_key(self, data: bytes) -> None:
        data_list = data.decode().split('\n')
        bytes_key = Converter.hex_to_bytes(data_list[1])

        if len(bytes_key)*8 not in VALID_KEYLEN:
            error_message = 'Not support key length.'
            raise ValueError(error_message)

        self.key = bytes_key
        self.round_key = self.gen_round_key()

        

class AESCrypto(AESKey):
    def __init__(self) -> None:
        super().__init__()


    def encrypt(self, data: bytes) -> bytes:
        if not isinstance(data, bytes):
            error_message = 'Invalid data type input.'
            raise ValueError(error_message)
        
        # 填充明文,使其長度為16的倍數
        padd_len = 16 - (len(data) % 16) if len(data) % 16 else 0
        padd_data = data
        for _ in range(padd_len):
            padd_data += b'\x00'
        
        # 分割block
        block_list = []
        for i in range(0, len(padd_data), 16):
            block_list.append(padd_data[i:i+16])

        # 加密所有的block
        cipher_text = b''
        for block in block_list:
            index = 0

            # 先把block拆成4x4大小矩陣
            word_list = []
            for i in range(0, 16, 4):
                word_list.append(block[i:i+4])

            # 初始輪
            add_round_key(word_list, self.round_key[index:index+4])
            index += 4
            
            # 中間輪
            iter_time = {128: 9, 192: 11, 256:13}
            for i in range(iter_time[self.keylen]):
                sub_bytes(word_list)
                shift_rows(word_list)
                mix_columns(word_list)
                add_round_key(word_list, self.round_key[index:index+4])
                index += 4
            
            # 最終輪
            sub_bytes(word_list)
            shift_rows(word_list)
            add_round_key(word_list, self.round_key[index:index+4])
            
            # 把此block的密文寫入結果
            for word in word_list:
                cipher_text += word

        cipher_text = base64.b64encode(cipher_text)
        return cipher_text


    def decrypt(self, padd_data: bytes) -> bytes:
        if not isinstance(padd_data, bytes):
            error_message = 'Invalid data type input.'
            raise ValueError(error_message)
        padd_data = base64.b64decode(padd_data)

        # 分割block
        block_list = []
        for i in range(0, len(padd_data), 16):
            block_list.append(padd_data[i:i+16])
        
        # 解密所有的block
        text = b''
        for block in block_list:
            index = len(self.round_key) - 4

            # 先把block拆成4x4大小矩陣
            word_list = []
            for i in range(0, 16, 4):
                word_list.append(block[i:i+4])
            
            # 初始輪
            add_round_key(word_list, self.round_key[index:index+4])
            index -= 4
            inv_shift_rows(word_list)
            inv_sub_bytes(word_list)

            # 中間輪
            iter_time = {128: 9, 192: 11, 256:13}
            for i in range(iter_time[self.keylen]):
                add_round_key(word_list, self.round_key[index:index+4])
                index -= 4
                inv_mix_columns(word_list)
                inv_shift_rows(word_list)
                inv_sub_bytes(word_list)
            
            # 最終輪
            add_round_key(word_list, self.round_key[index:index+4])

            # 把此block的明文寫入結果
            for word in word_list:
                text += word
        
        print(text)
        
        

            
            
            
        
        
        



