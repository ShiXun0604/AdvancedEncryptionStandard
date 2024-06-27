# External
from __future__ import annotations
import random, base64, hashlib
# internal
from AdvancedEncryptionStandard.Cipher import AESoperations as Aops
from AdvancedEncryptionStandard.Cipher.AESstatic import RCON, VALID_KEYLEN
from AdvancedEncryptionStandard.IO import Converter
from AdvancedEncryptionStandard.IO import Error as Error



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
        # 偵錯
        if self.keylen not in VALID_KEYLEN:
            error_message = 'Not support key length.'
            raise ValueError(error_message)
        
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
                b = Aops.sub_word(Aops.rot_word(W[i-1]))
                c = RCON[int(i/N)]
                word = Aops.xor_bytes(Aops.xor_bytes(a, b), c)
            elif N > 6 and i % N == 4:
                a = W[i-N]
                b = Aops.sub_word(W[i-1])
                word = Aops.xor_bytes(a, b)
            else:
                word = Aops.xor_bytes(W[i-N], W[i-1])

            W.append(word)

        self.round_key = W
        return W
        

    def extract_key(self) -> bytes:
        if not self.key:
            error_message = 'No AES key import/generate in class.'
            raise Error.KeyExtractionError(error_message)

        hex_key = Converter.bytes_to_hex(self.key)

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
            raise TypeError(error_message)
                
        # 填充明文,使其長度為16的倍數
        padd_len = 16 - (len(data) % 16) if len(data) % 16 else 0
        padd_data = data
        for _ in range(padd_len):
            padd_data += b'\x00'
                       
        # 分割block
        block_list = []
        for i in range(0, len(padd_data), 16):
            block_list.append(padd_data[i:i+16])

        # 將明文的長度以及hash值寫入最前面
        hash_value = '0x' + hashlib.sha256(data).hexdigest()
        hash_value = Converter.hex_to_bytes(hash_value)
        
        check_sum = padd_len.to_bytes(length=1, byteorder='big') + hash_value
    
        # 加密所有的block
        cipher_text = check_sum
        for block in block_list:
            index = 0

            # 先把block拆成4x4大小矩陣
            word_list = []
            for i in range(0, 16, 4):
                word_list.append(block[i:i+4])

            # 初始輪
            Aops.add_round_key(word_list, self.round_key[index:index+4])
            index += 4
            
            # 中間輪
            iter_time = {128: 9, 192: 11, 256:13}
            for i in range(iter_time[self.keylen]):
                Aops.sub_bytes(word_list)
                Aops.shift_rows(word_list)
                Aops.mix_columns(word_list)
                Aops.add_round_key(word_list, self.round_key[index:index+4])
                index += 4
            
            # 最終輪
            Aops.sub_bytes(word_list)
            Aops.shift_rows(word_list)
            Aops.add_round_key(word_list, self.round_key[index:index+4])
            
            # 把此block的密文寫入結果
            for word in word_list:
                cipher_text += word
        
        cipher_text = base64.b64encode(cipher_text)
        return cipher_text


    def decrypt(self, padd_data: bytes) -> bytes:
        # 除錯:輸入的type不正確
        if not isinstance(padd_data, bytes):
            error_message = 'Invalid data type input.'
            raise TypeError(error_message)
        # 除錯:class內沒有金鑰
        if not self.key:
            error_message = 'Decryption requires key. No key imported.'
            raise Error.NoKeyError(error_message)
        
        try:
            padd_data = base64.b64decode(padd_data)
            # 分割檢查碼
            check_sum = padd_data[:33]
            cipher_text = padd_data[33:]
            
            # 分割block
            block_list = []
            for i in range(0, len(cipher_text), 16):
                block_list.append(cipher_text[i:i+16])
            
            # 解密所有的block
            text = b''
            for block in block_list:
                index = len(self.round_key) - 4

                # 先把block拆成4x4大小矩陣
                word_list = []
                for i in range(0, 16, 4):
                    word_list.append(block[i:i+4])
                
                # 初始輪
                Aops.add_round_key(word_list, self.round_key[index:index+4])
                index -= 4
                Aops.inv_shift_rows(word_list)
                Aops.inv_sub_bytes(word_list)

                # 中間輪
                iter_time = {128: 9, 192: 11, 256:13}
                for i in range(iter_time[self.keylen]):
                    Aops.add_round_key(word_list, self.round_key[index:index+4])
                    index -= 4
                    Aops.inv_mix_columns(word_list)
                    Aops.inv_shift_rows(word_list)
                    Aops.inv_sub_bytes(word_list)
                
                # 最終輪
                Aops.add_round_key(word_list, self.round_key[index:index+4])

                # 把此block的明文寫入結果
                for word in word_list:
                    text += word
        except:
            error_message = 'Decrypt failed.'
            raise Error.DecryptionError(error_message)
        
        # 資料檢查
        padd_len = check_sum[0]
        hash_value = Converter.bytes_to_hex(check_sum[1:])[2:]
        
        text = text[:-padd_len]  # 去除padding

        # 檢查hash value是否匹配
        if hash_value != hashlib.sha256(text).hexdigest():  
            error_message = 'Decrypt failed.'
            raise Error.DecryptionError(error_message)
        
        return text