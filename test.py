from AdvancedEncryptionStandard.Cipher import Crypto
from AdvancedEncryptionStandard.IO import Converter




AES_key = Crypto.AESkey.generate_key(256)
b_AES_key = Converter.hex_to_bytes(AES_key)


Crypto.AESkey.gen_round_key(b_AES_key, 0)


