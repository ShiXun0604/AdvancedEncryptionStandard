from AdvancedEncryptionStandard.Cipher import Crypto
from AdvancedEncryptionStandard.IO import Converter



def key_generation_demo():
    AES_key = Crypto.AESKey.generate_key(256)

    with open('key.pem', 'wb') as f:
        f.write(AES_key.extract_key())


def encryption_demo():
    # 創建加密工具物件
    crypto_obj = Crypto.AESCrypto()

    # 載入金鑰
    with open('key.pem', 'rb') as f:
        key = f.read()
    crypto_obj.import_key(key)

    # 加密訊息
    data = '0x3243f6a8885a308d313198a2e03707343333'
    data = Converter.hex_to_bytes(data)
    cipher_text = crypto_obj.encrypt(data)

    # 儲存密文
    with open('cipher_text.bin', 'wb') as f:
        f.write(cipher_text)


def decryption_demo():
    # 創建加密工具物件
    crypto_obj = Crypto.AESCrypto()

    # 載入金鑰
    with open('key.pem', 'rb') as f:
        key = f.read()
    crypto_obj.import_key(key)

    # 載入密文
    with open('cipher_text.bin', 'rb') as f:
        cipher_text = f.read()

    # 解密訊息
    crypto_obj.decrypt(cipher_text)


encryption_demo()
a = decryption_demo()

