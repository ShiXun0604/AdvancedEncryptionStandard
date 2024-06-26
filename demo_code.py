from AdvancedEncryptionStandard.Cipher import Crypto
from AdvancedEncryptionStandard.IO import Converter
# example key:0x2b7e151628aed2a6abf7158809cf4f3c


def key_generation_demo():
    AES_key = Crypto.AESKey.generate_key(192)

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
    data = '嗨你好我是ShiXun,我正在練習寫程式。'.encode()
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
    data = crypto_obj.decrypt(cipher_text).decode()
    print(data)


if __name__ == '__main__':
    key_generation_demo()
    encryption_demo()
    decryption_demo()