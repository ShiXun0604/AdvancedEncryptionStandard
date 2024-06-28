##  簡介
* 此repository沒有使用任何外部crypt library實現AES加密算法，金鑰長度可接受128、192、256bits。
* 通過solar qube源碼掃描，security報警數=0。
* 明明有library，為甚麼要從頭開始寫呢?因為閒閒沒事做(X別人的library在做源碼掃描時總是很多問題跑出來，改別人300個問題不如從頭開始QQ。

## 注意事項
* 開發版本：python 3.9.1
* 外部引用：\_\_future\_\_、random、hashlib、base64


## 如何使用

### 1. 生成公鑰、私鑰對
&emsp;&emsp;載入Crypto module，此module包含加解密過程中所需的函式。
```python
from AdvancedEncryptionStandard.Cipher import Crypto
```

<br>

&emsp;&emsp;使用AESkey的generate_key()方法產生金鑰、長度限定128、192、256。並且可以使用extract_key()將金鑰檔(.pem)儲存下來。
```python
AES_key = Crypto.AESKey.generate_key(256)

with open('k1.pem', 'wb') as f:
    f.write(AES_key.extract_key())
```

<br>

### 2. 資料加密
&emsp;&emsp;加密可接受的資料型態為bytes，若不是bytes可使用package中的converter針對不同資料型態來源進行轉換。
```python
from  DualRegev.IO  import  Converter
```
<br>

&emsp;&emsp;以下是加密的詳細流程:首先建立加密物件，接著使用import_key方法把金鑰讀取進來後，使用encrypt方法加密即可。
```python
crypto_obj = Crypto.AESCrypto()

# 載入金鑰
with open('k1.pem', 'rb') as f:
    key = f.read()
crypto_obj.import_key(key)

# 加密訊息
data = 'sddas'
data = data.encode()
cipher_text = crypto_obj.encrypt(data)

# 儲存密文
with open('cipher_text.bin', 'wb') as f:
    f.write(cipher_text)
```
<br>

### 3. 資料解密
&emsp;&emsp;解密方法回傳的資料型態為bytes，使用AESCrypto中的方法decrypt即可進行解密。
```python
# 創建加密工具物件
crypto_obj = Crypto.AESCrypto()

# 載入金鑰
with open('k1.pem', 'rb') as f:
    key = f.read()
crypto_obj.import_key(key)

# 載入密文
with open('cipher_text.bin', 'rb') as f:
    cipher_text = f.read()

# 解密訊息
data = crypto_obj.decrypt(cipher_text).decode()
print(data)
```
