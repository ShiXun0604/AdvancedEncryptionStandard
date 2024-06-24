# Python版AES实现

# 常量定义
AES_Sbox = [
    99,124,119,123,242,107,111,197,48,1,103,43,254,215,171,
    118,202,130,201,125,250,89,71,240,173,212,162,175,156,164,114,192,183,253,
    147,38,54,63,247,204,52,165,229,241,113,216,49,21,4,199,35,195,24,150,5,154,
    7,18,128,226,235,39,178,117,9,131,44,26,27,110,90,160,82,59,214,179,41,227,
    47,132,83,209,0,237,32,252,177,91,106,203,190,57,74,76,88,207,208,239,170,
    251,67,77,51,133,69,249,2,127,80,60,159,168,81,163,64,143,146,157,56,245,
    188,182,218,33,16,255,243,210,205,12,19,236,95,151,68,23,196,167,126,61,
    100,93,25,115,96,129,79,220,34,42,144,136,70,238,184,20,222,94,11,219,224,
    50,58,10,73,6,36,92,194,211,172,98,145,149,228,121,231,200,55,109,141,213,
    78,169,108,86,244,234,101,122,174,8,186,120,37,46,28,166,180,198,232,221,
    116,31,75,189,139,138,112,62,181,102,72,3,246,14,97,53,87,185,134,193,29,
    158,225,248,152,17,105,217,142,148,155,30,135,233,206,85,40,223,140,161,
    137,13,191,230,66,104,65,153,45,15,176,84,187,22
]

AES_ShiftRowTab = [0,5,10,15,4,9,14,3,8,13,2,7,12,1,6,11]

AES_Sbox_Inv = [0] * 256
AES_ShiftRowTab_Inv = [0] * 16
AES_xtime = [0] * 256

# 初始化函数
def AES_Init():
    for i in range(256):
        AES_Sbox_Inv[AES_Sbox[i]] = i
    for i in range(16):
        AES_ShiftRowTab_Inv[AES_ShiftRowTab[i]] = i
    for i in range(128):
        AES_xtime[i] = i << 1
        AES_xtime[128 + i] = (i << 1) ^ 0x1b

AES_Init()

def printBytes(b):
    print(" ".join(map(str, b)))

def AES_SubBytes(state, sbox):
    for i in range(16):
        state[i] = sbox[state[i]]

def AES_AddRoundKey(state, rkey):
    for i in range(16):
        state[i] ^= rkey[i]

def AES_ShiftRows(state, shifttab):
    h = state.copy()
    for i in range(16):
        state[i] = h[shifttab[i]]

def AES_MixColumns(state):
    for i in range(0, 16, 4):
        s0, s1, s2, s3 = state[i:i+4]
        h = s0 ^ s1 ^ s2 ^ s3
        state[i] ^= h ^ AES_xtime[s0 ^ s1]
        state[i + 1] ^= h ^ AES_xtime[s1 ^ s2]
        state[i + 2] ^= h ^ AES_xtime[s2 ^ s3]
        state[i + 3] ^= h ^ AES_xtime[s3 ^ s0]

def AES_MixColumns_Inv(state):
    for i in range(0, 16, 4):
        s0, s1, s2, s3 = state[i:i+4]
        h = s0 ^ s1 ^ s2 ^ s3
        xh = AES_xtime[h]
        h1 = AES_xtime[AES_xtime[xh ^ s0 ^ s2]] ^ h
        h2 = AES_xtime[AES_xtime[xh ^ s1 ^ s3]] ^ h
        state[i] ^= h1 ^ AES_xtime[s0 ^ s1]
        state[i + 1] ^= h2 ^ AES_xtime[s1 ^ s2]
        state[i + 2] ^= h1 ^ AES_xtime[s2 ^ s3]
        state[i + 3] ^= h2 ^ AES_xtime[s3 ^ s0]

def AES_ExpandKey(key, keyLen):
    kl = keyLen
    ks, Rcon = 0, 1
    if kl == 16:
        ks = 16 * (10 + 1)
    elif kl == 24:
        ks = 16 * (12 + 1)
    elif kl == 32:
        ks = 16 * (14 + 1)
    else:
        raise ValueError("AES_ExpandKey: Only key lengths of 16, 24 or 32 bytes allowed!")
    
    for i in range(kl, ks, 4):
        temp = key[i-4:i]
        if i % kl == 0:
            temp = [AES_Sbox[temp[1]] ^ Rcon, AES_Sbox[temp[2]], AES_Sbox[temp[3]], AES_Sbox[temp[0]]]
            Rcon = (Rcon << 1) ^ (0x1b if Rcon >= 128 else 0)
        elif kl > 24 and i % kl == 16:
            temp = [AES_Sbox[temp[j]] for j in range(4)]
        for j in range(4):
            key.append(key[i + j - kl] ^ temp[j])
    return ks

def AES_Encrypt(block, key, keyLen):
    l = keyLen
    AES_AddRoundKey(block, key[0:16])
    for i in range(16, l - 16, 16):
        AES_SubBytes(block, AES_Sbox)
        AES_ShiftRows(block, AES_ShiftRowTab)
        AES_MixColumns(block)
        AES_AddRoundKey(block, key[i:i+16])
    AES_SubBytes(block, AES_Sbox)
    AES_ShiftRows(block, AES_ShiftRowTab)
    AES_AddRoundKey(block, key[i:i+16])

def AES_Decrypt(block, key, keyLen):
    l = keyLen
    AES_AddRoundKey(block, key[l-16:l])
    AES_ShiftRows(block, AES_ShiftRowTab_Inv)
    AES_SubBytes(block, AES_Sbox_Inv)
    for i in range(l-32, 0, -16):
        AES_AddRoundKey(block, key[i:i+16])
        AES_MixColumns_Inv(block)
        AES_ShiftRows(block, AES_ShiftRowTab_Inv)
        AES_SubBytes(block, AES_Sbox_Inv)
    AES_AddRoundKey(block, key[0:16])


def main():
    AES_Init()

    block = [0x11 * i for i in range(16)]
    print("原始訊息：", end=" "); printBytes(block)

    key = [i for i in range(32)]
    print("原始金鑰：", end=" "); printBytes(key)

    expandKeyLen = AES_ExpandKey(key, 32)
    print("展開金鑰：", end=" "); printBytes(key)

    AES_Encrypt(block, key, expandKeyLen)
    print("加密完後：", end=" "); printBytes(block)

    AES_Decrypt(block, key, expandKeyLen)
    print("解密完後：", end=" "); printBytes(block)

if __name__ == "__main__":
    main()
