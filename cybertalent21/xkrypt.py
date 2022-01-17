import string
from pwn import *
encryptedFlag = open('flagg.txt.x').readline()
INT_BITS = 32

def a( a1):
    if ( a1 == 1 ):
        return 1
    if ( (a1 & 1) != 0 ):
        return a(3 * a1 + 1) + 1
    return a(a1 // 2) + 1

def a2(c):
    v10 = 5 * c // 2
    v11 = v10 + 2 * a(c) - 1
    return v11

revMap = {}

#reverse map for a() func
for x in string.ascii_lowercase + string.digits:
    res = a2(ord(x)) & 0xff
    revMap[res] = x



def __ROL4__(n, d):
    return ((n << d)|(n >> (INT_BITS - d))) & 0xFFFFFFFF

def __ROR4__(n, d):
    return (n >> d)|(n << (INT_BITS - d)) & 0xFFFFFFFF

def minusEquals(subst,orig):
    if subst > orig:
        return orig+0x100000000-subst
    return orig-subst

def splt(line, n):
    return [line[i:i+n] for i in range(0, len(line), n)]

encryptedFlag = splt(encryptedFlag, 128)
flag = ''
for block in encryptedFlag:
    v6 = [u32(bytes.fromhex(x)) for x in splt(block, 8)]
    
    for i in range(10):
        v6[4] = __ROR4__(v6[4], 7)
        v6[4] ^= v6[9]
        v6[9] = minusEquals(v6[14], v6[9])
        v6[14] = __ROR4__(v6[14], 8)
        v6[14] ^= v6[3]
        v6[3] = minusEquals(v6[4], v6[3])
        v6[4] = __ROR4__(v6[4], 12)
        v6[4] ^= v6[9]
        v6[9] = minusEquals(v6[14], v6[9])
        v6[14] = __ROR4__(v6[14], 16)
        v6[14] ^= v6[3]
        v6[3] = minusEquals(v6[4], v6[3])
        v6[7] = __ROR4__(v6[7], 7)
        v6[7] ^= v6[8]
        v6[8] = minusEquals(v6[13], v6[8])
        v6[13] = __ROR4__(v6[13], 8)
        v6[13] ^= v6[2]
        v6[2] = minusEquals(v6[7], v6[2] )
        v6[7] = __ROR4__(v6[7], 12)
        v6[7] ^= v6[8]
        v6[8] = minusEquals(v6[13], v6[8])
        v6[13] = __ROR4__(v6[13], 16)
        v6[13] ^= v6[2]
        v6[2] = minusEquals(v6[7], v6[2])
        v6[6] = __ROR4__(v6[6], 7)
        v6[6] ^= v6[11]
        v6[11] = minusEquals(v6[12], v6[11])
        v6[12] = __ROR4__(v6[12], 8)
        v6[12] ^= v6[1]
        v6[1] = minusEquals(v6[6], v6[1])
        v6[6] = __ROR4__(v6[6], 12)
        v6[6] ^= v6[11]
        v6[11] = minusEquals(v6[12], v6[11] )
        v6[12] = __ROR4__(v6[12], 16)
        v6[12] ^= v6[1]
        v6[1] = minusEquals(v6[6], v6[1] )
        v6[5] = __ROR4__(v6[5], 7)
        v6[5] ^= v6[10]
        v6[10] = minusEquals(v6[15], v6[10])
        v6[15] = __ROR4__(v6[15], 8)
        v6[15] ^= v6[0]
        v6[0] = minusEquals(v6[5], v6[0])
        v6[5] = __ROR4__(v6[5], 12)
        v6[5] ^= v6[10]
        v6[10] = minusEquals(v6[15], v6[10])
        v6[15] = __ROR4__(v6[15], 16)
        v6[15] ^= v6[0]
        v6[0] = minusEquals(v6[5], v6[0] )
        v6[7] = __ROR4__(v6[7], 7)
        v6[7] ^= v6[11]
        v6[11] = minusEquals(v6[15], v6[11])
        v6[15] = __ROR4__(v6[15], 8)
        v6[15] ^= v6[3]
        v6[3] = minusEquals(v6[7], v6[3])
        v6[7] = __ROR4__(v6[7], 12)
        v6[7] ^= v6[11]
        v6[11] = minusEquals(v6[15], v6[11])
        v6[15] = __ROR4__(v6[15], 16)
        v6[15] ^= v6[3]
        v6[3] = minusEquals(v6[7], v6[3])
        v6[6] = __ROR4__(v6[6], 7)
        v6[6] ^= v6[10]
        v6[10] = minusEquals(v6[14], v6[10])
        v6[14] = __ROR4__(v6[14], 8)
        v6[14] ^= v6[2]
        v6[2] = minusEquals(v6[6], v6[2] )
        v6[6] = __ROR4__(v6[6], 12)
        v6[6] ^= v6[10]
        v6[10] = minusEquals(v6[14], v6[10])
        v6[14] = __ROR4__(v6[14], 16)
        v6[14] ^= v6[2]
        v6[2] = minusEquals(v6[6], v6[2] )
        v6[5] = __ROR4__(v6[5], 7)
        v6[5] ^= v6[9]
        v6[9] = minusEquals(v6[13], v6[9] )
        v6[13] = __ROR4__(v6[13], 8)
        v6[13] ^= v6[1]
        v6[1] = minusEquals(v6[5], v6[1] )
        v6[5] = __ROR4__(v6[5], 12)
        v6[5] ^= v6[9]
        v6[9] = minusEquals(v6[13], v6[9])
        v6[13] = __ROR4__(v6[13], 16)
        v6[13] ^= v6[1]
        v6[1] = minusEquals(v6[5], v6[1])
        v6[4] = __ROR4__(v6[4], 7)
        v6[4] ^= v6[8]
        v6[8] = minusEquals(v6[12], v6[8])
        v6[12] = __ROR4__(v6[12], 8)
        v6[12] ^= v6[0]
        v6[0] = minusEquals(v6[4], v6[0] )
        v6[4] = __ROR4__(v6[4], 12)
        v6[4] ^= v6[8]
        v6[8] = minusEquals(v6[12], v6[8])
        v6[12] = __ROR4__(v6[12], 16)
        v6[12] ^= v6[0]
        v6[0] = minusEquals(v6[4], v6[0] )


    for i in range(10):
        v6[15] ^= __ROR4__((v6[14] + v6[13]) & 0xffffffff, 14)
        v6[14] ^= __ROL4__((v6[13] + v6[12]) & 0xffffffff, 13)
        v6[13] ^= __ROL4__((v6[12] + v6[15]) & 0xffffffff, 9)
        v6[12] ^= __ROL4__((v6[15] + v6[14]) & 0xffffffff, 7)
        v6[10] ^= __ROR4__((v6[9] + v6[8]) & 0xffffffff, 14)
        v6[9] ^= __ROL4__((v6[8] + v6[11]) & 0xffffffff, 13)
        v6[8] ^= __ROL4__((v6[11] + v6[10]) & 0xffffffff, 9)
        v6[11] ^= __ROL4__((v6[10] + v6[9]) & 0xffffffff, 7)
        v6[5] ^= __ROR4__((v6[4] + v6[7]) & 0xffffffff, 14)
        v6[4] ^= __ROL4__((v6[7] + v6[6]) & 0xffffffff, 13)
        v6[7] ^= __ROL4__((v6[6] + v6[5]) & 0xffffffff, 9)
        v6[6] ^= __ROL4__((v6[5] + v6[4]) & 0xffffffff, 7)
        v6[0] ^= __ROR4__((v6[3] + v6[2]) & 0xffffffff, 14)
        v6[3] ^= __ROL4__((v6[2] + v6[1]) & 0xffffffff, 13)
        v6[2] ^= __ROL4__((v6[1] + v6[0]) & 0xffffffff, 9)
        v6[1] ^= __ROL4__((v6[0] + v6[3]) & 0xffffffff, 7)
        v6[15] ^= __ROR4__((v6[11] + v6[7]) & 0xffffffff, 14)
        v6[11] ^= __ROL4__((v6[7] + v6[3]) & 0xffffffff, 13)
        v6[7] ^= __ROL4__((v6[3] + v6[15]) & 0xffffffff, 9)
        v6[3] ^= __ROL4__((v6[15] + v6[11]) & 0xffffffff, 7)
        v6[10] ^= __ROR4__((v6[6] + v6[2]) & 0xffffffff, 14)
        v6[6] ^= __ROL4__((v6[2] + v6[14]) & 0xffffffff, 13)
        v6[2] ^= __ROL4__((v6[14] + v6[10]) & 0xffffffff, 9)
        v6[14] ^= __ROL4__((v6[10] + v6[6]) & 0xffffffff, 7)
        v6[5] ^= __ROR4__((v6[1] + v6[13]) & 0xffffffff, 14)
        v6[1] ^= __ROL4__((v6[13] + v6[9]) & 0xffffffff, 13)
        v6[13] ^= __ROL4__((v6[9] + v6[5]) & 0xffffffff, 9)
        v6[9] ^= __ROL4__((v6[5] + v6[1]) & 0xffffffff, 7)
        v6[0] ^= __ROR4__((v6[12] + v6[8]) & 0xffffffff, 14)
        v6[12] ^= __ROL4__((v6[8] + v6[4]) & 0xffffffff, 13)
        v6[8] ^= __ROL4__((v6[4] + v6[0]) & 0xffffffff, 9)
        v6[4] ^= __ROL4__((v6[0] + v6[12]) & 0xffffffff, 7)


    for i,x in enumerate(v6):
        if i % 5 == 0:
            for j in range(4):               
                mapIdx = ((x >> (j*8)) & 0xff)
                if mapIdx in revMap:
                    flag += revMap[mapIdx]
                else:
                    log.error("char not found in map")
                    exit(1)

assert flag == '0c508945bcf619c5fc4da1a560f92a6c'

print(flag)


