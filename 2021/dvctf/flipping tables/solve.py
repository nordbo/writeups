from pwn import *
import binascii
io = remote("challs.dvc.tf", 3333)
pwd = b''
while(True):
	arr = {}
	io.recvuntil('encrypt?')
	lolzz = b'41' * (31-len(pwd))
	io.sendline(lolzz)
	print(lolzz)
	real = io.recvline().split(b' ')[5][32:64]
	for i in range(0x100):
		io.recvuntil('encrypt?')
		io.sendline(b'41' * (31 - len(pwd)) + binascii.hexlify(pwd) + binascii.hexlify(bytes([i])))
		data = io.recvline().split(b' ')[5][32:64]
		aa = b'41' * (31 - len(pwd)) + binascii.hexlify(pwd) + binascii.hexlify(bytes([i]))
		print(f'pw: {pwd}, send: {aa}, recv: {data}, t: {real}')
		if data == real:	
			pwd += bytes([i])
			print(pwd)
			break
# new block @ 4141414141414141 = 8 bytes
#dvCTF{3CB_4ngry_0r4cl3}
