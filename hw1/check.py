#!/usr/bin/python3
import sys
from pwn import *

elf = ELF(sys.argv[1])

cmd = {
    "open": "opens a file",
    "read": "reads a file",
    "write": "writes to a file",
    "connect": "connects to a remote server",
    "getaddrinfo": "resolves a hostname to an IP address",
    "system": "executes a shell command",
    "close": "close a file"
}
with open("got.txt", "w") as f:
   for g in elf.got:
      if g in cmd:
         print("{} {}".format(g, elf.got[g]), file=f)

