from pwn import *

HOST = 'chall.polygl0ts.ch'
PORT = 9001
context.log_level = 'critical'

while True:
    io = remote(HOST,PORT)
    flag = 0
    io.recvline()
    payload = enhex(b'B').encode()
    for t in range(4):
        io.recvline()
        io.sendline(payload)
        server_response = io.recvline().decode().strip()
        print(server_response)
        if server_response!="it's valid":
            
            break
        else:
            print(r)
            flag = 1
    if flag:
        break

io.interactive()