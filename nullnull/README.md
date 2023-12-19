# CRYPTO: nullnull
solvers: [L3d](https://github.com/imL3d), [N04M1st3r](https://github.com/N04M1st3r)  
writeup-writer: [L3d](https://github.com/imL3d)  

**Description:**
>Welcome to my secure flag sharer where there are null nulls!
>  nc 0.cloud.chals.io 15076

**files (copy):** [server.py](files/server.py)

In this challenge we receive a connection to the server that sends us the flag encrypted strongly 
## Solution🕵️
Upon analyzing the server code we can understand that it encrypts the flag each time with a newly created key which is at least the length of the flag (essentially an [OTP](https://en.wikipedia.org/wiki/One-time_pad)).  
After goofing around and trying to break python's random ([it is possible!](https://www.kaggle.com/code/taahakhan/rps-cracking-random-number-generators)), we saw a little bug in this code: it never (never) includes a part of the original key in the ciphertext - ** the random key generation starts with 1, not 0 **.  
In order to exploit this vulnerability we just need to track the letters given, and with enough retries we can find out what characters aren't used... 
```python
import socket
from string import printable

options = [[p for p in printable[:-2]] for _ in range(49)]

sock = socket.socket()
sock.connect(('0.cloud.chals.io', 15076))
data = sock.recv(1024)

iteration = 1
while True:
    sock.sendall(b'Y\n')
    data = sock.recv(1024).decode()
    recived = ''.join(data.split('\n')[:-1])

    try:
        enc = eval(recived) # eval is evil... but we trust the server, right? RIGHT???
    except Exception as e:
        print(e)
        print(recived)
        exit()

    for i, c in enumerate(enc):
        if chr(c) in options[i]:
            options[i].remove(chr(c))

    print(f'{iteration=}')
    print([len(o) for o in options])
    iteration+=1

    with open('output.txt', 'w') as f:
        for o in options:
            f.write(str(o) + ', \n')

sock.close()
```
Running this code (for some reason `pwntools` didn't work if you wondered), results in the flag 🚩:   
`flag{so_many_possibilities_but_only_one_solution}` 
