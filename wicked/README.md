# CRYPTO: wicked
solvers: [L3d](https://github.com/imL3d)  
writeup-writer: [L3d](https://github.com/imL3d)  

**Description:**
>The dev team implemented their own crypto that's supposed to be perfect. Like super perfect. But there's no way they did it right... They gave me some ciphertext to try to decrypt. Can you help me?

**files (copy):** [ciphertext.txt](files/ciphertext.txt)

In this challenge we received 7 lines of encrypted text that we need to extract the flag from.
## Solution🕵️
In order to solve this challenge, we have to take advantage of the fact that the encrypted text was encrypted multiple times via the same [OTP](https://en.wikipedia.org/wiki/One-time_pad). Essentially, when an OTP is reused we can decipher it and using an existing part of the original messages we can start decrypting the messages (read more about this vulnerability [here](https://crypto.stackexchange.com/questions/59/taking-advantage-of-one-time-pad-key-reuse)).  
When implementing this to python3: 
```python
word = 'wicked'
word_hex = ''.join([hex(ord(c))[2:] for c in word])
word_int = int(word_hex, 16)

# xor two lines from the original chiphertext and store it in xored.txt
with open('xored.txt', 'r') as f: 
    for line in f:
        for hex_str in [line[i:i+len(word_hex)] for i  in range(len(line) - len(word_hex) + 1)]:
            new_hex = hex(int(hex_str, 16) ^ word_int)[2:]
            
            try:
                print(bytearray.fromhex(new_hex).decode())
            except Exception:
                pass
```

For example, when xor-ing the two last lines we receive:  
```
Blew u
ro⌂.t4
qu&z5\
```
From this we can see that we found the word wicked was included at the start of one of those encrypted lines. From here we can start to guess the rest of the line while trying to decrypt the lines with each other.  
At the end we find that the text is from the ["Wizard of Oz"](https://www.cs.cmu.edu/~rgs/oz-12.html).
The key that was used to encrypt the text was:
`466c61677b77686572655f6172655f656c70686562615f616e645f676c696e64615f695f74686f756768745f746869735f7761735f`
which translates to:  
`Flag{where_are_elpheba_and_glinda_i_thought_this_was_wicked}`  

---
This challenge was pretty guessy, but I still enjoyed it very much as it taught me more about OTPs and the process of reaching the solution on these types of guessy challenges.  
Sometimes the solution for these crypto challenges isn't clear from the start, and sometimes we don't have even a clue. In that situation, experience really helps (for example here I started analyzing the hex as bytes of a files, but then I noticed the line breaks which wouldn't be usual if it was part of a hex dump for example).  
Another tip is to try, try, and try more. You have an idea of what it can be? Don't be afraid to write an POC for it even if you are only 50% sure it will work. How else will you know?  
And the last thing is to consult your teammates (if you have some😔), and to try and be creative to look for other ways to tackle the challenge.  
  