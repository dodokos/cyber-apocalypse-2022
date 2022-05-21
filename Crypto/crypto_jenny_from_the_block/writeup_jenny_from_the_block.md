# Jenny From The Block - Crypto

## Description

Intrigued by the fact that you have found something your father made, and with much confidence that you can be useful to the team, you rush excitedly to integrate “Jenny” into the spaceship’s main operating system. For weeks, everything went smoothly, until you ran into a meteor storm. Having little to no data of training, the AI is now malfunctioning. Ulysses freaks out because he can no longer control the spaceship due to the AI overriding his manual commands. Big banging noises terrify your crew members. Everything is shaking. It’s time to act. Do you think you can temporarily shut down “Jenny” until she becomes more sophisticated?

----

## Initial analysis:

In every session the same randomly generated password is used for encrypting all blocks: 
```
while True:
    password = os.urandom(32)
    ct = encrypt(response, password)
```
Every plaintext to be encrypted contains a fixed part 
```
response = b'Command executed: ' + command + b'\n' + output
```
Therefore, a known plaintext attack is possible.
Coincidentally if the executed command is ```"cat secret.txt"```, ```len(b'Command executed: ' + b'cat secret.txt') == 32```which is precisely the length of one block.

## Attack:
1. Send ```cat secret.txt``` to the challenge server and observe the response ```ct```
2. For the first block we know both the plaintext ```pt = b'Command executed: cat secret.txt'```, and the ciphertext ```ct[:32]```
3. Because the encryption is just a simple addition, we can recover the secret ```secret = ct[:32] - pt```
4. The secret for a given block *i* depends on the the ciphertext and plaintext of the previous block *i-1*. We know the first plaintext and ciphertext (Step 2), therefore we can compute the secret ```secret2``` for block *2*, then compute the plaintext for block *2* ```pt2 = ct2 - secret2```. This process is repeated iteratively until the whole ciphertext has been decrypted. The flag is contained in the plaintext which is the output of ```cat secret.txt``` on the server.


```
from hashlib import sha256
from Crypto.Util.Padding import pad, unpad
import os

BLOCK_SIZE = 32

#Received as response to cat secret.txt
ciphertext = bytearray.fromhex('b3154c45da38fcb113347da9a17dc8889d83f5090a6601ec11bcd546cc8b17bce5563522f572ec15c427db6254760776c48496850b7b0a844f8e4e53657f84ff35c4e833584240f99240ab767f25e6aa52d8b19b1e39c00840143632bdf78d316f3d0bfbfe64d39edb38cbacb9923cd0626d6ad7fb7cb8817f462245a0fbc02c413bc98943926008f820f876b3349dcbd59aa3e7990c47b2198a729a998671f14ad37c8fa82ac94538ac0fad02fce84eae72e20918cf50605d0f2b25fd2525e3bd77873d8cec8c89de946e77c07215659e1b43fd943189df7e5db9a504ff22f9fe7b312a2a8893c2151c0c8e5d012eaebbd4b836022c5b1d977817e4caadccaa')


def decrypt_block(secret, ciphertext):
	result = [ciphertext[i] - secret[i] for i in range(BLOCK_SIZE)]
	result = [result[i] if result[i] > 0 else result[i] + 256 for i in range(BLOCK_SIZE)] 
	return bytearray(result)


known_plaintext = b'Command executed: cat secret.txt' + b'\n'


plaintext = known_plaintext[:BLOCK_SIZE]



for i in range(0, len(ciphertext) - BLOCK_SIZE, BLOCK_SIZE):
	secret = sha256(ciphertext[i:i+BLOCK_SIZE] + plaintext[i:i+BLOCK_SIZE]).digest()
	decr_plaintext = decrypt_block(secret, ciphertext[i+BLOCK_SIZE:i+BLOCK_SIZE+BLOCK_SIZE])
	plaintext = plaintext + decr_plaintext

print(plaintext)
```
