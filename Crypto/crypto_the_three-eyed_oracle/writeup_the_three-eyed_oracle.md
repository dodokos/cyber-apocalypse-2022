# The Three-Eyed Oracle - Crypto

## Description

Feeling very frustrated for getting excited about the AI and not thinking about the possibility of it malfunctioning, you blame the encryption of your brain. Feeling defeated and ashamed to have put Miyuki, who saved you, in danger, you slowly walk back to the lab. More determined than ever to find out what’s wrong with your brain, you start poking at one of its chips. This chip is linked to a decision-making algorithm based on human intuition. It seems to be encrypted… but some errors pop up when certain user data is entered. Is there a way to extract more information and fix the chip?

----

## Initial analysis:

The encryption uses AES ECB mode which is a no-go. Classic example why: https://crypto.stackexchange.com/questions/20941/why-shouldnt-i-use-ecb-encryption (scroll down to the penguin image).

Main take-away:
```
block_size = 16
randbytes1 = os.urandom(block_size)
randbytes2 = os.urandom(block_size)
known_block = b'\xAA' * block_size

c1 = AES_ECB_encrypt(key, randbytes1 + randbytes2 + known_block)
c2 = AES_ECB_encrypt(key, randbytes1 + known_block + randbytes2)
c3 = AES_ECB_encrypt(key, known_block + randbytes1 + randbytes2)

c1[32:] == c2[16:32] == c3[:16]
```
So if we are able to recover the ciphertext for one known block, we can then re-order the plaintext, so that the known block is placed elsewhere inside the plaintext, and we would still know the ciphertext block corresponding to the known block.

This is **not** the case for any other block cipher mode such as CBC, CTR, etc.

Based on the encryption function
```
def encrypt(key, msg):
    msg = bytes.fromhex(msg)
    crypto = AES.new(key, AES.MODE_ECB)
    padded = pad(prefix + msg + FLAG, 16)
    return crypto.encrypt(padded).hex()
```
the attacker controls the length of the message to be encrypted (```msg``` is attacker input), which leaks the flag length due to how PKCS7 padding works.
Example:
```
block_size = 16

msg = b'\xaa' * 15
pad(msg) == (b'\xaa' * 15 + b'\x01')

msg = b'\xaa' * 8
pad(msg) == (b'\xaa' * 8 + b'\x08' * 8)

msg = b'\xaa' * block_size
pad(msg) == b'\xaa' * block_size + b'\x10' * block_size
```

## Attack
1. Recover flag length. Start with a random message with length 1 byte. Observe the length *ct_len* of the returned ciphertext. Increase the message length by 1 byte and observe the response length. Repeat this process until the response length becomes greater than *ct_len* (to be precise it would be *ct_len* + *block_size*), you know that the padding scheme has added a full block of just padding (as in the last example above). Therefore you can conclude that the length of ```prefix + msg + FLAG``` is a multiple of *block_size* (here: 16). *prefix* and *msg* are both known, so you can compute```len(FLAG) = len(ciphertext) - 16 - len(prefix) - len(msg)```
In this challenge ```len(FLAG) = 25```
2. Adjust message length, so that ```len(prefix + msg + FLAG) % 16 == 1```
This ensures that 16-1=15 bytes of \x0F padding are added.
Thus the last plaintext block ends up being ```pt_last_block = FLAG[-1] + b'\x0F' * 15```
Observe the corresponding ciphertext ```ct_15_bytes_padding```.
3. Now we set up the second message block in a way such that the corresponding ciphertext block is the same as ```ct_15_bytes_padding```. Refer to source below for how to set up second plaintext block, so that the last flag byte can be guessed.
```
len(prefix) == 12 #Known based on chall source

#You can limit search range to just ASCII printable for faster recovery
for byte_to_guess in range(256):
    msg = b'\xFF' * (block_size - len(prefix))   #Random bytes to fill block 1
          + byte_to_guess                        #Guess last byte of the flag
          + b'\x0F' * 15                         #Known padding to fill block 2
                
    ciphertext_block2 = encrypt(key, plaintext)[16:32]
    if ciphertext_block2 == ct_15_bytes_padding:
        print(f"Last flag byte is {byte_to_guess})
```
4. Repeat the same process iteratively to recover the flag byte by byte.
In order to recover the 2nd to last flag byte, set up msg length so that 14 bytes of \x0E padding are added to the last 2 bytes of the flag. In other words
```last_block_of_padded_pt = b'UNKNOWN 2nd TO LAST FLAG BYTE' + b'LAST FLAG BYTE ALREADY RECOVERED ABOVE' + b'\x0E' * 14```
Observe the ciphertext corresponding to this message. Then set up the 2nd plaintext block as in Step 3 so that its corresponding ciphertext block mirrors the one you just observed. Guess the 2nd to last flag byte using the same technique as in step 3. Repeat ad infinitum until the whole flag is recovered. 
Total complexity without limiting search space to ASCII printable: 
Worst case: 256 * 25 guesses.
Average: 128 * 25 guesses.
