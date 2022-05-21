# Memory Acceleration - Crypto

## Description

Blah blah CTF description.

Vulnerable keyed pseudo hash function

----

## Initial analysis

The phash function kind of resembles a SPN (Substitution-Permutation Network) which is the construction used in almost all modern block ciphers such as AES.

The Sbox used in the phash function is the AES S-box. The phash function contains 13 rounds, so any classical linear/differential cryptanalysis "should" be pointless because the AES S Box is designed to withstand such techniques.

```
def rotl(n, b):
    return ((n << b) | (n >> (32 - b))) & 0xffffffff


def sub(b):
    b = long_to_bytes(b)
    return bytes([sbox[i] for i in b])


def phash(block, key1, key2):
    block = md5(block.encode()).digest()
    block = 4 * block
    blocks = [bytes_to_long(block[i:i+4]) for i in range(0, len(block), 4)]

    m = 0xffffffff
    rv1, rv2 = 0x2423380b4d045, 0x3b30fa7ccaa83
    x, y, z, u = key1, 0x39ef52e9f30b3, 0x253ea615d0215, 0x2cd1372d21d77

    for i in range(13):
        x, y = blocks[i] ^ x, blocks[i+1] ^ y
        z, u = blocks[i+2] ^ z, blocks[i+3] ^ u
        rv1 ^= (x := (x & m) * (m + (y >> 16)) ^ rotl(z, 3))
        rv2 ^= (y := (y & m) * (m + (z >> 16)) ^ rotl(x, 3))
        rv1, rv2 = rv2, rv1
        rv1 = sub(rv1)
        rv1 = bytes_to_long(rv1)

    h = rv1 + 0x6276137d7 & m
    key2 = sub(key2)

    for i, d in enumerate(key2):
        a = (h << 1) & m
        b = (h << 3) & m
        c = (h >> 4) & m
        h ^= (a + b + c - d)
        h += h
        h &= m

    h *= u * z
    h &= m

    return h
```
Looking deeper into the phash function, we see that ```key1``` and ```key2``` are used entirely independently which is a common red flag. In a typical construction both keys would be used together in at least one of the two for loops.

Furthermore, looking into the source, especially into lines
```
m = 0xffffffff
x, y, z, u = key1, 0x39ef52e9f30b3, 0x253ea615d0215, 0x2cd1372d21d77
for i in range(13):
    ...
    rv1 ^= (x := (x & m) * (m + (y >> 16)) ^ rotl(z, 3))
    ...
```
one  can observe that only the last 32 bits of ```key1``` are relevant (based on the mask ```m```). In other words,
```phash(block, 0xAA00000000, key2) == phash(block, 0x00000000, key2)```
This significantly limits the key space which has to be examined.

Furthermore, both keys are provided by the user and there are no limitations to their lenghts (even 1 byte keys are permitted).

The lenght of ```key2``` is critical because it determines the lenght of the second for loop.

Based on the complexity of the first loop, we can treat *h* as more or less a random value up until the beginning of the second for loop.

For the 'proof of work' to be successful, ```phash``` has to return 0.

Looking into the last 3 function lines
```
h *= u * z
h &= m
return h
```
*u* and *z* are actually constants which are set in the very beginning of the ```phash``` function and never modified.
*u* * *z* is non-zero, so for *h* to ultimately be zero, *h* also has to be zero after the end of the second for loop
```
for i, d in enumerate(key2):
        a = (h << 1) & m
        b = (h << 3) & m
        c = (h >> 4) & m
        h ^= (a + b + c - d)
        h += h
        h &= m

#h HAS to be 0 here, otherwise the return will never be 0

h *= u * z
h &= m
return h
```
Lets assume that we limit ```key2```to just a single byte. The loop above will be executed just once and we can re-write it:
```
key2 = sub(key2)

#Loop starts here:
d = key2                    #Line 1
a = (h << 1) & m            #Line 2
b = (h << 3) & m            #Line 3
c = (h >> 4) & m            #Line 4
h ^= (a + b + c - d)        #Line 5
h += h                      #Line 6
h &= m                      #Line 7
```
For *h* to be zero at the end of this snippet, the following **must** hold:

```
h = 0 mod 2**32 before Line 7
In Line 6: h = 2 * h, therefore
h = 0 mod 2**31 before Line 6
In Line 5  h = h ^ (a+b+c-d), therefore
a + b + c - d = h mod 2**31 before Line 5
```
We treat h as pseudo-random, so we assume to have no control over *a*, *b* and *c*. However, ```d = sub(key2)``` and ```key2``` is user-provided, so we have full control over ```d```.

Therefore, if we can find some *h*, such that ```h - (a + b + c) < 256 mod 2**31``` we can then specify ```key2``` such that ```d = sub(key2) = (h mod 2**31) - (a+b+c mod 2**31)```

This will result in ```a + b + c - d = h mod 2**31 befpre Line 5```which is the pre-requisite for ```phash```to return 0.

Reminder: *a*, *b* and *c* depend only on *h*. On the other hand, for a constant message to be 'hashed', *h* only depends on ```key1```.
As a consequence, we can brute force the key space for ```key1```until we find a suitable ```h``` and then we can compute a suitable single-byte ```key2```.


Here is a redacted ```phash```function which includes the check for *h* as described above. Crucially the function returns before ```key2``` is processed, so its value is irrelevant when checking for a suitable *h*.

```
def phash(block, key1, key2):
    #Only first 32 bits of key1 are relevant (c.f. x computations below)
    #block is constant, key1 and key2 are user provided
    block = md5(block.encode()).digest()
    block = 4 * block
    blocks = [bytes_to_long(block[i:i+4]) for i in range(0, len(block), 4)]

    # 64 byte (512 bits) of 4x repeating 128 bit values


    m = 0xffffffff
    rv1, rv2 = 0x2423380b4d045, 0x3b30fa7ccaa83

    x, y, z, u = key1, 0x39ef52e9f30b3, 0x253ea615d0215, 0x2cd1372d21d77
    x, y, z, u = key1, 0x39ef52e9f30b3, 0x253ea615d0215, 0x2cd1372d21d77


    for i in range(13):
        #Key addition
        x, y = blocks[i] ^ x, blocks[i+1] ^ y
        z, u = blocks[i+2] ^ z, blocks[i+3] ^ u

        #Max size of x,y,z,u at this point: 52 bits

        #Max size of y >> 16 is 52 - 16 = 36 bits
        x = (x & m) * (m + (y >> 16)) ^ rotl(z, 3)

        y = (y & m) * (m + (z >> 16)) ^ rotl(x, 3)

        rv1 ^= x
        rv2 ^= y
        #rv1 ^= (x := (x & m) * (m + (y >> 16)) ^ rotl(z, 3))
        #rv2 ^= (y := (y & m) * (m + (z >> 16)) ^ rotl(x, 3))

        #Swap halves
        rv1, rv2 = rv2, rv1
        #Substitution
        rv1 = sub(rv1)
        rv1 = bytes_to_long(rv1)

    
    h = rv1 + 0x6276137d7 & m
    

    a = (h << 1) & m
    b = (h << 3) & m
    c = (h >> 4) & m


    sum_to_eval = (a + b + c) % (2**31)
    h_to_eval = h % (2**31)

    difference = sum_to_eval - h_to_eval
    difference = difference + 2 ** 31 if difference < 0 else difference

    if difference < 256:
        print(f"Found d for key1 {key1}, key2 {key2} : It must be {difference}")
        return (difference, key1)

    return None

    key2 = sub(key2)

    for i, d in enumerate(key2):
        a = (h << 1) & m
        b = (h << 3) & m
        c = (h >> 4) & m
        # a + b + c - d must be == h mod 2^31
        h ^= (a + b + c - d)
        # h must be == 0 mod 2^31
        h += h
        h &= m

    #print(f"u is {u}, z is {z}")
    # u and z are constant for a given input "block"
    # h is 0 iff (u * z * h == 0 mod 2^32), i.e. h == 0 mod 2^32
    h *= u * z
    h &= m

    return h
```
And a script for repeatedly calling the redacted ```phash```until a suitable *h* is found:
```
from radected_pow import phash as redacted_phash

block_to_hash = "Query challenge container for block"
testkey1 = 0
testkey2 = 0
while redacted_phash(block_to_hash, testkey1, testkey2) == None:
 	testkey1 += 1
        #Progress checking
 	if testkey1 & 0xFFFF == 0:
 		print(f"Got to testkey {testkey1}")
 		print(f"Time elapsed so far: {time.time() - start} seconds")

 	if testkey1 > 0xFFFFFFFF:
 		print(f"No correct testkey1 found for block {testblock}")
 		break

d, correct_key1_candidate = redacted_phash(block_to_hash, testkey1, testkey2)

#After d is found, invert it in order to find key2, such that sub(key2) = d

data_to_submit = [
    (correct_key1_canditate, inverse_sbox[d])
]

#Submit key1 and key2
sock.sendall(str(data_to_submit[0][0]).encode())
print(sock.recv(1024).decode())
sock.sendall(str(data_to_submit[0][1]).encode())
print(sock.recv(1024).decode())
```
The same process is repeated in an identical fashion until 4 blocks have been 'hashed' correctly and the flag is returned.