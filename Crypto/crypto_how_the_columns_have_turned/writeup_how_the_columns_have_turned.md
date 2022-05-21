# How The Columns Have Turned - Crypto

## Description

A day before the memorial of the Dying Sun, Miyuki began talking about Broider, a death squad commander and a friend of Paulie’s capturer. He would be a party guest at Viryr’s palace. After examining a lot of different scenarios, Miyuki came up with a plan in which Paulie would lure Broider to a secluded location so the group could capture him. Following the plan, a wild chase had just begun when the two looked each other in the eye. After an extremely risky maneuver, Paulie outwitted Broider and led him into an alley in Vinyr’s undercity. The plan was a success. Your squad had managed to capture Broider and bring him back to the ship. After hours of interrogation by Ulysses, he revealed the final key to a series of encrypted messages. Can you find a way to decrypt the others? The flag consists entirely of uppercase characters and has the form HTB{SOMETHINGHERE}. You still have to add the {} yourself.

----

## Initial analysis
PRNG is nothing more than a CNG - Constant Number Generator
```
class PRNG:
    def __init__(self, seed):
        self.p = 0x2ea250216d705
        self.a = self.p
        self.b = int.from_bytes(os.urandom(16), 'big')
        self.rn = seed

    def next(self):
        self.rn = ((self.a * self.rn) + self.b) % self.p
        return self.rn
```

```self.a = self.p => (self.a * self.rn) % self.p = 0```
```self.rn = ((self.a * self.rn) + self.b) % self.p = (0 + self.b) = self.b```

Therefore each invocation of ```rng.next()```returns ```self.b``` which is derived randomly once during init and then kept constant. So we can conclude all blocks are 'encrypted' with the same key ```self.b``` which is provided in dialog.txt

## Attack
1. Now that the key and all ciphertexts are known, all we need to do is derive the decryption function by inverting the encryption function. No crypto knowledge / fancy crypto attack needed.


```
import os

def deriveKey(key):
    derived_key = []
    #print(len(key))

    for i, char in enumerate(key):
        previous_letters = key[:i]
        new_number = 1
        for j, previous_char in enumerate(previous_letters):
            if previous_char > char:
                derived_key[j] += 1
            else:
                new_number += 1
        derived_key.append(new_number)
    return derived_key


def transpose(array):
    return [row for row in map(list, zip(*array))]


def flatten(array):
    return "".join([i for sub in array for i in sub])


def twistedColumnarEncrypt(pt, key):
    derived_key = deriveKey(key)

    width = len(key)
    print(width)

    blocks = [pt[i:i + width] for i in range(0, len(pt), width)]
    blocks = transpose(blocks)

    ct = [blocks[derived_key.index(i + 1)][::-1] for i in range(width)]
    ct = flatten(ct)
    return ct

def inv_transpose(state):
    inv_transposed_state = [("".join([el[ind] for el in state])) for ind, _ in enumerate(state[0])]
    return inv_transposed_state

def twistedColumnarDecryption(ct, key):
    
    derived_key = deriveKey(key)
    
    message_len = len(ct)
    key_len = len(key)
    
    state = ["" for i in range(key_len)]
    
    #Message length taken from the provided ciphertext, sanity check
    if message_len != 105:
        input("Weird msg len")
    
    #De-flatten
    defl_ct = deflatten(ct, key_len, message_len)
    
    #Substitute backwards
    for i in range(key_len):
        state[derived_key.index(i+1)] = defl_ct[i][::-1]
    
    #Invert transposition
    state = inv_transpose(state)

    pt = "".join(state)
    return pt
    

def deflatten(ct, key_len, message_len):
    de_flattened_size = (int) (message_len / key_len)
    if de_flattened_size != 7:
        input("Something's wrong")
    de_flatten = [ct[i:i+de_flattened_size] for i in range(0, message_len, de_flattened_size)]
    compl_de_flatten = []
    for el in de_flatten:
        compl_de_flatten.append([el[i] for i in range(len(el))])

    return compl_de_flatten


class PRNG:
    def __init__(self, seed):
        self.p = 0x2ea250216d705
        self.a = self.p
        self.b = int.from_bytes(os.urandom(16), 'big')
        self.rn = seed

    def next(self):
        self.rn = ((self.a * self.rn) + self.b) % self.p
        
        #Constant RNG output !
        #self.rn = self.b % self.p
        return self.rn

def decryption_main():
    with open('encrypted_messages.txt', 'r') as f:
        ciphertexts = [msg.strip() for msg in f.readlines()]
    
    key = "729513912306026"

    for ct in ciphertexts:
        pt = twistedColumnarDecryption(ct, key)
        print(pt)


if __name__ == '__main__':
    decryption_main()
    #main()
```