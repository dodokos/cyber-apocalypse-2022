# Find Marher's Secret - Crypto

## Description

Blah - blah description from HTB

Essentially RC4 cipher related keys attack

----

## Approach

RC4 is used for encryption - known to be vulnerable, c.f. aircrackng, WEP

Cipher key is concatenated to IV which is **attacker** controlled, via encryption oracle. Hence, the Mantin, Fluhrer and Shamir related keys attack can be applied. https://www.liquisearch.com/fluhrer_mantin_and_shamir_attack/the_attack

A nice python implementation can be found here:
https://github.com/jvdsn/crypto-attacks/blob/master/attacks/rc4/fms.py

Key bytes are recovered one by one (known key length, refer to challenge source).

Here's a python skeleton for communicating with the challenge container.

 

```a
import binascii
import json
import socket

from rc4_attack import attack


def communicate_with_oracle(iv: bytearray, pt: bytes) -> bytearray:

	data_to_send = {
		'option': "encrypt",
		'iv': binascii.hexlify(iv).decode('utf-8'),
		'pt': binascii.hexlify(pt).decode('utf-8')
	}


	sock.sendall(json.dumps(data_to_send).encode())

	#Every now and then there is misalignment in the received message because of how data is sent thru socket by server
	received = sock.recv(1024).decode()
	while "response" not in received:
		received = sock.recv(1024).decode()

	json_start = received.find("{")
	json_end = received.find("}")

	json_resp = json.loads(received[json_start:json_end + 1])

	
	if json_resp["response"] != "success":
		print("Something wrong with communication")
		input("wait")
	if json_resp["pt"] != data_to_send["pt"]:
		print("Plaintexts dont match")
		input("wait, plaintexts")

	return binascii.unhexlify(json_resp["ct"])

HOST, PORT = "FILL IN MANUALLY"

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
# Connect to server and send data
sock.connect((HOST, PORT))

#Receive welcoem message from server
print(sock.recv(1024).decode())


key = attack(communicate_with_oracle, 27)

print(key)

sock.close()
```


