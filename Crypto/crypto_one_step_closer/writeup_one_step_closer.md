# One Step Closer - Crypto

## Description

HTB desr blah blah

RSA related message attack

----

## Initial analysis

Encryption function:
```
def encrypt_flag():
    a = random.getrandbits(1024)
    b = random.getrandbits(1024)

    flag = bytes_to_long(FLAG)

    msg = a*flag + b

    ct = pow(msg, e, n)
    return {'ct': format(ct, 'x'), 'n': format(n, 'x'), 'e': format(e, 'x'), 'a': format(a, 'x'), 'b': format(b, 'x')}
```
All plaintexts have the same structure, ```msg = a*flag + b``` where both *a* and *b* are known from the challenge response (see encrypt_flag return). In other words, all messages to be transmited are affine related. A bit of googling yields the RSA related message attack https://www.iacr.org/archive/pkc2005/33860001/33860001.pdf
Just the info in the abstract is enough to determine that the attack is feasible in the challenge scenario. It should be stressed that the time complexity of the attack is proportional to *e* which is 257 in our case. So the attack takes less than a second.

## Attack
A nice attack implementation can be found here:
https://github.com/jvdsn/crypto-attacks/blob/master/attacks/rsa/related_message.py

Al that is needed is a wrapper containing all known data (2 requested encryptions and their results)
```
import binascii
from related_message import attack
from Crypto.Util.number import long_to_bytes

resp1 = {
	"a":"186cc2676c45b67b3c1ab536fced530c6c5bdd0eed9a79bd1928ed23180459787345502a646ae8d8e2ec539fdf12090b478d56ef59f4144cc9d2dc6ff5baa94d369209c793bd4c21be4e6bae872cf3d9be30f86238ae5346d2cf497165d7b56e0d3db459cf63f2e8c5f5e6f42f4abdeffa4009e020b8e470199265b3414cb038",
	"b":"b12084b0ccf6c76269761b938769bcb8dd80054846851a9477a422f17914bd53cb4637a2c249eb06d636b8bcde2e51d31c6732415403be80fbf219c2bddd2e09098a823c0a4ba7967ccc185a61dfff9363da63e363bf695e0c3f5a54ebd2be37353b29a440e06095160c8da2d3868a2bedc4f75cc0c1d0472e99d3592b202583",
	"ct":"2d1be3a2731ccb89feee9208a8560e87ffefce141051711cdb6bd38b6e5d8387600ac52d00426f5196c94e744a1287b59272b1cfcf2f807ceebd2644bfc288784dac405a03e7917c7d345fd2defc9e020c4f0e1a90eb901a2519af7f3693b033df7174147791eaf7ea90301eb3735d5aad8fb7ce15ac98f62b235524cb36212f0f3c04a49298ff7ac181af04759fae06866aad5e1acc46e0e84959dca171071743bc1f538c5cbba835febaf375f71554704edf488ecd7712a9686dd31cb77b59de2a9600dbcd0778f1895754353d44bfcc6d6603774bc558d3a1382b4736214ca3dd572b6172d0a1c277176efd76ff1117d0e31fe68608aa3ffe4f38b05dbd8f",
	"e":"0101",
	"n":"934231328fa30aba684de9fdbc0441887845d22ff677d2aa1979c74e9693b5355f36459e4b51243e49361f7b5c6ef83a2e36aad6458df36634f43db5cf2b2653cd376b63fc24af571f7d1abfd6f12db4837346b4d94e8a50267cf2d4a33d175fbc02493df352d74e0fcfab208bbd84d024fd4dc856849005221db347f697ac85d4dafeb200b757c6728b83927fb5b15be4c0adaa2d1f559c7ce9e8fe53a22ff0ad6c8ce1f48086a4e45aaa590114d338157def42c2010d53ebd8e866514986c939f3863e55d67e03a3cceae6f1e13f40fa7608cf9f299256f94040d9ac69003acad5d9cdd246ab295c73948734aafebd41dce97a2d5df89a4cbe2e45f140e3bd"
}

resp2 = {
	"a":"6baafa8dc8d2ccc57dbf1f988a653a804e77a37c8daa93122ed7234498ededc0b2369ef93fe44b4114b042038d6b33552f576f012b90821d0fda5aba0825feac68ca0dbad776f765eafd5fd8ae79b1159193b88e8b028efbb4638c50dd08e2999cbcedd5908ec584ef3f6ce01d93ea2262a5bbd07c06ef880d5129df1c77b078",
	"b":"9ab70e30a8a176136cb70bca94ecc8d02d473172774630ad14d598855d25a005021d272f52992c61095815048e90944941a6b845e369efd4fb572fd1defeb2d2889fc899bd9579f1ac2083dbcfc28f0104e09b4114176df1b6e3105902ebcc6cef8c9fb362dbaedabc4a70f9e7a4abdb7023d42f82ea1d125642ec27db62818e",
	"ct":"095e6b70af5d7a31dca35f022e1d383a5b1fbe74ec55bdfa265fe117e2fefea97224479c717726ac58efb377a6f5abca636f3fc01a5da262e750b9aad66477013cfed901296dc3744c601519329b750bdc72fa1d8b11b19affd3b6f53e706509ac6aabd45bd464a2b2674bfd13894b03536c23b07cf72b16b5c66eb57e6c7f9a00c25339bda43a88c0c991fa0e50029499805ccaea4e4e7637a90b378919bec9fd87b540211331c30b06273307391c2ddd8579b205e353915db134c7986aff2095df6979bcebf48284e1750b2290c0754209e50a729e8b595724bd1a7855e256c90d860323f256bc9e07dfacb5dbf31c559a5bcf21818975950db989cda02140",
	"e":"0101",
	"n":"934231328fa30aba684de9fdbc0441887845d22ff677d2aa1979c74e9693b5355f36459e4b51243e49361f7b5c6ef83a2e36aad6458df36634f43db5cf2b2653cd376b63fc24af571f7d1abfd6f12db4837346b4d94e8a50267cf2d4a33d175fbc02493df352d74e0fcfab208bbd84d024fd4dc856849005221db347f697ac85d4dafeb200b757c6728b83927fb5b15be4c0adaa2d1f559c7ce9e8fe53a22ff0ad6c8ce1f48086a4e45aaa590114d338157def42c2010d53ebd8e866514986c939f3863e55d67e03a3cceae6f1e13f40fa7608cf9f299256f94040d9ac69003acad5d9cdd246ab295c73948734aafebd41dce97a2d5df89a4cbe2e45f140e3bd"
}


FLAG = b'HTB{--REDACTED--}'
#p = getPrime(1024)
#q = getPrime(1024)
#n = p * q
e = 257

a1 = int.from_bytes(binascii.unhexlify(resp1["a"]), byteorder='big')
a2 = int.from_bytes(binascii.unhexlify(resp2["a"]), byteorder='big')

b1 = int.from_bytes(binascii.unhexlify(resp1["b"]), byteorder='big')
b2 = int.from_bytes(binascii.unhexlify(resp2["b"]), byteorder='big')

ct1 = int.from_bytes(binascii.unhexlify(resp1["ct"]), byteorder='big')
ct2 = int.from_bytes(binascii.unhexlify(resp2["ct"]), byteorder='big')

e = int.from_bytes(binascii.unhexlify(resp1["e"]), byteorder='big')
n = int.from_bytes(binascii.unhexlify(resp1["n"]), byteorder='big')


def f1(message):
	return a1 * message + b1

def f2(message):
	return a2 * message + b2

secret = attack(n, e, c1, c2, f1, f2)
print(long_to_bytes(secret))
```



