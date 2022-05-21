# MOVs Like Jagger - Crypto

## Description

While following the breadcrumbs from the secret messages you managed to recover from Broider, Bonnie gathered more information from his well trusted “Tsirakia” and found out that the messages were about the destinations of a STS (Space Transportation Ship). The STS, named “Paketo”, is a notoriously large spaceship that transports military supplies for the Golden Fang mercenary army. After spending some time observing the seemingly random trajectory of Paketo, you and Paulie manually plotted the delivery locations and realized that the STS’s orbit forms an elliptic curve. Your spaceship’s advanced technology GPS has calculated the exact parameters of the curve. Can you somehow predict Paketo’s final destination and hijack it?

----

### Known parameters: 
* Curve: p, a, b
* Generator point: G
* Curve order: ec_order
* 2 Points P and Q (imitating 2 public keys in ECDH key exchange)

## Solving Approach
1. Check curve order prime factorization. Even wolframalpha works - no coding needed.

    ```ec_order = 434252269029337012720086440208 = 2^4 * 3 * 73 * 88591 * 3882601 * 360301137196997```
    
    Largest prime factor is 360301137196997, which is 49 bits long. A bit too long for pure Pohlig-Hellman DLOG alg which relies on small primes in group order factorization. In theory doable in O(2 ^ 25) time with BSDS/Pollard Rho. In practice, the challenge container might shut down and reset the parameters, rendering all computations useless.
2. Run partial Pohlig-Hellman +BSGS on all prime factors but the largest (done in ~3 seconds).
Decent script with minimal modifications needed (incorrect curve order): https://github.com/thewhiteninja/ctf/blob/master/polhig-hellman.py
3. For the last prime factor look up MOV attack which exploits low curve embedding degree (in our case 2 which apparently is way too low and vulnerable).
4. Compute
    ```
    last_exponent = ec_order // 360301137196997 
    G_times_last_exp = G * last_exponent
    Q_times_last_exp = Q * last_exponent
    ```
    which simulates the setup phase of the Pohlig-Hellman algorithm for the last, largest prime factor.
5. Run the MOV attack or its improved version, the Frey-Ruck attack, which essentially simplify the DLOG Problem by computing x = DLOG(G, Q)
    ```
    x * G = Q
    x = ?
    ```
    Nice implementation here: https://github.com/jvdsn/crypto-attacks.
    Make sure to change ```discrete_log``` to ```discrete_log_rho``` in the attack code, unless you have a lot of RAM for BSGS.
6. Get the DLOG solution from step 5 and paste it into the last step of Pohlig Hellman to compute CRT and the final result nQ.
7. Manually compute nQ * P and submit coordinates to get the flag.

