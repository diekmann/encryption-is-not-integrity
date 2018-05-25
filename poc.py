#!/usr/bin/env python3
import os
import string
from binascii import hexlify, unhexlify

import Crypto.PublicKey.RSA
import cryptography
from cryptography.hazmat.backends import openssl
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.serialization import load_pem_private_key, load_pem_public_key

if cryptography.__version__ not in ['1.9', '1.7.1']:
    print("Warning: only tested with cryptography 1.9 (venv) and 1.7.1 (debian). May not work on you system. You have {}".format(cryptography.__version__))
if Crypto.__version__ != '2.6.1':
    print("Warning: only tested with Crypto 2.6.1")


MARKDOWN = True

def h1(str_):
    if MARKDOWN:
        print("# {}\n\n".format(str_))
    else:
        print("= {} =\n\n".format(str_))

def h2(str_):
    if MARKDOWN:
        print("\n## {}\n".format(str_))
    else:
        print("=== {} ===\n\n".format(str_))

def codespan(str_):
    if MARKDOWN:
        print("```\n{}\n```".format(str_.lstrip('\n')))
    else:
        print("{}".format(str_))

def pythonspan(str_):
    if MARKDOWN:
        print("```python\n{}\n```".format(str_))
    else:
        print("{}".format(str_))

# about the coding style in this file:
# Most things are wrapped in functions so they are in their own isolated context and we can reuse them.


# Generate a 4096 bit RSA key pair for Alice, Bob, and Carol.
# I use Crypto instead of cryptography because I need a raw (textbook) RSA function
_K_ALICE_PRIV = Crypto.PublicKey.RSA.generate(4096)
_K_BOB_PRIV = Crypto.PublicKey.RSA.generate(4096)
_K_CAROL_PRIV = Crypto.PublicKey.RSA.generate(4096)

# Global storage a dict, so we do not access private data accidentally, ...
GLOB = None
def init_global_state(p, g):
    global GLOB
    GLOB = {'Alice': {'k_priv': _K_ALICE_PRIV},
            'Bob':   {'k_priv': _K_BOB_PRIV},
            'Carol': {'k_priv': _K_CAROL_PRIV},
            'pub': {'DH_g': g,
                    'DH_p': p,
                    'k_Alice_pub': _K_ALICE_PRIV.publickey(),
                    'k_Bob_pub': _K_BOB_PRIV.publickey(),
                    'k_Carol_pub': _K_CAROL_PRIV.publickey()}
           }

# The textbook RSA functions
def RSA_enc(k_pub, msg):
    # ignore the compatibility parameters
    return k_pub.encrypt(msg, None)[0]

def RSA_dec(k_priv, msg):
    return k_priv.decrypt(msg)

def RSA_sign(k_priv, msg):
    # ignore the compatibility parameters
    return k_priv.sign(msg, None)[0]

def RSA_verify(k_pub, msg, signature):
    assert isinstance(signature, int)
    # "... whereas the second item is always ignored."
    return k_pub.verify(msg, (signature, None))



# RFC 3526 1536-bit DH values
p_RFC3526_text = """
      FFFFFFFF FFFFFFFF C90FDAA2 2168C234 C4C6628B 80DC1CD1
      29024E08 8A67CC74 020BBEA6 3B139B22 514A0879 8E3404DD
      EF9519B3 CD3A431B 302B0A6D F25F1437 4FE1356D 6D51C245
      E485B576 625E7EC6 F44C42E9 A637ED6B 0BFF5CB6 F406B7ED
      EE386BFB 5A899FA5 AE9F2411 7C4B1FE6 49286651 ECE45B3D
      C2007CB8 A163BF05 98DA4836 1C55D39A 69163FA8 FD24CF5F
      83655D23 DCA3AD96 1C62F356 208552BB 9ED52907 7096966D
      670C354E 4ABC9804 F1746C08 CA237327 FFFFFFFF FFFFFFFF"""
p_RFC3526 = int.from_bytes(unhexlify(p_RFC3526_text.replace('\n', '').replace(' ', '')), 'big')
g_RFC3526 = 2

def check_RFC_prime():
    """Check that the nifty prime construction of the RFC produces exactly the hexdump of the prime"""
    from decimal import Decimal, ROUND_FLOOR, getcontext
    # need some precision to evaluate PI
    getcontext().prec = 2000

    # from the python docs
    def pi():
        """Compute Pi to the current precision.
        >>> print(pi())
        3.141592653589793238462643383
        """
        getcontext().prec += 2  # extra digits for intermediate steps
        three = Decimal(3)      # substitute "three=3.0" for regular floats
        lasts, t, s, n, na, d, da = 0, three, 3, 1, 0, 0, 24
        while s != lasts:
            lasts = s
            n, na = n+na, na+8
            d, da = d+da, da+32
            t = (t * n) / d
            s += t
        getcontext().prec -= 2
        return +s               # unary plus applies the new precision

    #   The prime is: 2^1536 - 2^1472 - 1 + 2^64 * { [2^1406 pi] + 741804 }
    f = 2**1536 - 2**1472 - 1 + 2**64 * ((Decimal(2**1406) * pi()).to_integral_exact(ROUND_FLOOR) + 741804)

    return p_RFC3526 == f
assert check_RFC_prime(), "Wow, this prime has parts of pi in it."


# ================= unit tests to assert primitives and library work as expected =================

# === Crypto textbook RSA ===
def test_textbook_RSA(k_priv):
    k_pub = k_priv.publickey()
    assert RSA_dec(k_priv, RSA_enc(k_pub, b"foobar"*42)) == b"foobar"*42
    assert RSA_enc(k_pub, b'') == b'\x00'

    assert RSA_verify(k_pub, b"foobar"*42, RSA_sign(k_priv, b"foobar"*42))
    assert RSA_sign(k_priv, b'') == 0
    assert RSA_verify(k_pub, b'', 0)
    assert RSA_verify(k_priv, b'\x01', 1)
    assert RSA_verify(k_priv, 0, 0)
    assert RSA_verify(k_priv, 1, 1)

    # It is really raw textbook RSA
    assert k_pub.encrypt(42, None)[0] == pow(42, k_pub.e, k_pub.n)
    assert pow(k_pub.encrypt(42, None)[0], k_priv.d, k_priv.n) == 42

    assert k_priv.sign(42, None)[0] == pow(42, k_priv.d, k_priv.n)
    assert k_pub.verify(42, (pow(42, k_priv.d, k_priv.n), None))
    
    # Check encoding
    from Crypto.Util.number import bytes_to_long, long_to_bytes
    assert k_pub.encrypt(b"foo", None)[0] == long_to_bytes(pow(bytes_to_long(b"foo"), k_pub.e, k_pub.n))
test_textbook_RSA(_K_ALICE_PRIV)


# === DH tiny self-contained implementation ===
def test_DH_manual(p, g):
    ## Alice:
    # get a random value
    xa = int.from_bytes(os.urandom(192), byteorder='big')
    assert 0 < xa < p
    # ya is party a's public key; ya = g ^ xa mod p
    ya = pow(g, xa, p)
    # print("Alice sends {},{},{}".format(ya, g, p))

    ## Bob:
    xb = int.from_bytes(os.urandom(192), byteorder='big')
    assert 0 < xb < p
    # yb is party b's public key; yb = g ^ xb mod p
    yb = pow(g, xb, p)
    # ZZ = (yb ^ xa)  mod p  = (ya ^ xb)  mod p
    ZZ_b = pow(ya, xb, p)
    # print("Bob sends {}".format(yb))

    ## Alice:
    ZZ_a = pow(yb, xa, p)

    ## Both have the same key
    assert ZZ_a == ZZ_b
test_DH_manual(p_RFC3526, g_RFC3526)


# === DH from library ===
def test_DH_lib(p, g):
    pn = dh.DHParameterNumbers(p, g)
    parameters = pn.parameters(openssl.backend)

    alice_private_key = parameters.generate_private_key()
    bob_private_key = parameters.generate_private_key() # xb

    alice_public_key = alice_private_key.public_key()
    assert alice_public_key.key_size == 1536
    bob_public_key = bob_private_key.public_key()
    assert bob_public_key.key_size == 1536

    shared_key_alice = alice_private_key.exchange(bob_public_key)
    shared_key_bob = bob_private_key.exchange(alice_public_key)

    assert shared_key_alice == shared_key_bob
    assert len(shared_key_alice)*8 == 1536
test_DH_lib(p_RFC3526, g_RFC3526)


# === DH from library double-checked with manual implementation ===
def test_DH_lib_manual(p, g):
    pn = dh.DHParameterNumbers(p, g)
    parameters = pn.parameters(openssl.backend)

    alice_private_key = parameters.generate_private_key()
    xa = alice_private_key.private_numbers().x
    bob_private_key = parameters.generate_private_key()
    xb = bob_private_key.private_numbers().x

    alice_public_key = alice_private_key.public_key()
    assert alice_public_key.key_size == 1536
    ya = alice_public_key.public_numbers().y
    assert ya == pow(g, xa, p)
    bob_public_key = bob_private_key.public_key()
    assert bob_public_key.key_size == 1536
    yb = bob_public_key.public_numbers().y
    assert yb == pow(g, xb, p)

    shared_key_alice = alice_private_key.exchange(bob_public_key)
    ZZ_a = pow(yb, xa, p)
    assert int.from_bytes(shared_key_alice, 'big') == ZZ_a
    shared_key_bob = bob_private_key.exchange(alice_public_key)
    ZZ_b = pow(ya, xb, p)
    assert int.from_bytes(shared_key_bob, 'big') == ZZ_b

    assert shared_key_alice == shared_key_bob
    assert len(shared_key_alice)*8 == 1536
    assert ZZ_a == ZZ_b
test_DH_lib_manual(p_RFC3526, g_RFC3526)
# ============================= end of unit tests =============================


# ============================= KDF =============================
# We don't need the details, I just want to input a random bitstring (not password!) and get back a 128 bit key
def kdf128(rawkey):
    assert isinstance(rawkey, bytes)
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=16,
        salt=None,
        info=None,
        backend=openssl.backend
        )
    return hkdf.derive(rawkey)

assert kdf128(b'foo') == kdf128(b'foo')
# ============================= end of KDF =============================


# ============================= AES CTR =============================
def aes128_ctr(nonce, key, data):
    cipher = Cipher(algorithms.AES(key), modes.CTR(nonce), backend=openssl.backend)
    encryptor = cipher.encryptor()
    return encryptor.update(data) + encryptor.finalize()

# encrypt and decrypt is the same in AES CTR. It is essentially a stream cipher.
assert aes128_ctr(b'8'*16, kdf128(b'rawkey'), aes128_ctr(b'8'*16, kdf128(b'rawkey'), b'foobar')) == b'foobar'
# ============================= end of AES CTR =============================


# ============================= Pretty printing =============================
def abbrev(msg):
    """Truncate long messages, only for pretty printing. Output is a hex string."""
    #if isinstance(msg, bytes) and len(msg) < 10:
    #    msg = hexlify(msg)
    if isinstance(msg, bytes) and len(msg) >= 16:
        msg = hexlify(msg)[:16].decode('ascii') + "... [{:d} bytes omitted]".format(len(msg) - 8)
    elif isinstance(msg, str):
        assert len([c for c in msg if c == ',']) == 1
        a, b = map(int, msg.split(','))
        # I expect a to be a 1536 bit DH value and b to be a 4096 bit RSA signature
        # throws `OverflowError: int too big to convert' on failure
        assert len(a.to_bytes(192, 'big')) == 192 and len(b.to_bytes(512, 'big')) == 512
        if a >= 2**8:
            a = "{:0384x}".format(a)
            assert len(a) == 192*2
            a = a[:16] + "...[{:d} bytes of y omitted]".format((len(a) - 16)//2)
        if b >= 2**8:
            b = "{:01024x}".format(b)
            assert len(b) == 512*2
            b = b[:16] + "...[{:d} bytes of signature omitted]".format((len(b) - 16)//2)
        msg = "{},{}".format(a, b)
    return msg
# ============================= end of Pretty printing =============================



# ============================= Start of Story=============================
h1("""Encryption is not Integrity""")

print("""Don't we all remember the following common setup from our introductory security course?
Bob wants to send a secret message to Alice.
In order to obtain a key for encrypting the message, Alice and Bob first use Diffie-Hellman (DH) to exchange a fresh session key.
With this fresh session key, Bob symmetrically encrypts the message and sends it to Alice.
Carol volunteers to transmit the messages between Bob and Alice.
Here is the setup:""")

codespan(r"""
   Alice                            Carol                             Bob
     |                                |                                |
     |      DH values from Alice      |                                |
     |------------------------------->|      DH values from Alice      |
     |                                |------------------------------->|
     |                                |                             compute session key
     |                                |                                |
     |                                |        DH values from Bob      |
     |        DH values from Bob      |<-------------------------------|
     |<-------------------------------|                                |
compute session key                   |                             encrypt message
     |                                |                             with session key
     |                                |                                |
     |                                |       encrypted message        |
     |       encrypted message        |<-------------------------------|
     |<-------------------------------|                                |
decrypt message                       |                                |
with session key
""")

print(r"""One of the first things we learn in our introductory security course is that Carol could Man-in-the-Middle (MitM) the DH exchange to obtain session keys with Alice and Bob herself, while poor Alice and poor Bob still believe they are talking privately with each other.
The next thing an introductory security course teaches us is how to prevent this attack.
And here is how this article differs from an introductory security course:
Bob has the misconception that he can use encryption to prevent unauthorized modification.
As the title suggests, this does not work out well for Bob.
Neighbors, don't act like Bob.

Let us hear the story of Alice, Bob, and Carol.
Bob will make five different attempts to transmit the encrypted message to Alice.
He will try to use RSA encryption to prevent a MitM attack.
The protocol aborts prematurely if Carol could break the key before Bob has sent the message.

I hear our quality-conscious readers ask "Story?", surely followed by "PoC or GTFO!".
Esteemed reader, don't worry, the text you are reading right now was generated by \texttt{poc.py}.
You can follow along by \texttt{git clone https://github.com/diekmann/encryption-is-not-integrity.git}.

"Couldn't Bob just use TLS?", you might ask.
For sure!
A TLS handshake would authenticate the DH values and everything would be fine.
But using a ready-made TLS implementation would also be boring.
Furthermore, the handshake sketched above is not TLS.
In the course of this story, Bob will use parts of the OpenSSL library to do parts of the DH handshake for him.
Will this help?
Let the story begin.

""")

h2("Run 0: Prologue and Short recap of Diffie-Hellman")


print("""Alice and Carol are just returning from their introductory security course.
Bob, who also attended the lecture, walks over to Alice.
"If a message is encrypted, an attacker cannot read it and thus cannot modify it," Bob says to Alice.
Alice knows that encryption does not provide integrity and immediately wants to call bullshit on Bob's claim.
But she hesitates for a moment.
Bob won't appreciate an abstract explanation anyway.
"Let's see where this is going," she thinks and agrees to follow his explanation.
"I hope there will be code?" Alice responds.
Bob nods.


"Carol, come over, Bob is explaining crypto," Alice shouts to Carol.
Bob starts explaining, "Let's first create a fresh session key so I can send a secret message to you, Alice."
Alice agrees, this sounds like a good idea.
To make the scenario realistic, Alice makes sure that neither Bob nor Carol can see her screen.
She opens her python3 shell and is about to generate some DH values.
"We need a large prime $p$ and a generator $g$," Alice says.
"607 is a prime", Bob says with Wikipedia open in his browser.
Alice, hoping that Bob is joking about the size of his prime, suggests the smallest prime from RFC 3526 as an example:""")

codespan(p_RFC3526_text)

print(r"""
This is a 1536-bit prime.
Alice notes fascinated, "this prime has $\pi$ in it!"
According to the RFC, the prime is $p = 2^{1536} - 2^{1472} - 1 + 2^{64} \cdot (\lfloor 2^{1406} pi \rfloor + 741804)$.
Alice continues to think aloud, "Let me reproduce this. Does that formula actually compute the prime? Python3 integers have unlimited precision, but $\pi$ is not an integer."
"Python also has floats," Bob replies.
Probably Bob had not been joking when he suggested 607 as large prime previously.
It seems that Bob has no idea what `large' means in cryptography.
Meanwhile, using""")
pythonspan(""">>> import decimal""")
print("""Alice has reproduced the calculation.
By the way, the generator $g$ for said prime is conveniently 2.
""")
assert check_RFC_prime()

print("""A small refresher on DH follows. Note that the RFC uses `^' for exponentiation.
""")
codespan("""=== BEGIN SNIPPET RFC 2631 ===
2.1.1.  Generation of ZZ

   [...] the shared secret ZZ is generated as follows:

     ZZ = g ^ (xb * xa) mod p

   Note that the individual parties actually perform the computations:

     ZZ = (yb ^ xa)  mod p  = (ya ^ xb)  mod p

   where ^ denotes exponentiation

         ya is party a's public key; ya = g ^ xa mod p
         yb is party b's public key; yb = g ^ xb mod p
         xa is party a's private key
         xb is party b's private key
         p is a large prime
=== END SNIPPET RFC 2631 ===""")
print()
print(r'''
Alice takes the initiative, "Okay, I generate a secret value $\mathit(xa)$, compute $\mathit{ya} = g^\mathit{xa} \bmod p$ and send to you $\mathit{ya}, g, p$. This is also how we did it in the lecture."''')
#For the 1536-bit (192 Byte) RFC 3526 prime, $\mathit{ya}$ will be 192 Byte.

# tightly pack y, g, and p such that it is less than the RSA modulus and we can encrypt without problem.
def fmt_ygp(y, g, p):
    # The dot in the beginning is needed such that Crypto RSA will not remove leading zeros
    return b'.' + y.to_bytes(192, byteorder='big') + b',' + g.to_bytes(1, byteorder='big') + b',' + p.to_bytes(192, byteorder='big')

def parse_ygp(ygp):
    #map(int, ygp.split(','))
    assert len(ygp) == 1 + 192 + 1 + 1 + 1 + 192
    assert ygp[0] == ord('.')
    y = int.from_bytes(ygp[1:193], byteorder='big')
    assert ygp[193] == ord(',')
    g = int(ygp[194])
    assert ygp[195] == ord(',')
    p = int.from_bytes(ygp[196:], byteorder='big')
    return (y, g, p)

print(r"""Bob then has to choose a secret value $\mathit(xb)$, compute $\mathit{yb} = g^\mathit{xb} \bmod p$ and send $\mathit{yb}$ back to Alice, so she can compute $\mathit{ZZ}_a$.
Bob then uses the key $\mathit{ZZ}_b$ he computed to encrypt a message and send it to Alice.
Since $\mathit{ZZ}_b = \mathit{ZZ}_a$, Alice can decrypt the message.
""")

print(r"""This is what Alice and Bob plan to do:""")
codespan(r"""
   Alice                            Carol                             Bob
xa = random()                         |                                |
ya = pow(g, xa, p)                    |                            xb = random()
     |                                |                            yb = pow(g, xb, p)
     |           (ya, g, p)           |                                |
     |------------------------------->|           (ya, g, p)           |
     |                                |------------------------------->|
     |                                |                            ZZ_b = pow(ya, xb, p)
     |                                |                                |
     |                                |               yb               |
     |               yb               |<-------------------------------|
     |<-------------------------------|                                |
ZZ_a = pow(yb, xa, p)                 |                            ciphertext =
     |                                |                            Enc(ZZ_b, message)
     |                                |           ciphertext           |
     |          ciphertext            |<-------------------------------|
     |<-------------------------------|                                |
Dec(ZZ_a, ciphertext)
= message
""")

def fmt_y(y):
    return y.to_bytes(192, byteorder='big')

def parse_y(y):
    assert len(y) <= 192
    return int.from_bytes(y, byteorder='big')


print(r""""Let's go then," Bob says.
"Wait," Alice intervenes, "DH is only secure against passive attackers. An active attacker could MitM our exchange."
Alice and Bob look at Carol, she smiles.
Alice continues, "What did you say in the beginning?"
"Right," Bob says, "we must encrypt our DH values, so Carol cannot MitM us."
Fortunately, Alice and Bob have 4096-bit RSA keys and have securely distributed their public keys beforehand.""")

print(r"""
"Okay, what should I do?" Alice asks.
She knows exactly what to do, but Bob's stackoverflow-driven approach to crypto may prove useful in the course of this story.
Bob types into Alice's terminal:""")
pythonspan(r""">>> import Crypto.PublicKey.RSA
>>> def RSA_enc(k_pub, msg):
...     return k_pub.encrypt(msg, None)[0]""")
print(r"""He comments, "We can ignore this None and only need the first value from the tuple. Both exist only for compatibility."
Bob is right about that and we now have a convenient textbook RSA encryption function at hand.
""")

### run 1
h2("Run 1: RSA-Encrypted textbook DH in one line of python")
init_global_state(p_RFC3526, g_RFC3526)

print(r"""
Now Alice and Bob are ready for their DH exchange.
In contrast to their original sketch, they will encrypt their DH values with RSA.""")

## Alice:
def alice_step1():
    g = GLOB['pub']['DH_g']
    p = GLOB['pub']['DH_p']

    # get a random private value and remember it
    xa = int.from_bytes(os.urandom(192), byteorder='big')
    GLOB['Alice']['xa'] = xa
    assert 0 < xa < p
    # compute public key
    ya = pow(g, xa, p)
    return RSA_enc(GLOB['pub']['k_Bob_pub'], fmt_ygp(ya, g, p))

print(r"""Alice generates:""")
pythonspan(r""">>> xa = int.from_bytes(os.urandom(192), byteorder='big')
>>> ya = pow(g, xa, p)""")
print(r"""and sends""")
pythonspan(r""">>> RSA_enc(k_Bob_pub, (ya, g, p))""")
thewire = alice_step1()
print("Alice sends {}.".format(abbrev(thewire)))

print(r"""How does Alice send the message?
She hands it over to Carol.
Carol starts fiddling around with with the data.
"What are you doing?" Bob asks.
Alice replies, "It is encrypted, those were your words. Carol will deliver the message to you."
""")

## Carol MitM: Alice->Carol->Bob
def carol_mitm_acb_trivial():
    # ignore wire; g and p are not a secret
    g = GLOB['pub']['DH_g']
    p = GLOB['pub']['DH_p']
    # get a random private value
    xc = 0
    # compute public key
    yc = pow(g, xc, p)
    assert yc == 1
    return RSA_enc(GLOB['pub']['k_Bob_pub'], fmt_ygp(yc, g, p))
thewire = carol_mitm_acb_trivial()
print("Carol forwards {}.".format(abbrev(thewire)))


## Bob:
def bob_step1(wire):
    ya, g, p = parse_ygp(RSA_dec(GLOB['Bob']['k_priv'], wire))
    assert g == GLOB['pub']['DH_g']
    assert p == GLOB['pub']['DH_p']
    xb = int.from_bytes(os.urandom(192), byteorder='big')
    GLOB['Bob']['xb'] = xb
    assert 0 < xb < p
    yb = pow(g, xb, p)
    # shared key
    ZZ_b = pow(ya, xb, p)
    GLOB['Bob']['key'] = ZZ_b
    return RSA_enc(GLOB['pub']['k_Alice_pub'], fmt_y(yb))
print(r"""Bob decrypts with his private RSA key, parses ya, g, p from the message, and computes""")
pythonspan(r""">>> xb = int.from_bytes(os.urandom(192), byteorder='big')
>>> yb = pow(g, xb, p)
>>> ZZ_b = pow(ya, xb, p)""")
print(r"""and sends""")
pythonspan(r""">>> RSA_enc(k_Alice_pub, yb)""")
thewire = bob_step1(thewire)
print("Bob sends {}.".format(abbrev(thewire)))

## Carol MitM: Bob->Carol->Alice
def carol_mitm_bca_trivial():
    return RSA_enc(GLOB['pub']['k_Alice_pub'], fmt_y(1))
thewire = carol_mitm_bca_trivial()
assert thewire == b'\x01'
# don't print the message yet, we don't want to spoil the surprise in the fourth run.
print("Carol forwards a different message.")

## Alice:
def alice_step2(wire):
    yb = parse_y(RSA_dec(GLOB['Alice']['k_priv'], wire))
    p = GLOB['pub']['DH_p']
    xa = GLOB['Alice']['xa']
    ZZ_a = pow(yb, xa, p)
    GLOB['Alice']['key'] = ZZ_a
alice_step2(thewire)
print("Alice performs her part to finish the DH handshake.")


## Both have the same key, despite the man in the middle!
assert GLOB['Alice']['key'] == GLOB['Bob']['key']
# Carol knows
assert GLOB['Alice']['key'] == 1 and GLOB['Bob']['key'] == 1
print('''Carol exclaims, "The key is 1!"''')
print(r"""Bob and Alice check.
Carol is right.
How can Carol know the established keys?
Bob is right about one thing, the DH values were encrypted, so a trivial textbook DH MitM attack does not work since Carol cannot get the ya and yb values.
But she doesn't need to.
This is what happened so far:""")

codespan(r"""
   Alice                            Carol                             Bob
     |                                |                                |
     |   RSA(k_Bob_pub, (ya, g, p))   |                                |
     |------------------------------->|                                |
     |                                |   RSA(k_Bob_pub, (1, g, p))    |
     |                                |------------------------------->|
     |                                |                           RSA decrypt
     |                                |                           ZZ_b = pow(1, xb, p)
     |                                |                                |
     |                                |                                |
     |                                |      RSA(k_Alice_pub, yb)      |
     |                                |<-------------------------------|
     |       RSA(k_Alice_pub, 1)      |
     |<-------------------------------|
RSA decrypt
ZZ_a = pow(1, xa, p)""")
print()
print(r"""The prime $p$, the generator $g$, and the public keys are public knowledge, also known to Carol (check your textbook, neighbor).
Consequently, Carol can encrypt DH values, but she cannot read the ones from Alice and Bob.
Bob computes the shared DH key as $\mathit{ya}^\mathit{xb} \bmod p$, where Carol supplied $1$ for $\mathit{ya}$.
Carol can be sure that Bob will compute a shared key of $1$, she doesn't need to know any encrypted values.
Same goes for the exchange with Alice.

"No No," Bob protests, "these values are not allowed in DH."
Alice checks RFC 2631 and quotes: <<The following algorithm MAY be used to validate a received public key y [...] Verify that y lies within the interval [2,p-1]. If it does not, the key is invalid.>>
Bob replies, "So y = 1 is clearly invalid, you must not do this Carol."
Alice objects, "The check is optional, see this all-caps MAY there?"
But Bob feels certain that he is right and insists, "Any library would reject this key!"
""")


### run 2, Bob uses library to prevent bad values
h2("Run 2: RSA-Encrypted textbook DH using parts of the OpenSSL library")
init_global_state(p_RFC3526, g_RFC3526)

print(r""""Sure, we'll give it a try." Alice responds.
She sticks to her old code because the RFC clearly states the check optional, but Bob can reject the weak values.
""")

## Alice:
thewire = alice_step1()
print("Alice sends {}.".format(abbrev(thewire)))

thewire = carol_mitm_acb_trivial()
print("Carol, testing the same trick again, forwards {}.".format(abbrev(thewire)))

## Bob:
def bob_step1_lib(wire):
    ya, g, p = parse_ygp(RSA_dec(GLOB['Bob']['k_priv'], wire))
    pn = dh.DHParameterNumbers(p, g)
    parameters = pn.parameters(openssl.backend)
    #fortunately, generator 2 is one of openssl's favorite

    xb = parameters.generate_private_key()

    # feed ya to the openssl library backend
    alice_public_key = dh.DHPublicNumbers(ya, pn).public_key(openssl.backend)
    assert alice_public_key.key_size == 1536

    yb = xb.public_key().public_numbers().y
    try:
        ZZ_b = xb.exchange(alice_public_key)
    except ValueError as e:
        return "ValueError: {}".format(e)
    GLOB['Bob']['key'] = ZZ_b
    return RSA_enc(GLOB['pub']['k_Alice_pub'], fmt_y(yb))

print(r"""Bob now uses \texttt{pyca/cryptography} with the openssl backend to do the DH computation.
Maybe just doing `ZZ_b = pow(ya, xb, p)` was too simple?
Let's see what happens when we use some part of the OpenSSL library (wrapped by \texttt{pyca/cryptography}) to perform the same computation.
A word of clarification: The OpenSSL library is only used to implement the DH part on Bob's side, the exchange is not tunneled over TLS.
The RSA-part remains unchanged.
""")
pythonspan(r""">>> from cryptography.hazmat.primitives.asymmetric import dh
>>> from cryptography.hazmat.backends import openssl
>>> pn = dh.DHParameterNumbers(p, g)
>>> parameters = pn.parameters(openssl.backend)
>>> xb = parameters.generate_private_key()
>>> # feed ya to the openssl library backend
>>> alice_public_key = dh.DHPublicNumbers(ya, pn).public_key(openssl.backend)
>>> assert alice_public_key.key_size == 1536 # 1536-bit MODP group of our prime
>>> yb = xb.public_key().public_numbers().y
>>> ZZ_b = xb.exchange(alice_public_key)""")
thewire = bob_step1_lib(thewire)
assert thewire == "ValueError: Public key value is invalid for this exchange."
print("""And indeed, the last line aborts with the exception `{}'
Alice and Bob abort the handshake.""".format(thewire))
#handshake aborted

print("""This is what happened so far:""")

codespan(r"""
   Alice                            Carol                             Bob
     |                                |                                |
     |   RSA(k_Bob_pub, (ya, g, p))   |                                |
     |------------------------------->|                                |
     |                                |   RSA(k_Bob_pub, (1, g, p))    |
     |                                |------------------------------->|
     |                                |                           RSA decrypt
     |                                |                           With (ya = 1, g, p)
     |                                |                           using openssl.backend to
     |                                |                           compute ZZ_b ...
     |                                |                           raise ValueError
""")

print("""
"Now you must behave, Carol. We will no longer accept your MitMed values. Now that we prohibit the two bad DH values and everything is encrypted, we are 100% secure," Bob says.""")


### run 3, Bob still uses library to prevent bad values
h2("Run 3: RSA-Encrypted textbook DH using parts of the OpenSSL library and custom Primes")
init_global_state(p_RFC3526, g_RFC3526)

print(r"""
Alice and Bob try the handshake again. Carol cannot send $ya = 1$ because Bob will detect it and abort the handshake.""")

## Alice:
thewire = alice_step1()
print("Alice sends {}.".format(abbrev(thewire)))


## Carol MitM: Alice->Carol->Bob
def carol_mitm_acb_badprime():
    #ignore wire, we cannot read it anyway

    g = 2
    # choose a new `prime'
    # we craft our own 'prime'
    p = pow(2, 1536) - 1
    assert(pow(2, 1536) - 1) % 3 == 0, "Actually, p is not a prime."

    # get a random private value
    xc = int.from_bytes(os.urandom(192), byteorder='big')

    # compute public key
    yc = pow(g, xc, p)

    return RSA_enc(GLOB['pub']['k_Bob_pub'], fmt_ygp(yc, g, p))
thewire = carol_mitm_acb_badprime()
print(r"""But Carol knows the math.
She chooses a specially-crafted `prime' $\mathit{pc}$ and computes a random, valid $\mathit{yc}$ value.""")
pythonspan(r""">>> pc = pow(2, 1536) - 1
>>> xc = int.from_bytes(os.urandom(192), byteorder='big')
>>> yc = pow(g, xc, pc)""")
print(r"""Well, $pc$ isn't actually a prime.
Let's see if OpenSSL accepts it as prime.
Reliably testing for primality is expensive,""", end='')
# Primality tests:
# Introduction to Modern Cryptography (2nd edition) by Jonathan Katz and Yehuda Lindell. Chapter 8.2.1  p.305
# or just https://en.wikipedia.org/wiki/Primality_test#Fast_deterministic_tests
print(r"""\footnote{Common primality tests are probabilistic and relatively fast, but can err. Deterministic primality tests in polynomial time exist. """, end='')
print(r"""Note that DH does not need an arbitrary prime and some $g$, but the generator should generate a not-too-small\textsuperscript{TM} subgroup.} """, end='')
print(r"""chances are good that the prime gets waved through.""")
print("Carol forwards {}.".format(abbrev(thewire)))


thewire = bob_step1_lib(thewire)
print("""After RSA decryption, Bob's code with the OpenSSL backend happily accepts all values.""")
print("Bob sends {}.".format(abbrev(thewire)))


## Carol MitM: Bob->Carol->Alice
def carol_mitm_bca_plausiblevalues(wire):
    # just send plausible values to let the exchange continue, we don't actually establish a key
    g = GLOB['pub']['DH_g']
    p = GLOB['pub']['DH_p']
    xc = int.from_bytes(os.urandom(192), byteorder='big')
    yc = pow(g, xc, p)
    # we don't know the shared key
    return RSA_enc(GLOB['pub']['k_Alice_pub'], fmt_y(yc))
thewire = carol_mitm_bca_plausiblevalues(thewire)
print(r"""Alice still thinks that the RFC 3526 prime is used.
Carol just forwards random plausible values to Alice, but she won't be able to MitM this key.""")
print("Carol forwards {}.".format(abbrev(thewire)))


alice_step2(thewire)

print("""The DH key exchange is completed successfully.""")



# if now Bob sends something encrypted, we can bruteforce it!!!!
### at Bob
print(r"""Now Bob can use the key $\mathit{ZZ}_b$ established with DH to send an encrypted message to Alice.""")
pythonspan(r""">>> iv = os.urandom(16)
>>> aeskey = kdf128(ZZ_b) # squash the key to 128 bit
>>> ct = aes128_ctr(iv, aeskey, b'Hey Alice! See, this is perfectly secure now.')
>>> wire = "{},{}".format(hexlify(iv).decode('ascii'), hexlify(ct).decode('ascii'))""")
def bob_send_encrypted_msg():
    iv = os.urandom(16)
    aeskey = kdf128(GLOB['Bob']['key']) # squash the key to 128 bit
    ct = aes128_ctr(iv, aeskey, b'Hey Alice! See, this is perfectly secure now.')
    return "{},{}".format(hexlify(iv).decode('ascii'), hexlify(ct).decode('ascii'))
thewire = bob_send_encrypted_msg()
print("Bob sends the IV and the ciphertext message {}.".format(thewire))

print("""In summary, this is what happened so far:""")

codespan(r"""
   Alice                            Carol                             Bob
     |                                |                                |
     |   RSA(k_Bob_pub, (ya, g, p))   |                                |
     |------------------------------->|                                |
     |                                |  RSA(k_Bob_pub, (yc, g, pc))   |
     |                                |------------------------------->|
     |                                |                           RSA decrypt
     |                                |                           using openssl.backend
     |                                |                           ZZ_b = pow(yc, xb, pc)
     |                                |                                |
     |                                |                                |
     |                                |      RSA(k_Alice_pub, yb)      |
     |                                |<-------------------------------|
     |    RSA(k_Alice_pub, garbage)   |                                |
     |<-------------------------------|                           ciphertext =
RSA decrypt                           |                           Enc(ZZ_b, message)
ZZ_a = garbage2                       |           ciphertext           |
     |                                |<-------------------------------|
""")

# Carol hax0rs it
print(r"""Carol chose a great `prime' $\mathit{pc} = 2^{1536} - 1$ and knows the key is broken: Only one bit is set!
She can just brute force all possible keys, the one that decrypts the ciphertext to printable ASCII text is most likely the correct key.""")
pythonspan(r""">>> iv, ct = map(unhexlify, wire.split(','))
>>> for i in range(1536):
...     keyguess = pow(2, i)
...     msg = aes128_ctr(iv, kdf128(keyguess.to_bytes(192, byteorder='big')), ct)
...     try:
...         if not all(c in string.printable for c in msg.decode('ascii')):
...             continue
...     except UnicodeDecodeError: #not ASCII
...         continue
...     break
""")
def carol_bruteforce_dh_weakprime(wire):
    iv, ct = map(unhexlify, wire.split(','))
    for i in range(1536):
        keyguess = pow(2, i)
        msg = aes128_ctr(iv, kdf128(keyguess.to_bytes(192, byteorder='big')), ct)
        try:
            msg = msg.decode('ascii')
            if not all(c in string.printable for c in msg):
                # Bob's message is likely only printable ASCII letters
                #print("Decodes but unlikely: {}".format(msg))
                continue
        except UnicodeDecodeError: #not ASCII
            continue
        break

    assert keyguess == int.from_bytes(GLOB['Bob']['key'], 'big')
    print("""The brute-forced key is {}, or in hex {} (exactly one bit set). Carol is correct."""
          .format(keyguess, str(keyguess.to_bytes(192, byteorder='big'))[1:]))
    print("She immediately shouts out the message `{}'".format(msg))
    return msg
Carol_remembers_message = carol_bruteforce_dh_weakprime(thewire)



# no need to forward to Alice. Alice would be unable to decrypt because the DH exchange with her is broken. But it is too late to react now.

print(r"""Bob is depressed.
"Why doesn't my code work?", he asks.
"Probably DH is not strong enough and we need to use elliptic curve DH?", he conjectures.
"Maybe Carol even has a quantum computer hidden in her pocket, let me find a post-quantum replacement for Diffie-Hellman, ..." he continues.
Carol interferes, "The same ideas of my attack also apply to ECDH or a post-quantum drop-in replacement with the same properties. Don't waste your time on this line of thought. If you cannot use textbook DH, ECDH (or the post-quantum candidates) won't help."
""")


# Run 4, we sign with plain textbook RSA
h2("Run 4: Textbook DH signed with textbook RSA")
init_global_state(p_RFC3526, g_RFC3526)
# Real-world notice: Use different RSA key pairs for signatures and encryption [RFC 8017]. But this doesn't change anything for our story.

print(r"""
Alice tries to put Bob on the right track, "Maybe RSA encryption does not help, but can we use RSA differently? Remember, encryption itself does not not provide integrity."
"Of course," Bob replies, "we need to sign the DH values. And signing with RSA is just encryption with the private key."
"Don't forget the padding," Alice is trying to help, but Bob immediately codes:""")
pythonspan(r""">>> import Crypto.PublicKey.RSA
>>> def RSA_sign(k_priv, msg):
...     # ignore the compatibility parameters
...     return k_priv.sign(msg, None)[0]
>>> def RSA_verify(k_pub, msg, signature):
...     # ignore the compatibility parameters
...     return k_pub.verify(msg, (signature, None))""")
print(r"""Again, Bob is right about ignoring the compatibility parameters.
However, Carol smiles as Bob completely ignored Alice's comment about padding.
""")

print(r""""Let's hardcode the prime $p$ and generator $g$ for simplicity and switch back to the trivial non-OpenSSL implementation." Alice suggests and everybody agrees.
This simplifies the DH exchange as now, only $y$ and the signature of $y$ will be exchanged.""")

# We can also switch to a simpler text-only wire format, so we can see more
# Before, we needed to be compact y,g,p to fit everything in a byte object less than the RSA modulus, now we just exchange the Y values.
# Gets nicer output, since now half of the message is plaintext

## Alice:
def alice_rsasign_step1():
    g = GLOB['pub']['DH_g']
    p = GLOB['pub']['DH_p']

    # get a random private value and remember it
    xa = int.from_bytes(os.urandom(192), byteorder='big')
    GLOB['Alice']['xa'] = xa
    assert 0 < xa < p
    # compute public key
    ya = pow(g, xa, p)
    return "{},{}".format(ya, RSA_sign(GLOB['Alice']['k_priv'], ya))
thewire = alice_rsasign_step1()
print(r"""Alice only sends the following in the first step:""")
pythonspan(r""">>> "{},{}".format(ya, RSA_sign(k_Alice_priv, ya))""")
print("Alice sends {}.".format(abbrev(thewire)))


## Carol MitM: Alice->Carol->Bob
def carol_mitm_acb_rsasign():
    # yes, RSA_verify(any_key, 1, 1) holds
    return "1,1"
thewire = carol_mitm_acb_rsasign()
print("Carol just forwards {}.".format(abbrev(thewire)))


## Bob:
def bob_rsasign_step1(wire):
    g = GLOB['pub']['DH_g']
    p = GLOB['pub']['DH_p']

    ya, signature = map(int, wire.split(','))

    # check signature
    if not RSA_verify(GLOB['pub']['k_Alice_pub'], ya, signature):
        print("Signature verification failed")
        return 'reject'

    xb = int.from_bytes(os.urandom(192), byteorder='big')
    GLOB['Bob']['xb'] = xb
    assert 0 < xb < p
    yb = pow(g, xb, p)
    # shared key
    ZZ_b = pow(ya, xb, p).to_bytes(192, byteorder='big')
    GLOB['Bob']['key'] = ZZ_b
    return "{},{}".format(yb, RSA_sign(GLOB['Bob']['k_priv'], yb))
thewire = bob_rsasign_step1(thewire)
print(r"""Bob parses the values, verifies the signature correctly and performs his step of the DH exchange.""")
pythonspan(r""">>> ya, signature = map(int, wire.split(','))
>>> if not RSA_verify(k_Alice_pub, ya, signature):
>>>     print("Signature verification failed")
>>>     return 'reject'
[...]
>>> return "{},{}".format(yb, RSA_sign(k_Bob_priv, yb))""")
print("Bob sends {}.".format(abbrev(thewire)))

## Carol MitM: Bob->Carol->Alice
# same trick works
thewire = carol_mitm_acb_rsasign()
print("Carol just forwards {}.".format(abbrev(thewire)))

## Alice:
def alice_rsasign_step2(wire):
    yb, signature = map(int, wire.split(','))

    # check signature
    if not RSA_verify(GLOB['pub']['k_Bob_pub'], yb, signature):
        print("Signature verification failed")
        return

    p = GLOB['pub']['DH_p']
    xa = GLOB['Alice']['xa']
    ZZ_a = pow(yb, xa, p).to_bytes(192, byteorder='big')
    GLOB['Alice']['key'] = ZZ_a
alice_rsasign_step2(thewire)


print(r"""Alice smiles as she receives the values.
Nevertheless, she performs the signature verification professionally.
Both the signature check at Bob and the signature check at Alice were successful and Alice and Bob agreed on a shared key.""")

print(r"""This is what happened so far, where \texttt{RSA} corresponds to `RSA_sign` as defined above:""")

codespan(r"""
   Alice                            Carol                             Bob
     |                                |                                |
     |   ya, RSA(k_Alice_priv, ya)    |                                |
     |------------------------------->|                                |
     |                                |               1,1              |
     |                                |------------------------------->|
     |                                |                           RSA_verify(k_Alice_pub, 1, 1)
     |                                |                           ZZ_b = pow(1, xb, p)
     |                                |                                |
     |                                |                                |
     |                                |     yb, RSA(k_Bob_priv, yb)    |
     |                                |<-------------------------------|
     |               1,1              |
     |<-------------------------------|
RSA_verify(k_Bob_pub, 1, 1)
ZZ_a = pow(1, xa, p)
""")

## Both have the same key, despite the man in the middle!
assert GLOB['Alice']['key'] == GLOB['Bob']['key']
# Carol knows
assert GLOB['Alice']['key'] == (1).to_bytes(192, byteorder='big') and GLOB['Bob']['key'] == (1).to_bytes(192, byteorder='big')
print('''Carol exclaims "The key is 1!"''')

print(r"""Bob is all lost, "How could this happen again? I checked the signature!"
"Indeed," Carol explains, "but you should have listened to Alice's remark about the padding.
RSA signatures are not just the textbook RSA operation with the private key.
Plain textbook RSA is just $\mathit{msg}^d \bmod N$, where $d$ is private.
Guess how I could forge a valid RSA private key operation without knowledge of $d$ if I may choose $\mathit{msg}$ freely?"
Bob looks desperate.
"Can Carol break RSA? What is the magic math behind her attack?", he wonders.
Carol helps, "$1^d \bmod N = 1$, for any $d$. Of course I did not break RSA. The way you tried to use RSA as a signature scheme is just not existentially unforgeable.
Paddings, or signature schemes, exist for a reason."
By the way, the RSA encryption without padding used in the previous runs is also dangerous.\footnote{Use OAEP!}
""")


# Run 5, we sign with RSA PSS as pyca/cryptography calls it, or RSASSA-PSS as RFC 8017 calls it
h2("Run 5: Textbook DH signed with RSASSA-PSS")
init_global_state(p_RFC3526, g_RFC3526)

# We no longer use pyCrypto!
# transform keys from Crypto objects to cryptography objects
def key_Crypto_to_cryptography(person):
    def to_PEM(key):
        return key.exportKey(format='PEM', passphrase=None, pkcs=1)

    GLOB[person]['k_priv'] = load_pem_private_key(to_PEM(GLOB[person]['k_priv']), None, openssl.backend)
    pub = 'k_{}_pub'.format(person)
    GLOB['pub'][pub] = load_pem_public_key(to_PEM(GLOB['pub'][pub]), openssl.backend)


for person in ('Alice', 'Bob', 'Carol'):
    key_Crypto_to_cryptography(person)

print(r"""Bob replaces the sign and verify functions:""")
pythonspan(r""">>> from cryptography.hazmat.primitives import hashes
>>> from cryptography.hazmat.primitives.asymmetric import padding
>>> def RSA_sign(k_priv, msg):
>>>     return k_priv.sign(
...         msg,
...         padding.PSS(
...             mgf=padding.MGF1(hashes.SHA256()),
...             salt_length=padding.PSS.MAX_LENGTH
...         ),
...         hashes.SHA256()
...     )""")
print(r"""The `RSA_verify` function is replaced accordingly.
""")

# make sure old defs are gone
del RSA_sign
del RSA_verify

new_RSA_sign_called = False

def RSA_sign(k_priv, msg):
    global new_RSA_sign_called
    new_RSA_sign_called = True
    # for compatibility with the previous implementation, msg is an int and the returned signature is also an int
    assert isinstance(msg, int)
    msg = fmt_y(msg)
    signature = k_priv.sign(
        msg,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return int.from_bytes(signature, byteorder='big')


new_RSA_verify_called = False

def RSA_verify(k_pub, msg, signature):
    global new_RSA_verify_called
    new_RSA_verify_called = True
    assert isinstance(msg, int)
    assert isinstance(signature, int)
    msg = fmt_y(msg)
    signature = signature.to_bytes(512, byteorder='big')
    try:
        # raises InvalidSignature if the signature does not validate.
        k_pub.verify(
            signature,
            msg,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
    except:
        return False
    else:
        return True


assert RSA_verify(GLOB['pub']['k_Alice_pub'], 42, RSA_sign(GLOB['Alice']['k_priv'], 42))
assert not RSA_verify(GLOB['pub']['k_Alice_pub'], 43, RSA_sign(GLOB['Alice']['k_priv'], 42))
assert new_RSA_sign_called and new_RSA_verify_called
new_RSA_sign_called = False
new_RSA_verify_called = False

#"""RSASSA-PSS is different from other RSA-based signature schemes in
#   that it is probabilistic rather than deterministic, incorporating a
#   randomly generated salt value.""" [RFC 8017]
assert RSA_sign(GLOB['Alice']['k_priv'], 42) != RSA_sign(GLOB['Alice']['k_priv'], 42), "probabilistic signature scheme is probabilistic"

# we replaced the RSA_sign and RSA_verify functions, we don't need to change anything in the code called by Alice and Bob
print(r"""Now Alice and Bob can try their handshake again.""")

## Alice:
thewire = alice_rsasign_step1()
assert new_RSA_sign_called
assert not new_RSA_verify_called
print("Alice sends {}.".format(abbrev(thewire)))

print(r"""Carol forwards the message unmodified.
Bob looks at Carol suspiciously.
"I cannot modify this without breaking the signature," Carol replies.
"Probably the DH prime is a bit too small for the future; Logjam predicts 1024-bit breakage. Maybe you could use fresh DH values for each exchange or switch to ECDH to be ready for the future, ... 
But I'm out of ideas for attack I could carry out on my slow laptop against your handshake for now." Carol concludes.
""")

## Bob:
thewire = bob_rsasign_step1(thewire)
assert new_RSA_verify_called
print("Bob sends {}.".format(abbrev(thewire)))

print("Carol forwards the message unmodified.")

## Alice:
alice_rsasign_step2(thewire)


assert GLOB['Alice']['key'] == GLOB['Bob']['key']
### at Bob
print(r"""Finally, Alice and Bob established a shared key and Carol does not know it.
""")
codespan(r"""
   Alice                            Carol                             Bob
     |                                |                                |
     |   ya, RSA(k_Alice_priv, ya)    |                                |
     |------------------------------->|                                |
     |                                |   ya, RSA(k_Alice_priv, ya)    |
     |                                |------------------------------->|
     |                                |                           RSA_verify(k_Alice_pub, ...)
     |                                |                           ZZ_b = pow(ya, xb, p)
     |                                |                                |
     |                                |                                |
     |                                |     yb, RSA(k_Bob_priv, yb)    |
     |                                |<-------------------------------|
     |    yb, RSA(k_Bob_priv, yb)     |
     |<-------------------------------|
RSA_verify(k_Bob_pub, ...)
ZZ_a = pow(yb, xa, p)
""")
print(r"""To complete the scenario, Bob uses the freshly established key to send an encrypted message to Alice.""")
pythonspan(r""">>> iv = os.urandom(16)
>>> aeskey = kdf128(ZZ_b) # squash the key to 128 bit
>>> ct = aes128_ctr(iv, aeskey, b'Hey Alice! See, this is perfectly secure now.')
>>> wire = "{},{}".format(hexlify(iv).decode('ascii'), hexlify(ct).decode('ascii')""")
thewire = bob_send_encrypted_msg()
print("Bob sends the IV and the ciphertext message {}.".format(thewire))


## Carol
def carol_modify_aesctr(wire):
    iv, ct = map(unhexlify, wire.split(','))
    assert len(ct) == len(Carol_remembers_message.encode('ascii'))
    print(r"""Carol remembers the plaintext Bob sent in run 3.""")
    print(r"""She realizes that this run's ciphertext has exactly the same length as the plaintext in run 3.""")

    # xor together the ciphertext and the old plaintext
    keystream = (a ^ b for a, b in zip(ct, Carol_remembers_message.encode('ascii')))

    # new ciphertext
    ct = bytes(a ^ b for a, b in zip(keystream, "Encryption is not Integrity.".encode('ascii')))
    return "{},{}".format(hexlify(iv).decode('ascii'), hexlify(ct).decode('ascii'))
thewire = carol_modify_aesctr(thewire)
print("Carol forwards a ciphertext which is slightly shorter:", thewire)


## Alice
def alice_receive_aesctr_message(wire):
    iv, ct = map(unhexlify, wire.split(','))
    aeskey = kdf128(GLOB['Alice']['key']) # squash the key to 128 bit
    return aes128_ctr(iv, aeskey, ct).decode('ascii')

print(r"""Alice reads out loud the message she received and decrypted: `{0:s}'
Bob shouts, "This is not the message! How can this happen? Did Carol break AES-CTR?"
Alice and Carol answer simultaneously, "AES-CTR is secure encryption, but {0:s}"
""".format(alice_receive_aesctr_message(thewire)))


