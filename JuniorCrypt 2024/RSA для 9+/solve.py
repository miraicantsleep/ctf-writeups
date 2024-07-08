#!/usr/bin/env python3

import sys
import base64

from pwn import *
context.log_level = 'debug'
def show(name, value, *, b64=True):
    log.info(f"{name}: {value}")

def show_b64(name, value):
    show(f"{name} (b64)", base64.b64encode(value).decode())

def show_hex(name, value):
    show(name, hex(value))

host = 'ctf.mf.grsu.by'
port = 9019

run = remote(host, port)

while True:
    # Read the RSA public exponent e
    run.recvuntil(b"e: ")
    estr = run.recvline().strip();
    e = int(estr, 16)
    show_hex("e", e)

    # Read the RSA private exponent d
    run.recvuntil(b"d: ")
    dstr = run.recvline().strip();
    d = int(dstr, 16)
    show_hex("d", d)

    # Read the RSA modulus
    run.recvuntil(b"n: ")
    nstr = run.recvline().strip();
    n = int(nstr, 16)
    show_hex("n", n)

    # Read the Base64 encoded secret
    run.recvuntil(b"secret ciphertext (b64): ")
    secretb64 = run.recvline().strip();
    secret = base64.b64decode(secretb64)
    show_b64("secret", secret)

    # Decrypt the RSA encrypted message
    plaintext = pow(int.from_bytes(secret, "little"), d, n).to_bytes(256, "little").strip(b"\x00")
    info(f"Decrypted secret: {plaintext}")
    run.sendline(base64.b64encode(plaintext).decode())