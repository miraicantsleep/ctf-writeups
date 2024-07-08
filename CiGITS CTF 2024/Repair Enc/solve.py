import requests
import time
from Crypto.Util.number import *
import random


def getprimes(x):
    prime = x
    if not prime & 1:
        prime += 1
    while not isPrime(prime):
        prime += 2
    return prime


def main():
    # url = "http://139.59.120.240:11171/encrypt"
    url = "http://127.0.0.1:5000/encrypt"

    plaintext = open("/dev/urandom", "rb").read(16).hex()
    data = {"plaintext": plaintext}
    response = requests.post(url, json=data)

    seedTime = int(time.time() * 100) % 10000
    print(response.text)

    # try to bruteforce seedtime because of latency
    for i in range(-100, 100):
        temp = seedTime + i
        random.seed(temp)
        checkNumber = random.getrandbits(512)
        if hex(checkNumber) == response.json()["checkNumber"]:
            seedTime = temp
            # print(f"Found seedTime")
            # print(f"checkNumber matched")
            print(f"seedTime: {hex(seedTime)}")
            print(f"checkNumber: {hex(checkNumber)}")
            break

    # get p and q
    p = getprimes(random.getrandbits(512))
    q = getprimes(p + 512)
    phi = (p - 1) * (q - 1)
    print(f"p: {hex(p)}")
    print(f"q: {hex(q)}")
    n = p * q
    c = int(response.json()["c"], 16)
    e = int(response.json()["e"], 16)
    d = pow(e, -1, phi)
    print(f"Found d: {hex(d)}")
    m = pow(c, d, n)
    print(f"m: {long_to_bytes(m)}")


if __name__ == "__main__":
    main()
