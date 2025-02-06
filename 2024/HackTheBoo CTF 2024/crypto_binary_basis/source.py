from Crypto.Util.number import getPrime, bytes_to_long
from math import prod

FLAG = open('flag.txt', 'rb').read()

primes = [getPrime(128) for _ in range(16)]

n = prod(primes)
e = 0x10001
m = bytes_to_long(FLAG)
c = pow(m, e, n)
treat = sum([primes[i]*2**(0x1337-158*(2*i+1)) for i in range(16)])

with open('output.txt', 'w') as f:
   f.write(f'{n = }\n')
   f.write(f'{e = }\n')
   f.write(f'{c = }\n')
   f.write(f'{treat = }\n')