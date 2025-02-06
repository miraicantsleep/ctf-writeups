#!/usr/bin/python3
from pwn import *
from ctypes import CDLL

# =========================================================
#                          SETUP                         
# =========================================================
exe = './rigged_slot1' # <-- change this
elf = context.binary = ELF(exe, checksec=True)
libc = '/lib/x86_64-linux-gnu/libc.so.6'
libr = CDLL(libc)
libc = ELF(libc, checksec=False)
context.log_level = 'debug'
context.terminal = ["tmux", "splitw", "-h"]
host, port = '', 1337 # <-- change this

def initialize(argv=[]):
    if args.GDB:
        return gdb.debug([exe] + argv, gdbscript=gdbscript)
    elif args.REMOTE:
        return remote(host, port)
    else:
        return process([exe] + argv)

gdbscript = '''
init-pwndbg
'''.format(**locals())

# =========================================================
#                         NOTES
# =========================================================

def generate_inputs():
    inputs = []
    verdict = []
    
    balance = 100
    target_balance = 133742
    
    max_user_input = 100
    min_user_input = 1
    number_of_rounds = 0
    
    print(f"Starting balance: ${balance}")
    print(f"Target balance: ${target_balance}\n")
    
    libr.srand(libr.time(None))
    
    while balance < target_balance:
        number_of_rounds += 1

        # Predict v4
        v4 = libr.rand() % 100

        if v4 == 0:
            v3 = 100
        elif v4 <= 9:
            v3 = 5
        elif v4 <= 14:
            v3 = 3
        elif v4 <= 19:
            v3 = 2
        elif v4 <= 29:
            v3 = 1
        else:
            v3 = 0

        v3_minus_1 = v3 - 1
        if v3_minus_1 > 0:
            outcome = 'Win'

            amount_needed = target_balance - balance
            required_user_input = amount_needed // v3_minus_1

            if required_user_input < min_user_input:
                userInput = min_user_input
            elif required_user_input > max_user_input:
                userInput = max_user_input
            else:
                userInput = required_user_input

            expected_win = v3_minus_1 * userInput
            balance += expected_win
            inputs.append(userInput)
            verdict.append(outcome)

        elif v3_minus_1 == 0:
            outcome = 'Neutral'
            userInput = min_user_input
            expected_win = 0
            inputs.append(userInput)
            verdict.append(outcome)

        else:
            outcome = 'Loss'
            userInput = min_user_input
            expected_loss = -v3_minus_1 * userInput 
            balance += expected_loss
            inputs.append(userInput)
            verdict.append(outcome)
            
        # Ensure balance doesn't go negative
        if balance <= 0:
            print("epic fail")
            break

        # Print results for the round
        print(f"Round {number_of_rounds}:")
        print(f"  Predicted v4: {v4}")
        print(f"  Predicted v3: {v3}")
        print(f"  Outcome: {outcome}")
        print(f"  userInput: {userInput}")

        if outcome == 'Win':
            print(f"  Expected Win: ${expected_win}")
        elif outcome == 'Loss':
            print(f"  Expected Loss: ${-expected_loss}")
        else:
            print("  No change in balance.")

        print(f"  New Balance: ${balance}\n")
        
    
    return inputs


# =========================================================
#                         EXPLOITS
# =========================================================
def exploit():
    global io
    io = initialize()
    rop = ROP(elf)
    
    uhhs = generate_inputs()
    print(uhhs)
    
    counter = 0
    for uhh in uhhs:
        io.sendlineafter(b'Enter your bet amount (up to $100 per spin): ', f'{uhh}'.encode())
        resp = io.recvline()
            
    
    
    
    io.interactive()
if __name__ == '__main__':
    exploit()