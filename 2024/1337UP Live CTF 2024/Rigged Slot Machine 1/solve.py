#!/usr/bin/python3
from pwn import *
from ctypes import CDLL
import time

# =========================================================
#                          SETUP                         
# =========================================================
exe = './rigged_slot1'  # Update with your executable
elf = context.binary = ELF(exe, checksec=True)
libc_path = '/lib/x86_64-linux-gnu/libc.so.6'  # Update if necessary
libr = CDLL(libc_path)
libc = ELF(libc_path, checksec=False)
context.log_level = 'debug'
context.terminal = ["tmux", "splitw", "-h"]
host, port = 'host_address', 1337  # Update with the actual host and port

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
#                         FUNCTIONS
# =========================================================

def generate_inputs():
    inputs = []
    outcomes = []
    
    balance = 100  # Starting balance
    number_of_rounds = 2000  # Number of rounds to play

    max_bet = 100
    min_bet = 1

    print(f"Starting balance: ${balance}\n")

    # Seed the PRNG with the current time
    # current_time = int(time.time())
    libr.srand(libr.time(None))

    for round_number in range(1, number_of_rounds + 1):
        # Predict v4
        v4 = libr.rand() % 100

        # Determine v3 based on v4
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
            userInput = max_bet  # Bet maximum to maximize profit
            expected_win = v3_minus_1 * userInput
            balance += expected_win
        elif v3_minus_1 == 0:
            outcome = 'Neutral'
            userInput = min_bet  # Bet minimum
            expected_win = 0  # No change in balance
        else:
            outcome = 'Loss'
            userInput = min_bet  # Bet minimum to minimize loss
            expected_loss = -v3_minus_1 * userInput  # Negative value
            balance += expected_loss

        inputs.append(userInput)
        outcomes.append(outcome)

        # Print results for the round
        print(f"Round {round_number}:")
        print(f"  Predicted v4: {v4}")
        print(f"  Predicted v3: {v3}")
        print(f"  Outcome: {outcome}")
        print(f"  Bet Amount: ${userInput}")

        if outcome == 'Win':
            print(f"  Expected Win: +${expected_win}")
        elif outcome == 'Loss':
            print(f"  Expected Loss: -${-expected_loss}")
        else:
            print("  No change in balance.")

        print(f"  New Balance: ${balance}\n")

        # Ensure balance doesn't go negative
        if balance <= 0:
            print("You've run out of money! Game over.")
            break

    print(f"Final Balance after {round_number} rounds: ${balance}")
    profit = balance - 100  # Starting balance was $100
    print(f"Total Profit: ${profit}")

    return inputs

# =========================================================
#                         EXPLOIT
# =========================================================

def exploit():
    io = initialize()

    # Generate bets for 1000 rounds
    bets = generate_inputs()
    
    # Send the bets to the game
    for bet in bets:
        io.sendlineafter(b'Enter your bet amount (up to $100 per spin): ', str(bet).encode())

    io.interactive()

if __name__ == '__main__':
    exploit()
