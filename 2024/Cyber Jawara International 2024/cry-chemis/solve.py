from pwn import *

def calculate_nim_sum(stones):
    nim_sum = 0
    for s in stones:
        nim_sum ^= s
    return nim_sum

def find_optimal_move(stones):
    nim_sum = calculate_nim_sum(stones)
    if nim_sum == 0:
        return None  # No winning move available

    for i in range(len(stones)):
        if stones[i] ^ nim_sum < stones[i]:
            return i + 1, stones[i] - (stones[i] ^ nim_sum)
    return None

def parse_stones(response):
    # Extract the numbers between the +---+ lines
    lines = response.splitlines()
    for line in lines:
        if "|" in line:
            parts = line.split("|")[1:-1]
            return [int(part.strip()) for part in parts]
    return None

def play_game():
    host = '68.183.177.211'
    port = 10001

    # Connect to the remote server
    conn = remote(host, port)
    response = conn.recvuntil(b"Your turn! Choose a set of stones (1-7): ").decode()
    print(response)

    # First move: take 0 stones to pass the turn to the computer
    conn.sendline(b"1")  # Choose any valid set (e.g., set 1)
    conn.sendline(b"0")  # Take 0 stones to pass the first turn

    # Receive the response after the computer's move
    response = conn.recvuntil(b"Your turn! Choose a set of stones (1-7): ").decode()
    print(response)

    while True:
        stones = parse_stones(response)
        if not stones:
            print("Could not parse stones.")
            break

        # Find the optimal move
        optimal_move = find_optimal_move(stones)
        if not optimal_move:
            print("No winning move available.")
            conn.close()
            break

        set_index, stones_to_take = optimal_move

        # Send the set number
        conn.sendline(str(set_index).encode())
        response = conn.recvuntil(b"How many stones to take from set ").decode()
        print(response)

        # Send the number of stones to take
        conn.sendline(str(stones_to_take).encode())
        response = conn.recvuntil(b"Your turn! Choose a set of stones (1-7): ").decode()
        print(response)

        # Check if the game is over
        if "You lost!" in response or "You won!" in response:
            print(response)
            conn.close()
            break

if __name__ == "__main__":
    play_game()
