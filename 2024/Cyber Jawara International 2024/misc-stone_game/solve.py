# This code finds the optimal move for the first player to guarantee a win in a Nim game.
def nim_solver(piles):
    xor_sum = 0
    for pile in piles:
        xor_sum ^= pile

    if xor_sum == 0:
        return "No winning move exists. The position is losing if the opponent plays optimally."

    # Find the pile to make the optimal move
    for i in range(len(piles)):
        target_pile = piles[i] ^ xor_sum
        if target_pile < piles[i]:
            return f"Remove {piles[i] - target_pile} from pile {i + 1}, leaving {target_pile} in that pile."

piles = [3, 4, 5, 2, 6, 3, 5]
result = nim_solver(piles)
print(result)
