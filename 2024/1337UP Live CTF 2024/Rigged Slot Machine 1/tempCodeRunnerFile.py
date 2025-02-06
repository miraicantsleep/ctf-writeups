import time
import ctypes

def predict_sequence_and_play():
    libc = ctypes.CDLL('libc.so.6')

    # Assume you know the seed used by the game
    # Adjust seed offset if necessary to synchronize with the game's seed
    seed_offset = 10  # Adjust this based on your observations
    game_seed = int(time.time()) + seed_offset

    # Seed your PRNG with the game's seed
    libc.srand(game_seed)

    # Starting balance and target balance
    balance = 100  # Starting with $100
    target_balance = 133742  # Target balance

    # Game parameters
    max_user_input = 100  # Adjust based on game's maximum allowed bet
    min_user_input = 1        # Minimum allowed bet
    number_of_rounds = 0      # We'll keep playing until we reach the target

    print(f"Starting balance: ${balance}")
    print(f"Target balance: ${target_balance}\n")

    # Loop until we reach or exceed the target balance
    while balance < target_balance:
        number_of_rounds += 1

        # Predict v4
        v4 = libc.rand() % 100

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

        # Determine outcome and choose userInput
        v3_minus_1 = v3 - 1
        if v3_minus_1 > 0:
            # Winning scenario
            outcome = 'Win'

            # Calculate the amount needed to reach the target
            amount_needed = target_balance - balance

            # Calculate the required userInput
            # amount_needed = (v3_minus_1) * userInput
            required_user_input = amount_needed // v3_minus_1

            # Ensure the userInput is within allowed limits
            if required_user_input < min_user_input:
                userInput = min_user_input
            elif required_user_input > max_user_input:
                userInput = max_user_input
            else:
                userInput = required_user_input

            expected_win = v3_minus_1 * userInput
            balance += expected_win

        elif v3_minus_1 == 0:
            # Neutral scenario
            outcome = 'Neutral'
            userInput = min_user_input  # Minimal bet
            expected_win = 0  # No change in balance

        else:
            # Losing scenario
            outcome = 'Loss'
            userInput = min_user_input  # Minimize loss
            expected_loss = -v3_minus_1 * userInput  # Negative value
            balance += expected_loss  # Subtract the loss from balance

        # Ensure balance doesn't go negative
        if balance <= 0:
            print("You've run out of money! Game over.")
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

        # Optional: Break if we've reached the target
        if balance >= target_balance:
            print(f"Target balance of ${target_balance} reached in {number_of_rounds} rounds!")
            break

    # If balance is still below target after the loop
    if balance < target_balance:
        print(f"Could not reach the target balance. Final balance: ${balance}")

    # Output the game seed for reference
    print(f"\nGame Seed Used: {game_seed}")

if __name__ == "__main__":
    predict_sequence_and_play()
