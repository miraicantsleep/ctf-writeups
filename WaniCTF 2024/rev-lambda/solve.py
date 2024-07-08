# Hard-coded string in the obfuscated code
encoded_string = "16_10_13_x_6t_4_1o_9_1j_7_9_1j_1o_3_6_c_1o_6r"

# Step 1: Process the encoded string
decoded_chars = []
for part in encoded_string.split('_'):
    # Convert from base 36, add 10, and convert to ASCII character
    if part.isdecimal():
        decoded_chars.append(chr(int(part, 36) + 10))
    else:
        # Handle non-decimal cases character by character for base-36
        decoded_value = 0
        for char in part:
            decoded_value = decoded_value * 36 + int(char, 36)
        decoded_chars.append(chr(decoded_value + 10))

processed_string = ''.join(decoded_chars)

# Step 2: Reverse transform to find the correct input
correct_input = []
for c in processed_string:
    # Apply reverse transformations
    # Reverse XOR with 123
    xored_char = chr(ord(c) ^ 123)
    # Reverse shift by +9
    original_char = chr(ord(xored_char) - 9)
    correct_input.append(original_char)

# Combine the characters to form the original input string
correct_input_string = ''.join(correct_input)
print(f"The correct input is: {correct_input_string}")
