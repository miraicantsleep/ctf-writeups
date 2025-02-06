import base64

# Initialize arrays with their ASCII values
arrays = {}
arrays['b_28_36'] = chr(65)   # 'A'
arrays['b_29_35'] = chr(66)   # 'B'
arrays['b_30_34'] = chr(67)   # 'C'
arrays['b_31_33'] = chr(68)   # 'D'
arrays['b_32_32'] = chr(69)   # 'E'
arrays['b_33_31'] = chr(70)   # 'F'
arrays['b_34_30'] = chr(71)   # 'G'
arrays['b_35_29'] = chr(72)   # 'H'
arrays['b_36_28'] = chr(73)   # 'I'
arrays['b_37_27'] = chr(74)   # 'J'
arrays['b_38_26'] = chr(75)   # 'K'
arrays['b_39_25'] = chr(76)   # 'L'
arrays['b_40_24'] = chr(77)   # 'M'
arrays['b_41_23'] = chr(78)   # 'N'
arrays['b_42_22'] = chr(79)   # 'O'
arrays['b_43_21'] = chr(80)   # 'P'
arrays['b_44_20'] = chr(81)   # 'Q'
arrays['b_45_19'] = chr(82)   # 'R'
arrays['b_46_18'] = chr(83)   # 'S'
arrays['b_47_17'] = chr(84)   # 'T'
arrays['b_48_16'] = chr(85)   # 'U'
arrays['b_49_15'] = chr(86)   # 'V'
arrays['b_50_14'] = chr(87)   # 'W'
arrays['b_51_13'] = chr(88)   # 'X'
arrays['b_52_12'] = chr(89)   # 'Y'
arrays['b_53_11'] = chr(90)   # 'Z'
arrays['b_54_10'] = chr(102)  # 'f'
arrays['b_55_9'] = chr(108)   # 'l'
arrays['b_56_8'] = chr(106)   # 'j'
arrays['b_57_7'] = chr(122)   # 'z'
arrays['b_58_6'] = chr(123)   # '{'
arrays['b_59_5'] = chr(125)   # '}'

# Constants (Not Base64 encoded)
aYyodk3 = "yyodk3"
aNtayodm = "ntayodm"
aZcg = "zcg"
asc_5238 = "::"

# Build the output message
output_message = ''
# Base64 encoded part
output_message += arrays['b_46_18']  # 'S'
output_message += arrays['b_31_33']  # 'D'
output_message += arrays['b_41_23']  # 'N'
output_message += arrays['b_46_18']  # 'S'
output_message += arrays['b_45_19']  # 'R'
output_message += arrays['b_47_17']  # 'T'
output_message += arrays['b_49_15']  # 'V'
output_message += arrays['b_54_10']  # 'f'
output_message += arrays['b_47_17']  # 'T'
output_message += arrays['b_49_15']  # 'V'
output_message += arrays['b_55_9']   # 'l'
output_message += arrays['b_54_10']  # 'f'
output_message += arrays['b_47_17']  # 'T'
output_message += arrays['b_55_9']   # 'l'
output_message += arrays['b_49_15']  # 'V'
output_message += arrays['b_41_23']  # 'N'
output_message += arrays['b_44_20']  # 'Q'
output_message += arrays['b_56_8']   # 'j'
output_message += arrays['b_41_23']  # 'N'
output_message += arrays['b_46_18']  # 'S'
output_message += arrays['b_51_13']  # 'X'
output_message += arrays['b_57_7']   # 'z'

# Constants
output_message += aYyodk3           # 'yyodk3'
output_message += aNtayodm          # 'ntayodm'
output_message += aZcg              # 'zcg'
output_message += asc_5238          # '::'

print(f"Full output message: {output_message}")

# Extract and decode the base64 encoded part
base64_part = output_message[:22]  # First 22 characters

# Fix padding
missing_padding = len(base64_part) % 4
if missing_padding != 0:
    base64_part += '=' * (4 - missing_padding)

# Decode the base64 part
decoded_bytes = base64.b64decode(base64_part)
decoded_part = decoded_bytes.decode('utf-8')
print(f"Decoded base64 part: {decoded_part}")

# Construct the flag
flag = f"FLAG{{{decoded_part}{aYyodk3}_{aNtayodm}_{aZcg}::}}"
print(f"Flag: {flag}")
