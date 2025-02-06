import base64
import zlib

# The encoded string from the PowerShell script output
encoded_str = "dY9RS8MwFIX/ynUIyWDKZNkYTjdSW/DFKe3Ux0ttbligpjVtGTL2311a58bA+xIO37nnntwtynUJirSxxFkYYBLFb1HMBsDUB+vPTtHrni3lU9RBbCpyZ44XmSTvz3HoHY+rYKuHE1Q3Y1GWI+FGCoVVqHMxwY2oUA8bqy52ZxGhXMlAJu2RdBwsU6W9Ay4/v6uv3MA9WNpAJ/hf3wGc9GvFoUorDqE+yGjgv2FX86ywlrIaybnC9WELfpQh3nvoiCks6NTkpG6hB9fwz+YMdnBkFdWYrVO3fzlraj31P1jMfwA="

# Step 1: Base64 decode
decoded_bytes = base64.b64decode(encoded_str)

# Step 2: Deflate decompression
decompressed_bytes = zlib.decompress(decoded_bytes, -zlib.MAX_WBITS)

# Step 3: Convert bytes back to string
output = decompressed_bytes.decode('utf-8')
print(output)
