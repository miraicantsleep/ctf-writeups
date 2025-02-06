import ctypes
from ctypes import c_uint, POINTER, byref
import sys

SHUFFLED_STRING = "1_n3}f3br9Ty{_6_rHnf01fg_14rlbtB60tuarun0c_tr1y3"

if sys.platform.startswith("linux"):
    libc = ctypes.CDLL("libc.so.6")
elif sys.platform.startswith("darwin"):
    libc = ctypes.CDLL("libc.dylib")
else:
    raise NotImplementedError("This decryptor is only supported on Linux and macOS systems.")

libc.rand_r.argtypes = [POINTER(c_uint)]
libc.rand_r.restype = ctypes.c_int

def get_swap_sequence(length: int, initial_seed: int = 0x13377331) -> list:
    """
    Generates the sequence of swap indices used during the shuffling process.

    Parameters:
        length (int): The length of the bytearray to be shuffled.
        initial_seed (int): The initial seed value for the random number generator.

    Returns:
        list of tuples: A list where each tuple contains a pair of indices (i, j) representing a swap.
    """
    seed = c_uint(initial_seed)
    swap_sequence = []
    
    for i in range(length - 1):
        rand = libc.rand_r(byref(seed))
        j = (rand % (length - i)) + i
        swap_sequence.append((i, j))
    
    return swap_sequence

def fryer_reverse(shuffled: bytearray) -> bytearray:
    """
    Reverses the shuffling performed by the fryer_shuffle function to retrieve the original bytearray.

    Parameters:
        shuffled (bytearray): The shuffled bytearray.

    Returns:
        bytearray: The original bytearray before shuffling.
    """
    length = len(shuffled)
    
    if length <= 1:
        return shuffled.copy()
    
    swap_sequence = get_swap_sequence(length)
    
    original = shuffled.copy()
    for i, j in reversed(swap_sequence):
        original[i], original[j] = original[j], original[i]
    
    return original

def main():
    try:
        shuffled_bytes = bytearray(SHUFFLED_STRING, 'utf-8')
    except UnicodeEncodeError as e:
        print(f"Error encoding the shuffled string: {e}")
        sys.exit(1)

    # Perform the reversal to get the original string
    try:
        recovered_bytes = fryer_reverse(shuffled_bytes)
        recovered_str = recovered_bytes.decode('utf-8', errors='replace')
    except Exception as e:
        print(f"Error during decryption: {e}")
        sys.exit(1)

    # Output the recovered original string
    print(f"{recovered_str}")

if __name__ == "__main__":
    main()
