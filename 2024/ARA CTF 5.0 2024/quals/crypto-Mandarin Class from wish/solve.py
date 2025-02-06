encrypted_flag = "㭪䫴㭪ひ灮带⯠⯠孨囖抸櫲婾懎囖崼敶栴囖溚⾈牂"

for key in range(501):
    original_flag = ""

    for ch in encrypted_flag:
        original_ch = chr(ord(ch) // key) if key != 0 else "?"
        original_flag += original_ch

    if "ARA5{" in original_flag:
        print("Found ARA5{ with key:", key)
        print("Original flag:", original_flag)
