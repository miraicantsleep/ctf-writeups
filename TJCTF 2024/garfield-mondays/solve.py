from hashlib import sha256

for hour in range(24):
    for minute in range(60):
        current_time = f"{hour:02d}:{minute:02d}"
        if sha256(current_time.encode()).hexdigest() == "cf4627b3786c8bad8cb855567bda362d8eca1809ea8839423682715cdf3aadad":
            print(current_time + " : " + sha256(current_time.encode()).hexdigest())
            break