from pwn import *
host = '94.237.62.94'
port = 38621
context.log_level = 'debug'

io = remote(host, port)

def set_address_pins(addr):
    address = [int(bit) for bit in f'{addr:011b}']
    for i in range(len(address)):
        if address[i] == 1:
            address[i] = 5
    payload = f'set_address_pins({address})'.encode()
    io.sendlineafter(b'>', payload)
    
def set_io_pins(data):
    binaryData = [int(bit) for bit in f'{data:08b}']
    for i in range(len(binaryData)):
        if binaryData[i] == 1:
            binaryData[i] = 5
    payload = f'set_io_pins({binaryData})'.encode()
    print(payload)
    io.sendlineafter(b'>', payload)

def set_ce_pin(volts): # chip enable
    io.sendlineafter(b'>', f'set_ce_pin({volts})'.encode())

def set_oe_pin(volts): # output enable
    io.sendlineafter(b'>', f'set_oe_pin({volts})'.encode())
    
def set_we_pin(volts): # write enable
    io.sendlineafter(b'>', f'set_we_pin({volts})'.encode())

def readData(address):
    set_address_pins(address)
    set_ce_pin(0)
    set_oe_pin(0)
    set_we_pin(5)
    io.sendlineafter(b'>', b'read_byte()')
    
def writeData(data, address):
    set_ce_pin(0)
    set_oe_pin(5)
    set_we_pin(0)
    set_io_pins(data)
    set_address_pins(address)
    io.sendlineafter(b'>', b'write_byte()')
    
    
def main():
    
    io.interactive()
    
if __name__ == '__main__':
    main() 
