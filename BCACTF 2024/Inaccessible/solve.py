import gdb
# gdb -x solve.py

gdb.execute("file ./inaccessible")
gdb.execute("break *_start+36")
gdb.execute("run")
gdb.execute("set $rdi = 0x4005ea")
gdb.execute("continue")