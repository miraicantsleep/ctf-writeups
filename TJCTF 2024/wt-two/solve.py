import gdb

flag = list("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")

gdb.execute("file ./wttwo")
gdb.execute("b *main+433")

checked = 0
for i in range(0, len(flag)):
    gdb.execute("run < " + "<(python -c 'print(\"" + "".join(flag) + "\")')")
    for _ in range(checked):
        gdb.execute("c")
    al = gdb.parse_and_eval("$rax")
    bl = gdb.parse_and_eval("$rbx")
    print("al: " + str(al))
    print("bl: " + str(bl))
    if al != bl:
        flag[i] = chr(al)
        checked += 1
        print("".join(flag))