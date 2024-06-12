# BabyHeap 🩸

> First blood btw 😎
![babyheap](https://github.com/miraicantsleep/ctf-writeups/assets/29684003/92eb391c-b812-4f0d-8395-cc47af184cc7)


## Analysis

Given a binary [eep](./eep), we first do a basic security checks first:

```
BabyHeap main !1 ?5 ❯ pwn checksec eep
[*] '/mnt/d/ctf-writeups/CiGITS CTF 2024/BabyHeap/eep'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

- `i386-32-little` means it's a 32-bit binary
- `Partial RELRO` means the GOT entry is writable
- `No canary found` means there's no stack canary
- `NX enabled` means the stack is not executable
- `PIE enabled` means the binary is position-independent

And when we try to decompile it:

```c

/* WARNING: Function: __x86.get_pc_thunk.bx replaced with injection: get_pc_thunk_bx */

void main(void)

{
  int iVar1;
  EVP_PKEY_CTX *in_stack_ffffffe0;
  char local_14 [4];
  undefined *puStack_10;

  puStack_10 = &stack0x00000004;
  init(in_stack_ffffffe0);
LAB_000116aa:
  menu();
  read(0,local_14,4);
  iVar1 = atoi(local_14);
  if (iVar1 == 4) {
                    /* WARNING: Subroutine does not return */
    exit(0);
  }
  if (iVar1 < 5) {
    if (iVar1 == 3) {
      print_target();
      goto LAB_000116aa;
    }
    if (iVar1 < 4) {
      if (iVar1 == 1) {
        add_target();
      }
      else {
        if (iVar1 != 2) goto LAB_00011710;
        del_target();
      }
      goto LAB_000116aa;
    }
  }
LAB_00011710:
  puts("Invalid choice");
  goto LAB_000116aa;
}
```

We can see that there are 3 functionality, that is `add_target`, `del_target`, and `print_target`. When we try to decompile the mentioned functions:

#### add_target

```c

/* WARNING: Function: __x86.get_pc_thunk.bx replaced with injection: get_pc_thunk_bx */

void add_target(void)

{
  int iVar1;
  void *pvVar2;
  char buffer [8];
  size_t malloc_sz;
  int i;

  if (count < 6) {
    for (i = 0; i < 5; i = i + 1) {
      if (*(int *)(targetlist + i * 4) == 0) {
        pvVar2 = malloc(8);
        *(void **)(targetlist + i * 4) = pvVar2;
        if (*(int *)(targetlist + i * 4) == 0) {
          puts("Error!");
                    /* WARNING: Subroutine does not return */
          exit(-1);
        }
        **(code ***)(targetlist + i * 4) = print_target_content;
        printf("Note size :");
        read(0,buffer,8);
        malloc_sz = atoi(buffer);
        iVar1 = *(int *)(targetlist + i * 4);
        pvVar2 = malloc(malloc_sz);
        *(void **)(iVar1 + 4) = pvVar2;
        if (*(int *)(*(int *)(targetlist + i * 4) + 4) != 0) {
          printf("Content :");
          read(0,*(void **)(*(int *)(targetlist + i * 4) + 4),malloc_sz);
          puts("Success !");
          count = count + 1;
          return;
        }
        puts("Error!");
                    /* WARNING: Subroutine does not return */
        exit(-1);
      }
    }
  }
  else {
    puts("Full");
  }
  return;
}
```

`add_target` function does the following:
- It will malloc 8 bytes for the targetlist, but since malloc always mallocs in multiples of 16 and always mallocs bigger than we asked for, it will actually malloc 16 bytes.
- It will then malloc the size of the note content, and store it in the targetlist array.
- Then it does this `**(code ***)(targetlist + i * 4) = print_target_content;` which is a function pointer to `print_target_content` function.
- Then it will read our input to the note content with our `malloc_sz` as it's limit.
- Then it increments the count, this count variable is to track how many allocations have occured.

#### del_target

```c

/* WARNING: Function: __x86.get_pc_thunk.bx replaced with injection: get_pc_thunk_bx */

void del_target(void)

{
  char local_14 [4];
  int local_10;

  printf("Index :");
  read(0,local_14,4);
  local_10 = atoi(local_14);
  if ((-1 < local_10) && (local_10 < count)) {
    if (*(int *)(targetlist + local_10 * 4) != 0) {
      free(*(void **)(*(int *)(targetlist + local_10 * 4) + 4));
      free(*(void **)(targetlist + local_10 * 4));
      puts("Success");
    }
    return;
  }
  puts("Error!");
                    /* WARNING: Subroutine does not return */
  _exit(0);
}
```

`del_target` function does the following:
- First it frees the note content, then it frees the targetlist.

The vulnerability lies here, because when we free a chunk, the the pointer to the note content is still in the targetlist array, and we can still access it. And also, there's no `count` variable decrement, so we can still access the freed chunk.

#### print_target

```c

/* WARNING: Function: __x86.get_pc_thunk.bx replaced with injection: get_pc_thunk_bx */

void print_target(void)

{
  char buffer [4];
  int index;

  printf("Index :");
  read(0,buffer,4);
  index = atoi(buffer);
  if ((-1 < index) && (index < count)) {
    if (*(int *)(targetlist + index * 4) != 0) {
      (***(code ***)(targetlist + index * 4))(*(undefined4 *)(targetlist + index * 4));
    }
    return;
  }
  puts("Error!");
                    /* WARNING: Subroutine does not return */
  _exit(0);
}
```

`print_target` function does the following:
- It reads our input to the index, then it checks if the index is less than the count.
- If it is, then it will call `print_target` `(remember the [**(code ***)(targetlist + i * 4) = print_target_content;] the program does?)`. This is a function pointer to `print_target_content` function.
- Then it will call the function pointer with the pointer to the note content as it's argument.

## Exploitation

So the plan is to:

1. Allocate 2 chunks of different sizes, the first one is the same as the `malloc(8)` and the other to be different sizes.
2. Frees those chunks, so we have 3 tcaches entry of 16 bytes.
3. Create a chunk again of size 8 (well 16) then deletes it.
4. Create a chunk again, this time, don't put anything in the note content, now the new malloc will point to the `print_target_content` address.
5. Print the target, and we will get the address of the `print_target_content` function, then calculate ELF base.