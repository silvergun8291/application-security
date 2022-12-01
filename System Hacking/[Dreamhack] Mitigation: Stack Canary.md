### 1. 서론

**스택 카나리**

함수 프롤로그에서 스택 버퍼와 반환 주소 사이에 임의의 값을 삽입하고 에필로그에서 해당 값의 변조를 확인하는 보호 기법입니다.

스택 버퍼 오버플로우로 반환 주소를 덮으려면 먼저 카나리 값을 덮어야 하기 때문에, 카나리 값을 모르는 공격자는 카나리 값을 변조하게 됩니다. 그러면 에필로그에서 변조가 확인되어 공격자는 실행 흐름을 흭득하지 못하게 됩니다.


<br>

---

<br>

### 2. 카나리의 작동 원리

```c
// Name: canary.c

#include <unistd.h>

int main() {
  char buf[8];
  read(0, buf, 32);

  return 0;
}
```

```bash
$ gcc -o canary canary.c
$ gcc -o no_canary canary.c -fno-stack-protector
$ ls
canary  canary.c  no_canary
```

<br>

**카나리 비활성화**

```bash
$ ./no_canary
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
Segmentation fault (core dumped)
```

카나리 비활성화의 경우 Segmentation fault가 발생했습니다.

<br>

**카나리 활성화**

```bash
$ ./canary
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
*** stack smashing detected ***: <unknown> terminated
Aborted (core dumped)
```

카나리 활성화의 경우 Segmentation fault가 아닌 stack smashing detected와 Aborted가 발생했습니다.

이는 스택 버퍼 오버플로우가 탐지되어 프로세스가 강제 종료되었음을 의미합니다.

#

canary와 no\_canary의 디스어셈블 결과를 비교해보면

```bash
   0x00000000000006b2 <+8>:     mov    rax,QWORD PTR fs:0x28
   0x00000000000006bb <+17>:    mov    QWORD PTR [rbp-0x8],rax
   0x00000000000006bf <+21>:    xor    eax,eax
```

```bash
   0x00000000000006dc <+50>:    mov    rcx,QWORD PTR [rbp-0x8]
   0x00000000000006e0 <+54>:    xor    rcx,QWORD PTR fs:0x28
   0x00000000000006e9 <+63>:    je     0x6f0 <main+70>
   0x00000000000006eb <+65>:    call   0x570 <__stack_chk_fail@plt>
```

canary의 main 함수 프롤로그와 에필로그에 각 코드들이 추가되었습니다.

<br>

**카나리 동적 분석**

프롤로그 부분인 main+8에 break point를 걸고 동적 분석을 해보면

```bash
$ gdb canary
gdb-peda$ break * main+8
Breakpoint 1 at 0x6b2
gdb-peda$ run
[-------------------------------------code-------------------------------------]
   0x5555554006aa <main>:       push   rbp
   0x5555554006ab <main+1>:     mov    rbp,rsp
   0x5555554006ae <main+4>:     sub    rsp,0x10
=> 0x5555554006b2 <main+8>:     mov    rax,QWORD PTR fs:0x28    // rax = fs: 0x28
   0x5555554006bb <main+17>:    mov    QWORD PTR [rbp-0x8],rax
   0x5555554006bf <main+21>:    xor    eax,eax
```

fs는 세그먼트 레지스터의 일종으로, 리눅스는 프로세스가 시작될 때 fs:0x28에 랜덤 값을 저장합니다.

따라서 rax에는 fs:0x28의 랜덤 값이 저장됩니다.

<br>

**\*fs, gs 레지스터\***

목적이 정해지지 않아 운영체제가 임의로 사용할 수 있는 레지스터

리눅스는 fs를 **Thread Local Storage(TLS)**를 가리키는 포인터로 사용

여기서는 TLS에 카나리를 비롯하여 프로세스 실행에 필요한 여러 데이터가 저장된다

다음 줄의 코드를 실행시키고 RAX 값을 봐보면

```bash
gdb-peda$ ni
[----------------------------------registers-----------------------------------]
RAX: 0x7772f8ab6ccc8700

[-------------------------------------code-------------------------------------]
   0x5555554006ab <main+1>:     mov    rbp,rsp
   0x5555554006ae <main+4>:     sub    rsp,0x10
   0x5555554006b2 <main+8>:     mov    rax,QWORD PTR fs:0x28
=> 0x5555554006bb <main+17>:    mov    QWORD PTR [rbp-0x8],rax
   0x5555554006bf <main+21>:    xor    eax,eax
```

NULL(00) 바이트로 시작하는 랜덤값이 저장되어 있습니다.

<br>

**카나리 검사**

에필로그 부분인 main+50에 break point를 걸고 분석을 해보면

```bash
gdb-peda$ break * main+50
Breakpoint 2 at 0x5555554006dc
gdb-peda$ continue
Continuing.
[----------------------------------registers-----------------------------------]
RAX: 0x0
RBX: 0x0
RCX: 0x7ffff7af2031 (<__GI___libc_read+17>:     cmp    rax,0xfffffffffffff000)
[-------------------------------------code-------------------------------------]
=> 0x5555554006dc <main+50>:    mov    rcx,QWORD PTR [rbp-0x8]
   0x5555554006e0 <main+54>:    xor    rcx,QWORD PTR fs:0x28
   0x5555554006e9 <main+63>:    je     0x5555554006f0 <main+70>
   0x5555554006eb <main+65>:    call   0x555555400570 <__stack_chk_fail@plt>
   0x5555554006f0 <main+70>:    leave
```

rbp-0x8에 저장된 카나리를 꺼내서 rcx에 대입하고 rcx를 fs:0x28의 값과 xor 합니다.

두 값이 동일하면 연산 결과가 0이 되어 je 조건을 만족하게 되고, main 함수가 정상적으로 반환됩니다.

그러나 두 값이 다르면 \_\_stack\_chk\_fail@plt가 호출되면서 프로그램이 강제 종료됩니다.

<br>

'H' 16개를 입력해서 실행 흐름이 어떻게 되는지 살펴보면

```bash
gdb-peda$ break * main+50
Breakpoint 1 at 0x6dc
gdb-peda$ run
Starting program: /home/ion/dreamhack/Stack_Canary/canary
HHHHHHHHHHHHHHHH
[-------------------------------------code-------------------------------------]
=> 0x5555554006dc <main+50>:    mov    rcx,QWORD PTR [rbp-0x8]
   0x5555554006e0 <main+54>:    xor    rcx,QWORD PTR fs:0x28
   0x5555554006e9 <main+63>:    je     0x5555554006f0 <main+70>
   0x5555554006eb <main+65>:    call   0x555555400570 <__stack_chk_fail@plt>
   0x5555554006f0 <main+70>:    leave
[------------------------------------stack-------------------------------------]
0000| 0x7fffffffe180 ('H' <repeats 16 times>, "\n\a@UUU")
0008| 0x7fffffffe188 ("HHHHHHHH\n\a@UUU")
```

버퍼 오버플로우가 발생해서 rbp-0x8의 카나리 값이 'H' 16개로 변경되었습니다.

<br>

코드를 계속 실행시켜보면

```bash
gdb-peda$ ni
[-------------------------------------code-------------------------------------]
   0x5555554006dc <main+50>:    mov    rcx,QWORD PTR [rbp-0x8]
   0x5555554006e0 <main+54>:    xor    rcx,QWORD PTR fs:0x28
   0x5555554006e9 <main+63>:    je     0x5555554006f0 <main+70>
=> 0x5555554006eb <main+65>:    call   0x555555400570 <__stack_chk_fail@plt>
   0x5555554006f0 <main+70>:    leave
   0x5555554006f1 <main+71>:    ret
```

\_\_stack\_chk\_fail@plt가 실행되고

<br>

```bash
gdb-peda$ ni
*** stack smashing detected ***: <unknown> terminated

Program received signal SIGABRT, Aborted.
```

stack smashing detected 메세지가 출력되면서 프로세스가 강제 종료되었습니다.

<br>

---

<br>

### 3. 카나리 생성 과정

카나리 값은 프로세스가 시작될 때, TLS에 전역 변수로 저장되고, 각 함수마다 프롤로그와 에필로그에 이 값을 참조합니다.

#

**TLS 주소 파악**  
fs는 TLS를 가리키므로 fs의 값을 알면 TLS의 주소를 알 수 있습니다. 그러나 리눅스에서 fs의 값은 arch\_prctl(int code, unsigned long addr) 시스템 콜을 사용해야만 조회하거나 설정할 수 있습니다.

이 시스템 콜에 중단점을 걸어서 fs의 값을 조사해보겠습니다.

#

**\*arch\_prctl(ARCH\_SET\_FS, addr)\***

이 시스템 콜을 호출하면 fs의 값이 addr로 설정됩니다.

#

```bash
gdb-peda$ catch syscall arch_prctl
Catchpoint 1 (syscall 'arch_prctl' [158])
gdb-peda$ run
[----------------------------------registers-----------------------------------]
RAX: 0xffffffffffffffda
RBX: 0x1
RCX: 0x7ffff7dd4024 (<init_tls+276>:    test   eax,eax)
RDX: 0x7ffff7feee10 --> 0xf
RSI: 0x7ffff7fee4c0 (0x00007ffff7fee4c0)
RDI: 0x1002
```

rdi의 값인 0x1002는 ARCH\_SET\_FS의 상수 값이고 rsi의 값인 0x7ffff7fee4c0이 addr이기 때문에,

TLS는0x7ffff7fee4c0에 저장되고 fs는 이곳을 가리키게 됩니다.

<br>

**\*catch\***

특정 이벤트가 발생했을 때, 프로세스를 중지시키는 명령어  
Ex) catch syscall arch\_prctl // arch\_prctl에 catch point를 설정

카나리가 저장될 fs+0x28 (0x7ffff7fee4c0+0x28)의 값을 봐보면

```bash
gdb-peda$ x/gx 0x7ffff7fee4c0+0x28
0x7ffff7fee4e8: 0x0000000000000000
```

아직 값이 설정되어 있지 않습니다.

<br>

**카나리 값 설정**

gdb의 watch 명령어로 TLS+0x28에 값을 쓸 때 프로세스를 중단시켜서 TLS+0x28 값을 봐보면

```bash
gdb-peda$ watch *(0x7ffff7fee4c0+0x28)
Hardware watchpoint 1: *(0x7ffff7fee4c0+0x28)
gdb-peda$ continue
Continuing.

Hardware watchpoint 1: *(0x7ffff7fee4c0+0x28)

Old value = 0x0
New value = 0xacc4800
security_init () at rtld.c:807
807     rtld.c: No such file or directory.
gdb-peda$ x/gx 0x7ffff7fee4c0+0x28
0x7ffff7fee4e8: 0x17e8c3b70acc4800
```

security\_init 함수가 실행되는 곳에서 프로세스가 중단됐고 TLS+0x28에는 0x17e8c3b70acc4800가 들어있습니다.

<br>

**\*watch\***

특정 주소에 저장된 값이 변경되면 프로세스를 중단시키는 명령어

Ex) watch \*(0x7ffff7fee4c0+0x28)

0x7ffff7fee4c0+0x28의 값이 변경되면 프로세스를 중단시킨다.

<br>

---

<br>

### 4. 카나리 우회

**무차별 대입 (Brute Force)**

현실적으로 불가능한 방법입니다.

<br>

**TLS 접근**

실행 중에 TLS의 주소를 알 수 있고 TLS에 설정된 카나리 값을 읽거나 조작할 수 있다면, 스택 버퍼 오버플로우를 수행할 때 알아낸 카나리 값 또는 조작한 카나리 값으로 스택 카나리를 덮어서 카나리 검사를 우회할 수 있습니다.

<br>

**스택 카나리 릭**

스택 카나리를 읽을 수 있는 취약점이 있다면, 이를 이용하여 카나리 검사를 우회할 수 있습니다.

#

---

<br>

> [Mitigation: Stack Canary
](https://dreamhack.io/lecture/courses/112)
