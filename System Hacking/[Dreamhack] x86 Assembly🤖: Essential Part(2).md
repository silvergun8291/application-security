## 어셈블리 명령어 Pt.2

### Opcode: 스택

`push val` : val을 스택 최상단에 쌓음

**연산**

```
rsp -= 8
[rsp] = val
```

![push](https://user-images.githubusercontent.com/81484874/196717751-d3562f97-294b-4429-9d83-5cff919161ab.jpg)


<br>


`pop reg` : 스택 최상단의 값을 꺼내서 reg에 대입

**연산**

```
rsp += 8
reg = [rsp-8]
```

![pop](https://user-images.githubusercontent.com/81484874/196717930-63d7ec18-416c-4c96-b16b-10840d929baf.jpg)


<br>
<br>


### Opcode: 프로시저

프로시저를 부르는 행위를 `호출(Call)` 이라고 부르고, 프로시저에서 돌아오는 것을 `반환(Return)` 이라고 부릅니다.

프로시저를 실행하고 나서 원래의 실행 흐름으로 돌아오기 위해, `call 다음의 명령어 주소(return address)` 를 스택에 저장하고 프로시저로 `rip` 를 이동시킵니다.

#

`call addr` : addr에 위치한 프로시저 호출

**연산**

```
push return_address
jmp addr
```

![call](https://user-images.githubusercontent.com/81484874/196717181-50a6d4f7-9621-4290-a29a-78fa248df8a5.jpg)


<br>


`leave` : 스택프레임 정리

**연산**

```
mov rsp, rbp
pop rbp
```

![leave](https://user-images.githubusercontent.com/81484874/196724013-3d781d69-6c32-463a-b1ec-9d61725d8272.jpg)


<br>


`ret` : return address로 반환

**연산**

```
pop rip
```

![ret](https://user-images.githubusercontent.com/81484874/196730815-d3646340-f01f-431e-9cc5-80dc7dd956fb.jpg)


<br>
<br>


### 함수 프롤로그

```
push rbp
mov rbp, rsp
```

> `RBP` : 스택의 바닥을 가리키는 레지스터, 변수 접근을 위한 `base` 로 사용합니다.    Ex) [rbp-10]

`SFP` 에 돌아갈 함수의 `RBP` 주소를 push 하고 `RBP` 위치를 현재 `RSP` 로 세팅합니다.

![프롤로그](https://user-images.githubusercontent.com/81484874/196740054-8c2a5a37-6699-450d-bc71-eafc7955dcd8.jpg)


<br>
<br>


### 함수 에필로그

```
leave
ret
```

RSP 값을 RBP가 있는 곳까지 내려서 스택을 정리하고 RBP 위치를 원래 함수의 RBP 위치로 되돌립니다.
그후 함수 호출 이후 명령어가 있는 주소로 점프합니다.

![에필로그](https://user-images.githubusercontent.com/81484874/196739836-4deefb66-6c77-45c0-a35c-e9b0099cce20.jpg)


<br>
<br>


### Opcode: 시스템 콜

운영체제는 연결된 하드웨어 및 소프트웨어에 접근할 수 있으며, 이들을 제어할 수도 있습니다. 그리고 해킹으로부터 이 막강한 권한을 보호하기 위해 커널 모드와 유저 모드로 권한을 나눕니다.

커널 모드 : 운영체제가 전체 시스템을 제어하기 위해 시스템 소프트웨어에 부여하는 권합니다.
유저 모드 : 운영체제가 사용자에게 부여하는 권한입니다.

 시스템 콜(system call, syscall)은 유저 모드에서 커널 모드의 시스템 소프트웨어에게 어떤 동작을 요청하기 위해 사용합니다.
x64아키텍처에는 시스템 콜을 위해 syscall 명령어가 있습니다.

syscall : 필요한 기능과 인자에 대한 정보를 레지스터로 전달하면, 커널이 이를 읽어서 요청을 처리합니다.

요청 : rax
인자 순서 : rdi → rsi → rdx → rcx → r8 → r9 → stack

### x64 syscall 테이블

| syscall | rax | arg0 (rdi) | arg1 (rsi) | arg2 (rdx) |
| --- | --- | --- | --- | --- |
| read | 0x00 | unsigned int fd | char \*buf | size\_t count |
| write | 0x01 | unsigned int fd | const char \*buf | size\_t count |
| open | 0x02 | const char \*filename | int flags | umode\_t mode |
| close | 0x03 | unsigned int fd |   |   |
| mprotect | 0x0a | unsigned long start | size\_t len | unsigned long prot |
| connect | 0x2a | int sockfd | struct sockaddr \*addr | int addrlen |
| execve | 0x3b | const char \*filename | const char \*const \*argv | const char \*const \*envp |

#

```bash
Ex) 화면에 Hello World 출력
화면 출력 → write syscall 사용

[Register]
rax = 0x1   ; write → 0x1
rdi = 0x1   ; stdout → 0x1
rsi = 0x401000  ; "Hello World"가 시작하는 주소
rdx = 0xb   ; Hello World가 11글자 이기 때문에 크기에 0xb 입력
[Memory]
0x401000 | "Hello Wo"   
0x401008 | "rld"    
[Code]  
syscall
```

#

---

<br>

> [x86 Assembly: Essential Part(2)](https://dreamhack.io/lecture/courses/63)




