### 어셈블리 언어

어셈블리 언어는 기계어와 치환되는 언어입니다.

기본 구조는 `명령어(Opcode)` 와 `피연산자(Operand)` 로 구성됩니다.

```bash
opcode operand1 operand2

Ex) mov eax, 3
opcode = mov
operand1 = eax
operand2 = 3
```

<br>
<br>


### 명령어

![image](https://user-images.githubusercontent.com/81484874/196702497-b51b8d43-7968-40ea-916d-39c3bb477190.png)


<br>
<br>


### 피연산자

-   상수
-   레지스터
-   메모리

메모리 피연산자는 `[ ]` 로 둘러싸인 것으로 표현되며, 앞에 크기 지정자는 `TYPE PTR` 이 추가될 수 있습니다.

타입에는 BYTE, WORD, DWORD, QWORD가 올 수 있으며, 각각 1BYTE, 2BYTE, 4BYTE, 8BYTE의 크기를 지정합니다.

![image](https://user-images.githubusercontent.com/81484874/196702894-f6d77e04-0aa0-487c-9412-b2c3b41aa39d.png)

<br>
<br>


### 데이터 이동 명령어

어떤 값을 레지스터나 메모리에 옮기도록 지시합니다.

![image](https://user-images.githubusercontent.com/81484874/196702953-6a2c7234-8f3f-41fa-832d-c856e8a8dc1f.png)
![image](https://user-images.githubusercontent.com/81484874/196702997-347a50ab-4383-42bf-bd5d-b6f16cdabd11.png)


<br>

**예제 - 데이터 이동**

```bash
[Register]
rbx = 0x401A40
=================================
[Memory]
0x401a40 | 0x0000000012345678
0x401a48 | 0x0000000000C0FFEE
0x401a50 | 0x00000000DEADBEEF
0x401a58 | 0x00000000CAFEBABE
0x401a60 | 0x0000000087654321
=================================
[Code]
1: mov rax, [rbx+8]
2: lea rax, [rbx+8]
```

**1\. Code를 1까지 실행했을 때, rax에 저장된 값은?**

rax = \[rbx+8\]

rax = 0xC0FFEE

#

**2\. Code를 2까지 실행했을 때, rax에 들어있는 값은?**

rax = \[rbx+8\]

rax = 0x401a48


<br>
<br>


### 산술 연산

덧셈, 뻴셈, 곱셈, 나눗셈 연산을 지시합니다.

![image](https://user-images.githubusercontent.com/81484874/196703128-0e731399-cc9a-4e0c-bd6f-a2ed8b81958a.png)

![image](https://user-images.githubusercontent.com/81484874/196703153-c3e5b6ee-cec0-48f7-9249-d6b3b0b27db9.png)

![image](https://user-images.githubusercontent.com/81484874/196703173-61f860d3-0d87-4b06-9426-e1d4e4ef9cf6.png)

![image](https://user-images.githubusercontent.com/81484874/196703202-5ffb892b-f40e-4d0f-b9bd-953451b98b7e.png)


<br>


**예제 - 덧셈과 뺄셈**

```bash
[Register]
rax = 0x31337
rbx = 0x555555554000
rcx = 0x2
=================================
[Memory]
0x555555554000| 0x0000000000000000
0x555555554008| 0x0000000000000001
0x555555554010| 0x0000000000000003
0x555555554018| 0x0000000000000005
0x555555554020| 0x000000000003133A
==================================
[Code]
1: add rax, [rbx+rcx*8]
2: add rcx, 2
3: sub rax, [rbx+rcx*8]
4: inc rax
```

**1\. Code를 1까지 실행했을 때, rax에 저장된 값은?**

rax = rax + \[0x555555554010\]

rax = 0x31337 + 0x00003 = 0x3133A

#

**2\. Code를 3까지 실행했을 때, rax에 저장된 값은?**

rcx = rcx + 0x2

rcx = 0x2 + 0x2 = 0x4

rax = 0x3133A

rax = rax - \[0x555555554020\]

rax = 0x3133A - 0x3133A = 0

#

**3\. Code를 4까지 실행했을 때, rax에 저장된 값은?**

rax = 0x0

rax = rax + 1

rax = 0 + 1 = 1


<br>
<br>


### 논리 연산 명령어 - and & or

논리 연산 명령어는 and, or, xor, neg 등의 비트 연산을 지시합니다.

```bash
and dst, src: dst ← dst and src

Ex) and eax, ebx	; eax = eax and ebx
```

```bash
or dst, src: dst ← dst or src

Ex) or eax, ebx    ; eax = eax or src
```

<br>

**예제 - 논리 연산(and & or)**

```bash
[Register]
rax = 0xffffffff00000000
rbx = 0x00000000ffffffff
rcx = 0x123456789abcdef0
==================================
[Code]
1: and rax, rcx
2: and rbx, rcx
3: or rax, rbx
```

**1\. Code를 1까지 실행했을 때, rax에 저장된 값은?**

rax = rax and rcx

rax = 0xffffffff00000000 and 0x123456789abcdef0 = 0x1234567800000000

#

**2\. Code를 2까지 실행했을 때, rbx에 저장된 값은?**

rbx = rbx and rcx

rbx = 0x00000000ffffffff and 0x123456789abcdef0 = 0x000000009abcdef0

#

**3\. Code를 3까지 실행했을 때, rax에 저장된 값은?**

rax = rax or rbx

rax = 0x1234567800000000 or 0x000000009abcdef0 = 0x123456789abcdef0


<br>
<br>


### 논리 연산 명령어 - xor & not

```bash
xor dst, src: dst ← dst xor src

Ex) xor eax, ebx	; eax = eax xor ebx
```

```bash
not op: !op

Ex) not eax    ; !eax
```

<br>

**예제 - 논리 연산(xor, not)**

```bash
[Register]
rax = 0x35014541
rbx = 0xdeadbeef
==================================
[Code]
1: xor rax, rbx
2: xor rax, rbx
3: not eax
```

**1\. Code를 1까지 실행했을 때, rax에 저장되는 값은?**

rax = rax xor rbx

rax = 0x35014541 xor 0xdeadbeef = 0xebacfbae

#

**2\. Code를 2까지 실행했을 때, rax에 저장되는 값은?**

rax = rax xor rbx

rax = 0xebacfbae xor 0xdeadbeef = 0x35014541

→ xor 연산을 동일 값으로 두 번 실행할 경우, 원래 값으로 돌아갑니다.

#

**3\. Code를 3까지 실행했을 때, rax에 저장되는 값은?**

!eax

rax = 0xcafebabe


<br>
<br>


### 비교 명령어

두 피연산자의 값을 비교하는 플래그를 설정합니다.

```bash
cmp op1, op2: op1과 op2를 비교 (op1 - op2 연산 실행)

Ex)
mov rax, 0xA
mov rbx, 0xA
cmp rax, rbx ; ZF=1    ; Zero Flag가 1이기 때문에, op1 - op2 = 0 → 두 값이 같다
```

```bash
test op1, op2: op1과 op2를 비교 (op1 and op2 연산 실행)

Ex)
xor rax, rax
test rax, rax ; ZF=1	; Zero Flag가 설정됬기 때문에, rax and rax = 0 → rax는 0이다.
```


<br>
<br>


### 분기 명령어

rip를 이동시켜 실행 흐름을 바꿉니다.

```bash
jmp addr: addr로 rip를 이동시킵니다.

Ex)
xor rax, rax
jmp 1 ; jump to 1
```

```bash
je addr: 직전에 비교한 두 피연산자가 같으면 점프 (jump if equal)

Ex)
mov rax, 0xcafebabe
mov rbx, 0xcafebabe
cmp rax, rbx ; rax == rbx
je 1 ; jump to 1
```

```bash
jg addr: 직전에 비교한 두 연산자 중 전자가 더 크면 점프 (jump if greater)

Ex)
mov rax, 0x31337
mov rbx, 0x13337
cmp rax, rbx ; rax > rbx
jg 1  ; jump to 1
```

#

---

<br>

> [x86 Assembly: Essential Part(1)](https://dreamhack.io/lecture/courses/37)
