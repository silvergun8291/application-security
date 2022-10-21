## pwntools 사용법

### import

```python
from pwn import *
```

<br>

### process() 함수

로컬 바이너리 대상 익스플로잇에 사용

```python
p = process('./test')   #로컬 바이너리 'test'를 대상으로 익스플로잇 수행
```

<br>

### remote() 함수

원격 서버를 대상으로 할 때 사용

```python
p = remote('example.com',31337)   #'example.com'의 31337 포트에서 실행 중인 프로세스를 대상으로 익스플로잇 수행
```

<br>

### send() 함수

데이터를 프로세스에 전송

```python
p.send('A')                   # ./test에 'A'를 입력
p.sendline('A')               # ./test에 'A'+'\n'을 입력
p.sendafter('hello','A')      # ./test가 'hello'를 출력하면, 'A'를 입력
p.sendlineafter('hello','A')  # ./test가 'hello'를 출력하면, 'A' + '\n'을 입력
```

<br>

### recv() 함수

데이터를 받기 위해 사용

```python
data = p.recv(1024)         #p가 출력하는 데이터를 최대 1024바이트까지 받아서 data에 저장
data = p.recvline()         #p가 출력하는 데이터를 개행문자를 만날 때까지 받아서 data에 저장
data = p.recvn(5)           #p가 출력하는 데이터를 5바이트만 받아서 data에 저장
data = p.recvuntil('hello') #p가 출력하는 데이터를 'hello'가 출력될 때까지 받아서 data에 저장
data = p.recvall()          #p가 출력하는 데이터를 프로세스가 종료될 받아서 data에 저장
```

**주의!**

```python
recv(n)   # n 바이트 이하 입력에도 정상 종료
recvn(n)  # 정확히 n 바이트 데이터를 입력 받지 못하면 계속 기다림
```

<br>

### packing & unpacking 함수

`p32()` : 32 bit 리틀 엔디안 방식으로 packing 해주는 함수

`p64()` : 64 bit 리틀 엔디안 방식으로 packing 해주는 함수

```python
p32(0x12345678)	  # \x78\x56\x34\x12
p64(0x12345678)	  # \x00\x00\x00\x00\x78\x56\x34\x12
```

#

`u32()` : 32 bit 리틀 엔디안 방식을 unpacking 해주는 함수

`u64()` : 64 bit 리틀 엔디안 방식을 unpacking 해주는 함수

```python
u32(\x78\x56\x34\x12)	                  # 305419896 (0x12345678)
u64(\x00\x00\x00\x00\x78\x56\x34\x12)	  # 305419896 (0x12345678)
```

<br>

### interactive() 함수

직접 입력을 주면서 출력을 확인하고 싶을 때 사용

```python
p.interactive()
```

<br>

### ELF 관련 함수

```python
e = ELF('./test')	                    # ELF 파일 선택
libc = ELF("./libc.so.6")

puts_plt = e.plt['puts']	            # ./test에서 puts()의 PLT 주소를 찾아 대입
puts_got = e.got['puts']	            # ./test에서 puts()의 GOT 주소를 찾아 대입
puts_symbols = e.symbols['puts']	    # ./test에서 puts()의 함수의 주소를 찾아 대입
sh = list(libc.search(b"/bin/sh"))[0]	# "/bin/sh"의 주소를 찾아 대입
bss = e.bss()
```

<br>

### context.log

익스플로잇 디버깅을 위한 로깅 기능, 로그 레벨은 `context.log_level` 변수로 조절

```python
context.log_level = 'error'   # 에러만 출력
context.log_level = 'debug'   # 대상 프로세스와 익스플로잇간에 오가는 모든 데이터를 화면에 출력
context.log_level = 'info'    # 비교적 중요한 정보들만 출력
```

<br>

### context.arch

아키텍처 정보 지정

```python
context.arch = "amd64"  # x86-64 아키텍처
context.arch = "i386"   # x86 아키텍처
context.arch = "arm"    # arm 아키텍처
```

<br>

### shellcraft() 함수

쉘 코드 작성 함수

```python
code = shellcraft.sh()	# 쉘을 실행하는 쉘 코드
```

<br>

### asm() 함수

어셈블리어를 기계어로 변환할 때 사용

```python
code = asm(code)	# code를 기계어로 어셈블
```

<br>

### close() 함수

서버와의 연결을 끊을 때 사용

```python
p.close()
```

<br>

### slog 함수

```python
def slog(name, addr):
        return success(": ".join([name, hex(addr)]))
```

**Ex)**

```bash
[+] read: 0x7fb440b54020
[+] libc_base: 0x7fb440a44000
[+] system: 0x7fb440a93420
```

<br>

### offset Leak

```python
read_offset = libc.symbols["read"]
system_offset = libc.symbols["system"]
```

<br>

### 가젯 구하기

```python
r = ROP(e)
pop_rdi = r.find_gadget(['pop rdi', 'ret'])[0]
pop_rsi_r15 = r.find_gadget(['pop rsi', 'pop r15', 'ret'])[0]
ret = r.find_gadget(['ret'])[0]
```

<br>

### 카나리 릭

```python
canary = u64(b'\x00'+p.recvn(7))	# cananry에 \x00 + 릭한 카나리 값
slog("Canary", canary)
```

<br>

### system 함수 주소 Leak

```python
p.sendafter("Buf: ", payload)           # puts()와 read got를 이용해서 read() 주소 출력
read = u64(p.recvn(6)+b'\x00'*2)        # 화면에 출력된 read() 주소를 read에 대입
lb = read - libc.symbols["read"]        # libc base = read 주소 - read symbols
system = lb + libc.symbols["system"]    # system = libc base + system symbols
slog("system", system)
```

<br>


### 디버깅

```python
gdb.attach(p)
```

```bash
$ gdb -p PID
$ source ~/gef/gef.py
```

<br>

### PIE Base Leak

```python
pie_base = p.libs()["binary 절대 경로"]
func = func_offset + pie_base
```

<br>

### offset 찾기 자동화

```python
#--------Offset--------#
from pwn import *

def get_offset():
    io = e.process()
    io.sendline(cyclic(1024))
    io.wait()
    core = io.corefile
    io.close()
    os.remove(core.file.name)
    offset = cyclic_find(core.read(core.rsp, 4))

    return offset
```
