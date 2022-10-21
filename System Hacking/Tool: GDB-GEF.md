### gef 실행

```bash
(gdb) source /home/kali/gef/gef.py
GEF for linux ready, type `gef' to start, `gef config' to configure
90 commands loaded and 5 functions added for GDB 10.1.90.20210103-git in 0.01ms using Python engine 3.10
gef➤
```

<br>
<br>

### disas

해당 함수의 어셈블리어 출력

```bash
gef➤  disas main
Dump of assembler code for function main:
   0x0000555555555149 <+0>:     push   rbp
   0x000055555555514a <+1>:     mov    rbp,rsp
   0x000055555555514d <+4>:     sub    rsp,0x40
   0x0000555555555151 <+8>:     mov    DWORD PTR [rbp-0x34],edi
   0x0000555555555154 <+11>:    mov    QWORD PTR [rbp-0x40],rsi
   0x0000555555555158 <+15>:    mov    rax,QWORD PTR [rbp-0x40]
   0x000055555555515c <+19>:    add    rax,0x8
   0x0000555555555160 <+23>:    mov    rdx,QWORD PTR [rax]
   0x0000555555555163 <+26>:    lea    rax,[rbp-0x30]
   0x0000555555555167 <+30>:    mov    rsi,rdx
   0x000055555555516a <+33>:    mov    rdi,rax
   0x000055555555516d <+36>:    call   0x555555555030 <strcpy@plt>
=> 0x0000555555555172 <+41>:    lea    rax,[rbp-0x30]
   0x0000555555555176 <+45>:    mov    rdi,rax
   0x0000555555555179 <+48>:    mov    eax,0x0
   0x000055555555517e <+53>:    call   0x555555555040 <printf@plt>
   0x0000555555555183 <+58>:    mov    eax,0x0
   0x0000555555555188 <+63>:    leave  
   0x0000555555555189 <+64>:    ret
```

<br>
<br>

### Ctrl + L

화면 지우기 단축키

<br>
<br>


### aslr

`ASLR` 확인 명령어

```bash
aslr 		# aslr 체크
aslr on 	# aslr ON
aslr off  	# aslr OFF

gef➤  aslr
ASLR is currently disabled
gef➤  aslr on
[+] Enabling ASLR
gef➤  aslr off
[+] Disabling ASLR
```

<br>
<br>


### Python Input

`argv[]` Input

```bash
gef➤  r $(python2 -c 'print "A"*0x111')
Starting program: /home/ion/wargame/rtc/ex $(python -c 'print "A"*0x111')
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
```

`STDIN` Input

```bash
gef➤  r <<< $(python2 -c 'print "A"*57')
Starting program: /home/ion/wargame/rtc/rtc <<< $(python -c 'print "A"*57')
```

<br>
<br>


### canary

`cananry` 정보 출력 명령어

```bash
gef➤  canary
[+] The canary of process 115 is at 0x7fffffffe439, value is 0x706576d1167af900
```

<br>
<br>


### checksec

보호 기법 확인 명령어

```bash
gef➤  checksec
[+] checksec for '/home/ion/wargame/rop/rop'
Canary                        : ✓ (value: 0x706576d1167af900)
NX                            : ✓
PIE                           : ✘
Fortify                       : ✘
RelRO                         : Partial
```

<br>
<br>


### deference

특정 주소의 메모리 값과 메모리가 참조하고 있는 주소를 재귀적으로 보여주는 명령어

```bash
gef➤  dereference $rbp+0x10 -l 8
0x007fffffffdf50│+0x0000: 0x007fffffffe038  →  0x007fffffffe39e  →  "/home/kali/tmp/ex"
0x007fffffffdf58│+0x0008: 0x00000001f7fca000
0x007fffffffdf60│+0x0010: 0x00555555555195  →  <main+0> push rbp
0x007fffffffdf68│+0x0018: 0x007fffffffe379  →  0xe56c81cb766165e9
0x007fffffffdf70│+0x0020: 0x005555555551c0  →  <__libc_csu_init+0> push r15
0x007fffffffdf78│+0x0028: 0xf26a272b42366461
0x007fffffffdf80│+0x0030: 0x00555555555070  →  <_start+0> xor ebp, ebp
0x007fffffffdf88│+0x0038: 0x0000000000000000
```

<br>
<br>


### edit-flags
  
플래그 수정 명령어

```bash
flags [(+|-|~)FLAGNAME ...]		# + (set), - (unset), ~ (toggle)

gef➤  flags
[ZERO carry PARITY adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
gef➤  flags -ZERO +CARRY
[zero CARRY PARITY adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
gef➤  flags
[zero CARRY PARITY adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
```

<br>
<br>


### elf-info  
  
`ELF Binary` 정보 출력 명령어

```bash
gef➤  elf
Magic                 : 7f 45 4c 46
Class                 : 0x2 - ELF_64_BITS
Endianness            : 0x1 - LITTLE_ENDIAN
Version               : 0x1
OS ABI                : 0x0 - SYSTEMV
ABI Version           : 0x0
Type                  : 0x2 - ET_EXEC
Machine               : 0x3e - X86_64
Program Header Table  : 0x00000000000040
Section Header Table  : 0x00000000001a10
Header Table          : 0x00000000000040
ELF Version           : 0x1
Header size           : 64 (0x40)
Entry point           : 0x000000004005c0

────────────────────────────────────────────────────────────── Program Header ──────────────────────────────────────────────────────────────
  [ #] Type           Offset   Virtaddr   Physaddr  FileSiz   MemSiz Flags    Align
  [ 0] PT_PHDR          0x40   0x400040   0x400040    0x1f8    0x1f8 PF_R       0x8
  [ 1] PT_INTERP       0x238   0x400238   0x400238     0x1c     0x1c PF_R       0x1
  [ 2] PT_LOAD           0x0   0x400000   0x400000    0x988    0x988 None  0x200000
  [ 3] PT_LOAD         0xe10   0x600e10   0x600e10    0x240    0x260 None  0x200000
  [ 4] PT_DYNAMIC      0xe20   0x600e20   0x600e20    0x1d0    0x1d0 None       0x8
  [ 5] PT_NOTE         0x254   0x400254   0x400254     0x44     0x44 PF_R       0x4
  [ 6] PT_GNU_EH_FRAME    0x84c   0x40084c   0x40084c     0x3c     0x3c PF_R       0x4
  [ 7] PT_GNU_STACK      0x0        0x0        0x0      0x0      0x0 None      0x10
  [ 8] PT_GNU_RELRO    0xe10   0x600e10   0x600e10    0x1f0    0x1f0 PF_R       0x1

────────────────────────────────────────────────────────────── Section Header ──────────────────────────────────────────────────────────────
  [ #] Name                            Type    Address   Offset     Size   EntSiz Flags Link Info    Align
  [ 0]                                 UNKN        0x0      0x0      0x0      0x0 UNKNOWN_FLAG  0x0  0x0      0x0
  [ 1] .interp                 SHT_PROGBITS   0x400238    0x238     0x1c      0x0 ALLOC  0x0  0x0      0x1
  [ 2] .note.ABI-tag               SHT_NOTE   0x400254    0x254     0x20      0x0 ALLOC  0x0  0x0      0x4
  [ 3] .note.gnu.build-id          SHT_NOTE   0x400274    0x274     0x24      0x0 ALLOC  0x0  0x0      0x4
  [ 4] .gnu.hash               SHT_GNU_HASH   0x400298    0x298     0x28      0x0 ALLOC  0x5  0x0      0x8
  [ 5] .dynsym                   SHT_DYNSYM   0x4002c0    0x2c0     0xf0     0x18 ALLOC  0x6  0x1      0x8
  [ 6] .dynstr                   SHT_STRTAB   0x4003b0    0x3b0     0x79      0x0 ALLOC  0x0  0x0      0x1
  [ 7] .gnu.version          SHT_GNU_versym   0x40042a    0x42a     0x14      0x2 ALLOC  0x5  0x0      0x2
  [ 8] .gnu.version_r       SHT_GNU_verneed   0x400440    0x440     0x30      0x0 ALLOC  0x6  0x1      0x8
  [ 9] .rela.dyn                   SHT_RELA   0x400470    0x470     0x60     0x18 ALLOC  0x5  0x0      0x8
  [10] .rela.plt                   SHT_RELA   0x4004d0    0x4d0     0x78     0x18 UNKNOWN_FLAG  0x5 0x16      0x8
  [11] .init                   SHT_PROGBITS   0x400548    0x548     0x17      0x0 UNKNOWN_FLAG  0x0  0x0      0x4
  [12] .plt                    SHT_PROGBITS   0x400560    0x560     0x60     0x10 UNKNOWN_FLAG  0x0  0x0     0x10
  [13] .text                   SHT_PROGBITS   0x4005c0    0x5c0    0x242      0x0 UNKNOWN_FLAG  0x0  0x0     0x10
  [14] .fini                   SHT_PROGBITS   0x400804    0x804      0x9      0x0 UNKNOWN_FLAG  0x0  0x0      0x4
  [15] .rodata                 SHT_PROGBITS   0x400810    0x810     0x39      0x0 ALLOC  0x0  0x0      0x4
  [16] .eh_frame_hdr           SHT_PROGBITS   0x40084c    0x84c     0x3c      0x0 ALLOC  0x0  0x0      0x4
  [17] .eh_frame               SHT_PROGBITS   0x400888    0x888    0x100      0x0 ALLOC  0x0  0x0      0x8
  [18] .init_array           SHT_INIT_ARRAY   0x600e10    0xe10      0x8      0x8 UNKNOWN_FLAG  0x0  0x0      0x8
  [19] .fini_array           SHT_FINI_ARRAY   0x600e18    0xe18      0x8      0x8 UNKNOWN_FLAG  0x0  0x0      0x8
  [20] .dynamic                 SHT_DYNAMIC   0x600e20    0xe20    0x1d0     0x10 UNKNOWN_FLAG  0x6  0x0      0x8
  [21] .got                    SHT_PROGBITS   0x600ff0    0xff0     0x10      0x8 UNKNOWN_FLAG  0x0  0x0      0x8
  [22] .got.plt                SHT_PROGBITS   0x601000   0x1000     0x40      0x8 UNKNOWN_FLAG  0x0  0x0      0x8
  [23] .data                   SHT_PROGBITS   0x601040   0x1040     0x10      0x0 UNKNOWN_FLAG  0x0  0x0      0x8
  [24] .bss                      SHT_NOBITS   0x601050   0x1050     0x20      0x0 UNKNOWN_FLAG  0x0  0x0     0x10
  [25] .comment                SHT_PROGBITS        0x0   0x1050     0x29      0x1 UNKNOWN_FLAG  0x0  0x0      0x1
  [26] .symtab                   SHT_SYMTAB        0x0   0x1080    0x648     0x18 UNKNOWN_FLAG 0x1b 0x2b      0x8
  [27] .strtab                   SHT_STRTAB        0x0   0x16c8    0x245      0x0 UNKNOWN_FLAG  0x0  0x0      0x1
  [28] .shstrtab                 SHT_STRTAB        0x0   0x190d    0x103      0x0 UNKNOWN_FLAG  0x0  0x0      0x1
```

<br>
<br>


### eval

식을 계산하는 명령어

```bash
gef➤  $ 10
10
0xa
0b1010
b'\n'
b'\n'
gef➤  $ 0x315+0x12
807
0x327
0b1100100111
b"\x03'"
b"'\x03"
```

<br>
<br>


### format-string-helper

```bash
printf()
sprintf()
fprintf()
snprintf()
vsnprintf()

포맷 스트링 버그가 발생할 수 있는 함수에 break point를 걸어주는 명령어
```

```bash
gef➤  fmtstr-helper
[+] Enabled 5 FormatString breakpoints
```

<br>
<br>


### functions
  
GEF가 제공하는 유용한 함수 명령어 출력  
  
```bash
$\_base(\[filepath\]) : 해당 파일의 base address에 offset을 더해서 반환  
$\_bss(\[offset\]) : bss base address에 offset을 더해서 반환  
$\_got(\[offset\]) : got base address에 offset을 더해서 반환  
$\_heap(\[offset\]) : heap base address에 offset을 더해서 반환  
$\_stack(\[offset\]) : stack base address에 offset을 더해서 반환
```

```bash
gef➤  deref -l 4 $_bss(0x30)
0x00000000601080│+0x0000:  add BYTE PTR [rax], al
0x00000000601088│+0x0008:  add BYTE PTR [rax], al
0x00000000601090│+0x0010:  add BYTE PTR [rax], al
0x00000000601098│+0x0018:  add BYTE PTR [rax], al
gef➤  deref -l 4 $_base(\"libc\")
0x007ffff79e2000│+0x0000: 0x03010102464c457f
0x007ffff79e2008│+0x0008: 0x0000000000000000
0x007ffff79e2010│+0x0010: 0x00000001003e0003
0x007ffff79e2018│+0x0018: 0x0000000000021da0
```

<br>
<br>


### gef
  
GEF 명령어 설명 출력 명령어


<br>
<br>

### got  
  
`got` 정보 출력 명령어

```bash
gef➤  got

GOT protection: Partial RelRO | GOT functions: 5

[0x601018] puts@GLIBC_2.2.5  →  0x7ffff7a62970
[0x601020] __stack_chk_fail@GLIBC_2.4  →  0x400586
[0x601028] printf@GLIBC_2.2.5  →  0x7ffff7a46e40
[0x601030] read@GLIBC_2.2.5  →  0x4005a6
[0x601038] setvbuf@GLIBC_2.2.5  →  0x7ffff7a632a0
gef➤  got print

GOT protection: Partial RelRO | GOT functions: 5

[0x601028] printf@GLIBC_2.2.5  →  0x7ffff7a46e40
```

<br>
<br>


### search-pattern

메모리의 모든 세그먼트에서 특정 패턴을 검색해주는 명령어 `(alias: grep)`

```bash
gef➤  search-pattern /bin/sh
[+] Searching '/bin/sh' in memory
[+] In '/usr/lib/x86_64-linux-gnu/libc-2.33.so'(0x7ffff7f52000-0x7ffff7f9e000), permission=r--
  0x7ffff7f6c882 - 0x7ffff7f6c889  →   "/bin/sh" 
gef➤  grep /bin/sh
[+] Searching '/bin/sh' in memory
[+] In '/usr/lib/x86_64-linux-gnu/libc-2.33.so'(0x7ffff7f52000-0x7ffff7f9e000), permission=r--
  0x7ffff7f6c882 - 0x7ffff7f6c889  →   "/bin/sh"
```

<br>
<br>


### help  
  
GEF 명령어들을 출력해주는 명령어

```bash
gef➤  help
```

<br>
<br>


### hexdump 
  
특정 주소에 들어있는 값을 출력해주는 명령어

```bash
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x007fffffffde08│+0x0000: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA[...]"      ← $rsp
0x007fffffffde10│+0x0008: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA[...]"
0x007fffffffde18│+0x0010: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA[...]"
0x007fffffffde20│+0x0018: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA[...]"
0x007fffffffde28│+0x0020: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA[...]"
0x007fffffffde30│+0x0028: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA[...]"
0x007fffffffde38│+0x0030: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA[...]"
0x007fffffffde40│+0x0038: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA[...]"
────────────────────────────────────────────────────────────────────────────────────────────────────────────────

gef➤  hexdump byte 0x007fffffffde20 --size 16
0x00007fffffffde20     41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41    AAAAAAAAAAAAAAAA

gef➤  hexdump qword 0x007fffffffde20 --size 16
0x007fffffffde20│+0x0000   0x4141414141414141   
0x007fffffffde28│+0x0008   0x4141414141414141   
0x007fffffffde30│+0x0010   0x4141414141414141   
0x007fffffffde38│+0x0018   0x4141414141414141   
0x007fffffffde40│+0x0020   0x4141414141414141   
0x007fffffffde48│+0x0028   0x4141414141414141   
0x007fffffffde50│+0x0030   0x4141414141414141   
0x007fffffffde58│+0x0038   0x4141414141414141   
0x007fffffffde60│+0x0040   0x4141414141414141   
0x007fffffffde68│+0x0048   0x4141414141414141   
0x007fffffffde70│+0x0050   0x4141414141414141   
0x007fffffffde78│+0x0058   0x4141414141414141   
0x007fffffffde80│+0x0060   0x4141414141414141   
0x007fffffffde88│+0x0068   0x4141414141414141   
0x007fffffffde90│+0x0070   0x4141414141414141   
0x007fffffffde98│+0x0078   0x4141414141414141   

gef➤  hexdump word 0x007fffffffde20 --size 16
0x007fffffffde20│+0x0000   0x4141   
0x007fffffffde22│+0x0002   0x4141   
0x007fffffffde24│+0x0004   0x4141   
0x007fffffffde26│+0x0006   0x4141   
0x007fffffffde28│+0x0008   0x4141   
0x007fffffffde2a│+0x000a   0x4141   
0x007fffffffde2c│+0x000c   0x4141   
0x007fffffffde2e│+0x000e   0x4141   
0x007fffffffde30│+0x0010   0x4141   
0x007fffffffde32│+0x0012   0x4141   
0x007fffffffde34│+0x0014   0x4141   
0x007fffffffde36│+0x0016   0x4141   
0x007fffffffde38│+0x0018   0x4141   
0x007fffffffde3a│+0x001a   0x4141   
0x007fffffffde3c│+0x001c   0x4141   
0x007fffffffde3e│+0x001e   0x4141
```

<br>
<br>


### highlight

특정 문자열을 원하는 색상으로 커스텀 해주는 명령어

```bash
gef➤  hl add AAAA yellow
gef➤  hl add BBBB blue
gef➤  hl add CCCC red
```

![](https://velog.velcdn.com/images/silvergun8291/post/1fc99f99-43e2-4ea9-87b8-33b910ab7c54/image.png)


<br>
<br>


### nop

`instructions` 을 스킵 할 수 있게 해주는 명령어

```bash
gef➤  nop
[*] Patching 1 bytes at 0x5555555551da might result in corruption
[+] Patching 1 bytes from 0x5555555551da
gef➤  disas main
Dump of assembler code for function main:
   0x00005555555551cc <+0>:     push   rbp
   0x00005555555551cd <+1>:     mov    rbp,rsp
   0x00005555555551d0 <+4>:     lea    rax,[rip+0xe3c]        # 0x555555556013
   0x00005555555551d7 <+11>:    mov    rdi,rax
=> 0x00005555555551da <+14>:    nop
   0x00005555555551db <+15>:    push   rcx
   0x00005555555551dc <+16>:    (bad)  
   0x00005555555551dd <+17>:    (bad)  
   0x00005555555551de <+18>:    (bad)  
   0x00005555555551df <+19>:    mov    eax,0x0
   0x00005555555551e4 <+24>:    call   0x555555555169 <vuln>
   0x00005555555551e9 <+29>:    mov    eax,0x0
   0x00005555555551ee <+34>:    pop    rbp
   0x00005555555551ef <+35>:    ret    
End of assembler dump.
```

<br>
<br>


### patch

특정 주소의 값을 변경하는 명령어

```bash
 → 0x555555555141 <main+8>         lea    rax, [rip+0xebc]        # 0x555555556004
   0x555555555148 <main+15>        mov    QWORD PTR [rbp-0x8], rax
   0x55555555514c <main+19>        mov    rax, QWORD PTR [rbp-0x8]
   0x555555555150 <main+23>        mov    rdi, rax
   0x555555555153 <main+26>        mov    eax, 0x0
   0x555555555158 <main+31>        call   0x555555555030 <system@plt>

gef➤  x/s 0x555555556004
0x555555556004: "/bin/ls"

gef➤  patch string 0x555555556004 "/bin/sh"
gef➤  c
Continuing.
[Detaching after vfork from child process 69313]
$ ls
got  got.c
```

<br>
<br>


 ### pattern

사이클릭 패턴을 만들고 검색할 수 있는 명령어

오버플로우 발생 지점부터 데이터 오염 지점까지 오프셋을 구할 때 유용 

Ex)

```bash
gef➤  pattern create 100
[+] Generating a pattern of 100 bytes (n=8)
aaaaaaaabaaaaaaacaaaaaaadaaaaaaaeaaaaaaafaaaaaaagaaaaaaahaaaaaaaiaaaaaaajaaaaaaakaaaaaaalaaaaaaamaaa
[+] Saved as '$_gef0'
gef➤  c
Starting program: /home/kali/tmp/bof2 
aaaaaaaabaaaaaaacaaaaaaadaaaaaaaeaaaaaaafaaaaaaagaaaaaaahaaaaaaaiaaaaaaajaaaaaaakaaaaaaalaaaaaaamaaa
```

```bash
gef➤  x/gx $rsp
0x7fffffffdf48: 0x616161616161616a
gef➤  pattern search 0x616161616161616a
[+] Searching for '0x616161616161616a'
[+] Found at offset 72 (little-endian search) likely
[+] Found at offset 65 (big-endian search)
```

`buffer ~ RET` 거리는 72 Byte

#

맞는지 어셈블리어를 봐보면

```bash
gef➤  disas main
Dump of assembler code for function main:
   0x0000555555555149 <+0>:     push   rbp
   0x000055555555514a <+1>:     mov    rbp,rsp
   0x000055555555514d <+4>:     sub    rsp,0x40
   0x0000555555555151 <+8>:     lea    rax,[rbp-0x40]
   0x0000555555555155 <+12>:    mov    rdi,rax
   0x0000555555555158 <+15>:    mov    eax,0x0
   0x000055555555515d <+20>:    call   0x555555555040 <gets@plt>
   0x0000555555555162 <+25>:    lea    rax,[rbp-0x40]
   0x0000555555555166 <+29>:    mov    rdi,rax
   0x0000555555555169 <+32>:    mov    eax,0x0
   0x000055555555516e <+37>:    call   0x555555555030 <printf@plt>
   0x0000555555555173 <+42>:    mov    eax,0x0
   0x0000555555555178 <+47>:    leave  
=> 0x0000555555555179 <+48>:    ret    
End of assembler dump.
gef➤  $ 0x40
64
```

`buffer~RBP` 까지 거리는 64 Byte 니까 `buffer~RET` 까지 거리는 72 Byte

<br>
<br>


### pie

`PIE` 방어기법이 걸려있을 때 유용한 명령어

#

`pie breakpoint` : PIE 방어 기법이 걸려 있어도 break point를 걸 수 있는 명령어

```bash
gef➤  disas main
Dump of assembler code for function main:
   0x0000000000001139 <+0>:     push   rbp
   0x000000000000113a <+1>:     mov    rbp,rsp
   0x000000000000113d <+4>:     sub    rsp,0x10
   0x0000000000001141 <+8>:     lea    rax,[rip+0xebc]        # 0x2004
   0x0000000000001148 <+15>:    mov    QWORD PTR [rbp-0x8],rax
   0x000000000000114c <+19>:    mov    rax,QWORD PTR [rbp-0x8]
   0x0000000000001150 <+23>:    mov    rdi,rax
   0x0000000000001153 <+26>:    mov    eax,0x0
   0x0000000000001158 <+31>:    call   0x1030 <system@plt>
   0x000000000000115d <+36>:    mov    eax,0x0
   0x0000000000001162 <+41>:    leave  
   0x0000000000001163 <+42>:    ret    
End of assembler dump.
gef➤  pie breakpoint main+31
gef➤  pie breakpoint main+41
```

#

`pie info` : PIE break point 출력

```bash
gef➤  pie info
VNum    Num     Addr              
     1  N/A     0x1158            
     2  N/A     0x1162
```

#

`pie delete` : PIE break point 삭제

```bash
gef➤  pie delete 2
gef➤  pie info
VNum    Num     Addr              
     1  N/A     0x1158
```

#

`pie run` : 디버깅 시작 (PIE break point를 걸었을 때는 pie run으로 디버깅을 시작해야 함)

```bash
gef➤  pie run
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
   0x55555555514c <main+19>        mov    rax, QWORD PTR [rbp-0x8]
   0x555555555150 <main+23>        mov    rdi, rax
   0x555555555153 <main+26>        mov    eax, 0x0
 → 0x555555555158 <main+31>        call   0x555555555030 <system@plt>
   ↳  0x555555555030 <system@plt+0>   jmp    QWORD PTR [rip+0x2fe2]        # 0x555555558018 <system@got.plt>
      0x555555555036 <system@plt+6>   push   0x0
      0x55555555503b <system@plt+11>  jmp    0x555555555020
      0x555555555040 <__cxa_finalize@plt+0> jmp    QWORD PTR [rip+0x2fb2]        # 0x555555557ff8
      0x555555555046 <__cxa_finalize@plt+6> xchg   ax, ax
      0x555555555048                  add    BYTE PTR [rax], al
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── arguments (guessed) ────
system@plt (
   $rdi = 0x0000555555556004 → 0x00736c2f6e69622f ("/bin/ls"?)
)
```

`system` 함수에 `break point` 가 걸려 있는걸 확인할 수 있습니다.


<br>
<br>

### registers

`register` 를 출력해주는 명령어

```bash
gef➤  reg
$rax   : 0x0               
$rbx   : 0x0000555555555170  →  <__libc_csu_init+0> push r15
$rcx   : 0x00007ffff7fa2738  →  0x00007ffff7fa4b00  →  0x0000000000000000
$rdx   : 0x00007fffffffe048  →  0x00007fffffffe3ae  →  "POWERSHELL_TELEMETRY_OPTOUT=1"
$rsp   : 0x00007fffffffdf30  →  0x00007fffffffe030  →  0x0000000000000001
$rbp   : 0x00007fffffffdf40  →  0x0000000000000000
$rsi   : 0x00007fffffffe038  →  0x00007fffffffe39b  →  "/home/kali/tmp/got"
$rdi   : 0x0000555555556004  →  0x00736c2f6e69622f ("/bin/ls"?)
$rip   : 0x0000555555555158  →  <main+31> call 0x555555555030 <system@plt>
$r8    : 0x0               
$r9    : 0x00007ffff7fdc1f0  →  <_dl_fini+0> push rbp
$r10   : 0x69682ac         
$r11   : 0x206             
$r12   : 0x0000555555555050  →  <_start+0> xor ebp, ebp
$r13   : 0x0               
$r14   : 0x0               
$r15   : 0x0               
$eflags: [zero carry PARITY adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x33 $ss: 0x2b $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00
```

```bash
gef➤  reg $rax $rip $rsp
$rax   : 0x0               
$rsp   : 0x00007fffffffdf30  →  0x00007fffffffe030  →  0x0000000000000001
$rip   : 0x0000555555555158  →  <main+31> call 0x555555555030 <system@plt>
```

<br>
<br>


### shellcode

`shellcode` 를 검색하고 download 할 수 있는 명령어

```bash
gef➤  shellcode search x86-64
[+] Showing matching shellcodes
[+] Id  Platform        Description
866     FreeBSD/x86-64  execve - 28 bytes
865     FreeBSD/x86-64  bind_tcp with passcode - 127 bytes
106     FreeBSD/x86-64  exec(/bin/sh) Shellcode - 31 bytes
104     FreeBSD/x86-64  execve /bin/sh shellcode 34 bytes
103     FreeBSD/x86-64  Execve /bin/sh - Anti-Debugging
907     Linux/x86-64    Dynamic null-free reverse TCP shell - 65 bytes
905     Linux/x86-64    execveat("/bin//sh") - 29 bytes
896     Linux/x86-64    Add map in /etc/hosts file - 110 bytes
895     Linux/x86-64    Connect Back Shellcode - 139 bytes
894     Linux/x86-64    access() Egghunter - 49 bytes
892     Linux/x86-64    Shutdown - 64 bytes
891     Linux/x86-64    Read password - 105 bytes
890     Linux/x86-64    Password Protected Reverse Shell - 136 bytes
889     Linux/x86-64    Password Protected Bind Shell - 147 bytes
888     Linux/x86-64    Add root - Polymorphic - 273 bytes
884     Linux/x86-64    Bind TCP stager with egghunter - 157 bytes
880     Linux/x86-64    Add user and password with open,write,close - 358 bytes
879     Linux/x86-64    Add user and password with echo cmd - 273 bytes
878     Linux/x86-64    Read /etc/passwd - 82 bytes
877     Linux/x86-64    shutdown -h now - 65 bytes
873     Linux/x86-64    TCP Bind 4444 with password - 173 bytes
871     Linux/x86-64    TCP reverse shell with password - 138 bytes
870     Linux/x86-64    TCP bind shell with password - 175 bytes
867     Linux/x86-64    Reads data from /etc/passwd to /tmp/outfile - 118 bytes
859     Linux/x86-64    shell bind TCP random port - 57 bytes
858     Linux/x86-64    TCP bind shell - 150 bytes
857     Linux/x86-64    Reverse TCP shell - 118 bytes
801     Linux/x86-64    add user with passwd - 189 bytes
683     Linux/x86-64    execve(/sbin/iptables, [/sbin/iptables, -F], NULL) - 49 bytes
806     Linux/x86-64    Execute /bin/sh - 27 bytes
822     Linux/x86-64    bind-shell with netcat - 131 bytes
823     Linux/x86-64    connect back shell with netcat - 109 bytes
815     Linux/x86-64    setreuid(0,0) execve(/bin/ash,NULL,NULL) + XOR - 85 bytes
816     Linux/x86-64    setreuid(0,0) execve(/bin/csh, [/bin/csh, NULL]) + XOR - 87 bytes
817     Linux/x86-64    setreuid(0,0) execve(/bin/ksh, [/bin/ksh, NULL]) + XOR - 87 bytes
818     Linux/x86-64    setreuid(0,0) execve(/bin/zsh, [/bin/zsh, NULL]) + XOR - 87 bytes
78      Linux/x86-64    bindshell port:4444 shellcode - 132 bytes
77      Linux/x86-64    setuid(0) + execve(/bin/sh) 49 bytes
76      Linux/x86-64    execve(/bin/sh, [/bin/sh], NULL) - 33 bytes
603     Linux/x86-64    execve(/bin/sh); - 30 bytes
602     Linux/x86-64    reboot(POWER_OFF) - 19 bytes
605     Linux/x86-64    sethostname() & killall - 33 bytes
736     Osx/x86-64      setuid shell x86_64 - 51 bytes
761     Osx/x86-64      reverse tcp shellcode - 131 bytes
786     Osx/x86-64      universal OSX dyld ROP shellcode
[+] Use `shellcode get <id>` to fetch shellcode
```
#

```bash
gef➤  shellcode get 603
[+] Downloading shellcode id=603
[+] Downloaded, written to disk...
[+] Shellcode written to '/tmp/gef/sc-10wcqa1a.txt'
```

#

```bash
kali@kali  ~/tmp  cat /tmp/gef/sc-10wcqa1a.txt 
# Linux/x86_64 execve("/bin/sh"); 30 bytes shellcode
# Date: 2010-04-26
# Author: zbt
# Tested on: x86_64 Debian GNU/Linux
 
/*
    ; execve("/bin/sh", ["/bin/sh"], NULL)
 
    section .text
            global _start
 
    _start:
            xor     rdx, rdx
            mov     qword rbx, '//bin/sh'
            shr     rbx, 0x8
            push    rbx
            mov     rdi, rsp
            push    rax
            push    rdi
            mov     rsi, rsp
            mov     al, 0x3b
            syscall
*/
 
int main(void)
{
    char shellcode[] =
    "\x48\x31\xd2"                                  // xor    %rdx, %rdx
    "\x48\xbb\x2f\x2f\x62\x69\x6e\x2f\x73\x68"      // mov      $0x68732f6e69622f2f, %rbx
    "\x48\xc1\xeb\x08"                              // shr    $0x8, %rbx
    "\x53"                                          // push   %rbx
    "\x48\x89\xe7"                                  // mov    %rsp, %rdi
    "\x50"                                          // push   %rax
    "\x57"                                          // push   %rdi
    "\x48\x89\xe6"                                  // mov    %rsp, %rsi
    "\xb0\x3b"                                      // mov    $0x3b, %al
    "\x0f\x05";                                     // syscall
 
    (*(void (*)()) shellcode)();
     
    return 0;
}%
```

<br>
<br>


### stub

해당 함수를 무시하는 명령어

```bash
gef➤  disas main
Dump of assembler code for function main:
   0x000055555555517b <+0>:     push   rbp
   0x000055555555517c <+1>:     mov    rbp,rsp
=> 0x000055555555517f <+4>:     lea    rax,[rip+0xe9f]        # 0x555555556025
   0x0000555555555186 <+11>:    mov    rdi,rax
   0x0000555555555189 <+14>:    call   0x555555555030 <puts@plt>
   0x000055555555518e <+19>:    mov    eax,0x0
   0x0000555555555193 <+24>:    call   0x555555555139 <A>
   0x0000555555555198 <+29>:    mov    eax,0x0
   0x000055555555519d <+34>:    call   0x55555555514f <B>
   0x00005555555551a2 <+39>:    mov    eax,0x0
   0x00005555555551a7 <+44>:    call   0x555555555165 <C>
   0x00005555555551ac <+49>:    mov    eax,0x0
   0x00005555555551b1 <+54>:    pop    rbp
   0x00005555555551b2 <+55>:    ret    
End of assembler dump.
```

```bash
gef➤  stub B
Breakpoint 1 at 0x555555555153
[+] All calls to 'B' will be skipped (with return value set to 0x0)
gef➤  c
Continuing.
Hello~
function A
[+] Ignoring call to 'B' (setting return value to 0x0)
function C
[Inferior 1 (process 83853) exited normally]
```

<br>
<br>


### vmmap

전체 메모리 공간 매핑을 출력하는 명령어

```bash
gef➤  vmmap
[ Legend:  Code | Heap | Stack ]
Start              End                Offset             Perm Path
0x0000555555554000 0x0000555555555000 0x0000000000000000 r-- /home/kali/tmp/trace
0x0000555555555000 0x0000555555556000 0x0000000000001000 r-x /home/kali/tmp/trace
0x0000555555556000 0x0000555555557000 0x0000000000002000 r-- /home/kali/tmp/trace
0x0000555555557000 0x0000555555558000 0x0000000000002000 r-- /home/kali/tmp/trace
0x0000555555558000 0x0000555555559000 0x0000000000003000 rw- /home/kali/tmp/trace
0x00007ffff7dd2000 0x00007ffff7dd4000 0x0000000000000000 rw- 
0x00007ffff7dd4000 0x00007ffff7dfa000 0x0000000000000000 r-- /usr/lib/x86_64-linux-gnu/libc-2.33.so
0x00007ffff7dfa000 0x00007ffff7f52000 0x0000000000026000 r-x /usr/lib/x86_64-linux-gnu/libc-2.33.so
0x00007ffff7f52000 0x00007ffff7f9e000 0x000000000017e000 r-- /usr/lib/x86_64-linux-gnu/libc-2.33.so
0x00007ffff7f9e000 0x00007ffff7f9f000 0x00000000001ca000 --- /usr/lib/x86_64-linux-gnu/libc-2.33.so
0x00007ffff7f9f000 0x00007ffff7fa2000 0x00000000001ca000 r-- /usr/lib/x86_64-linux-gnu/libc-2.33.so
0x00007ffff7fa2000 0x00007ffff7fa5000 0x00000000001cd000 rw- /usr/lib/x86_64-linux-gnu/libc-2.33.so
0x00007ffff7fa5000 0x00007ffff7fb0000 0x0000000000000000 rw- 
0x00007ffff7fc6000 0x00007ffff7fca000 0x0000000000000000 r-- [vvar]
0x00007ffff7fca000 0x00007ffff7fcc000 0x0000000000000000 r-x [vdso]
0x00007ffff7fcc000 0x00007ffff7fcd000 0x0000000000000000 r-- /usr/lib/x86_64-linux-gnu/ld-2.33.so
0x00007ffff7fcd000 0x00007ffff7ff1000 0x0000000000001000 r-x /usr/lib/x86_64-linux-gnu/ld-2.33.so
0x00007ffff7ff1000 0x00007ffff7ffb000 0x0000000000025000 r-- /usr/lib/x86_64-linux-gnu/ld-2.33.so
0x00007ffff7ffb000 0x00007ffff7ffd000 0x000000000002e000 r-- /usr/lib/x86_64-linux-gnu/ld-2.33.so
0x00007ffff7ffd000 0x00007ffff7fff000 0x0000000000030000 rw- /usr/lib/x86_64-linux-gnu/ld-2.33.so
0x00007ffffffde000 0x00007ffffffff000 0x0000000000000000 rw- [stack]
```

<br>
<br>


### xfiles

로드된 라이브러리의 메모리 구조를 출력하는 명령어

```bash
gef➤  xfiles
Start              End                Name                  File
0x0000555555554318 0x0000555555554334 .interp               /home/kali/tmp/trace
0x0000555555554338 0x0000555555554358 .note.gnu.property    /home/kali/tmp/trace
0x0000555555554358 0x000055555555437c .note.gnu.build-id    /home/kali/tmp/trace
0x000055555555437c 0x000055555555439c .note.ABI-tag         /home/kali/tmp/trace
0x00005555555543a0 0x00005555555543c4 .gnu.hash             /home/kali/tmp/trace
0x00005555555543c8 0x0000555555554470 .dynsym               /home/kali/tmp/trace
0x0000555555554470 0x00005555555544f2 .dynstr               /home/kali/tmp/trace
0x00005555555544f2 0x0000555555554500 .gnu.version          /home/kali/tmp/trace
0x0000555555554500 0x0000555555554520 .gnu.version_r        /home/kali/tmp/trace
0x0000555555554520 0x00005555555545e0 .rela.dyn             /home/kali/tmp/trace
0x00005555555545e0 0x00005555555545f8 .rela.plt             /home/kali/tmp/trace
0x0000555555555000 0x0000555555555017 .init                 /home/kali/tmp/trace
0x0000555555555020 0x0000555555555040 .plt                  /home/kali/tmp/trace
0x0000555555555040 0x0000555555555048 .plt.got              /home/kali/tmp/trace
0x0000555555555050 0x0000555555555231 .text                 /home/kali/tmp/trace
0x0000555555555234 0x000055555555523d .fini                 /home/kali/tmp/trace
0x0000555555556000 0x0000555555556018 .rodata               /home/kali/tmp/trace
0x0000555555556018 0x0000555555556074 .eh_frame_hdr         /home/kali/tmp/trace
0x0000555555556078 0x0000555555556200 .eh_frame             /home/kali/tmp/trace
0x0000555555557de8 0x0000555555557df0 .init_array           /home/kali/tmp/trace
0x0000555555557df0 0x0000555555557df8 .fini_array           /home/kali/tmp/trace
0x0000555555557df8 0x0000555555557fd8 .dynamic              /home/kali/tmp/trace
0x0000555555557fd8 0x0000555555558000 .got                  /home/kali/tmp/trace
0x0000555555558000 0x0000555555558020 .got.plt              /home/kali/tmp/trace
0x0000555555558020 0x0000555555558030 .data                 /home/kali/tmp/trace
0x0000555555558030 0x0000555555558038 .bss                  /home/kali/tmp/trace
0x00007ffff7fcc238 0x00007ffff7fcc25c .note.gnu.build-id    /lib64/ld-linux-x86-64.so.2
0x00007ffff7fcc260 0x00007ffff7fcc32c .hash                 /lib64/ld-linux-x86-64.so.2
0x00007ffff7fcc330 0x00007ffff7fcc420 .gnu.hash             /lib64/ld-linux-x86-64.so.2
0x00007ffff7fcc420 0x00007ffff7fcc720 .dynsym               /lib64/ld-linux-x86-64.so.2
0x00007ffff7fcc720 0x00007ffff7fcc959 .dynstr               /lib64/ld-linux-x86-64.so.2
0x00007ffff7fcc95a 0x00007ffff7fcc99a .gnu.version          /lib64/ld-linux-x86-64.so.2
0x00007ffff7fcc9a0 0x00007ffff7fcca44 .gnu.version_d        /lib64/ld-linux-x86-64.so.2
0x00007ffff7fcca48 0x00007ffff7fccb38 .rela.dyn             /lib64/ld-linux-x86-64.so.2
0x00007ffff7fccb38 0x00007ffff7fccb98 .rela.plt             /lib64/ld-linux-x86-64.so.2
0x00007ffff7fcd000 0x00007ffff7fcd050 .plt                  /lib64/ld-linux-x86-64.so.2
0x00007ffff7fcd050 0x00007ffff7ff078e .text                 /lib64/ld-linux-x86-64.so.2
0x00007ffff7ff1000 0x00007ffff7ff6c3b .rodata               /lib64/ld-linux-x86-64.so.2
0x00007ffff7ff6c3c 0x00007ffff7ff7480 .eh_frame_hdr         /lib64/ld-linux-x86-64.so.2
0x00007ffff7ff7480 0x00007ffff7ffa37c .eh_frame             /lib64/ld-linux-x86-64.so.2
0x00007ffff7ffbc60 0x00007ffff7ffce78 .data.rel.ro          /lib64/ld-linux-x86-64.so.2
0x00007ffff7ffce78 0x00007ffff7ffcfe8 .dynamic              /lib64/ld-linux-x86-64.so.2
0x00007ffff7ffcfe8 0x00007ffff7ffcff0 .got                  /lib64/ld-linux-x86-64.so.2
0x00007ffff7ffd000 0x00007ffff7ffd038 .got.plt              /lib64/ld-linux-x86-64.so.2
0x00007ffff7ffd040 0x00007ffff7ffe078 .data                 /lib64/ld-linux-x86-64.so.2
0x00007ffff7ffe080 0x00007ffff7ffe218 .bss                  /lib64/ld-linux-x86-64.so.2
0x00007ffff7fca120 0x00007ffff7fca164 .hash                 /home/kali/tmp/trace
0x00007ffff7fca168 0x00007ffff7fca1b8 .gnu.hash             /home/kali/tmp/trace
0x00007ffff7fca1b8 0x00007ffff7fca2d8 .dynsym               /home/kali/tmp/trace
0x00007ffff7fca2d8 0x00007ffff7fca34a .dynstr               /home/kali/tmp/trace
0x00007ffff7fca34a 0x00007ffff7fca362 .gnu.version          /home/kali/tmp/trace
0x00007ffff7fca368 0x00007ffff7fca3a0 .gnu.version_d        /home/kali/tmp/trace
0x00007ffff7fca3a0 0x00007ffff7fca4c0 .dynamic              /home/kali/tmp/trace
0x00007ffff7fca4c0 0x00007ffff7fca524 .note                 /home/kali/tmp/trace
0x00007ffff7fca524 0x00007ffff7fca560 .eh_frame_hdr         /home/kali/tmp/trace
0x00007ffff7fca560 0x00007ffff7fca644 .eh_frame             /home/kali/tmp/trace
0x00007ffff7fca650 0x00007ffff7fcabf5 .text                 /home/kali/tmp/trace
0x00007ffff7fcabf5 0x00007ffff7fcac49 .altinstructions      /home/kali/tmp/trace
0x00007ffff7fcac49 0x00007ffff7fcac65 .altinstr_replacement /home/kali/tmp/trace
0x00007ffff7dd4350 0x00007ffff7dd4370 .note.gnu.property    /lib/x86_64-linux-gnu/libc.so.6
0x00007ffff7dd4370 0x00007ffff7dd4394 .note.gnu.build-id    /lib/x86_64-linux-gnu/libc.so.6
0x00007ffff7dd4394 0x00007ffff7dd43b4 .note.ABI-tag         /lib/x86_64-linux-gnu/libc.so.6
0x00007ffff7dd43b8 0x00007ffff7dd7970 .hash                 /lib/x86_64-linux-gnu/libc.so.6
0x00007ffff7dd7970 0x00007ffff7ddb6e0 .gnu.hash             /lib/x86_64-linux-gnu/libc.so.6
0x00007ffff7ddb6e0 0x00007ffff7de99a8 .dynsym               /lib/x86_64-linux-gnu/libc.so.6
0x00007ffff7de99a8 0x00007ffff7defcde .dynstr               /lib/x86_64-linux-gnu/libc.so.6
0x00007ffff7defcde 0x00007ffff7df0fc4 .gnu.version          /lib/x86_64-linux-gnu/libc.so.6
0x00007ffff7df0fc8 0x00007ffff7df1480 .gnu.version_d        /lib/x86_64-linux-gnu/libc.so.6
0x00007ffff7df1480 0x00007ffff7df14c0 .gnu.version_r        /lib/x86_64-linux-gnu/libc.so.6
0x00007ffff7df14c0 0x00007ffff7df8f78 .rela.dyn             /lib/x86_64-linux-gnu/libc.so.6
0x00007ffff7df8f78 0x00007ffff7df93f8 .rela.plt             /lib/x86_64-linux-gnu/libc.so.6
0x00007ffff7dfa000 0x00007ffff7dfa310 .plt                  /lib/x86_64-linux-gnu/libc.so.6
0x00007ffff7dfa310 0x00007ffff7dfa330 .plt.got              /lib/x86_64-linux-gnu/libc.so.6
0x00007ffff7dfa340 0x00007ffff7f50ab9 .text                 /lib/x86_64-linux-gnu/libc.so.6
0x00007ffff7f50ac0 0x00007ffff7f5192c __libc_freeres_fn     /lib/x86_64-linux-gnu/libc.so.6
0x00007ffff7f52000 0x00007ffff7f76f78 .rodata               /lib/x86_64-linux-gnu/libc.so.6
0x00007ffff7f76f80 0x00007ffff7f76f9c .interp               /lib/x86_64-linux-gnu/libc.so.6
0x00007ffff7f76f9c 0x00007ffff7f7d548 .eh_frame_hdr         /lib/x86_64-linux-gnu/libc.so.6
0x00007ffff7f7d548 0x00007ffff7f9da88 .eh_frame             /lib/x86_64-linux-gnu/libc.so.6
0x00007ffff7f9da88 0x00007ffff7f9de8e .gcc_except_table     /lib/x86_64-linux-gnu/libc.so.6
0x00007ffff7f9f680 0x00007ffff7f9f690 .tdata                /lib/x86_64-linux-gnu/libc.so.6
0x00007ffff7f9f690 0x00007ffff7f9f708 .tbss                 /lib/x86_64-linux-gnu/libc.so.6
0x00007ffff7f9f690 0x00007ffff7f9f6a0 .init_array           /lib/x86_64-linux-gnu/libc.so.6
0x00007ffff7f9f6a0 0x00007ffff7fa1b60 .data.rel.ro          /lib/x86_64-linux-gnu/libc.so.6
0x00007ffff7fa1b60 0x00007ffff7fa1d30 .dynamic              /lib/x86_64-linux-gnu/libc.so.6
0x00007ffff7fa1d30 0x00007ffff7fa1ff0 .got                  /lib/x86_64-linux-gnu/libc.so.6
0x00007ffff7fa2000 0x00007ffff7fa2198 .got.plt              /lib/x86_64-linux-gnu/libc.so.6
0x00007ffff7fa21a0 0x00007ffff7fa37c0 .data                 /lib/x86_64-linux-gnu/libc.so.6
0x00007ffff7fa37c0 0x00007ffff7fa3898 __libc_subfreeres     /lib/x86_64-linux-gnu/libc.so.6
0x00007ffff7fa38a0 0x00007ffff7fa4608 __libc_IO_vtables     /lib/x86_64-linux-gnu/libc.so.6
0x00007ffff7fa4608 0x00007ffff7fa4610 __libc_atexit         /lib/x86_64-linux-gnu/libc.so.6
0x00007ffff7fa4620 0x00007ffff7fad1e8 .bss                  /lib/x86_64-linux-gnu/libc.so.6
0x00007ffff7fad1e8 0x00007ffff7fad378 __libc_freeres_ptrs   /lib/x86_64-linux-gnu/libc.so.6
```

<br>
<br>


### xinfo

특정 주소에 대한 정보를 출력하는 명령어

```bash
gef➤  xinfo 0x555555555139
───────────────────────────────────────────────────────────────── xinfo: 0x555555555139 ─────────────────────────────────────────────────────────────────
Page: 0x0000555555555000  →  0x0000555555556000 (size=0x1000)
Permissions: r-x
Pathname: /home/kali/tmp/trace
Offset (from page): 0x139
Inode: 2628325
Segment: .text (0x0000555555555050-0x0000555555555231)
Offset (from segment): 0xe9
Symbol: func
```

<br>
<br>


### context

프로그램의 맥락 (Register, Stack, Code, threads, trace)를 보여주는 명령어

* `Register` : 레지스터 값들을 보여줌
* `Stack` : 스택 값들을 보여줌
* `Code` : 어셈블리어 코드를 보여줌
* `trace` : rip에 도달 할 때까지 어떤 함수들이 중첩되어 호출되었는지 보여줌

```bash
gef➤  context


[ Legend: Modified register | Code | Heap | Stack | String ]
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x007fffffffdeb0  →  "AAAAAAAAA"
$rbx   : 0x005555555551c0  →  <__libc_csu_init+0> push r15
$rcx   : 0x007ffff7fa29a0  →  0x00000000fbad2288
$rdx   : 0x0               
$rsp   : 0x007fffffffdeb0  →  "AAAAAAAAA"
$rbp   : 0x007fffffffdf30  →  0x007fffffffdf40  →  0x0000000000000000
$rsi   : 0x4141414141414141 ("AAAAAAAA"?)
$rdi   : 0x007ffff7fa5680  →  0x0000000000000000
$rip   : 0x00555555555181  →  <vuln+40> lea rax, [rbp-0x80]
$r8    : 0x007fffffffdeb0  →  "AAAAAAAAA"
$r9    : 0x0               
$r10   : 0x5d              
$r11   : 0x246             
$r12   : 0x00555555555070  →  <_start+0> xor ebp, ebp
$r13   : 0x0               
$r14   : 0x0               
$r15   : 0x0               
$eflags: [zero carry PARITY adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x33 $ss: 0x2b $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00 
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x007fffffffdeb0│+0x0000: "AAAAAAAAA"    ← $rax, $rsp, $r8
0x007fffffffdeb8│+0x0008: 0x00555555550041 ("A"?)
0x007fffffffdec0│+0x0010: 0x007ffff7fa37a8  →  0x007ffff7fa36c0  →  0x00000000fbad2a84
0x007fffffffdec8│+0x0018: 0x007ffff7fa44a0  →  0x0000000000000000
0x007fffffffded0│+0x0020: 0x0000000000000000
0x007fffffffded8│+0x0028: 0x007ffff7e54b39  →  <_IO_do_write+25> cmp rbx, rax
0x007fffffffdee0│+0x0030: 0x0000000000000a ("\n"?)
0x007fffffffdee8│+0x0038: 0x007ffff7e54fa3  →  <_IO_file_overflow+259> cmp eax, 0xffffffff
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
   0x555555555174 <vuln+27>        mov    rdi, rax
   0x555555555177 <vuln+30>        mov    eax, 0x0
   0x55555555517c <vuln+35>        call   0x555555555050 <gets@plt>
 → 0x555555555181 <vuln+40>        lea    rax, [rbp-0x80]
   0x555555555185 <vuln+44>        mov    rdi, rax
   0x555555555188 <vuln+47>        mov    eax, 0x0
   0x55555555518d <vuln+52>        call   0x555555555040 <printf@plt>
   0x555555555192 <vuln+57>        nop    
   0x555555555193 <vuln+58>        leave  
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "ex", stopped 0x555555555181 in vuln (), reason: BREAKPOINT
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x555555555181 → vuln()
[#1] 0x5555555551b2 → main()
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
```

#
---
#

<br>

> [xor-memory - GEF - GDB Enhanced Features documentation (hugsy.github.io)](https://hugsy.github.io/gef/commands/xor-memory/)


> [Home - GEF-Legacy - GDB Enhanced Features (for GDB-Python2) documentation](https://gef-legacy.readthedocs.io/en/latest/)
