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



