### 범용 레지스터

![image](https://user-images.githubusercontent.com/81484874/196694263-badc408a-98a5-4381-9cf4-bdf7ba52e93f.png)


<br>
<br>


### 세그먼트 레지스터

x64 아키텍처에서는 cs, ss, ds, es, fs, gs 총 6가지 세그먼트 레지스터가 존재하며 각각의 크기는 16bit 입니다.

cs, ds, ss 레지스터는 코드 영역과 데이터, 스택 메모리 영역을 가리킬 때 사용되고, 나머지 레지스터는 범용적인 용도로 제작된 레지스터입니다.


<br>
<br>


### 명령어 포인터 레지스터

CPU가 어느 부분의 코드를 실행할지 가리키는 역할을 합니다.

x64아키텍처에서는 rip이며, 크기는 8 Byte 입니다.


<br>
<br>


### 플래그 레지스터

프로세서의 현재 상태를 저장하고 있는 레지스터입니다.

x64아키텍처에서는 RFLAG라고 불리는 64bit 크기의 플래그 레지스터가 존재하고 이중 오른쪽의 20여 개의 비트만 사용합니다.

![image](https://user-images.githubusercontent.com/81484874/196698132-a5378086-3c8d-4fb6-93ab-9b930ec5d02c.png)

<br>
<br>


### 레지스터 호환

![image](https://user-images.githubusercontent.com/81484874/196698165-e980bb8a-3bc9-47a4-b367-7c45f7f395c0.png)


#

---

<br>

> [\[Dreamhack\] Background: Computer Architecture](https://dreamhack.io/lecture/courses/43)

