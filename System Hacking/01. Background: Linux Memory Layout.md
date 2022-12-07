### 세그먼트

리눅스에서는 프로세스의 메모리를 적재되는 데이터의 용도별로 총 5가지의 세그먼트로 구분합니다.

크게 코드 세크먼트, 데이터 세그먼트, BSS 세그먼트, 힙 세그먼트, 스택 세그먼트가 있습니다.

이렇게 메모리를 용도별로 나누면, 각 용도에 맞게 적절한 권한(읽기, 쓰기, 실행)을 부여할 수 있다는 장점이 있습니다.

![image](https://user-images.githubusercontent.com/81484874/196686274-5becd622-4ac6-4e15-adca-d04439b9bd1d.png)



<br>
<br>


### 코드 세그먼트

실행 가능한 기계어 코드가 위치하는 영역으로 텍스트 세그먼트라고도 불립니다.

코드를 읽고 실행해야 하기 때문에 읽기 권한과 실행 권한이 있습니다.

![code](https://user-images.githubusercontent.com/81484874/196691897-27063e57-2a9b-44ec-89de-4fd8e550e530.jpg)

```c
int main() {
  return 31337;
}
```

위의 `main()` 함수를 컴파일 하면 `554889e5b8697a00005dc3` 라는 기계어 코드가 되는데, 이 코드가 코드 세그먼트에 위치하게 됩니다.


<br>
<br>


### 데이터 세그먼트

초기화된 전역 변수 및 전역 상수들이 위치합니다.

읽기와 쓰기 권한 또는 읽기 전용 권한이 있습니다.

#

데이터 세그먼트는 다시 쓰기 가능한 data 세그먼트와 쓰기 불가능한 rodata(read-only data) 세그먼트로 분류됩니다.

data 세그먼트 : 전역 변수와 같이 프로그램이 실행되면서 값이 변할 수 있는 데이터들이 위치합니다.

rodata 세그먼트 : 상수 같이 프로그램이 실행되면서 값이 변하면 안 되는 데이터들이 위치합니다.

![data](https://user-images.githubusercontent.com/81484874/196692462-f406bfcb-22b1-4f46-967a-a3cc04125dca.jpg)

```c
int data_num = 31337;                       // data
char data_rwstr[] = "writable_data";        // data
const char data_rostr[] = "readonly_data";  // rodata
char *str_ptr = "readonly";  // str_ptr은 data, 문자열 "readonly"는 rodata

int main() { ... }
```


<br>
<br>


### BSS 세그먼트

초기화되지 않은 전역 변수가 위치하고 이 세그먼트의 메모리 영역은 프로그램이 시작될 때, 모두 0으로 값이 초기화됩니다. 그래서 초기화 되지 않은 전역 변수의 값은 0이 됩니다.

읽기와 쓰기 권한이 부여됩니다.

![bss](https://user-images.githubusercontent.com/81484874/196692698-36358ace-a4d0-46cd-9ad8-ebfa54809609.jpg)

```c
int bss_data;	// bss segment

int main() {...}
```


<br>
<br>


### 스택 세그먼트

함수의 인자나 지역 변수와 같은 임시 변수들이 저장됩니다.

운영체제는 프로세스가 시작할 때 작은 크기의 스택 세그먼트를 먼저 할당해주고, 부족해질 때마다 이를 확장해줍니다. 이때 스택은 낮은 주소 쪽으로 확장됩니다.

읽기와 쓰기 권한이 부여됩니다.

![stack](https://user-images.githubusercontent.com/81484874/196692955-b3b8d055-7126-4c52-b3ab-62aa68e8b249.jpg)

```c
void func() {
  int choice = 0;
  
  scanf("%d", &choice);
  
  if (choice)
    call_true();
  else
    call_false();
    
  return 0;
}
```

지역변수 `choice` 가 스택에 저장됩니다.


<br>
<br>


### 힙 세그먼트

힙 데이터가 위치하는 세그먼트로 스택과 마찬가지로 실행 중에 동적으로 할당될 수 있고 스택 세그먼트와 반대 방향으로 자랍니다.

읽기와 쓰기 권한이 부여됩니다.

![heap](https://user-images.githubusercontent.com/81484874/196693699-9e8bc817-b17d-4858-a604-f170fea28fce.jpg)

```c
int main() {
  int *heap_data_ptr =
      malloc(sizeof(*heap_data_ptr));  // 동적 할당한 힙 영역의 주소를 가리킴
  *heap_data_ptr = 31337;              // 힙 영역에 값을 씀
  printf("%d\n", *heap_data_ptr);  // 힙 영역의 값을 사용함
  return 0;
}
```

`*heap_data_ptr` 이 int형이기 때문에 4 Byte 크기의 메모리 공간이 동적으로 할당되어 힙 세그먼트에 들어가게 되고 `heap_data_ptr`은 지역변수 이기 때문에 스택 세그먼트로 들어가게 됩니다.

#
---

<br>

> [Background: Linux Memory Layout
](https://dreamhack.io/lecture/courses/52)
