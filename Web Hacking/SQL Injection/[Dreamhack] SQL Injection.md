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











