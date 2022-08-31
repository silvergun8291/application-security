### 문제 코드

```python
users = {
    'guest': 'guest',
    'user': 'user1234',
    'admin': FLAG
}
```

* guest와 user의 아이디와 비밀번호가 나와있습니다.

<br>

```python
@app.route('/')
def index():
    session_id = request.cookies.get('sessionid', None)
    try:
        # get username from session_storage 
        username = session_storage[session_id]
    except KeyError:
        return render_template('index.html')

    return render_template('index.html', text=f'Hello {username}, {"flag is " + FLAG if username == "admin" else "you are not admin"}')
```

* 메인 페이지 코드입니다.
* username이 admin이면 FLAG를 출력해줍니다.

<br>

```python
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'GET':
        return render_template('login.html')
    elif request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        try:
            # you cannot know admin's pw 
            pw = users[username]
        except:
            return '<script>alert("not found user");history.go(-1);</script>'
        if pw == password:
            resp = make_response(redirect(url_for('index')) )
            session_id = os.urandom(32).hex()
            session_storage[session_id] = username
            resp.set_cookie('sessionid', session_id)
            return resp 
        return '<script>alert("wrong password");history.go(-1);</script>'
```

* 로그인 페이지 코드입니다.
* session id가 session storage에 저장됩니다.

<br>

```python
@app.route('/admin')
def admin():
    # what is it? Does this page tell you session? 
    # It is weird... TODO: the developer should add a routine for checking privilege 
    return session_storage
```
* /admin 페이지 코드입니다.
* session_storage를 반환합니다.

⇾ /admin 페이지에 접속하면 admin의 session_id 값을 얻을 수 있습니다.

<br>
<br>


### 익스플로잇

#### 1. guest 계정으로 로그인

<img src="https://velog.velcdn.com/images/silvergun8291/post/be836779-c2f7-44e4-ab6f-0168e244495f/image.png">

<img src="https://velog.velcdn.com/images/silvergun8291/post/51795632-6281-4983-b2f0-ecd9b2d09861/image.png">

아직 admin 계정으로 로그인 하지 않아서 FLAG 대신 you are not admin이 출력됩니다.

#

#### 2. /admin 페이지 접속

```url
http://host3.dreamhack.games:16061/admin
```

<img src="https://velog.velcdn.com/images/silvergun8291/post/35163ea8-c334-4cb1-9984-58ff06d5cb20/image.png">

admin의 session_id 값이 출력되었습니다.

#

#### 3. session_id 값 변조

<img src="https://velog.velcdn.com/images/silvergun8291/post/b208097d-410d-47ab-92d9-16e542042755/image.png">

session_id 값을 변조하고 새로고침을 하면

<img src="https://velog.velcdn.com/images/silvergun8291/post/b1f92cc3-015c-4a4d-87ca-a144be60fb9f/image.png">

username이 admin으로 변경되어 FLAG가 출력되었습니다.
