### 문제 코드

```python
users = {
    'guest': 'guest',
    'admin': FLAG
}
```

* users의 아이디와 비밀번호가 나와 있습니다.

#

```python
@app.route('/')
def index():
    username = request.cookies.get('username', None)
    if username:
        return render_template('index.html', text=f'Hello {username}, {"flag is " + FLAG if username == "admin" else "you are not admin"}')
    return render_template('index.html')
```
* 메인 페이지 코드입니다.
* 요청에 포함된 cookie에 따라 username이 결정됩니다.
* username이 admin이면 FLAG를 출력합니다.

#

```python
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'GET':
        return render_template('login.html')
    elif request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        try:
            pw = users[username]
        except:
            return '<script>alert("not found user");history.go(-1);</script>'
        if pw == password:
            resp = make_response(redirect(url_for('index')) )
            resp.set_cookie('username', username)
            return resp 
        return '<script>alert("wrong password");history.go(-1);</script>'
```

* 로그인 페이지입니다.

⇾ cookie의 username을 admin으로 조작하면 admin으로 로그인 할 수 있습니다.


<br>
<br>


### 익스플로잇

#### 1. guest로 로그인

<img src="https://velog.velcdn.com/images/silvergun8291/post/f4201053-24a3-4a5a-afe7-8776f220b287/image.png">

<img src="https://velog.velcdn.com/images/silvergun8291/post/c0b973b3-5fa7-4124-85ca-f19d569356a7/image.png">

아직 admin 계정으로 로그인하지 않아서 FLAG 대신 you are not admin이 출력됩니다.

#

#### 2. cookie의 username 값 변경

<img src="https://velog.velcdn.com/images/silvergun8291/post/c9c25ba6-b92d-488b-9256-9923af1d6f7d/image.png">

username 값을 변경하고 새로고침을 해보면

<img src="https://velog.velcdn.com/images/silvergun8291/post/86f8cea7-7f34-4539-9a35-0ec14753c8ee/image.png">

admin으로 로그인되어 FLAG가 출력되었습니다.
