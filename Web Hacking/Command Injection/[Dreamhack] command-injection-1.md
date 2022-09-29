### 문제 코드

```python
@APP.route('/ping', methods=['GET', 'POST'])
def ping():
    if request.method == 'POST':
        host = request.form.get('host')
        cmd = f'ping -c 3 "{host}"'
        try:
            output = subprocess.check_output(['/bin/sh', '-c', cmd], timeout=5)
            return render_template('ping_result.html', data=output.decode('utf-8'))
        except subprocess.TimeoutExpired:
            return render_template('ping_result.html', data='Timeout !')
        except subprocess.CalledProcessError:
            return render_template('ping_result.html', data=f'an error occurred while executing the command. -> {cmd}')

    return render_template('ping.html')
```

* 사용자로 부터 `host`에 데이터를 받아옵니다.
* `ping -c 3` 뒤에 `host` 값을 붙입니다.
* `/bin/sh ping -c 3 [host]`를 실행하고 출력 문자열을 리턴합니다.

⇾ 명령어를 실행하고 실행 결과를 리턴하는 함수에 사용자가 인자를 전달할 수 있기 때문에 `commnad injection`이 발생합니다.


<br>
<br>


### 익스플로잇


<img src="https://velog.velcdn.com/images/silvergun8291/post/a6409bac-abaf-49b3-9856-46f8771fa782/image.png">

* Host 값을 입력하는 입력창에 8.8.8.8을 입력하고 결과를 확인해보면


<br>


<img src="https://velog.velcdn.com/images/silvergun8291/post/fea6dfac-6db6-448b-b92c-2203d580aa10/image.png">

코드에서 확인한 것 처럼 `ping -c 3 8.8.8.8`  명령을 실행한 결과를 보여줍니다.


<br>


이번에는 `8.8.8.8";"cat" "flag.py` 를 입력값으로 줘서 `command injection`을 시도해보면 

<img src="https://velog.velcdn.com/images/silvergun8291/post/54165cfa-a702-4ca2-9b47-61ede1e9176f/image.png">

`요청한 형식과 일치시키세요.` 라는 메시지가 출력되고 전송이 되지 않습니다. 입력값에 필터링이 걸려 있는거 같습니다.


<br>


처음에는 host에 `8.8.8.8` 을 써서 보내고 프록시를 이용해서 중간에서 host 값을 변조해야 할거 같습니다.

<br>

<img src="https://velog.velcdn.com/images/silvergun8291/post/6a952fc9-0402-4cea-9018-98485b5ee782/image.jpg">


> **\*프록시\***
#
서버와 클라이언트 사이에 중계기로써 대리로 통신을 수행하는 것을 말합니다.

<br>

프록시로 `Burp Suit` 를 사용해서 host 값을 `8.8.8.8`에서 `8.8.8.8";"cat" "flag.py`로 변조해서 보내보겠습니다.

<img src="https://velog.velcdn.com/images/silvergun8291/post/b3630c71-9892-4dc6-be24-d1f00e08f104/image.png">

<img src="https://velog.velcdn.com/images/silvergun8291/post/65c5d7d9-3b58-476c-ace4-29fcec9a1063/image.png">

<img src="https://velog.velcdn.com/images/silvergun8291/post/bea02451-4f30-4da9-9a7b-ab1e72057ee9/image.png">

<img src="https://velog.velcdn.com/images/silvergun8291/post/8c83a273-f9ab-492d-a86e-3df3bd3aa56d/image.png">

결과를 확인해보면 `ping -c 3 8.8.8.8;cat flag.py`가 실행되어서 FLAG가 출력되었습니다.


<br>
<br>

> 출처:  https://dreamhack.io/
