## Command Injection

이용자의 입력을 시스템 명령어로 실행하게 하는 취약점을 `Command Injection`이라고 부릅니다.

`Command Injection`은 `os.system()` 처럼 명령어를 실행하는 함수에 이용자가 임의의 인자를 전달할 수 있을 때 발생합니다. 예를 들어 `os.system()` 함수에 `/bin/sh`을 인자로 전달 할 수 있다면 쉘을 띄어 우리가 원하는 모든 행위들을 할 수 있습니다.

그러면 어떻게 시스템 함수에 원하는 인자를 전달할 수 있을까요? 리눅스 쉘 프로그램에서 지원하는 메타 문자를 사용하면 됩니다.

`&&`, `;`, `|` 같은 메타 문자들은 여러 개의 명령어를 연속으로 실행시킬 수 있습니다.


<br>
<br>


### Command Injection 실습

아래 코드는 Command Injection이 발생하는 예제 코드입니다.

```python
@app.route('/ping')

def ping():
	ip = request.args.get('ip')
	return os.system(f'ping -c 3 {ip}')
```

* URL 쿼리를 통해 전달되는 `ip`값을 ping 명령어의 인자로 전달합니다.


<br>

Command Injection 취약점을 이용해서 `id` 명령어를 실행해보면

```bash
$ ping -c 3 ; id
ping command is work
        Injected Command: id
        성공하셨습니다!
```




